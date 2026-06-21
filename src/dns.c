/* src/dns.c - name resolution + address utilities (ports system_dns,
 * string_is_ipv4, resolve_host_or_ip_to_ip, get_local_ip). */
#include "zcio/dns.h"
#include "internal.h"

/* True if `s` is a dotted-quad IPv4 literal. Port of string_is_ipv4. */
bool zcio_is_ipv4(const char *s) {
    if (!s || !*s) return false;
    int seg = 0;            /* current segment index 0..3            */
    int seg_len = 0;        /* digits in current segment             */
    int seg_val = 0;        /* numeric value of current segment      */
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        unsigned char ch = *p;
        if (ch >= '0' && ch <= '9') {
            if (++seg_len > 3) return false;
            seg_val = seg_val * 10 + (ch - '0');
            continue;
        }
        if (ch == '.') {
            if (seg >= 3) return false;       /* too many dots        */
            if (seg_len == 0) return false;   /* empty segment        */
            if (seg_val > 255) return false;
            ++seg;
            seg_len = 0;
            seg_val = 0;
            continue;
        }
        return false;                          /* invalid character    */
    }
    if (seg != 3) return false;                /* need exactly 4 parts */
    if (seg_len == 0 || seg_val > 255) return false;
    return true;
}

/* queryFamily: resolve all records of `family` into a NULL-terminated string
 * vector. Returns NULL on failure (caller distinguishes via *out_count). */
static char **dns_query_family(int family, const char *host, size_t *out_count) {
    if (out_count) *out_count = 0;
    if (!host) return NULL;
    zcio_socket_startup();

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *result = NULL;
    int ret = getaddrinfo(host, NULL, &hints, &result);
    if (ret != 0 || !result) {
        zcio_fail_(ZCIO_ERR_DNS, "getaddrinfo(%s) failed: %s", host, gai_strerror(ret));
        return NULL;
    }

    /* count first */
    size_t n = 0;
    for (struct addrinfo *p = result; p; p = p->ai_next) ++n;

    char **vec = (char **)zcio_xcalloc(n + 1, sizeof *vec);
    if (!vec) {
        freeaddrinfo(result);
        zcio_fail_(ZCIO_ERR_NOMEM, "dns: out of memory");
        return NULL;
    }

    size_t i = 0;
    char ipstr[INET6_ADDRSTRLEN];
    for (struct addrinfo *p = result; p; p = p->ai_next) {
        const char *conv = NULL;
        if (family == AF_INET) {
            struct sockaddr_in *v4 = (struct sockaddr_in *)p->ai_addr;
            conv = inet_ntop(AF_INET, &v4->sin_addr, ipstr, sizeof ipstr);
        } else {
            struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)p->ai_addr;
            conv = inet_ntop(AF_INET6, &v6->sin6_addr, ipstr, sizeof ipstr);
        }
        if (!conv) continue;
        char *dup = zcio_strdup_(ipstr);
        if (!dup) {
            freeaddrinfo(result);
            zcio_strv_free(vec, i);
            zcio_fail_(ZCIO_ERR_NOMEM, "dns: out of memory");
            return NULL;
        }
        vec[i++] = dup;
    }
    freeaddrinfo(result);
    vec[i] = NULL;
    if (out_count) *out_count = i;
    return vec;
}

char **zcio_dns_query_a(const char *host, size_t *out_count) {
    return dns_query_family(AF_INET, host, out_count);
}

char **zcio_dns_query_aaaa(const char *host, size_t *out_count) {
#if defined(_WIN32)
    /* Original falls back to A on Windows. */
    return dns_query_family(AF_INET, host, out_count);
#else
    return dns_query_family(AF_INET6, host, out_count);
#endif
}

void zcio_strv_free(char **v, size_t count) {
    if (!v) return;
    for (size_t i = 0; i < count; ++i) free(v[i]);
    free(v);
}

/* Resolve `host` (literal or name) to a single IPv4 string. Caller frees. */
char *zcio_resolve_ipv4(const char *host) {
    if (!host) return NULL;
    if (zcio_is_ipv4(host)) return zcio_strdup_(host);

    size_t n = 0;
    char **ips = zcio_dns_query_a(host, &n);
    if (!ips || n == 0) {
        if (ips) zcio_strv_free(ips, n);
        zcio_fail_(ZCIO_ERR_DNS, "could not resolve host: %s", host);
        return NULL;
    }
    char *ip = zcio_strdup_(ips[0]);
    zcio_strv_free(ips, n);
    if (!ip) zcio_fail_(ZCIO_ERR_NOMEM, "dns: out of memory");
    return ip;
}

/* Best-effort primary local IPv4 via UDP-connect-to-8.8.8.8. Caller frees. */
char *zcio_local_ipv4(void) {
    zcio_socket_startup();
    zcio_socket fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == ZCIO_INVALID_SOCKET) {
        zcio_fail_(ZCIO_ERR, "local_ipv4: socket() failed");
        return NULL;
    }

    struct sockaddr_in remote;
    memset(&remote, 0, sizeof remote);
    remote.sin_family = AF_INET;
    remote.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &remote.sin_addr);

    if (connect(fd, (struct sockaddr *)&remote, sizeof remote) != 0) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR, "local_ipv4: connect() failed");
        return NULL;
    }

    struct sockaddr_in local;
    socklen_t addr_len = sizeof local;
    if (getsockname(fd, (struct sockaddr *)&local, &addr_len) != 0) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR, "local_ipv4: getsockname() failed");
        return NULL;
    }

    char buf[64] = {0};
    inet_ntop(AF_INET, &local.sin_addr, buf, sizeof buf);
    zcio_closesocket(fd);
    char *out = zcio_strdup_(buf);
    if (!out) zcio_fail_(ZCIO_ERR_NOMEM, "local_ipv4: out of memory");
    return out;
}
