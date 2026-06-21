/* src/http.c - minimal synchronous HTTP/1.1 client.
 *
 * Port of http_client.cpp + http_common.cpp. Parses a URL, opens a TCP (or
 * TLS) connection through the net layer, writes a request, reads and parses the
 * response (status line + headers + Content-Length body), and follows 3xx
 * redirects (up to ZCIO_HTTP_MAX_REDIRECTS).
 *
 * Memory ownership: zcio_http_request fills a zcio_http_response whose every
 * string field (protocol/version/status_code/status_text/headers_json/body) is
 * malloc'd; the caller releases the whole struct with zcio_http_response_free.
 * On any error a zeroed struct (status == 0, all pointers NULL) is returned;
 * zcio_http_response_free is safe to call on it (it only frees non-NULL fields).
 */
#include "zcio/http.h"
#include "zcio/net.h"
#include "zcio/tls.h"
#include "zcio/stream.h"
#include "internal.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ZCIO_HTTP_MAX_REDIRECTS 5

/* Hard cap on a single response (headers + body) to bound memory use against a
 * hostile or runaway server. 64 MiB. */
#define ZCIO_HTTP_MAX_RESPONSE ((size_t)64 * 1024 * 1024)

/* ------------------------------ URL parsing ----------------------------- */

typedef struct {
    char *scheme;   /* malloc'd, lowercased */
    bool  secure;   /* https? */
    char *host;     /* malloc'd */
    int   port;
    char *path;     /* malloc'd, includes leading '/'; "/" if empty */
} zcio_url;

static void url_free(zcio_url *u) {
    if (!u) return;
    free(u->scheme);
    free(u->host);
    free(u->path);
    u->scheme = u->host = u->path = NULL;
}

/* Parse `uri` into *out. Returns ZCIO_OK or a negated zcio_result. */
static int url_parse(const char *uri, zcio_url *out) {
    memset(out, 0, sizeof *out);
    if (!uri) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "http: NULL url");

    const char *colon = strchr(uri, ':');
    if (!colon)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: scheme not found in '%s'", uri);

    size_t scheme_len = (size_t)(colon - uri);
    char *scheme = (char *)zcio_xmalloc(scheme_len + 1);
    if (!scheme) return zcio_fail_(ZCIO_ERR_NOMEM, "http: out of memory");
    for (size_t i = 0; i < scheme_len; i++)
        scheme[i] = (char)tolower((unsigned char)uri[i]);
    scheme[scheme_len] = '\0';

    if (strcmp(scheme, "http") != 0 && strcmp(scheme, "https") != 0) {
        free(scheme);
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: unsupported scheme '%s'", uri);
    }
    out->scheme = scheme;
    out->secure = (strcmp(scheme, "https") == 0);

    /* Skip "://" (or just ':'). */
    const char *p = colon + 1;
    if (p[0] == '/' && p[1] == '/') p += 2;

    /* authority runs up to the first '/' (or end). */
    const char *slash = strchr(p, '/');
    const char *auth = p;
    size_t auth_len = slash ? (size_t)(slash - p) : strlen(p);

    /* path. */
    const char *path_src = slash ? slash : "/";
    out->path = zcio_strdup_(path_src);
    if (!out->path) { url_free(out); return zcio_fail_(ZCIO_ERR_NOMEM, "http: out of memory"); }

    /* Strip userinfo: "user:pass@host" -> skip past the last '@' in authority. */
    {
        const char *at = NULL;
        for (size_t i = 0; i < auth_len; i++)
            if (auth[i] == '@') at = auth + i;
        if (at) {
            size_t consumed = (size_t)(at + 1 - auth);
            auth += consumed;
            auth_len -= consumed;
        }
    }

    /* Split host[:port]. Handle IPv6 literal in brackets "[::1]" / "[::1]:8443". */
    const char *host_begin;
    size_t host_len;
    const char *port_str = NULL;
    size_t port_str_len = 0;

    if (auth_len > 0 && auth[0] == '[') {
        const char *rb = memchr(auth, ']', auth_len);
        if (!rb) { url_free(out); return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: unterminated IPv6 literal in '%s'", uri); }
        host_begin = auth + 1;
        host_len = (size_t)(rb - host_begin);
        const char *after = rb + 1;
        size_t after_len = auth_len - (size_t)(after - auth);
        if (after_len > 0) {
            if (after[0] != ':') { url_free(out); return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: malformed authority in '%s'", uri); }
            port_str = after + 1;
            port_str_len = after_len - 1;
        }
    } else {
        const char *port_sep = memchr(auth, ':', auth_len);
        host_begin = auth;
        host_len = port_sep ? (size_t)(port_sep - auth) : auth_len;
        if (port_sep) {
            port_str = port_sep + 1;
            port_str_len = auth_len - (host_len + 1);
        }
    }

    out->host = (char *)zcio_xmalloc(host_len + 1);
    if (!out->host) { url_free(out); return zcio_fail_(ZCIO_ERR_NOMEM, "http: out of memory"); }
    memcpy(out->host, host_begin, host_len);
    out->host[host_len] = '\0';

    if (port_str && port_str_len > 0) {
        /* Parse and validate the port strictly: digits only, range 1..65535. */
        char pbuf[16];
        if (port_str_len >= sizeof pbuf) {
            url_free(out);
            return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: invalid port in '%s'", uri);
        }
        memcpy(pbuf, port_str, port_str_len);
        pbuf[port_str_len] = '\0';
        char *end = NULL;
        long port = strtol(pbuf, &end, 10);
        if (end == pbuf || *end != '\0' || port < 1 || port > 65535) {
            url_free(out);
            return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: invalid port in '%s'", uri);
        }
        out->port = (int)port;
    } else {
        out->port = out->secure ? 443 : 80;
    }

    return ZCIO_OK;
}

/* ------------------------- dynamic byte buffer -------------------------- */

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} buf_t;

static int buf_reserve(buf_t *b, size_t extra) {
    if (extra > SIZE_MAX - b->len) return ZCIO_ERR_NOMEM; /* len+extra overflow */
    size_t need = b->len + extra;
    if (need <= b->cap) return ZCIO_OK;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) { cap = need; break; } /* doubling would overflow */
        cap *= 2;
    }
    char *nd = (char *)realloc(b->data, cap);
    if (!nd) return ZCIO_ERR_NOMEM;
    b->data = nd;
    b->cap = cap;
    return ZCIO_OK;
}

static int buf_append(buf_t *b, const void *src, size_t n) {
    if (n == 0) return ZCIO_OK;
    int r = buf_reserve(b, n);
    if (r != ZCIO_OK) return r;
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return ZCIO_OK;
}

static int buf_append_str(buf_t *b, const char *s) {
    return buf_append(b, s, strlen(s));
}

static int buf_append_char(buf_t *b, char c) {
    return buf_append(b, &c, 1);
}

/* ----------------------------- JSON helper ------------------------------ */

/* Append `s` to `b` with quotes/backslashes escaped (minimal JSON escaping). */
static int json_append_escaped(buf_t *b, const char *s) {
    for (; *s; s++) {
        if (*s == '"' || *s == '\\') {
            if (buf_append_char(b, '\\') != ZCIO_OK) return ZCIO_ERR_NOMEM;
        }
        if (buf_append_char(b, *s) != ZCIO_OK) return ZCIO_ERR_NOMEM;
    }
    return ZCIO_OK;
}

/* ------------------------- request construction ------------------------- */

/* Reject strings containing CR, LF, or other control chars (0x00-0x1F, 0x7F)
 * that could be used for HTTP request/header injection. Returns true if safe. */
static bool header_token_ok(const char *s) {
    if (!s) return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p < 0x20 || *p == 0x7f) return false;
    }
    return true;
}

/* Build "VERB PATH HTTP/1.1\r\nHost: ..\r\n<headers>\r\nContent-Length: n\r\n\r\n"
 * followed by the raw body, into *out. Returns ZCIO_OK or negated result. */
static int build_request(buf_t *out, const char *method, const zcio_url *u,
                         const zcio_http_header *headers, size_t header_count,
                         const void *body, size_t body_len) {
    memset(out, 0, sizeof *out);
    char clbuf[32];

    /* Guard against CRLF/header injection via a hostile method. */
    if (!header_token_ok(method))
        return zcio_fail_(ZCIO_ERR_INVALID_ARG, "http: illegal characters in method");

    if (buf_append_str(out, method) != ZCIO_OK) goto oom;
    if (buf_append_char(out, ' ') != ZCIO_OK) goto oom;
    if (buf_append_str(out, u->path) != ZCIO_OK) goto oom;
    if (buf_append_str(out, " HTTP/1.1\r\nHost: ") != ZCIO_OK) goto oom;
    if (buf_append_str(out, u->host) != ZCIO_OK) goto oom;
    if (buf_append_str(out, "\r\n") != ZCIO_OK) goto oom;

    for (size_t i = 0; i < header_count; i++) {
        if (!headers[i].key) continue;
        /* Skip any header whose key or value carries injection characters. */
        if (!header_token_ok(headers[i].key)) continue;
        if (headers[i].value && !header_token_ok(headers[i].value)) continue;
        if (buf_append_str(out, headers[i].key) != ZCIO_OK) goto oom;
        if (buf_append_str(out, ": ") != ZCIO_OK) goto oom;
        if (buf_append_str(out, headers[i].value ? headers[i].value : "") != ZCIO_OK) goto oom;
        if (buf_append_str(out, "\r\n") != ZCIO_OK) goto oom;
    }

    snprintf(clbuf, sizeof clbuf, "Content-Length: %zu\r\n\r\n", body_len);
    if (buf_append_str(out, clbuf) != ZCIO_OK) goto oom;

    if (body && body_len)
        if (buf_append(out, body, body_len) != ZCIO_OK) goto oom;

    return ZCIO_OK;
oom:
    free(out->data);
    memset(out, 0, sizeof *out);
    return zcio_fail_(ZCIO_ERR_NOMEM, "http: out of memory building request");
}

/* --------------------------- response reading --------------------------- */

/* Read the entire response (headers + body) off `s` into a single buffer. */
static int read_all(zcio_stream *s, buf_t *out) {
    memset(out, 0, sizeof *out);
    char chunk[8192];
    for (;;) {
        int64_t r = zcio_read(s, chunk, sizeof chunk);
        if (r < 0) {
            free(out->data);
            memset(out, 0, sizeof *out);
            return zcio_fail_((zcio_result)r, "http: read failed");
        }
        if (r == 0) break; /* EOF */
        if (out->len + (size_t)r > ZCIO_HTTP_MAX_RESPONSE) {
            free(out->data);
            memset(out, 0, sizeof *out);
            return zcio_fail_(ZCIO_ERR_PROTOCOL,
                              "http: response exceeds %zu byte limit", ZCIO_HTTP_MAX_RESPONSE);
        }
        if (buf_append(out, chunk, (size_t)r) != ZCIO_OK) {
            free(out->data);
            memset(out, 0, sizeof *out);
            return zcio_fail_(ZCIO_ERR_NOMEM, "http: out of memory reading response");
        }
    }
    return ZCIO_OK;
}

/* Find a header value (case-insensitive key) in the raw header block
 * [hdr_begin, hdr_end). Returns a malloc'd copy of the value or NULL. */
static char *find_header_value(const char *hdr_begin, const char *hdr_end, const char *key) {
    size_t key_len = strlen(key);
    const char *line = hdr_begin;
    while (line < hdr_end) {
        const char *eol = memchr(line, '\n', (size_t)(hdr_end - line));
        const char *line_end = eol ? eol : hdr_end;
        const char *colon = memchr(line, ':', (size_t)(line_end - line));
        if (colon) {
            size_t this_key_len = (size_t)(colon - line);
            /* strip trailing \r already excluded; key has no spaces */
            if (this_key_len == key_len) {
                bool match = true;
                for (size_t i = 0; i < key_len; i++) {
                    if (tolower((unsigned char)line[i]) != tolower((unsigned char)key[i])) {
                        match = false; break;
                    }
                }
                if (match) {
                    const char *v = colon + 1;
                    while (v < line_end && (*v == ' ' || *v == '\t')) v++;
                    const char *ve = line_end;
                    while (ve > v && (ve[-1] == '\r')) ve--;
                    size_t vlen = (size_t)(ve - v);
                    char *out = (char *)zcio_xmalloc(vlen + 1);
                    if (!out) return NULL;
                    memcpy(out, v, vlen);
                    out[vlen] = '\0';
                    return out;
                }
            }
        }
        if (!eol) break;
        line = eol + 1;
    }
    return NULL;
}

/* dup a [begin,end) range into a malloc'd NUL-terminated string. */
static char *dup_range(const char *begin, const char *end) {
    size_t n = (size_t)(end - begin);
    char *out = (char *)zcio_xmalloc(n + 1);
    if (!out) return NULL;
    memcpy(out, begin, n);
    out[n] = '\0';
    return out;
}

/* Parse the raw response in `raw` and fill *resp. `location_out` (may be NULL)
 * receives a malloc'd Location header value when present (for redirects).
 * Returns ZCIO_OK or negated result. */
static int parse_response(const buf_t *raw, zcio_http_response *resp, char **location_out) {
    memset(resp, 0, sizeof *resp);
    if (location_out) *location_out = NULL;

    /* find header/body separator "\r\n\r\n". */
    const char *data = raw->data;
    size_t len = raw->len;
    const char *sep = NULL;
    if (data) {
        for (size_t i = 0; i + 3 < len; i++) {
            if (data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n') {
                sep = data + i; break;
            }
        }
    }
    if (!sep)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: no header terminator in response");

    const char *body_begin = sep + 4;
    const char *hdr_block = data;     /* whole [start, sep) includes status line */

    /* status line ends at first \n. */
    const char *sl_end = memchr(hdr_block, '\n', (size_t)(sep - hdr_block));
    if (!sl_end)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: malformed status line");
    const char *sl = hdr_block;
    const char *sl_stop = sl_end;
    if (sl_stop > sl && sl_stop[-1] == '\r') sl_stop--;

    /* "HTTP/1.1 200 OK" : split into proto/version, code, text. */
    const char *space1 = memchr(sl, ' ', (size_t)(sl_stop - sl));
    if (!space1)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: malformed status line");

    /* protocol/version from "HTTP/1.1". */
    const char *pv = sl;
    const char *pv_end = space1;
    const char *vslash = memchr(pv, '/', (size_t)(pv_end - pv));
    if (vslash) {
        resp->protocol = dup_range(pv, vslash);            /* "HTTP" */
        resp->version  = dup_range(vslash + 1, pv_end);    /* "1.1"  */
    } else {
        resp->protocol = dup_range(pv, pv_end);
        resp->version  = zcio_strdup_("");
    }

    const char *space2 = NULL;
    {
        const char *q = space1 + 1;
        space2 = memchr(q, ' ', (size_t)(sl_stop - q));
    }
    const char *code_begin = space1 + 1;
    const char *code_end = space2 ? space2 : sl_stop;
    resp->status_code = dup_range(code_begin, code_end);
    if (space2 && space2 + 1 <= sl_stop)
        resp->status_text = dup_range(space2 + 1, sl_stop);
    else
        resp->status_text = zcio_strdup_("");

    resp->status = resp->status_code ? atoi(resp->status_code) : 0;

    /* header lines: from after status line up to sep. */
    const char *hdr_begin = sl_end + 1;

    /* Build headers_json: {"k":"v",...} */
    buf_t json = {0};
    if (buf_append_char(&json, '{') != ZCIO_OK) goto oom;
    {
        const char *line = hdr_begin;
        bool first = true;
        while (line < sep) {
            const char *eol = memchr(line, '\n', (size_t)(sep - line));
            const char *line_end = eol ? eol : sep;
            const char *trim_end = line_end;
            if (trim_end > line && trim_end[-1] == '\r') trim_end--;
            if (trim_end == line) { if (!eol) break; line = eol + 1; continue; }

            const char *colon = memchr(line, ':', (size_t)(trim_end - line));
            if (colon) {
                char *k = dup_range(line, colon);
                const char *v = colon + 1;
                while (v < trim_end && (*v == ' ' || *v == '\t')) v++;
                char *val = dup_range(v, trim_end);
                if (!k || !val) { free(k); free(val); goto oom; }
                if (!first) { if (buf_append_char(&json, ',') != ZCIO_OK) { free(k); free(val); goto oom; } }
                first = false;
                int ok = buf_append_char(&json, '"') == ZCIO_OK
                      && json_append_escaped(&json, k) == ZCIO_OK
                      && buf_append_str(&json, "\":\"") == ZCIO_OK
                      && json_append_escaped(&json, val) == ZCIO_OK
                      && buf_append_char(&json, '"') == ZCIO_OK;
                free(k); free(val);
                if (!ok) goto oom;
            }
            if (!eol) break;
            line = eol + 1;
        }
    }
    if (buf_append_char(&json, '}') != ZCIO_OK) goto oom;
    if (buf_append_char(&json, '\0') != ZCIO_OK) goto oom;
    resp->headers_json = json.data; /* transfer ownership */
    json.data = NULL;

    /* Location for redirects. */
    if (location_out)
        *location_out = find_header_value(hdr_begin, sep, "Location");

    /* Body: prefer Content-Length, else everything to EOF. */
    {
        char *cl = find_header_value(hdr_begin, sep, "Content-Length");
        size_t avail = (size_t)((data + len) - body_begin);
        size_t body_len = avail;
        if (cl) {
            long long n = atoll(cl);
            free(cl);
            if (n >= 0 && (size_t)n < avail) body_len = (size_t)n;
        }
        char *body = (char *)zcio_xmalloc(body_len + 1);
        if (!body) goto oom;
        memcpy(body, body_begin, body_len);
        body[body_len] = '\0';
        resp->body = body;
        resp->body_size = body_len;
    }

    return ZCIO_OK;
oom:
    free(json.data);
    {
        if (location_out) { free(*location_out); *location_out = NULL; }
    }
    zcio_http_response_free(resp);
    memset(resp, 0, sizeof *resp);
    return zcio_fail_(ZCIO_ERR_NOMEM, "http: out of memory parsing response");
}

/* ------------------------- single request round ------------------------- */

/* Perform one request/response exchange (no redirect handling). Fills *resp
 * and, when non-NULL, *location_out with a malloc'd redirect target. When
 * `prev` is non-NULL it receives a copy of the parsed URL of THIS request
 * (caller owns and must url_free it) so a redirect can be resolved/validated
 * against the request that produced it. Returns ZCIO_OK or a negated result
 * (leaving *resp zeroed on error). */
static int do_exchange(const char *method, const char *url,
                       const zcio_http_header *headers, size_t header_count,
                       const void *body, size_t body_len,
                       zcio_http_response *resp, char **location_out,
                       zcio_url *prev) {
    memset(resp, 0, sizeof *resp);
    if (location_out) *location_out = NULL;

    zcio_url u;
    int pr = url_parse(url, &u);
    if (pr != ZCIO_OK) return pr;

    /* Hand the caller a copy of the parsed URL for redirect resolution. */
    if (prev) {
        memset(prev, 0, sizeof *prev);
        prev->scheme = zcio_strdup_(u.scheme);
        prev->secure = u.secure;
        prev->host   = zcio_strdup_(u.host);
        prev->port   = u.port;
        prev->path   = zcio_strdup_(u.path);
        if ((u.scheme && !prev->scheme) || (u.host && !prev->host) || (u.path && !prev->path)) {
            url_free(prev);
            url_free(&u);
            return zcio_fail_(ZCIO_ERR_NOMEM, "http: out of memory");
        }
    }

    /* Establish connection. */
    zcio_tls_ctx *tls = NULL;
    zcio_tcp_client *client = NULL;
    if (u.secure) {
        tls = zcio_tls_client_ctx(u.host);
        if (!tls) { url_free(&u); return zcio_fail_(ZCIO_ERR_TLS, "http: TLS context creation failed"); }
        client = zcio_tcp_client_connect_tls(u.host, u.port, tls, true);
    } else {
        client = zcio_tcp_client_connect(u.host, u.port);
    }
    if (!client) {
        if (tls) zcio_tls_ctx_free(tls);
        url_free(&u);
        return zcio_fail_(ZCIO_ERR_CONNECT, "http: connect to %s:%d failed", u.host, u.port);
    }

    zcio_stream *s = zcio_tcp_client_stream(client);
    if (!s) {
        zcio_tcp_client_free(client);
        if (tls) zcio_tls_ctx_free(tls);
        url_free(&u);
        return zcio_fail_(ZCIO_ERR, "http: no stream for connection");
    }

    /* Build and send request. */
    buf_t req;
    int br = build_request(&req, method, &u, headers, header_count, body, body_len);
    if (br != ZCIO_OK) {
        zcio_tcp_client_free(client);
        if (tls) zcio_tls_ctx_free(tls);
        url_free(&u);
        return br;
    }

    int64_t wrote = zcio_write_full(s, req.data, req.len);
    free(req.data);
    if (wrote < 0 || (size_t)wrote != req.len) {
        zcio_tcp_client_free(client);
        if (tls) zcio_tls_ctx_free(tls);
        url_free(&u);
        return zcio_fail_(ZCIO_ERR, "http: failed to send request");
    }

    /* Read the full response, then parse. */
    buf_t raw;
    int rr = read_all(s, &raw);
    zcio_tcp_client_free(client);
    if (tls) zcio_tls_ctx_free(tls);
    url_free(&u);
    if (rr != ZCIO_OK) return rr;

    int p = parse_response(&raw, resp, location_out);
    free(raw.data);
    return p;
}

/* ------------------------------ redirects ------------------------------- */

/* Resolve a redirect Location against the URL that produced it (`prev`).
 *
 * Security: if the previous request was secure (https) we REFUSE to follow a
 * target that downgrades to plaintext http. On refusal *out is left NULL and
 * the function returns ZCIO_ERR_PROTOCOL so the caller stops and returns the
 * 3xx response as-is rather than resending headers in cleartext.
 *
 * Supports:
 *   - absolute "http(s)://..." targets (downgrade-checked),
 *   - relative "/path" targets, resolved against prev's scheme/host/port.
 * Returns ZCIO_OK with a malloc'd absolute URL in *out, or a negated result. */
static int resolve_redirect(const zcio_url *prev, const char *location, char **out) {
    *out = NULL;
    if (!location || !*location) return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: empty Location");

    /* Absolute URL? (has a scheme before any '/'). */
    bool absolute = false;
    {
        const char *c = strchr(location, ':');
        const char *s = strchr(location, '/');
        if (c && (!s || c < s)) absolute = true;
    }

    if (absolute) {
        /* Downgrade guard: https -> http is refused. */
        if (prev && prev->secure) {
            size_t n = strlen(location);
            if (n >= 5 && (location[0]=='h'||location[0]=='H') &&
                tolower((unsigned char)location[1])=='t' &&
                tolower((unsigned char)location[2])=='t' &&
                tolower((unsigned char)location[3])=='p' &&
                (location[4]==':' /* "http:" exactly, not "https:" */)) {
                return zcio_fail_(ZCIO_ERR_PROTOCOL,
                                  "http: refusing https->http redirect downgrade");
            }
        }
        *out = zcio_strdup_(location);
        return *out ? ZCIO_OK : zcio_fail_(ZCIO_ERR_NOMEM, "http: out of memory");
    }

    /* Relative target: must be rooted ('/path'); resolve against prev. */
    if (!prev || !prev->scheme || !prev->host)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: cannot resolve relative redirect");
    if (location[0] != '/')
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: unsupported relative redirect '%s'", location);

    /* scheme://host[:port]path  (wrap IPv6 host in brackets if needed). */
    bool v6 = strchr(prev->host, ':') != NULL;
    int default_port = prev->secure ? 443 : 80;
    char portbuf[16];
    portbuf[0] = '\0';
    if (prev->port != default_port)
        snprintf(portbuf, sizeof portbuf, ":%d", prev->port);

    size_t need = strlen(prev->scheme) + 3 /* :// */
                + (v6 ? 2 : 0) + strlen(prev->host)
                + strlen(portbuf) + strlen(location) + 1;
    char *abs = (char *)zcio_xmalloc(need);
    if (!abs) return zcio_fail_(ZCIO_ERR_NOMEM, "http: out of memory");
    snprintf(abs, need, "%s://%s%s%s%s%s",
             prev->scheme,
             v6 ? "[" : "", prev->host, v6 ? "]" : "",
             portbuf, location);
    *out = abs;
    return ZCIO_OK;
}

/* ------------------------------- public API ----------------------------- */

zcio_http_response zcio_http_request(const char *method, const char *url,
                                     const zcio_http_header *headers, size_t header_count,
                                     const void *body, size_t n) {
    zcio_http_response resp;
    memset(&resp, 0, sizeof resp);

    char *current = zcio_strdup_(url);
    if (url && !current) {
        zcio_fail_(ZCIO_ERR_NOMEM, "http: out of memory");
        return resp; /* zeroed */
    }

    for (int redirect = 0; redirect <= ZCIO_HTTP_MAX_REDIRECTS; redirect++) {
        char *location = NULL;
        zcio_url prev;
        int r = do_exchange(method, current, headers, header_count, body, n,
                            &resp, &location, &prev);
        if (r != ZCIO_OK) {
            free(current);
            free(location);
            /* resp already zeroed by do_exchange on error */
            memset(&resp, 0, sizeof resp);
            return resp;
        }

        /* Follow 3xx with a Location header. */
        bool is_redirect = (resp.status >= 300 && resp.status < 400);
        if (is_redirect && location && location[0] && redirect < ZCIO_HTTP_MAX_REDIRECTS) {
            char *next = NULL;
            int rr = resolve_redirect(&prev, location, &next);
            free(location);
            url_free(&prev);
            if (rr != ZCIO_OK || !next) {
                /* Refused (e.g. downgrade) or unresolvable: return the 3xx
                 * response as-is rather than resending in cleartext. */
                free(next);
                break;
            }
            free(current);
            current = next;              /* take ownership */
            zcio_http_response_free(&resp);
            memset(&resp, 0, sizeof resp);
            continue;
        }
        free(location);
        url_free(&prev);
        break;
    }

    free(current);
    return resp;
}

zcio_http_response zcio_http_get(const char *url) {
    return zcio_http_request("GET", url, NULL, 0, NULL, 0);
}

zcio_http_response zcio_http_delete(const char *url) {
    return zcio_http_request("DELETE", url, NULL, 0, NULL, 0);
}

zcio_http_response zcio_http_post(const char *url, const void *body, size_t n) {
    return zcio_http_request("POST", url, NULL, 0, body, n);
}

zcio_http_response zcio_http_put(const char *url, const void *body, size_t n) {
    return zcio_http_request("PUT", url, NULL, 0, body, n);
}

void zcio_http_response_free(zcio_http_response *r) {
    if (!r) return;
    /* Only non-NULL fields were malloc'd; safe on a zeroed struct. */
    free((void *)r->protocol);
    free((void *)r->version);
    free((void *)r->status_code);
    free((void *)r->status_text);
    free((void *)r->headers_json);
    free((void *)r->body);
    memset(r, 0, sizeof *r);
}
