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
#include <stdlib.h>
#include <string.h>

#define ZCIO_HTTP_MAX_REDIRECTS 5

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

    /* host[:port] runs up to the first '/'. */
    const char *slash = strchr(p, '/');
    size_t hostport_len = slash ? (size_t)(slash - p) : strlen(p);

    /* path. */
    const char *path_src = slash ? slash : "/";
    out->path = zcio_strdup_(path_src);
    if (!out->path) { url_free(out); return zcio_fail_(ZCIO_ERR_NOMEM, "http: out of memory"); }

    /* split host / port within hostport_len. */
    const char *port_sep = NULL;
    for (size_t i = 0; i < hostport_len; i++) {
        if (p[i] == ':') { port_sep = p + i; break; }
    }

    size_t host_len = port_sep ? (size_t)(port_sep - p) : hostport_len;
    out->host = (char *)zcio_xmalloc(host_len + 1);
    if (!out->host) { url_free(out); return zcio_fail_(ZCIO_ERR_NOMEM, "http: out of memory"); }
    memcpy(out->host, p, host_len);
    out->host[host_len] = '\0';

    if (port_sep) {
        const char *port_str = port_sep + 1;
        size_t port_str_len = hostport_len - (host_len + 1);
        if (port_str_len == 0) {
            out->port = out->secure ? 443 : 80;
        } else {
            out->port = atoi(port_str);   /* port_str points into uri, atoi stops at '/' */
            if (out->port <= 0) out->port = out->secure ? 443 : 80;
        }
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
    if (b->len + extra <= b->cap) return ZCIO_OK;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < b->len + extra) cap *= 2;
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

/* Build "VERB PATH HTTP/1.1\r\nHost: ..\r\n<headers>\r\nContent-Length: n\r\n\r\n"
 * followed by the raw body, into *out. Returns ZCIO_OK or negated result. */
static int build_request(buf_t *out, const char *method, const zcio_url *u,
                         const zcio_http_header *headers, size_t header_count,
                         const void *body, size_t body_len) {
    memset(out, 0, sizeof *out);
    char clbuf[32];

    if (buf_append_str(out, method) != ZCIO_OK) goto oom;
    if (buf_append_char(out, ' ') != ZCIO_OK) goto oom;
    if (buf_append_str(out, u->path) != ZCIO_OK) goto oom;
    if (buf_append_str(out, " HTTP/1.1\r\nHost: ") != ZCIO_OK) goto oom;
    if (buf_append_str(out, u->host) != ZCIO_OK) goto oom;
    if (buf_append_str(out, "\r\n") != ZCIO_OK) goto oom;

    for (size_t i = 0; i < header_count; i++) {
        if (!headers[i].key) continue;
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
 * and, when non-NULL, *location_out with a malloc'd redirect target. Returns
 * ZCIO_OK or a negated result (leaving *resp zeroed on error). */
static int do_exchange(const char *method, const char *url,
                       const zcio_http_header *headers, size_t header_count,
                       const void *body, size_t body_len,
                       zcio_http_response *resp, char **location_out) {
    memset(resp, 0, sizeof *resp);
    if (location_out) *location_out = NULL;

    zcio_url u;
    int pr = url_parse(url, &u);
    if (pr != ZCIO_OK) return pr;

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
        int r = do_exchange(method, current, headers, header_count, body, n, &resp, &location);
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
            free(current);
            current = location;          /* take ownership */
            zcio_http_response_free(&resp);
            memset(&resp, 0, sizeof resp);
            continue;
        }
        free(location);
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
