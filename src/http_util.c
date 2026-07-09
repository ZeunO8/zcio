/* src/http_util.c - shared plumbing for the HTTP server modules.
 *
 * Growable byte buffers, bounded header lists, limit resolution, and the
 * validation/formatting helpers every protocol module leans on. All of it is
 * single-pass and allocation-bounded: caps are checked BEFORE memory is
 * committed, and nothing here is super-linear in attacker-controlled input.
 */
#include "http_internal.h"

#include <ctype.h>
#include <time.h>

/* ========================================================================= *
 *  zhs_buf
 * ========================================================================= */

int zhs_buf_reserve_(zhs_buf *b, size_t extra) {
    if (extra > SIZE_MAX - b->len) return ZCIO_ERR_NOMEM;
    size_t need = b->len + extra;
    if (need <= b->cap) return ZCIO_OK;
    size_t cap = b->cap ? b->cap : 256;
    while (cap < need) {
        if (cap > SIZE_MAX / 2) { cap = need; break; }
        cap *= 2;
    }
    uint8_t *nd = (uint8_t *)realloc(b->data, cap);
    if (!nd) return ZCIO_ERR_NOMEM;
    b->data = nd;
    b->cap = cap;
    return ZCIO_OK;
}

int zhs_buf_append_(zhs_buf *b, const void *src, size_t n) {
    if (n == 0) return ZCIO_OK;
    int r = zhs_buf_reserve_(b, n);
    if (r != ZCIO_OK) return r;
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return ZCIO_OK;
}

int zhs_buf_append_str_(zhs_buf *b, const char *s) {
    return zhs_buf_append_(b, s, strlen(s));
}

int zhs_buf_append_u8_(zhs_buf *b, uint8_t v) {
    return zhs_buf_append_(b, &v, 1);
}

void zhs_buf_consume_(zhs_buf *b, size_t n) {
    if (n > ZHS_AVAIL(b)) n = ZHS_AVAIL(b); /* defensive clamp */
    b->off += n;
    /* Compact so a long-lived connection cannot accrete a dead prefix: free
     * region reset when empty, memmove when the prefix dominates the data. */
    if (b->off == b->len) {
        b->off = b->len = 0;
    } else if (b->off >= 4096 && b->off >= b->len - b->off) {
        memmove(b->data, b->data + b->off, b->len - b->off);
        b->len -= b->off;
        b->off = 0;
    }
}

void zhs_buf_reset_(zhs_buf *b) { b->off = b->len = 0; }

void zhs_buf_free_(zhs_buf *b) {
    if (!b) return;
    free(b->data);
    memset(b, 0, sizeof *b);
}

/* ========================================================================= *
 *  limits
 * ========================================================================= */

void zhs_limits_resolve_(zhs_limits *lim, const zcio_http_server_config *cfg) {
    memset(lim, 0, sizeof *lim);
    lim->max_header_bytes      = cfg && cfg->max_header_bytes      ? cfg->max_header_bytes      : (size_t)32 * 1024;
    lim->max_headers           = cfg && cfg->max_headers           ? cfg->max_headers           : 128;
    lim->max_body_bytes        = cfg && cfg->max_body_bytes        ? cfg->max_body_bytes        : (size_t)64 * 1024 * 1024;
    lim->max_url_bytes         = cfg && cfg->max_url_bytes         ? cfg->max_url_bytes         : 8192;
    lim->max_streams           = cfg && cfg->max_streams           ? cfg->max_streams           : 128;
    lim->max_requests_per_conn = cfg && cfg->max_requests_per_conn ? cfg->max_requests_per_conn : 1024;
    lim->max_connections       = cfg && cfg->max_connections       ? cfg->max_connections       : 1024;
    lim->max_out_bytes         = cfg && cfg->max_out_bytes         ? cfg->max_out_bytes         : (size_t)4 * 1024 * 1024;
    lim->header_timeout_ms     = cfg && cfg->header_timeout_ms     ? cfg->header_timeout_ms     : 10000;
    lim->idle_timeout_ms       = cfg && cfg->idle_timeout_ms       ? cfg->idle_timeout_ms       : 60000;
    lim->write_timeout_ms      = cfg && cfg->write_timeout_ms      ? cfg->write_timeout_ms      : 30000;
    lim->drain_timeout_ms      = cfg && cfg->drain_timeout_ms      ? cfg->drain_timeout_ms      : 5000;
}

/* ========================================================================= *
 *  zhs_hdrs
 * ========================================================================= */

int zhs_hdrs_add_(zhs_hdrs *h, const char *name, size_t nlen,
                  const char *value, size_t vlen,
                  const zhs_limits *lim, bool lower_name) {
    if (h->n >= lim->max_headers)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: too many headers");
    /* Accumulated name+value bytes ride under the same roof as the raw header
     * block; the +32-per-field mirrors RFC 9113's list-size accounting. The cap
     * (2x the header budget) and the running sum are both computed overflow-safe
     * so a pathological max_header_bytes near SIZE_MAX can't wrap the check. */
    size_t cap = lim->max_header_bytes > SIZE_MAX / 2
               ? SIZE_MAX : lim->max_header_bytes * 2;
    if (nlen > lim->max_header_bytes || vlen > lim->max_header_bytes ||
        nlen + vlen + 32 > cap - h->bytes)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: header block too large");

    if (h->n == h->cap) {
        size_t ncap = h->cap ? h->cap * 2 : 8;
        if (ncap > lim->max_headers) ncap = lim->max_headers;
        zhs_hdr *nv = (zhs_hdr *)realloc(h->v, ncap * sizeof *nv);
        if (!nv) return ZCIO_ERR_NOMEM;
        h->v = nv;
        h->cap = ncap;
    }

    char *nm = (char *)zcio_xmalloc(nlen + 1);
    char *vl = (char *)zcio_xmalloc(vlen + 1);
    if (!nm || !vl) { free(nm); free(vl); return ZCIO_ERR_NOMEM; }
    for (size_t i = 0; i < nlen; i++)
        nm[i] = lower_name ? (char)tolower((unsigned char)name[i]) : name[i];
    nm[nlen] = '\0';
    memcpy(vl, value, vlen);
    vl[vlen] = '\0';

    h->v[h->n].name = nm;
    h->v[h->n].value = vl;
    h->n++;
    h->bytes += nlen + vlen + 32;
    return ZCIO_OK;
}

/* ci compare against a stored (lowercased) name. */
static bool hdr_name_eq(const char *stored, const char *query) {
    size_t i = 0;
    for (; stored[i] && query[i]; i++)
        if (stored[i] != (char)tolower((unsigned char)query[i])) return false;
    return stored[i] == '\0' && query[i] == '\0';
}

const char *zhs_hdrs_get_(const zhs_hdrs *h, const char *name) {
    if (!h || !name) return NULL;
    for (size_t i = 0; i < h->n; i++)
        if (hdr_name_eq(h->v[i].name, name)) return h->v[i].value;
    return NULL;
}

size_t zhs_hdrs_count_(const zhs_hdrs *h, const char *name) {
    size_t c = 0;
    if (!h || !name) return 0;
    for (size_t i = 0; i < h->n; i++)
        if (hdr_name_eq(h->v[i].name, name)) c++;
    return c;
}

void zhs_hdrs_free_(zhs_hdrs *h) {
    if (!h) return;
    for (size_t i = 0; i < h->n; i++) {
        free(h->v[i].name);
        free(h->v[i].value);
    }
    free(h->v);
    memset(h, 0, sizeof *h);
}

/* ========================================================================= *
 *  validation
 * ========================================================================= */

/* RFC 9110 tchar: "!#$%&'*+-.^_`|~" / DIGIT / ALPHA */
static bool is_tchar(unsigned char c) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
        return true;
    switch (c) {
        case '!': case '#': case '$': case '%': case '&': case '\'':
        case '*': case '+': case '-': case '.': case '^': case '_':
        case '`': case '|': case '~':
            return true;
        default:
            return false;
    }
}

bool zhs_token_ok_(const char *s, size_t n) {
    if (!s || n == 0) return false;
    for (size_t i = 0; i < n; i++)
        if (!is_tchar((unsigned char)s[i])) return false;
    return true;
}

bool zhs_lower_token_ok_(const char *s, size_t n) {
    if (!s || n == 0) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 'A' && c <= 'Z') return false;
        if (!is_tchar(c)) return false;
    }
    return true;
}

bool zhs_value_ok_(const char *s, size_t n) {
    if (!s) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c < 0x20 && c != '\t') || c == 0x7f) return false;
    }
    return true;
}

/* --- UTF-8 (Bjoern Hoehrmann's DFA; states are multiples of 12) ---------- */

static const uint8_t utf8_dfa[] = {
    /* byte -> character class */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, 9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, 7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2, 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
    10,3,3,3,3,3,3,3,3,3,3,3,3,4,3,3, 11,6,6,6,5,8,8,8,8,8,8,8,8,8,8,8,
    /* class + state -> new state */
    0,12,24,36,60,96,84,12,12,12,48,72, 12,12,12,12,12,12,12,12,12,12,12,12,
    12, 0,12,12,12,12,12, 0,12, 0,12,12, 12,24,12,12,12,12,12,24,12,24,12,12,
    12,12,12,12,12,12,12,24,12,12,12,12, 12,24,12,12,12,12,12,12,12,24,12,12,
    12,12,12,12,12,12,12,36,12,36,12,12, 12,36,12,12,12,12,12,36,12,36,12,12,
    12,36,12,12,12,12,12,12,12,12,12,12,
};

uint32_t zhs_utf8_step_(uint32_t state, uint8_t byte) {
    return utf8_dfa[256 + state + utf8_dfa[byte]];
}

bool zhs_utf8_valid_(const void *s, size_t n) {
    const uint8_t *p = (const uint8_t *)s;
    uint32_t st = ZHS_UTF8_ACCEPT;
    for (size_t i = 0; i < n; i++) {
        st = zhs_utf8_step_(st, p[i]);
        if (st == ZHS_UTF8_REJECT) return false;
    }
    return st == ZHS_UTF8_ACCEPT;
}

/* ========================================================================= *
 *  request-target decoding
 * ========================================================================= */

static int hexval(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Percent-decode [in, in+n) into out (same size or smaller). Rejects bad %XX
 * and decoded control bytes / NUL outright. Returns decoded length or a
 * negated zcio_result. */
static int64_t pct_decode(const char *in, size_t n, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < n;) {
        unsigned char c = (unsigned char)in[i];
        if (c == '%') {
            if (n - i < 3) return ZCIO_ERR_PROTOCOL; /* need "%XX" */
            int hi = hexval((unsigned char)in[i + 1]);
            int lo = hexval((unsigned char)in[i + 2]);
            if (hi < 0 || lo < 0) return ZCIO_ERR_PROTOCOL;
            c = (unsigned char)((hi << 4) | lo);
            i += 3;
        } else {
            i += 1;
        }
        /* Decoded control bytes (incl. NUL) never reach a handler. */
        if (c < 0x20 || c == 0x7f) return ZCIO_ERR_PROTOCOL;
        out[o++] = (char)c;
    }
    return (int64_t)o;
}

/* RFC 3986 remove_dot_segments on an already-decoded, '/'-rooted path.
 * In-place segment stack; linear time. An attempt to pop above the root
 * ("/../") is treated as hostile and rejected. */
static int remove_dot_segments(char *path, size_t len, size_t *out_len) {
    size_t o = 0; /* output write cursor; output always starts with '/' */
    size_t i = 0;
    while (i < len) {
        /* invariant: path[i] == '/' at each segment start */
        size_t seg = i + 1;
        size_t end = seg;
        while (end < len && path[end] != '/') end++;
        size_t slen = end - seg;
        if (slen == 1 && path[seg] == '.') {
            /* skip "." */
        } else if (slen == 2 && path[seg] == '.' && path[seg + 1] == '.') {
            /* pop last output segment */
            if (o == 0) return ZCIO_ERR_PROTOCOL; /* escape above root */
            while (o > 0 && path[o - 1] != '/') o--;
            if (o > 0) o--; /* remove the '/' too */
        } else {
            path[o++] = '/';
            memmove(path + o, path + seg, slen);
            o += slen;
        }
        i = end;
        /* trailing '/' (incl. after "." / "..") keeps directory-ish shape */
        if (i == len - 1 && path[i] == '/') {
            path[o++] = '/';
            break;
        }
    }
    if (o == 0) path[o++] = '/';
    *out_len = o;
    return ZCIO_OK;
}

int zhs_decode_target_(const char *raw, size_t rawlen, const zhs_limits *lim,
                       char **path_out, char **query_out) {
    *path_out = NULL;
    *query_out = NULL;
    if (!raw || rawlen == 0)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: empty request target");
    if (rawlen > lim->max_url_bytes)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: request target too long");

    /* Asterisk-form (OPTIONS *) passes through verbatim. */
    if (rawlen == 1 && raw[0] == '*') {
        *path_out = zcio_strdup_("*");
        return *path_out ? ZCIO_OK : ZCIO_ERR_NOMEM;
    }
    if (raw[0] != '/')
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: non-origin-form target");

    /* Split at the first '?'; the query stays raw (but CTL-checked). */
    size_t plen = rawlen;
    const char *q = memchr(raw, '?', rawlen);
    if (q) plen = (size_t)(q - raw);

    char *path = (char *)zcio_xmalloc(plen + 2); /* room for lone "/" */
    if (!path) return ZCIO_ERR_NOMEM;
    int64_t dlen = pct_decode(raw, plen, path);
    if (dlen < 0) {
        free(path);
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: malformed request path");
    }
    size_t norm_len = 0;
    if (remove_dot_segments(path, (size_t)dlen, &norm_len) != ZCIO_OK) {
        free(path);
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: path escapes root");
    }
    path[norm_len] = '\0';

    if (q) {
        size_t qlen = rawlen - plen - 1;
        if (!zhs_value_ok_(q + 1, qlen)) {
            free(path);
            return zcio_fail_(ZCIO_ERR_PROTOCOL, "http: control bytes in query");
        }
        char *query = (char *)zcio_xmalloc(qlen + 1);
        if (!query) { free(path); return ZCIO_ERR_NOMEM; }
        memcpy(query, q + 1, qlen);
        query[qlen] = '\0';
        *query_out = query;
    }
    *path_out = path;
    return ZCIO_OK;
}

/* ========================================================================= *
 *  formatting
 * ========================================================================= */

void zhs_http_date_(char out[32]) {
    static const char *DAYS[] = { "Sun","Mon","Tue","Wed","Thu","Fri","Sat" };
    static const char *MONS[] = { "Jan","Feb","Mar","Apr","May","Jun",
                                  "Jul","Aug","Sep","Oct","Nov","Dec" };
    time_t now = time(NULL);
    struct tm tm_utc;
#if defined(_WIN32)
    gmtime_s(&tm_utc, &now);
#else
    gmtime_r(&now, &tm_utc);
#endif
    snprintf(out, 32, "%s, %02d %s %04d %02d:%02d:%02d GMT",
             DAYS[tm_utc.tm_wday], tm_utc.tm_mday, MONS[tm_utc.tm_mon],
             tm_utc.tm_year + 1900, tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec);
}

const char *zhs_status_text_(int status) {
    switch (status) {
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 204: return "No Content";
        case 206: return "Partial Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 411: return "Length Required";
        case 413: return "Content Too Large";
        case 414: return "URI Too Long";
        case 415: return "Unsupported Media Type";
        case 421: return "Misdirected Request";
        case 426: return "Upgrade Required";
        case 429: return "Too Many Requests";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 505: return "HTTP Version Not Supported";
        default:  return "";
    }
}

/* ========================================================================= *
 *  request teardown
 * ========================================================================= */

void zhs_req_reset_(zcio_http_req *req) {
    if (!req) return;
    free(req->method);
    free(req->path);
    free(req->query);
    free(req->authority);
    zhs_hdrs_free_(&req->headers);
    zhs_buf_free_(&req->body);
    memset(req, 0, sizeof *req);
}
