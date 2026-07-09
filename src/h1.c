/* src/h1.c - HTTP/1.1 (RFC 9112) request parser + response serializer.
 *
 * A sans-I/O state machine: zh1_feed_ consumes bytes from the loop's input
 * zhs_buf and appends wire bytes (responses, including its own error responses)
 * to the loop's output zhs_buf. It never touches a socket. Parsing is strictly
 * single-pass and linear; every wire length is bounds-checked against zhs_limits
 * before it drives a copy, and the smuggling defenses (CRLF-only line endings,
 * no obs-fold, single Host, no TE+CL, strict chunked framing) are enforced, not
 * optional.
 *
 * Ownership: the request object (c->req) and its malloc'd fields belong to this
 * module and are released by zhs_req_reset_ between pipelined requests and by
 * zh1_free_. The out buffer and the per-connection loop context (c->user) are
 * borrowed from http_server.c and outlive the zh1_conn.
 */
#include "http_internal.h"

/* Private cross-TU helper defined in http_server.c: the configured public
 * redirect host (cfg->host), or NULL to fall back to the request's Host header.
 * `struct zcio_http_server` is opaque to this module, so redirect mode reaches
 * cfg->host through this accessor rather than the (pinned) http_internal.h. */
const char *zhs_redirect_host_(struct zcio_http_server *srv);

/* Parser stages. Body framing splits into the CL path and the chunked
 * sub-states; TRAILER reads the (ignored, bounded) chunked trailer section. */
enum {
    H1_REQLINE = 0,
    H1_HEADERS,
    H1_BODY_CL,
    H1_CHUNK_SIZE,
    H1_CHUNK_DATA,
    H1_CHUNK_CRLF,
    H1_TRAILER,
    H1_DEAD,        /* error/redirect emitted; connection is closing */
};

/* Stage helper results. Negative zcio_result codes are returned directly for
 * hard (OOM) errors and take precedence in the feed dispatcher. */
enum { P_MORE = 1, P_NEXT = 2, P_CLOSE = 3, P_COMPLETE = 4 };

/* finish_request outcomes. */
enum { FIN_OK = 0, FIN_DETACHED = 1, FIN_HARD = 2 };

/* A chunk-size line (size + extensions) longer than this is treated as hostile
 * even though the header cap is larger: extensions carry no useful payload. */
#define H1_CHUNK_LINE_MAX 4096u

struct zh1_conn {
    struct zcio_http_server *srv;
    const zhs_limits *lim;      /* borrowed; stable for the conn's lifetime */
    uint32_t          flags;    /* ZH1_F_SECURE / ZH1_F_REDIRECT */
    zhs_buf          *out;      /* borrowed (loop-owned, stable address) */
    void             *user;     /* loop per-connection context */

    int      state;
    zcio_http_req req;          /* the request under assembly */

    size_t   head_bytes;        /* request-line + header bytes this section */
    bool     receiving;         /* actively reading a request head */
    bool     is_http10;         /* HTTP/1.0 (non-persistent by default) */
    bool     keep_alive;        /* client permits persistence for this request */
    bool     graceful;          /* server asked: close after the current req */
    bool     close_after;       /* this response closes the connection */
    uint32_t req_count;         /* requests already completed */

    bool     chunked;
    uint64_t cl_remaining;      /* Content-Length bytes still to read */
    uint64_t chunk_remaining;   /* current chunk bytes still to read */
};

/* ========================================================================= *
 *  tiny local helpers (kept out of ctype to stay locale-independent)
 * ========================================================================= */

static bool h1_is_digit(int c) { return c >= '0' && c <= '9'; }

static int h1_hex(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool h1_ci_eq_n(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int ca = (unsigned char)a[i], cb = (unsigned char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return false;
    }
    return true;
}
static bool h1_ci_eq(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    return la == lb && h1_ci_eq_n(a, b, la);
}

static char *h1_dupn(const uint8_t *s, size_t n) {
    char *p = (char *)zcio_xmalloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

/* True iff `tok` appears as a comma-separated element of `list` (ci, OWS-trimmed). */
static bool h1_token_in_list(const char *list, const char *tok) {
    size_t tl = strlen(tok);
    const char *p = list;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        const char *start = p;
        while (*p && *p != ',') p++;
        const char *end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;
        if ((size_t)(end - start) == tl && h1_ci_eq_n(start, tok, tl)) return true;
    }
    return false;
}

/* Decoded byte count of a base64 string, or -1 if not well-formed base64. */
static int h1_b64_declen(const char *s) {
    size_t n = strlen(s);
    if (n == 0 || n % 4 != 0) return -1;
    size_t pad = 0;
    if (s[n - 1] == '=') pad++;
    if (n >= 2 && s[n - 2] == '=') pad++;
    for (size_t i = 0; i < n - pad; i++) {
        int c = (unsigned char)s[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '+' || c == '/';
        if (!ok) return -1;
    }
    return (int)(n / 4 * 3 - pad);
}

/* Find a CRLF-terminated line in `in` without consuming it. Returns 1 with the
 * line body (CRLF excluded) and the total consumed length (CRLF included), 0 if
 * no complete line is buffered yet, or -1 on a bare LF (smuggling defense). */
static int h1_find_line(zhs_buf *in, const uint8_t **line, size_t *linelen,
                        size_t *consumed) {
    const uint8_t *p = ZHS_PTR(in);
    size_t avail = ZHS_AVAIL(in);
    const uint8_t *lf = (const uint8_t *)memchr(p, '\n', avail);
    if (!lf) return 0;
    size_t idx = (size_t)(lf - p);
    if (idx == 0 || p[idx - 1] != '\r') return -1;  /* bare LF / lone \n */
    *line = p;
    *linelen = idx - 1;
    *consumed = idx + 1;
    return 1;
}

/* ========================================================================= *
 *  response serialization
 * ========================================================================= */

#define APP(expr) do { if ((expr) != ZCIO_OK) return ZCIO_ERR_NOMEM; } while (0)

/* Minimal self-generated error/redirect responses always close the connection
 * and never carry a body. */
static int h1_emit_simple(zh1_conn *c, int status, const char *extra_name,
                          const char *extra_value) {
    zhs_buf *o = c->out;
    char sl[64], date[32];
    snprintf(sl, sizeof sl, "HTTP/1.1 %d %s\r\n", status, zhs_status_text_(status));
    zhs_http_date_(date);
    APP(zhs_buf_append_str_(o, sl));
    APP(zhs_buf_append_str_(o, "date: "));
    APP(zhs_buf_append_str_(o, date));
    APP(zhs_buf_append_str_(o, "\r\nserver: zcio\r\n"));
    if (extra_name && extra_value) {
        APP(zhs_buf_append_str_(o, extra_name));
        APP(zhs_buf_append_str_(o, ": "));
        APP(zhs_buf_append_str_(o, extra_value));
        APP(zhs_buf_append_str_(o, "\r\n"));
    }
    APP(zhs_buf_append_str_(o, "content-length: 0\r\nconnection: close\r\n\r\n"));
    c->close_after = true;
    c->state = H1_DEAD;
    return P_CLOSE;
}

static int h1_error(zh1_conn *c, int status) {
    return h1_emit_simple(c, status, NULL, NULL);
}

/* respond_fn: serialize a FINAL (already validated + merged) header set with h1
 * framing. The policy layer supplied Date/Server/HSTS/Alt-Svc; we add
 * Content-Length and Connection and honor body suppression. */
static int h1_respond(zcio_http_req *req, int status,
                      const zcio_http_header *hdrs, size_t nhdrs,
                      const void *body, size_t body_len) {
    zh1_conn *c = (zh1_conn *)req->owner;
    zhs_buf  *o = c->out;

    bool bodiless = (status >= 100 && status < 200) || status == 204 || status == 304;
    bool suppress = bodiless || req->is_head;

    /* Persist unless the client, the server (graceful), an earlier error, or
     * the per-connection request cap forces a close. */
    bool close_conn = c->close_after || c->graceful || !c->keep_alive ||
                      (c->req_count + 1 >= c->lim->max_requests_per_conn);

    char sl[64];
    snprintf(sl, sizeof sl, "HTTP/1.1 %d %s\r\n", status, zhs_status_text_(status));
    APP(zhs_buf_append_str_(o, sl));

    for (size_t i = 0; i < nhdrs; i++) {
        APP(zhs_buf_append_str_(o, hdrs[i].key));
        APP(zhs_buf_append_str_(o, ": "));
        APP(zhs_buf_append_str_(o, hdrs[i].value ? hdrs[i].value : ""));
        APP(zhs_buf_append_str_(o, "\r\n"));
    }

    /* Bodiless statuses carry no framing; HEAD keeps the would-be GET length. */
    if (!bodiless) {
        char clbuf[48];
        snprintf(clbuf, sizeof clbuf, "content-length: %zu\r\n", body_len);
        APP(zhs_buf_append_str_(o, clbuf));
    }
    APP(zhs_buf_append_str_(o, close_conn ? "connection: close\r\n\r\n"
                                          : "connection: keep-alive\r\n\r\n"));
    if (!suppress && body && body_len)
        APP(zhs_buf_append_(o, body, body_len));

    if (close_conn) c->close_after = true;
    /* Over the per-connection output cap: keep the queued bytes but close once
     * they drain (never grow without bound across pipelined responses). */
    if (o->len > c->lim->max_out_bytes) c->close_after = true;
    return ZCIO_OK;
}

/* Redirect-listener response: 301 to the https:// equivalent. */
static int h1_redirect(zh1_conn *c) {
    const char *host = zhs_redirect_host_(c->srv);
    if (!host || !host[0]) host = c->req.authority;   /* fall back to Host */
    if (!host || !host[0]) return h1_error(c, 400);

    zhs_buf *o = c->out;
    char date[32];
    zhs_http_date_(date);
    APP(zhs_buf_append_str_(o, "HTTP/1.1 301 Moved Permanently\r\ndate: "));
    APP(zhs_buf_append_str_(o, date));
    APP(zhs_buf_append_str_(o, "\r\nserver: zcio\r\nlocation: https://"));
    APP(zhs_buf_append_str_(o, host));
    APP(zhs_buf_append_str_(o, c->req.path ? c->req.path : "/"));
    if (c->req.query) {
        APP(zhs_buf_append_str_(o, "?"));
        APP(zhs_buf_append_str_(o, c->req.query));
    }
    APP(zhs_buf_append_str_(o, "\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"));
    c->close_after = true;
    c->state = H1_DEAD;
    return P_CLOSE;
}

/* ========================================================================= *
 *  request line
 * ========================================================================= */

static int h1_reqline(zh1_conn *c, zhs_buf *in) {
    if (ZHS_AVAIL(in) > 0) c->receiving = true;

    const uint8_t *line; size_t llen, consumed;
    int fr = h1_find_line(in, &line, &llen, &consumed);
    if (fr == 0) {
        if (ZHS_AVAIL(in) > c->lim->max_header_bytes) return h1_error(c, 431);
        return P_MORE;
    }
    if (fr < 0) return h1_error(c, 400);                 /* bare LF */
    if (consumed > c->lim->max_header_bytes - c->head_bytes)
        return h1_error(c, 431);
    c->head_bytes += consumed;

    /* No leading whitespace / empty request line. */
    if (llen == 0 || line[0] == ' ' || line[0] == '\t') {
        zhs_buf_consume_(in, consumed);
        return h1_error(c, 400);
    }

    /* METHOD SP request-target SP HTTP-version */
    const uint8_t *sp1 = (const uint8_t *)memchr(line, ' ', llen);
    if (!sp1) { zhs_buf_consume_(in, consumed); return h1_error(c, 400); }
    size_t mlen = (size_t)(sp1 - line);
    const uint8_t *tstart = sp1 + 1;
    size_t after_m = llen - mlen - 1;
    const uint8_t *sp2 = (const uint8_t *)memchr(tstart, ' ', after_m);
    if (!sp2) { zhs_buf_consume_(in, consumed); return h1_error(c, 400); }
    size_t tlen = (size_t)(sp2 - tstart);
    const uint8_t *vstart = sp2 + 1;
    size_t vlen = (size_t)(llen - (size_t)(vstart - line));

    if (!zhs_token_ok_((const char *)line, mlen)) {
        zhs_buf_consume_(in, consumed);
        return h1_error(c, 400);
    }

    /* Version: exactly HTTP/1.0 or HTTP/1.1; a well-formed other version is 505. */
    if (vlen == 8 && memcmp(vstart, "HTTP/1.1", 8) == 0) {
        c->is_http10 = false;
    } else if (vlen == 8 && memcmp(vstart, "HTTP/1.0", 8) == 0) {
        c->is_http10 = true;
    } else if (vlen >= 6 && memcmp(vstart, "HTTP/", 5) == 0 && h1_is_digit(vstart[5])) {
        zhs_buf_consume_(in, consumed);
        return h1_error(c, 505);
    } else {
        zhs_buf_consume_(in, consumed);
        return h1_error(c, 400);
    }

    if (tlen > c->lim->max_url_bytes) {
        zhs_buf_consume_(in, consumed);
        return h1_error(c, 414);
    }

    c->req.method = h1_dupn(line, mlen);
    if (!c->req.method) { zhs_buf_consume_(in, consumed); return ZCIO_ERR_NOMEM; }
    c->req.is_head = (mlen == 4 && memcmp(line, "HEAD", 4) == 0);

    int dr = zhs_decode_target_((const char *)tstart, tlen, c->lim,
                                &c->req.path, &c->req.query);
    zhs_buf_consume_(in, consumed);
    if (dr != ZCIO_OK) return h1_error(c, 400);

    c->req.version = 1;
    c->state = H1_HEADERS;
    return P_NEXT;
}

/* ========================================================================= *
 *  header block + framing
 * ========================================================================= */

/* Validate Content-Length across all occurrences, returning the value or a
 * negative error status to emit (400 or 413). */
static int h1_frame_content_length(zh1_conn *c, uint64_t *out) {
    const zhs_hdrs *h = &c->req.headers;
    const char *first = NULL;
    for (size_t i = 0; i < h->n; i++) {
        if (strcmp(h->v[i].name, "content-length") != 0) continue;
        /* Reject ANY duplicate Content-Length (even byte-identical): a
         * downstream that rejects duplicates would frame differently. */
        if (first) return 400;
        first = h->v[i].value;
    }
    if (!first || !first[0]) return 400;
    uint64_t v = 0;
    for (const char *p = first; *p; p++) {
        if (!h1_is_digit((unsigned char)*p)) return 400;    /* digits only, no sign/list */
        if (v > (UINT64_MAX - 9) / 10) return 413;          /* overflow => too large */
        v = v * 10 + (uint64_t)(*p - '0');
    }
    if (v > c->lim->max_body_bytes) return 413;
    *out = v;
    return 0;
}

static int h1_headers(zh1_conn *c, zhs_buf *in) {
    for (;;) {
        const uint8_t *line; size_t llen, consumed;
        int fr = h1_find_line(in, &line, &llen, &consumed);
        if (fr == 0) {
            if (ZHS_AVAIL(in) > c->lim->max_header_bytes) return h1_error(c, 431);
            return P_MORE;
        }
        if (fr < 0) return h1_error(c, 400);
        if (consumed > c->lim->max_header_bytes - c->head_bytes)
            return h1_error(c, 431);
        c->head_bytes += consumed;

        if (llen == 0) { zhs_buf_consume_(in, consumed); break; }  /* end of head */

        /* obs-fold (leading SP/HTAB continuation) is rejected outright. */
        if (line[0] == ' ' || line[0] == '\t') {
            zhs_buf_consume_(in, consumed);
            return h1_error(c, 400);
        }
        const uint8_t *colon = (const uint8_t *)memchr(line, ':', llen);
        if (!colon) { zhs_buf_consume_(in, consumed); return h1_error(c, 400); }
        size_t nlen = (size_t)(colon - line);
        /* A non-token name (which also forbids whitespace before ':') is 400. */
        if (!zhs_token_ok_((const char *)line, nlen)) {
            zhs_buf_consume_(in, consumed);
            return h1_error(c, 400);
        }
        const uint8_t *vs = colon + 1, *ve = line + llen;
        while (vs < ve && (*vs == ' ' || *vs == '\t')) vs++;
        while (ve > vs && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
        size_t vlen = (size_t)(ve - vs);
        if (!zhs_value_ok_((const char *)vs, vlen)) {
            zhs_buf_consume_(in, consumed);
            return h1_error(c, 400);
        }
        int a = zhs_hdrs_add_(&c->req.headers, (const char *)line, nlen,
                              (const char *)vs, vlen, c->lim, true);
        zhs_buf_consume_(in, consumed);
        if (a == ZCIO_ERR_PROTOCOL) return h1_error(c, 431);   /* a cap tripped */
        if (a != ZCIO_OK) return a;                            /* NOMEM: hard */
    }

    /* --- Host --- */
    const zhs_hdrs *h = &c->req.headers;
    size_t hostc = zhs_hdrs_count_(h, "host");
    if (!c->is_http10 && hostc != 1) return h1_error(c, 400);
    if (c->is_http10 && hostc > 1)  return h1_error(c, 400);
    if (hostc >= 1) {
        const char *hv = zhs_hdrs_get_(h, "host");
        const char *at = strrchr(hv, '@');          /* strip any userinfo */
        c->req.authority = zcio_strdup_(at ? at + 1 : hv);
        if (!c->req.authority) return ZCIO_ERR_NOMEM;
    }

    /* --- redirect mode: answer 301 before any body handling --- */
    if (c->flags & ZH1_F_REDIRECT) return h1_redirect(c);

    /* --- body framing --- */
    const char *te = zhs_hdrs_get_(h, "transfer-encoding");
    size_t tec = zhs_hdrs_count_(h, "transfer-encoding");
    size_t clc = zhs_hdrs_count_(h, "content-length");
    if (te && clc) return h1_error(c, 400);          /* TE + CL smuggling */
    /* Transfer-Encoding is undefined in HTTP/1.0; a 1.0 hop that ignores it and
     * falls back to read-to-close is a TE-desync vector. Refuse it outright. */
    if (te && c->is_http10) return h1_error(c, 400);

    c->head_bytes = 0;   /* fresh budget for the (chunked) trailer section */
    if (te) {
        if (tec != 1 || !h1_ci_eq(te, "chunked")) return h1_error(c, 501);
        c->chunked = true;
        c->chunk_remaining = 0;
        c->state = H1_CHUNK_SIZE;
    } else if (clc) {
        uint64_t cl = 0;
        int e = h1_frame_content_length(c, &cl);
        if (e) return h1_error(c, e);
        c->cl_remaining = cl;
        c->state = H1_BODY_CL;
    } else {
        c->cl_remaining = 0;                         /* no body */
        c->state = H1_BODY_CL;
    }

    /* --- keep-alive intent --- */
    const char *conn = zhs_hdrs_get_(h, "connection");
    if (c->is_http10)
        c->keep_alive = conn && h1_token_in_list(conn, "keep-alive");
    else
        c->keep_alive = !(conn && h1_token_in_list(conn, "close"));

    return P_NEXT;
}

/* ========================================================================= *
 *  body
 * ========================================================================= */

static int h1_append_body(zh1_conn *c, const uint8_t *p, size_t n) {
    return zhs_buf_append_(&c->req.body, p, n) == ZCIO_OK ? 0 : ZCIO_ERR_NOMEM;
}

static int h1_body_cl(zh1_conn *c, zhs_buf *in) {
    if (c->cl_remaining == 0) return P_COMPLETE;
    size_t avail = ZHS_AVAIL(in);
    if (avail == 0) return P_MORE;
    size_t take = avail < c->cl_remaining ? avail : (size_t)c->cl_remaining;
    int e = h1_append_body(c, ZHS_PTR(in), take);
    if (e) return e;
    zhs_buf_consume_(in, take);
    c->cl_remaining -= take;
    return c->cl_remaining == 0 ? P_COMPLETE : P_MORE;
}

static int h1_body_chunk(zh1_conn *c, zhs_buf *in) {
    for (;;) {
        if (c->state == H1_CHUNK_SIZE) {
            const uint8_t *line; size_t llen, consumed;
            int fr = h1_find_line(in, &line, &llen, &consumed);
            if (fr == 0) {
                if (ZHS_AVAIL(in) > H1_CHUNK_LINE_MAX) return h1_error(c, 400);
                return P_MORE;
            }
            if (fr < 0) return h1_error(c, 400);
            if (llen > H1_CHUNK_LINE_MAX) { zhs_buf_consume_(in, consumed); return h1_error(c, 400); }

            uint64_t size = 0; size_t i = 0; bool any = false;
            for (; i < llen; i++) {
                int hv = h1_hex(line[i]);
                if (hv < 0) break;
                if (size > (UINT64_MAX >> 4)) { zhs_buf_consume_(in, consumed); return h1_error(c, 400); }
                size = (size << 4) | (uint64_t)hv;
                any = true;
            }
            /* after the hex size, only a chunk-extension (";...") may follow */
            if (!any || (i < llen && line[i] != ';')) {
                zhs_buf_consume_(in, consumed);
                return h1_error(c, 400);
            }
            zhs_buf_consume_(in, consumed);
            if (size == 0) { c->state = H1_TRAILER; continue; }
            if (size > c->lim->max_body_bytes - c->req.body.len)
                return h1_error(c, 413);           /* running total cap */
            c->chunk_remaining = size;
            c->state = H1_CHUNK_DATA;
            continue;
        }
        if (c->state == H1_CHUNK_DATA) {
            if (c->chunk_remaining > 0) {
                size_t avail = ZHS_AVAIL(in);
                if (avail == 0) return P_MORE;
                size_t take = avail < c->chunk_remaining ? avail : (size_t)c->chunk_remaining;
                int e = h1_append_body(c, ZHS_PTR(in), take);
                if (e) return e;
                zhs_buf_consume_(in, take);
                c->chunk_remaining -= take;
                if (c->chunk_remaining > 0) return P_MORE;
            }
            c->state = H1_CHUNK_CRLF;
            continue;
        }
        if (c->state == H1_CHUNK_CRLF) {
            if (ZHS_AVAIL(in) < 2) return P_MORE;
            const uint8_t *p = ZHS_PTR(in);
            if (p[0] != '\r' || p[1] != '\n') return h1_error(c, 400);
            zhs_buf_consume_(in, 2);
            c->state = H1_CHUNK_SIZE;
            continue;
        }
        /* H1_TRAILER: consume (ignore) trailer fields until the empty line. */
        {
            const uint8_t *line; size_t llen, consumed;
            int fr = h1_find_line(in, &line, &llen, &consumed);
            if (fr == 0) {
                if (ZHS_AVAIL(in) > c->lim->max_header_bytes) return h1_error(c, 431);
                return P_MORE;
            }
            if (fr < 0) return h1_error(c, 400);
            if (consumed > c->lim->max_header_bytes - c->head_bytes)
                return h1_error(c, 431);
            c->head_bytes += consumed;
            zhs_buf_consume_(in, consumed);
            if (llen == 0) return P_COMPLETE;      /* end of trailer */
            /* trailer fields are not surfaced to the handler */
        }
    }
}

/* ========================================================================= *
 *  dispatch + pipelining
 * ========================================================================= */

/* RFC 6455 opening-handshake validation (does not itself upgrade). */
static void h1_detect_ws(zh1_conn *c) {
    zcio_http_req *r = &c->req;
    if (c->is_http10) return;
    if (!r->method || strcmp(r->method, "GET") != 0) return;
    const zhs_hdrs *h = &r->headers;
    const char *upg = zhs_hdrs_get_(h, "upgrade");
    const char *con = zhs_hdrs_get_(h, "connection");
    const char *key = zhs_hdrs_get_(h, "sec-websocket-key");
    const char *ver = zhs_hdrs_get_(h, "sec-websocket-version");
    if (!upg || !h1_token_in_list(upg, "websocket")) return;
    if (!con || !h1_token_in_list(con, "upgrade")) return;
    if (!key || h1_b64_declen(key) != 16) return;
    if (!ver || strcmp(ver, "13") != 0) return;
    r->ws_upgrade = true;
}

static int h1_finish(zh1_conn *c) {
    zcio_http_req *r = &c->req;
    r->version   = 1;
    r->secure    = (c->flags & ZH1_F_SECURE) != 0;
    r->owner     = c;
    r->stream_id = 0;
    r->respond_fn = h1_respond;

    /* NUL-terminate the body for text convenience (not counted in len). */
    if (zhs_buf_reserve_(&r->body, 1) != ZCIO_OK) return FIN_HARD;
    r->body.data[r->body.len] = '\0';

    h1_detect_ws(c);

    int d = zhs_dispatch_(c->srv, r);
    if (d == 1) return FIN_DETACHED;    /* WebSocket detach: conn handed off */
    c->req_count++;
    return FIN_OK;
}

/* Reset per-request state for the next pipelined request on a kept-alive conn. */
static void h1_reset_next(zh1_conn *c) {
    zhs_req_reset_(&c->req);
    c->state = H1_REQLINE;
    c->head_bytes = 0;
    c->receiving = false;
    c->chunked = false;
    c->cl_remaining = 0;
    c->chunk_remaining = 0;
    c->keep_alive = false;
    c->is_http10 = false;
}

/* ========================================================================= *
 *  public entry points
 * ========================================================================= */

zh1_conn *zh1_new_(struct zcio_http_server *srv, const zhs_limits *lim,
                   uint32_t flags, zhs_buf *out, void *user) {
    zh1_conn *c = (zh1_conn *)zcio_xcalloc(1, sizeof *c);
    if (!c) { zcio_fail_(ZCIO_ERR_NOMEM, "h1: out of memory"); return NULL; }
    c->srv = srv;
    c->lim = lim;
    c->flags = flags;
    c->out = out;
    c->user = user;
    c->state = H1_REQLINE;
    return c;
}

int zh1_feed_(zh1_conn *c, zhs_buf *in) {
    int dispatched = 0;
    for (;;) {
        int r;
        switch (c->state) {
            case H1_REQLINE: r = h1_reqline(c, in); break;
            case H1_HEADERS: r = h1_headers(c, in); break;
            case H1_BODY_CL: r = h1_body_cl(c, in); break;
            case H1_CHUNK_SIZE:
            case H1_CHUNK_DATA:
            case H1_CHUNK_CRLF:
            case H1_TRAILER:  r = h1_body_chunk(c, in); break;
            case H1_DEAD:     return ZH1_CLOSE;
            default:          return zcio_fail_(ZCIO_ERR_PROTOCOL, "h1: bad state");
        }
        if (r < 0) return r;                 /* hard error (OOM) */
        switch (r) {
            case P_MORE:  return dispatched ? ZH1_DISPATCHED : ZH1_NEED_MORE;
            case P_NEXT:  continue;
            case P_CLOSE: return ZH1_CLOSE;
            case P_COMPLETE: {
                int f = h1_finish(c);
                if (f == FIN_DETACHED) return ZH1_DETACHED;
                if (f == FIN_HARD)     return ZCIO_ERR_NOMEM;
                dispatched++;
                if (c->close_after) return ZH1_CLOSE;   /* keep-alive denied */
                h1_reset_next(c);
                continue;
            }
            default: return zcio_fail_(ZCIO_ERR_PROTOCOL, "h1: bad stage code");
        }
    }
}

bool zh1_idle_(const zh1_conn *c) {
    return c->state == H1_REQLINE && !c->receiving;
}

bool zh1_mid_headers_(const zh1_conn *c) {
    return c->receiving && (c->state == H1_REQLINE || c->state == H1_HEADERS);
}

/* True while a request is being received (head OR body), i.e. from the first
 * byte of a request until it is dispatched. Lets the loop bound the whole
 * receive with an absolute deadline so a trickled body cannot hold a slot by
 * resetting the per-read idle timer one byte at a time. */
bool zh1_receiving_(const zh1_conn *c) {
    return c->receiving;
}

void zh1_graceful_(zh1_conn *c) { c->graceful = true; }

void *zh1_user_(zh1_conn *c) { return c->user; }

void zh1_free_(zh1_conn *c) {
    if (!c) return;
    zhs_req_reset_(&c->req);
    free(c);
}
