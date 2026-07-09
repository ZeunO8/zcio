/* src/h3.c - HTTP/3 (RFC 9114) server over the OpenSSL QUIC stack.
 *
 * Unlike h1/h2 (sans-I/O state machines the loop feeds bytes), QUIC owns its
 * own UDP socket and datagram engine, so this module is a self-contained
 * mini event source: it exposes the UDP fd + the next QUIC timer deadline to
 * the server's poll set (zh3_fd_ / zh3_timeout_ms_) and does all accept /
 * read / dispatch / write work inside zh3_process_.
 *
 * The whole real implementation is gated on OpenSSL >= 3.5 with QUIC compiled
 * in (the SSL_new_listener / SSL_accept_connection / SSL_accept_stream server
 * API). Without it every entry point degrades to a harmless stub so ZCIO_TLS=
 * none and older-OpenSSL builds stay green. Setup is failure-tolerant end to
 * end: any error in zh3_new_ yields a clean NULL (never a half-built server),
 * and every accept / read / write loop is bounded so a hostile or broken peer
 * can neither hang nor spin us.
 *
 * Framing (RFC 9114 §7): a request rides one client-initiated bidirectional
 * stream carrying HEADERS (type 0x1, a QPACK field section) then optional
 * DATA (type 0x0) frames, terminated by the stream FIN. We reply on the same
 * stream with HEADERS + DATA and conclude it. Client-initiated unidirectional
 * streams (control, QPACK encoder/decoder) are drained and ignored — we run
 * QPACK with a zero-capacity dynamic table, so no encoder state is needed.
 *
 * Ownership: zh3_srv owns the SSL_CTX, the listener SSL, the UDP fd, and the
 * connection table. Each zh3_conn owns its connection SSL, its control-stream
 * SSL, and its stream table. Each zh3_stream owns its stream SSL plus the
 * request under construction. zh3_free_ tears the tree down leaf-first; per
 * SSL_free(3) a QUIC stream and its parent connection may be freed in any
 * order, so the order here is for clarity, not correctness.
 */
#include "http_internal.h"

#if defined(ZCIO_TLS_OPENSSL)
#  include <openssl/opensslv.h>
#endif

/* Real path only when the QUIC server API is actually present. The extra
 * OPENSSL_NO_QUIC guard beyond the mandated version check keeps a QUIC-less
 * OpenSSL 3.5+ build falling back to the stubs instead of failing to compile
 * (OSSL_QUIC_server_method and friends do not exist there). */
#if defined(ZCIO_TLS_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30500000L && \
    !defined(OPENSSL_NO_QUIC)
#  define ZH3_REAL 1
#else
#  define ZH3_REAL 0
#endif

#if ZH3_REAL
/* ========================================================================= *
 *  Real HTTP/3 implementation (OpenSSL >= 3.5 QUIC)
 * ========================================================================= */

#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/err.h>
#include "tls_ossl_internal.h"

#include <ctype.h>

/* HTTP/3 frame + unidirectional-stream type codes we care about. */
#define H3_FRAME_DATA      0x00u
#define H3_FRAME_HEADERS   0x01u
#define H3_FRAME_SETTINGS  0x04u
#define H3_FRAME_GOAWAY    0x07u
#define H3_UNI_CONTROL     0x00u

/* Bound every "drain what's queued" loop so a misbehaving peer/engine can
 * never keep us spinning inside a single process() pass. */
#define ZH3_ACCEPT_CAP   1024
#define ZH3_READ_CAP     4096
#define ZH3_WRITE_STALL  1000

/* Consume the (checked) result of a best-effort OpenSSL call. Several QUIC
 * setters are marked warn_unused_result but are advisory here; swallowing the
 * code keeps -Wall -Wextra quiet without a bare cast (which GCC ignores). */
#define ZH3_IGN_INT(expr) do { int zh3_ign_ = (expr); (void)zh3_ign_; } while (0)

/* Per-stream frame-parser state (single request stream). */
enum { ZH3_PS_HDR = 0, ZH3_PS_HEADERS, ZH3_PS_DATA, ZH3_PS_SKIP };

typedef struct zh3_conn zh3_conn;

typedef struct zh3_stream {
    SSL       *ssl;          /* the QUIC stream SSL object (owned)            */
    zh3_conn  *conn;         /* back-pointer (not owned)                      */
    uint64_t   id;           /* QUIC stream id                                */
    bool       is_uni;       /* client uni stream: drain + ignore             */
    bool       fin;          /* peer concluded its send side (FIN)            */
    bool       headers_seen; /* a HEADERS frame decoded OK                    */
    bool       dispatched;   /* handler already run for this stream           */
    bool       done;         /* no longer active; free once its send drains   */
    int        pstate;       /* ZH3_PS_*                                      */
    uint64_t   fremain;      /* payload bytes left in the current frame       */
    zhs_buf    in;           /* raw inbound bytes not yet parsed              */
    zhs_buf    hdr;          /* accumulated HEADERS payload (encoded)         */
    zcio_http_req req;       /* request under construction / to dispatch      */
} zh3_stream;

struct zh3_conn {
    SSL          *ssl;         /* QUIC connection SSL object (owned)          */
    SSL          *control;     /* our server control stream (owned) or NULL  */
    zh3_stream  **streams;     /* tracked streams                            */
    size_t        nstreams;
    size_t        cap_streams;
    uint32_t      requests;    /* request streams accepted (per-conn cap)     */
    bool          shutdown_sent;
    bool          goaway_sent;
};

struct zh3_srv {
    struct zcio_http_server *srv; /* owning server (dispatch target); borrowed */
    SSL_CTX     *ctx;
    SSL         *listener;
    zcio_socket  fd;              /* UDP socket we bound (we own + close it)   */
    zhs_limits   lim;
    zh3_conn   **conns;
    size_t        nconns;
    size_t        cap_conns;
    bool          draining;       /* graceful shutdown in progress             */
};

/* ----------------------------- small helpers ---------------------------- */

/* Report a setup failure (with the OpenSSL error string when present) and
 * return NULL so zh3_new_ callers get a clean, crash-free UNSUPPORTED. */
static zh3_srv *h3_setup_fail(const char *what) {
    unsigned long e = ERR_get_error();
    char buf[192];
    if (e) {
        ERR_error_string_n(e, buf, sizeof buf);
        zcio_fail_(ZCIO_ERR_UNSUPPORTED, "http3: %s: %s", what, buf);
    } else {
        zcio_fail_(ZCIO_ERR_UNSUPPORTED, "http3: %s", what);
    }
    return NULL;
}

static char *h3_strndup(const char *s, size_t n) {
    char *o = (char *)zcio_xmalloc(n + 1);
    if (!o) return NULL;
    memcpy(o, s, n);
    o[n] = '\0';
    return o;
}

/* Decode one RFC 9000 §16 varint from p[0,avail). Returns the byte length
 * (1/2/4/8) and writes *out, or 0 when `avail` cannot hold the full varint
 * (caller waits for more). The value is at most 62 bits, so never overflows. */
static size_t h3_varint(const uint8_t *p, size_t avail, uint64_t *out) {
    if (avail < 1) return 0;
    size_t len = (size_t)1 << (p[0] >> 6);   /* top 2 bits select 1/2/4/8 */
    if (avail < len) return 0;
    uint64_t v = (uint64_t)(p[0] & 0x3f);
    for (size_t i = 1; i < len; i++) v = (v << 8) | p[i];
    *out = v;
    return len;
}

/* Append a QUIC varint (minimal encoding). v must fit in 62 bits (all our
 * emitted lengths/types do). Returns ZCIO_OK / ZCIO_ERR_NOMEM. */
static int h3_put_varint(zhs_buf *b, uint64_t v) {
    uint8_t t[8];
    if (v <= 0x3f) {
        t[0] = (uint8_t)v;
        return zhs_buf_append_(b, t, 1);
    }
    if (v <= 0x3fff) {
        t[0] = (uint8_t)(0x40 | (v >> 8)); t[1] = (uint8_t)v;
        return zhs_buf_append_(b, t, 2);
    }
    if (v <= 0x3fffffff) {
        t[0] = (uint8_t)(0x80 | (v >> 24)); t[1] = (uint8_t)(v >> 16);
        t[2] = (uint8_t)(v >> 8);           t[3] = (uint8_t)v;
        return zhs_buf_append_(b, t, 4);
    }
    t[0] = (uint8_t)(0xc0 | (v >> 56)); t[1] = (uint8_t)(v >> 48);
    t[2] = (uint8_t)(v >> 40);          t[3] = (uint8_t)(v >> 32);
    t[4] = (uint8_t)(v >> 24);          t[5] = (uint8_t)(v >> 16);
    t[6] = (uint8_t)(v >> 8);           t[7] = (uint8_t)v;
    return zhs_buf_append_(b, t, 8);
}

/* ----------------------------- header decode ---------------------------- */

/* Collected while QPACK-decoding a HEADERS block; pseudo-headers land in the
 * named slots, ordinary fields go straight into req->headers. */
typedef struct {
    zcio_http_req    *req;
    const zhs_limits *lim;
    char *method, *path, *scheme, *authority; /* malloc'd pseudo-header values */
    bool  regular_seen;   /* a non-pseudo field already emitted                */
    bool  bad;            /* malformed request (fail after decode)             */
    int   err;            /* first hard error (NOMEM) to propagate             */
} h3_hdr_ctx;

static bool h3_name_is(const char *n, size_t nlen, const char *lit) {
    size_t l = strlen(lit);
    return nlen == l && memcmp(n, lit, l) == 0;
}

/* RFC 9114 §4.2: connection-specific fields are forbidden in HTTP/3. */
static bool h3_conn_specific(const char *n, size_t nlen) {
    return h3_name_is(n, nlen, "connection") ||
           h3_name_is(n, nlen, "keep-alive") ||
           h3_name_is(n, nlen, "proxy-connection") ||
           h3_name_is(n, nlen, "transfer-encoding") ||
           h3_name_is(n, nlen, "upgrade");
}

/* zqp_decode_ emit callback. Nonzero return aborts decoding (used only for a
 * hard OOM); malformed inputs set ctx->bad and are rejected after decode. */
static int h3_emit(void *u, const char *name, size_t nlen,
                   const char *value, size_t vlen) {
    h3_hdr_ctx *c = (h3_hdr_ctx *)u;
    if (c->bad || c->err) return 0;

    if (nlen > 0 && name[0] == ':') {
        /* Pseudo-headers must precede all ordinary fields and be known+unique. */
        if (c->regular_seen) { c->bad = true; return 0; }
        if (!zhs_value_ok_(value, vlen)) { c->bad = true; return 0; }
        char **slot = NULL;
        if      (h3_name_is(name, nlen, ":method"))    slot = &c->method;
        else if (h3_name_is(name, nlen, ":path"))      slot = &c->path;
        else if (h3_name_is(name, nlen, ":scheme"))    slot = &c->scheme;
        else if (h3_name_is(name, nlen, ":authority")) slot = &c->authority;
        else { c->bad = true; return 0; }           /* unknown pseudo-header  */
        if (*slot) { c->bad = true; return 0; }      /* duplicate              */
        if (vlen == 0) { c->bad = true; return 0; }
        char *v = h3_strndup(value, vlen);
        if (!v) { c->err = ZCIO_ERR_NOMEM; return ZCIO_ERR_NOMEM; }
        *slot = v;
        return 0;
    }

    /* Ordinary field. Names must already be lowercase tokens (RFC 9114 §4.1.2). */
    c->regular_seen = true;
    if (!zhs_lower_token_ok_(name, nlen)) { c->bad = true; return 0; }
    if (!zhs_value_ok_(value, vlen))      { c->bad = true; return 0; }
    if (h3_conn_specific(name, nlen))     { c->bad = true; return 0; }
    /* TE, if present, may only carry "trailers". */
    if (h3_name_is(name, nlen, "te") &&
        !(vlen == 8 && memcmp(value, "trailers", 8) == 0)) { c->bad = true; return 0; }

    int r = zhs_hdrs_add_(&c->req->headers, name, nlen, value, vlen, c->lim, false);
    if (r == ZCIO_ERR_NOMEM) { c->err = r; return r; }
    if (r != ZCIO_OK) { c->bad = true; return 0; }   /* a cap -> malformed     */
    return 0;
}

/* Decode the fully-buffered HEADERS payload (st->hdr) into st->req. Returns
 * ZCIO_OK on a well-formed request, or a negated result (PROTOCOL/NOMEM). */
static int h3_decode_headers(zh3_stream *st, const zhs_limits *lim) {
    /* An empty field section is malformed (a valid QPACK block always carries
     * at least the encoded prefix); reject before handing zqp_decode_ a
     * zero-length buffer. */
    if (ZHS_AVAIL(&st->hdr) == 0) {
        zhs_buf_free_(&st->hdr);
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "http3: empty HEADERS frame");
    }

    h3_hdr_ctx c;
    memset(&c, 0, sizeof c);
    c.req = &st->req;
    c.lim = lim;

    int r = zqp_decode_(ZHS_PTR(&st->hdr), ZHS_AVAIL(&st->hdr),
                        lim->max_header_bytes, h3_emit, &c);
    zhs_buf_free_(&st->hdr);

    if (r == ZCIO_ERR_NOMEM || c.err == ZCIO_ERR_NOMEM) r = ZCIO_ERR_NOMEM;
    else if (r != ZCIO_OK || c.bad || !c.method || !c.path || !c.scheme)
        r = ZCIO_ERR_PROTOCOL;
    else
        r = ZCIO_OK;

    if (r == ZCIO_OK) {
        st->req.method  = c.method; c.method = NULL;   /* transfer ownership */
        st->req.is_head = strcmp(st->req.method, "HEAD") == 0;
        int dr = zhs_decode_target_(c.path, strlen(c.path), lim,
                                    &st->req.path, &st->req.query);
        if (dr != ZCIO_OK) r = dr;
        if (r == ZCIO_OK && c.authority) {
            st->req.authority = c.authority; c.authority = NULL;
        }
    }

    free(c.method);
    free(c.path);
    free(c.scheme);
    free(c.authority);
    if (r != ZCIO_OK)
        return zcio_fail_(r == ZCIO_ERR_NOMEM ? ZCIO_ERR_NOMEM : ZCIO_ERR_PROTOCOL,
                          "http3: malformed request headers");
    return ZCIO_OK;
}

/* ------------------------------ frame parse ----------------------------- */

/* Advance the per-stream frame parser over whatever is buffered in st->in,
 * consuming complete frames and stopping when it needs more bytes. All wire
 * lengths are bounds-checked before they drive a copy or a body append. */
static int h3_parse(zh3_stream *st, const zhs_limits *lim) {
    for (;;) {
        if (st->pstate == ZH3_PS_HDR) {
            size_t avail = ZHS_AVAIL(&st->in);
            if (avail == 0) return ZCIO_OK;
            const uint8_t *p = ZHS_PTR(&st->in);
            uint64_t ftype = 0, flen = 0;
            size_t n1 = h3_varint(p, avail, &ftype);
            if (n1 == 0) return ZCIO_OK;                  /* need more bytes */
            size_t n2 = h3_varint(p + n1, avail - n1, &flen);
            if (n2 == 0) return ZCIO_OK;                  /* need more bytes */
            zhs_buf_consume_(&st->in, n1 + n2);   /* >= 2 bytes: guarantees progress */

            if (ftype == H3_FRAME_HEADERS && !st->headers_seen) {
                if (flen > lim->max_header_bytes)
                    return zcio_fail_(ZCIO_ERR_PROTOCOL,
                                      "http3: HEADERS frame exceeds header cap");
                st->pstate = ZH3_PS_HEADERS;
            } else if (ftype == H3_FRAME_DATA) {
                st->pstate = ZH3_PS_DATA;
            } else {
                /* Second HEADERS (trailers), or any other/unknown frame:
                 * skip its payload. We never act on trailers or GREASE. */
                st->pstate = ZH3_PS_SKIP;
            }
            st->fremain = flen;
        } else if (st->pstate == ZH3_PS_HEADERS) {
            if (st->fremain > 0) {
                size_t avail = ZHS_AVAIL(&st->in);
                if (avail == 0) return ZCIO_OK;
                size_t take = avail < st->fremain ? avail : (size_t)st->fremain;
                if (zhs_buf_append_(&st->hdr, ZHS_PTR(&st->in), take) != ZCIO_OK)
                    return ZCIO_ERR_NOMEM;
                zhs_buf_consume_(&st->in, take);
                st->fremain -= take;
            }
            if (st->fremain == 0) {   /* whole field section buffered */
                int r = h3_decode_headers(st, lim);
                if (r != ZCIO_OK) return r;
                st->headers_seen = true;
                st->pstate = ZH3_PS_HDR;
            }
        } else if (st->pstate == ZH3_PS_DATA) {
            if (st->fremain > 0) {
                size_t avail = ZHS_AVAIL(&st->in);
                if (avail == 0) return ZCIO_OK;
                size_t take = avail < st->fremain ? avail : (size_t)st->fremain;
                size_t have = st->req.body.len;          /* body.off is always 0 */
                if (take > lim->max_body_bytes - have)
                    return zcio_fail_(ZCIO_ERR_PROTOCOL,
                                      "http3: request body exceeds %zu-byte cap",
                                      lim->max_body_bytes);
                if (zhs_buf_append_(&st->req.body, ZHS_PTR(&st->in), take) != ZCIO_OK)
                    return ZCIO_ERR_NOMEM;
                zhs_buf_consume_(&st->in, take);
                st->fremain -= take;
            }
            if (st->fremain == 0) st->pstate = ZH3_PS_HDR;
        } else { /* ZH3_PS_SKIP */
            if (st->fremain > 0) {
                size_t avail = ZHS_AVAIL(&st->in);
                if (avail == 0) return ZCIO_OK;
                size_t take = avail < st->fremain ? avail : (size_t)st->fremain;
                zhs_buf_consume_(&st->in, take);
                st->fremain -= take;
            }
            if (st->fremain == 0) st->pstate = ZH3_PS_HDR;
        }
    }
}

/* ------------------------------ responding ------------------------------ */

/* Write the whole response blob to a stream, pumping the QUIC engine when the
 * send buffer fills. Bounded by ZH3_WRITE_STALL no-progress spins so it never
 * hangs on a stalled peer (the response is best-effort on failure). */
static int h3_stream_write_all(zh3_stream *st, const uint8_t *p, size_t n) {
    size_t off = 0;
    int stalls = 0;
    while (off < n) {
        size_t w = 0;
        if (SSL_write_ex(st->ssl, p + off, n - off, &w) == 1 && w > 0) {
            off += w;
            stalls = 0;
            continue;
        }
        int err = SSL_get_error(st->ssl, 0);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            if (++stalls > ZH3_WRITE_STALL)
                return zcio_fail_(ZCIO_ERR_TIMEOUT, "http3: response write stalled");
            (void)SSL_handle_events(st->conn->ssl);   /* flush toward the wire */
            continue;
        }
        return zcio_fail_(ZCIO_ERR, "http3: response write failed");
    }
    return ZCIO_OK;
}

/* QPACK-encode one response field, forcing a lowercase name (HTTP/3 requires
 * it; the respond-policy layer may hand us canonical-case names). */
static int h3_encode_field(zhs_buf *out, const char *name, const char *value) {
    size_t n = name ? strlen(name) : 0;
    if (n == 0) return ZCIO_OK;
    char stackbuf[128];
    char *low = stackbuf;
    if (n >= sizeof stackbuf) {
        low = (char *)zcio_xmalloc(n + 1);
        if (!low) return ZCIO_ERR_NOMEM;
    }
    for (size_t i = 0; i < n; i++) low[i] = (char)tolower((unsigned char)name[i]);
    low[n] = '\0';
    int r = zqp_encode_(out, low, value ? value : "");
    if (low != stackbuf) free(low);
    return r;
}

/* respond_fn installed on every h3 request. `hdrs` is the final, filtered
 * header set from the respond policy; we add the QPACK :status pseudo-header,
 * emit a HEADERS frame then (unless suppressed) a DATA frame, and conclude the
 * stream to signal end-of-response. */
static int h3_respond(zcio_http_req *req, int status,
                      const zcio_http_header *hdrs, size_t nhdrs,
                      const void *body, size_t body_len) {
    zh3_stream *st = (zh3_stream *)req->owner;
    if (!st || !st->ssl)
        return zcio_fail_(ZCIO_ERR, "http3: response on a dead stream");

    /* Never send a response body for HEAD / 1xx / 204 / 304 (RFC 9110). */
    bool no_body = req->is_head || status < 200 || status == 204 || status == 304;

    zhs_buf fields = {0};
    zhs_buf out = {0};
    int r = zqp_prefix_encode_(&fields);
    if (r == ZCIO_OK) r = zqp_encode_status_(&fields, status);
    for (size_t i = 0; r == ZCIO_OK && i < nhdrs; i++) {
        if (!hdrs[i].key) continue;
        r = h3_encode_field(&fields, hdrs[i].key, hdrs[i].value);
    }
    /* HEADERS frame: type, length, QPACK field section. */
    if (r == ZCIO_OK) r = h3_put_varint(&out, H3_FRAME_HEADERS);
    if (r == ZCIO_OK) r = h3_put_varint(&out, ZHS_AVAIL(&fields));
    if (r == ZCIO_OK) r = zhs_buf_append_(&out, ZHS_PTR(&fields), ZHS_AVAIL(&fields));
    /* DATA frame (single, holding the whole body). */
    if (r == ZCIO_OK && !no_body && body && body_len) {
        if (r == ZCIO_OK) r = h3_put_varint(&out, H3_FRAME_DATA);
        if (r == ZCIO_OK) r = h3_put_varint(&out, body_len);
        if (r == ZCIO_OK) r = zhs_buf_append_(&out, body, body_len);
    }

    if (r == ZCIO_OK) r = h3_stream_write_all(st, ZHS_PTR(&out), ZHS_AVAIL(&out));
    zhs_buf_free_(&fields);
    zhs_buf_free_(&out);

    /* Conclude our send side regardless: on a write failure this resets the
     * stream cleanly rather than leaving it dangling. */
    ZH3_IGN_INT(SSL_stream_conclude(st->ssl, 0));
    return r;
}

/* ------------------------------ streams --------------------------------- */

static void h3_stream_free(zh3_stream *st) {
    if (!st) return;
    zhs_buf_free_(&st->in);
    zhs_buf_free_(&st->hdr);
    zhs_req_reset_(&st->req);      /* frees any partially built request */
    if (st->ssl) SSL_free(st->ssl);
    free(st);
}

static zh3_stream *h3_stream_new(zh3_conn *c, SSL *ss, bool uni) {
    zh3_stream *st = (zh3_stream *)zcio_xcalloc(1, sizeof *st);
    if (!st) return NULL;
    st->ssl    = ss;
    st->conn   = c;
    st->is_uni = uni;
    st->id     = SSL_get_stream_id(ss);
    st->pstate = ZH3_PS_HDR;
    return st;
}

static int h3_streams_push(zh3_conn *c, zh3_stream *st) {
    if (c->nstreams == c->cap_streams) {
        size_t ncap = c->cap_streams ? c->cap_streams * 2 : 8;
        zh3_stream **nv = (zh3_stream **)realloc(c->streams, ncap * sizeof *nv);
        if (!nv) return ZCIO_ERR_NOMEM;
        c->streams = nv;
        c->cap_streams = ncap;
    }
    c->streams[c->nstreams++] = st;
    return ZCIO_OK;
}

/* True once a done stream's send side has fully flushed, so freeing it will
 * not drop a not-yet-sent response. Undispatched/uni streams are free anytime;
 * if the engine can't tell us the used count, free rather than leak. */
static bool h3_stream_drained(zh3_stream *st) {
    if (st->is_uni || !st->dispatched) return true;
    uint64_t used = 0;
    if (SSL_get_stream_write_buf_used(st->ssl, &used) != 1) return true;
    return used == 0;
}

/* Read everything currently available on the stream into st->in, parsing as we
 * go so st->in never buffers more than one partial frame. Sets *fin on FIN.
 * ZCIO_OK to keep the stream, negative to drop it. */
static int h3_stream_read(zh3_stream *st, const zhs_limits *lim, bool *fin) {
    uint8_t tmp[4096];
    for (int guard = 0; guard < ZH3_READ_CAP; guard++) {
        size_t n = 0;
        if (SSL_read_ex(st->ssl, tmp, sizeof tmp, &n) == 1 && n > 0) {
            if (!st->is_uni) {
                if (zhs_buf_append_(&st->in, tmp, n) != ZCIO_OK) return ZCIO_ERR_NOMEM;
                int r = h3_parse(st, lim);
                if (r != ZCIO_OK) return r;
            }
            /* uni streams (control / QPACK enc+dec): drained and discarded. */
            continue;
        }
        int err = SSL_get_error(st->ssl, 0);
        if (err == SSL_ERROR_WANT_READ)   return ZCIO_OK;   /* nothing more now */
        if (err == SSL_ERROR_ZERO_RETURN) { *fin = true; return ZCIO_OK; } /* FIN */
        return ZCIO_ERR_PROTOCOL;         /* reset / connection error: drop it   */
    }
    return ZCIO_OK;
}

/* Run the handler for a completed request stream (headers decoded, peer FIN at
 * a clean frame boundary). zhs_dispatch_ guarantees exactly one response via
 * our respond_fn; we then release the request and retire the stream. */
static void h3_maybe_dispatch(zh3_srv *h, zh3_stream *st) {
    if (st->dispatched || !st->fin || st->is_uni) return;
    if (!st->headers_seen || st->pstate != ZH3_PS_HDR) {
        st->done = true;              /* truncated / never-complete request */
        return;
    }
    /* NUL-terminate the body for text convenience without counting it. */
    if (zhs_buf_reserve_(&st->req.body, 1) == ZCIO_OK)
        st->req.body.data[st->req.body.len] = '\0';

    st->req.version    = 3;
    st->req.secure     = true;
    st->req.srv        = h->srv;
    st->req.owner      = st;
    st->req.stream_id  = (int64_t)st->id;
    st->req.respond_fn = h3_respond;

    (void)zhs_dispatch_(h->srv, &st->req);   /* h3 never detaches (ws is h1) */
    zhs_req_reset_(&st->req);
    st->dispatched = true;
    st->done = true;
}

/* --------------------------- connections -------------------------------- */

/* Open our server control stream and send an (empty) SETTINGS frame — RFC 9114
 * requires each side's control stream to lead with SETTINGS. Best-effort:
 * retried by the caller while the connection has no control stream yet. */
static void h3_open_control(zh3_conn *c) {
    if (c->control) return;
    SSL *ctl = SSL_new_stream(c->ssl, SSL_STREAM_FLAG_UNI | SSL_STREAM_FLAG_NO_BLOCK);
    if (!ctl) return;                 /* no uni credit yet; try again later */
    c->control = ctl;
    /* control-stream type (0x00), then SETTINGS (type 0x04, length 0). */
    uint8_t pre[3] = { (uint8_t)H3_UNI_CONTROL, (uint8_t)H3_FRAME_SETTINGS, 0x00 };
    size_t w = 0;
    ZH3_IGN_INT(SSL_write_ex(ctl, pre, sizeof pre, &w));
}

/* Best-effort HTTP/3 GOAWAY(0) on the control stream: tells the peer we will
 * process no further requests before the CONNECTION_CLOSE lands. */
static void h3_send_goaway(zh3_conn *c) {
    if (!c->control || c->goaway_sent) return;
    c->goaway_sent = true;
    uint8_t f[3] = { (uint8_t)H3_FRAME_GOAWAY, 0x01, 0x00 }; /* type, len=1, id=0 */
    size_t w = 0;
    ZH3_IGN_INT(SSL_write_ex(c->control, f, sizeof f, &w));
}

static zh3_conn *h3_conn_new(SSL *conn_ssl) {
    zh3_conn *c = (zh3_conn *)zcio_xcalloc(1, sizeof *c);
    if (!c) return NULL;
    c->ssl = conn_ssl;
    /* Non-blocking, no implicit default stream: we accept every incoming
     * stream explicitly via SSL_accept_stream. */
    ZH3_IGN_INT(SSL_set_blocking_mode(conn_ssl, 0));
    ZH3_IGN_INT(SSL_set_default_stream_mode(conn_ssl, SSL_DEFAULT_STREAM_MODE_NONE));
    ZH3_IGN_INT(SSL_set_incoming_stream_policy(conn_ssl,
                    SSL_INCOMING_STREAM_POLICY_ACCEPT, 0));
    h3_open_control(c);
    return c;
}

static void h3_conn_free(zh3_conn *c) {
    if (!c) return;
    for (size_t i = 0; i < c->nstreams; i++) h3_stream_free(c->streams[i]);
    free(c->streams);
    if (c->control) SSL_free(c->control);
    if (c->ssl) SSL_free(c->ssl);
    free(c);
}

static int h3_conns_push(zh3_srv *h, zh3_conn *c) {
    if (h->nconns == h->cap_conns) {
        size_t ncap = h->cap_conns ? h->cap_conns * 2 : 8;
        zh3_conn **nv = (zh3_conn **)realloc(h->conns, ncap * sizeof *nv);
        if (!nv) return ZCIO_ERR_NOMEM;
        h->conns = nv;
        h->cap_conns = ncap;
    }
    h->conns[h->nconns++] = c;
    return ZCIO_OK;
}

/* Accept queued streams on a connection, enforcing the per-connection stream
 * and request caps. Over-limit or unwanted streams are freed (which resets /
 * STOP_SENDINGs them at the QUIC layer). */
static void h3_accept_streams(zh3_srv *h, zh3_conn *c, int *work) {
    for (int g = 0; g < ZH3_ACCEPT_CAP; g++) {
        SSL *ss = SSL_accept_stream(c->ssl, SSL_ACCEPT_STREAM_NO_BLOCK);
        if (!ss) break;
        bool uni = SSL_get_stream_type(ss) != SSL_STREAM_TYPE_BIDI;
        if (!uni) {
            if (c->requests >= h->lim.max_requests_per_conn ||
                c->nstreams >= h->lim.max_streams) {
                SSL_free(ss);                 /* refuse: cap reached */
                continue;
            }
            c->requests++;
        } else if (c->nstreams >= h->lim.max_streams + 8) {
            SSL_free(ss);                     /* bound uni-stream tracking too */
            continue;
        }
        zh3_stream *st = h3_stream_new(c, ss, uni);
        if (!st) { SSL_free(ss); break; }
        if (h3_streams_push(c, st) != ZCIO_OK) { h3_stream_free(st); break; }
        (*work)++;
    }
}

/* Read/parse/dispatch each stream, then reap streams whose send side drained.
 * Swap-remove keeps the table compact without preserving order. */
static void h3_pump_streams(zh3_srv *h, zh3_conn *c, int *work) {
    for (size_t i = 0; i < c->nstreams; ) {
        zh3_stream *st = c->streams[i];
        if (!st->done) {
            bool fin = st->fin;
            int r = h3_stream_read(st, &h->lim, &fin);
            st->fin = fin;
            if (r != ZCIO_OK)          st->done = true;   /* drop on error */
            else if (!st->is_uni)      h3_maybe_dispatch(h, st);
            else if (fin)              st->done = true;   /* uni fully drained */
            (*work)++;
        }
        if (st->done && h3_stream_drained(st)) {
            h3_stream_free(st);
            c->streams[i] = c->streams[--c->nstreams];
            continue;
        }
        i++;
    }
}

/* Drive/observe connection close. Returns true when the connection is fully
 * finished and can be freed. */
static bool h3_conn_closed(zh3_conn *c, bool draining) {
    if (draining) {
        if (!c->shutdown_sent) {
            ZH3_IGN_INT(SSL_shutdown_ex(c->ssl, SSL_SHUTDOWN_FLAG_NO_BLOCK, NULL, 0));
            c->shutdown_sent = true;
        }
        /* Re-pump the close; 1 means CONNECTION_CLOSE has been flushed. */
        if (SSL_shutdown_ex(c->ssl, SSL_SHUTDOWN_FLAG_NO_BLOCK, NULL, 0) == 1)
            return true;
        return false;
    }
    SSL_CONN_CLOSE_INFO info;
    memset(&info, 0, sizeof info);
    return SSL_get_conn_close_info(c->ssl, &info, sizeof info) == 1;
}

/* ============================ public entry points ======================= */

/* ALPN selection: HTTP/3 mandates ALPN, so accept only "h3"; anything else
 * fails the handshake. *out points into the peer's buffer, which OpenSSL
 * copies immediately — the canonical usage. */
static int h3_alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                      const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl; (void)arg;
    for (unsigned int i = 0; i + 1 <= inlen; ) {
        unsigned int l = in[i];
        if (i + 1u + l > inlen) break;
        if (l == 2 && in[i + 1] == 'h' && in[i + 2] == '3') {
            *out = &in[i + 1];
            *outlen = 2;
            return SSL_TLSEXT_ERR_OK;
        }
        i += 1u + l;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/* Bind a non-blocking UDP socket on INADDR_ANY:port. Returns the fd or
 * ZCIO_INVALID_SOCKET (no error message; the caller reports context). */
static zcio_socket h3_udp_bind(int port) {
    zcio_socket_startup();
    zcio_socket fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == ZCIO_INVALID_SOCKET) return ZCIO_INVALID_SOCKET;
    zcio_socket_nosigpipe(fd);

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&reuse, sizeof reuse);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        zcio_closesocket(fd);
        return ZCIO_INVALID_SOCKET;
    }
    if (zcio_set_nonblocking(fd, true) != ZCIO_OK) {
        zcio_closesocket(fd);
        return ZCIO_INVALID_SOCKET;
    }
    return fd;
}

zh3_srv *zh3_new_(struct zcio_http_server *srv, const zcio_http_server_config *cfg,
                  const zhs_limits *lim, int port) {
    if (!srv || !cfg || !lim) {
        zcio_fail_(ZCIO_ERR_INVALID_ARG, "http3: NULL argument");
        return NULL;
    }

    /* QUIC requires its own OSSL_QUIC_server_method SSL_CTX; a borrowed TLS
     * ctx (cfg->tls) cannot be reused here, so we build our own and load key
     * material from cfg's files, falling back to a self-signed localhost cert. */
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (!ctx) return h3_setup_fail("SSL_CTX_new(QUIC server)");

    if (cfg->cert_file && cfg->key_file) {
        if (SSL_CTX_use_certificate_chain_file(ctx, cfg->cert_file) != 1) {
            SSL_CTX_free(ctx);
            return h3_setup_fail("load certificate");
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, cfg->key_file, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ctx);
            return h3_setup_fail("load private key");
        }
        if (SSL_CTX_check_private_key(ctx) != 1) {
            SSL_CTX_free(ctx);
            return h3_setup_fail("private key does not match certificate");
        }
    } else if (!zcio_ossl_selfsign_install_(ctx)) {
        SSL_CTX_free(ctx);
        return h3_setup_fail("self-signed certificate generation");
    }

    SSL_CTX_set_alpn_select_cb(ctx, h3_alpn_cb, NULL);

    zcio_socket fd = h3_udp_bind(port);
    if (fd == ZCIO_INVALID_SOCKET) {
        SSL_CTX_free(ctx);
        zcio_fail_(ZCIO_ERR_UNSUPPORTED, "http3: bind UDP :%d failed", port);
        return NULL;
    }

    SSL *listener = SSL_new_listener(ctx, 0);
    if (!listener) {
        zcio_closesocket(fd);
        SSL_CTX_free(ctx);
        return h3_setup_fail("SSL_new_listener");
    }
    /* SSL_set_fd installs a datagram BIO with BIO_NOCLOSE for QUIC, so we keep
     * ownership of the fd and close it ourselves in zh3_free_. */
    if (SSL_set_fd(listener, (int)fd) != 1) {
        SSL_free(listener);
        zcio_closesocket(fd);
        SSL_CTX_free(ctx);
        return h3_setup_fail("SSL_set_fd(listener)");
    }
    if (SSL_set_blocking_mode(listener, 0) != 1 || SSL_listen(listener) != 1) {
        SSL_free(listener);
        zcio_closesocket(fd);
        SSL_CTX_free(ctx);
        return h3_setup_fail("SSL_listen");
    }

    zh3_srv *h = (zh3_srv *)zcio_xcalloc(1, sizeof *h);
    if (!h) {
        SSL_free(listener);
        zcio_closesocket(fd);
        SSL_CTX_free(ctx);
        zcio_fail_(ZCIO_ERR_NOMEM, "http3: out of memory");
        return NULL;
    }
    h->srv      = srv;
    h->ctx      = ctx;
    h->listener = listener;
    h->fd       = fd;
    h->lim      = *lim;
    return h;
}

int zh3_fd_(zh3_srv *h) {
    return h ? (int)h->fd : -1;
}

int zh3_timeout_ms_(zh3_srv *h) {
    if (!h || !h->listener) return -1;
    long long best = -1;   /* -1 == no (finite) deadline pending */
    struct timeval tv;
    int inf = 0;
    if (SSL_get_event_timeout(h->listener, &tv, &inf) == 1 && !inf) {
        long long ms = (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
        best = ms < 0 ? 0 : ms;
    }
    for (size_t i = 0; i < h->nconns; i++) {
        inf = 0;
        if (SSL_get_event_timeout(h->conns[i]->ssl, &tv, &inf) == 1 && !inf) {
            long long ms = (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
            if (ms < 0) ms = 0;
            if (best < 0 || ms < best) best = ms;
        }
    }
    return best < 0 ? -1 : (int)best;
}

int zh3_process_(zh3_srv *h) {
    if (!h || !h->listener) return ZCIO_ERR_INVALID_ARG;
    int work = 0;

    /* Ingest datagrams + service listener timers. */
    (void)SSL_handle_events(h->listener);

    /* Accept new connections (never while draining or at the connection cap). */
    if (!h->draining) {
        for (int g = 0; g < ZH3_ACCEPT_CAP && h->nconns < h->lim.max_connections; g++) {
            SSL *cs = SSL_accept_connection(h->listener, SSL_ACCEPT_CONNECTION_NO_BLOCK);
            if (!cs) break;
            zh3_conn *c = h3_conn_new(cs);
            if (!c) { SSL_free(cs); break; }
            if (h3_conns_push(h, c) != ZCIO_OK) { h3_conn_free(c); break; }
            work++;
        }
    }

    /* Service each tracked connection; swap-remove the finished ones. */
    for (size_t i = 0; i < h->nconns; ) {
        zh3_conn *c = h->conns[i];
        (void)SSL_handle_events(c->ssl);
        if (!h->draining) {
            if (!c->control) h3_open_control(c);   /* retry until uni credit */
            h3_accept_streams(h, c, &work);
        }
        h3_pump_streams(h, c, &work);

        if (h3_conn_closed(c, h->draining)) {
            h3_conn_free(c);
            h->conns[i] = h->conns[--h->nconns];
            work++;
            continue;
        }
        i++;
    }
    return work;
}

void zh3_graceful_(zh3_srv *h) {
    if (!h) return;
    h->draining = true;
    /* Stop accepting, tell peers via GOAWAY, and begin each connection's
     * CONNECTION_CLOSE. zh3_process_ then pumps the closes to completion. */
    for (size_t i = 0; i < h->nconns; i++) {
        zh3_conn *c = h->conns[i];
        h3_send_goaway(c);
        if (!c->shutdown_sent) {
            ZH3_IGN_INT(SSL_shutdown_ex(c->ssl, SSL_SHUTDOWN_FLAG_NO_BLOCK, NULL, 0));
            c->shutdown_sent = true;
        }
    }
}

bool zh3_idle_(const zh3_srv *h) {
    return !h || h->nconns == 0;
}

void zh3_free_(zh3_srv *h) {
    if (!h) return;
    for (size_t i = 0; i < h->nconns; i++) h3_conn_free(h->conns[i]);
    free(h->conns);
    if (h->listener) SSL_free(h->listener);
    if (h->ctx) SSL_CTX_free(h->ctx);
    if (h->fd != ZCIO_INVALID_SOCKET) zcio_closesocket(h->fd);
    free(h);
}

#else  /* !ZH3_REAL */
/* ========================================================================= *
 *  Stubs: HTTP/3 unavailable (no OpenSSL, OpenSSL < 3.5, or QUIC compiled out)
 * ========================================================================= */

zh3_srv *zh3_new_(struct zcio_http_server *srv, const zcio_http_server_config *cfg,
                  const zhs_limits *lim, int port) {
    (void)srv; (void)cfg; (void)lim; (void)port;
    zcio_fail_(ZCIO_ERR_UNSUPPORTED, "HTTP/3 requires OpenSSL >= 3.5 QUIC");
    return NULL;
}

int  zh3_fd_(zh3_srv *h)         { (void)h; return -1; }
int  zh3_timeout_ms_(zh3_srv *h) { (void)h; return -1; }
int  zh3_process_(zh3_srv *h)    { (void)h; return ZCIO_ERR_UNSUPPORTED; }
void zh3_graceful_(zh3_srv *h)   { (void)h; }
bool zh3_idle_(const zh3_srv *h) { (void)h; return true; }
void zh3_free_(zh3_srv *h)       { (void)h; }

#endif /* ZH3_REAL */
