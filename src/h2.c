/* src/h2.c - HTTP/2 (RFC 9113) framing, streams, flow control, flood guards.
 *
 * Sans-I/O, like h1.c: zh2_feed_ consumes a zhs_buf of received bytes and
 * appends wire bytes to the connection's out buffer (owned by the loop); the
 * loop moves bytes to/from the socket and calls zh2_pump_ when out drains.
 * HPACK (de)compression is delegated to hpack.c (zhp_*); this file owns the
 * decoder's dynamic-table state for the connection.
 *
 * Ownership:
 *   - zh2_conn owns: the HPACK decoder (zhp_dec), the stream table and every
 *     zh2_stream in it, and the header-block reassembly buffer. `out` is
 *     BORROWED (the loop owns it; stable address for the conn's lifetime).
 *   - each zh2_stream owns its zcio_http_req input storage (freed after
 *     dispatch) and its response-body copy (resp_body, pumped out as DATA).
 *   - zh2_free_ releases all of the above.
 *
 * Security posture (all enforced before memory is committed):
 *   - inbound frame length is rejected if it exceeds our advertised
 *     MAX_FRAME_SIZE, so every per-frame allocation/copy is <= 16 KiB;
 *   - header-block reassembly caps both accumulated bytes and CONTINUATION
 *     frame count (CVE-2024-27316-class CONTINUATION flood);
 *   - streams reset before we answer are counted (CVE-2023-44487 rapid reset);
 *   - PING/SETTINGS ACK generation is bounded per feed and by the out cap;
 *   - request body is capped at max_body_bytes; flow-control windows are
 *     maintained and every window arithmetic is overflow-checked.
 */
#include "http_internal.h"

/* ========================================================================= *
 *  Wire constants
 * ========================================================================= */

/* Client connection preface (RFC 9113 sec. 3.4). May arrive split. */
static const char ZH2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#define ZH2_PREFACE_LEN 24   /* strlen(ZH2_PREFACE) */

#define ZH2_FRAME_HDR 9      /* length(24) type(8) flags(8) R(1)|stream(31) */

/* Frame types. */
enum {
    ZH2_FT_DATA          = 0x0,
    ZH2_FT_HEADERS       = 0x1,
    ZH2_FT_PRIORITY      = 0x2,
    ZH2_FT_RST_STREAM    = 0x3,
    ZH2_FT_SETTINGS      = 0x4,
    ZH2_FT_PUSH_PROMISE  = 0x5,
    ZH2_FT_PING          = 0x6,
    ZH2_FT_GOAWAY        = 0x7,
    ZH2_FT_WINDOW_UPDATE = 0x8,
    ZH2_FT_CONTINUATION  = 0x9,
};

/* Frame flags (meaning is per-type; the bit values overlap intentionally). */
enum {
    ZH2_FL_END_STREAM  = 0x01,  /* DATA, HEADERS                */
    ZH2_FL_ACK         = 0x01,  /* SETTINGS, PING               */
    ZH2_FL_END_HEADERS = 0x04,  /* HEADERS, CONTINUATION        */
    ZH2_FL_PADDED      = 0x08,  /* DATA, HEADERS                */
    ZH2_FL_PRIORITY    = 0x20,  /* HEADERS                      */
};

/* Error codes (RFC 9113 sec. 7). */
enum {
    ZH2_E_NO_ERROR            = 0x0,
    ZH2_E_PROTOCOL_ERROR      = 0x1,
    ZH2_E_INTERNAL_ERROR      = 0x2,
    ZH2_E_FLOW_CONTROL_ERROR  = 0x3,
    ZH2_E_STREAM_CLOSED       = 0x5,
    ZH2_E_FRAME_SIZE_ERROR    = 0x6,
    ZH2_E_REFUSED_STREAM      = 0x7,
    ZH2_E_COMPRESSION_ERROR   = 0x9,
    ZH2_E_ENHANCE_YOUR_CALM   = 0xb,
};

/* SETTINGS identifiers (RFC 9113 sec. 6.5.2). */
enum {
    ZH2_S_HEADER_TABLE_SIZE      = 0x1,
    ZH2_S_ENABLE_PUSH            = 0x2,
    ZH2_S_MAX_CONCURRENT_STREAMS = 0x3,
    ZH2_S_INITIAL_WINDOW_SIZE    = 0x4,
    ZH2_S_MAX_FRAME_SIZE         = 0x5,
    ZH2_S_MAX_HEADER_LIST_SIZE   = 0x6,
};

/* Our advertised settings / fixed protocol values. */
#define ZH2_OUR_MAX_FRAME       16384        /* SETTINGS_MAX_FRAME_SIZE we send  */
#define ZH2_OUR_INITIAL_WINDOW  65535        /* our per-stream receive window    */
#define ZH2_CONN_WINDOW         65535        /* our connection receive window    */
#define ZH2_DEFAULT_INIT_WINDOW 65535        /* protocol default (peer, pre-SETTINGS) */
#define ZH2_DEFAULT_MAX_FRAME   16384        /* protocol default (peer)          */
#define ZH2_MAX_WINDOW          0x7fffffff   /* 2^31 - 1                         */

/* Flood guards. */
#define ZH2_CONT_MAX          64   /* CONTINUATION frames per header block  */
#define ZH2_PING_PER_FEED    128   /* PING(non-ACK) answered per feed       */
#define ZH2_SETTINGS_PER_FEED 64   /* SETTINGS(non-ACK) applied per feed    */

/* emit()-level request malformation sentinel (distinct from ZCIO_* codes,
 * which are all <= 0). Signals a *stream* error (RST_STREAM PROTOCOL_ERROR)
 * as opposed to an HPACK/connection error. */
#define ZH2_HERR_MALFORMED 1

/* ========================================================================= *
 *  Structures
 * ========================================================================= */

typedef struct zh2_stream {
    uint32_t id;
    struct zh2_conn *conn;

    /* receive side */
    int64_t recv_window;      /* our advertised per-stream window remaining */
    bool    got_headers;      /* HEADERS decoded, request object populated  */
    bool    end_stream_recv;  /* client half-closed (END_STREAM seen)       */
    bool    dispatched;       /* zhs_dispatch_ already run                   */

    /* send side */
    int64_t  send_window;         /* peer per-stream window for our DATA     */
    bool     responded;           /* respond_fn ran                          */
    bool     resp_headers_done;   /* HEADERS frame(s) queued to out          */
    bool     resp_end_after_body; /* END_STREAM rides the final DATA frame   */
    bool     send_done;           /* our side fully sent                     */
    zhs_buf  resp_body;           /* response body copy, pumped as DATA      */
    size_t   body_off;            /* bytes of resp_body already framed        */

    zcio_http_req req;            /* request being assembled / dispatched     */
} zh2_stream;

struct zh2_conn {
    struct zcio_http_server *srv;
    const zhs_limits        *lim;
    bool                     secure;
    zhs_buf                 *out;   /* BORROWED (loop owns it)                */

    zhp_dec *dec;                   /* HPACK decoder + dynamic table          */

    /* connection state */
    size_t  preface_got;            /* bytes of the 24-byte preface consumed  */
    bool    preface_done;
    bool    need_settings;          /* first frame after preface must be SETTINGS */
    bool    closing;                /* GOAWAY sent / graceful: refuse new     */
    bool    goaway_sent;
    bool    peer_goaway;            /* peer sent us GOAWAY                     */
    bool    got_error;              /* connection error: close after out drains */
    bool    oom;                    /* fatal allocation failure               */

    /* flow control */
    int64_t recv_window;            /* our connection receive window          */
    int64_t send_window;            /* peer connection window for our DATA    */
    uint32_t peer_initial_window;   /* peer SETTINGS_INITIAL_WINDOW_SIZE      */
    uint32_t peer_max_frame;        /* peer SETTINGS_MAX_FRAME_SIZE           */

    /* stream table */
    zh2_stream **streams;
    size_t       nstreams, streams_cap;
    uint32_t     last_client_id;    /* highest client stream id accepted      */
    uint32_t     open_count;        /* concurrent open streams                */
    uint32_t     total_streams;     /* lifetime stream count                  */
    uint32_t     rapid_reset;       /* streams reset before we answered       */

    /* header-block reassembly (HEADERS + CONTINUATION for one stream) */
    bool        hdr_active;
    uint32_t    hdr_id;
    zh2_stream *hdr_stream;         /* target stream, or NULL if refused      */
    int         hdr_refuse;         /* RST code to send at END_HEADERS, or 0  */
    bool        hdr_trailer;        /* accumulating trailers (no pseudo)      */
    bool        hdr_end_stream;     /* END_STREAM flag from the HEADERS frame */
    zhs_buf     hdr_block;          /* accumulated header-block fragment      */
    uint32_t    cont_count;         /* CONTINUATION frames this block         */
};

/* Header-decode sink (one per header block). */
typedef struct {
    const zhs_limits *lim;
    bool  trailer;       /* trailers: pseudo-headers are illegal        */
    bool  seen_regular;  /* a regular field was seen (pseudo now late)  */
    int   herr;          /* 0 ok, ZH2_HERR_MALFORMED, or ZCIO_ERR_NOMEM */
    char *method, *scheme, *path, *authority;
    zhs_hdrs headers;    /* regular request headers (lowercased on wire) */
} zh2_hdrctx;

/* ========================================================================= *
 *  Byte helpers
 * ========================================================================= */

static uint32_t rd24(const uint8_t *p) {
    return (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | (uint32_t)p[2];
}
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8  | (uint32_t)p[3];
}
static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}
static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}

/* ========================================================================= *
 *  Frame emission (all onto the borrowed out buffer)
 * ========================================================================= */

/* Append a complete frame (9-byte header + optional payload). Returns ZCIO_OK
 * or ZCIO_ERR_NOMEM. `sid` must be < 2^31 (top reserved bit is left 0). */
static int h2_frame(zh2_conn *c, uint32_t len, uint8_t type, uint8_t flags,
                    uint32_t sid, const void *payload) {
    uint8_t h[ZH2_FRAME_HDR];
    h[0] = (uint8_t)(len >> 16); h[1] = (uint8_t)(len >> 8); h[2] = (uint8_t)len;
    h[3] = type; h[4] = flags;
    h[5] = (uint8_t)(sid >> 24); h[6] = (uint8_t)(sid >> 16);
    h[7] = (uint8_t)(sid >> 8);  h[8] = (uint8_t)sid;
    int r = zhs_buf_append_(c->out, h, ZH2_FRAME_HDR);
    if (r != ZCIO_OK) return r;
    if (len && payload) return zhs_buf_append_(c->out, payload, len);
    return ZCIO_OK;
}

/* The queue_* helpers below flip c->oom on allocation failure; callers proceed
 * and feed reports the fatal error once the frame loop unwinds. */
static void q_rst(zh2_conn *c, uint32_t id, uint32_t code) {
    uint8_t p[4]; wr32(p, code);
    if (h2_frame(c, 4, ZH2_FT_RST_STREAM, 0, id, p) != ZCIO_OK) c->oom = true;
}
static void q_window_update(zh2_conn *c, uint32_t id, uint32_t incr) {
    if (incr == 0) return;
    uint8_t p[4]; wr32(p, incr);
    if (h2_frame(c, 4, ZH2_FT_WINDOW_UPDATE, 0, id, p) != ZCIO_OK) c->oom = true;
}
static void q_settings_ack(zh2_conn *c) {
    if (h2_frame(c, 0, ZH2_FT_SETTINGS, ZH2_FL_ACK, 0, NULL) != ZCIO_OK) c->oom = true;
}
static void q_ping_ack(zh2_conn *c, const uint8_t data[8]) {
    if (h2_frame(c, 8, ZH2_FT_PING, ZH2_FL_ACK, 0, data) != ZCIO_OK) c->oom = true;
}
static void q_goaway(zh2_conn *c, uint32_t code) {
    if (c->goaway_sent) return;
    uint8_t p[8];
    wr32(p, c->last_client_id);   /* last stream id we processed */
    wr32(p + 4, code);
    if (h2_frame(c, 8, ZH2_FT_GOAWAY, 0, 0, p) != ZCIO_OK) c->oom = true;
    c->goaway_sent = true;
}

/* Connection error: GOAWAY(code) then close once out drains. */
static void conn_error(zh2_conn *c, uint32_t code) {
    q_goaway(c, code);
    c->got_error = true;
    c->closing   = true;
}

/* ========================================================================= *
 *  Stream table
 * ========================================================================= */

static bool find_index(zh2_conn *c, uint32_t id, size_t *idx) {
    for (size_t i = 0; i < c->nstreams; i++)
        if (c->streams[i]->id == id) { *idx = i; return true; }
    return false;
}
static zh2_stream *find_stream(zh2_conn *c, uint32_t id) {
    size_t idx;
    return find_index(c, id, &idx) ? c->streams[idx] : NULL;
}

/* Create + register a stream. NULL on OOM (caller sets c->oom). */
static zh2_stream *h2_stream_new(zh2_conn *c, uint32_t id) {
    if (c->nstreams == c->streams_cap) {
        size_t ncap = c->streams_cap ? c->streams_cap * 2 : 8;
        zh2_stream **nv = (zh2_stream **)realloc(c->streams, ncap * sizeof *nv);
        if (!nv) return NULL;
        c->streams = nv;
        c->streams_cap = ncap;
    }
    zh2_stream *st = (zh2_stream *)zcio_xcalloc(1, sizeof *st);
    if (!st) return NULL;
    st->id = id;
    st->conn = c;
    st->recv_window = ZH2_OUR_INITIAL_WINDOW;
    st->send_window = (int64_t)c->peer_initial_window;
    c->streams[c->nstreams++] = st;
    c->open_count++;
    return st;
}

/* Remove + free the stream at slot `idx`. */
static void stream_close(zh2_conn *c, size_t idx) {
    zh2_stream *st = c->streams[idx];
    zhs_buf_free_(&st->resp_body);
    zhs_req_reset_(&st->req);
    free(st);
    c->streams[idx] = c->streams[--c->nstreams];
    if (c->open_count) c->open_count--;
}

/* Send RST_STREAM and drop the stream. `st` is invalid afterwards. */
static void rst_stream(zh2_conn *c, zh2_stream *st, uint32_t code) {
    q_rst(c, st->id, code);
    size_t idx;
    if (find_index(c, st->id, &idx)) stream_close(c, idx);
}

/* ========================================================================= *
 *  Flow control (receive side): account consumed bytes, replenish windows.
 * ========================================================================= *
 * We top a window back up to full as soon as it drops within one max-frame of
 * empty, so the window never dips below ZH2_OUR_MAX_FRAME and a legitimate
 * full-size frame can never trip the pre-consume flow-control check. */
static void recv_consume(zh2_conn *c, zh2_stream *st, uint32_t len, bool stream_open) {
    c->recv_window -= (int64_t)len;
    if (c->recv_window <= (int64_t)ZH2_CONN_WINDOW - (int64_t)ZH2_OUR_MAX_FRAME) {
        uint32_t delta = (uint32_t)((int64_t)ZH2_CONN_WINDOW - c->recv_window);
        q_window_update(c, 0, delta);
        c->recv_window = ZH2_CONN_WINDOW;
    }
    if (st && stream_open) {
        st->recv_window -= (int64_t)len;
        if (st->recv_window <= (int64_t)ZH2_OUR_INITIAL_WINDOW - (int64_t)ZH2_OUR_MAX_FRAME) {
            uint32_t delta = (uint32_t)((int64_t)ZH2_OUR_INITIAL_WINDOW - st->recv_window);
            q_window_update(c, st->id, delta);
            st->recv_window = ZH2_OUR_INITIAL_WINDOW;
        }
    }
}

/* ========================================================================= *
 *  Header decoding: emit sink + request assembly
 * ========================================================================= */

static char *dup_n(const char *s, size_t n) {
    char *o = (char *)zcio_xmalloc(n + 1);
    if (!o) return NULL;
    if (n) memcpy(o, s, n);
    o[n] = '\0';
    return o;
}

/* Length-aware equality against a NUL-terminated literal. */
static bool nm_eq(const char *s, size_t n, const char *lit) {
    return strlen(lit) == n && memcmp(s, lit, n) == 0;
}

/* Connection-specific headers forbidden over HTTP/2 (RFC 9113 sec. 8.2.2). */
static bool is_conn_specific(const char *n, size_t nl) {
    return nm_eq(n, nl, "connection") || nm_eq(n, nl, "keep-alive") ||
           nm_eq(n, nl, "proxy-connection") || nm_eq(n, nl, "transfer-encoding") ||
           nm_eq(n, nl, "upgrade");
}

/* zhp_emit_fn: called once per decoded field, in order, with borrowed
 * name/value. Returns 0 to continue, nonzero to abort the decode (the return
 * value becomes zhp_decode_'s result; we disambiguate via ctx->herr). */
static int h2_emit(void *u, const char *name, size_t nlen,
                   const char *value, size_t vlen) {
    zh2_hdrctx *x = (zh2_hdrctx *)u;

    if (nlen > 0 && name[0] == ':') {          /* pseudo-header */
        if (x->trailer || x->seen_regular) {   /* pseudo in trailer / after regular */
            x->herr = ZH2_HERR_MALFORMED; return -1;
        }
        char **slot = NULL;
        if      (nm_eq(name, nlen, ":method"))    slot = &x->method;
        else if (nm_eq(name, nlen, ":scheme"))    slot = &x->scheme;
        else if (nm_eq(name, nlen, ":path"))      slot = &x->path;
        else if (nm_eq(name, nlen, ":authority")) slot = &x->authority;
        else { x->herr = ZH2_HERR_MALFORMED; return -1; }   /* unknown pseudo */
        if (*slot) { x->herr = ZH2_HERR_MALFORMED; return -1; } /* duplicate */
        char *v = dup_n(value, vlen);
        if (!v) { x->herr = ZCIO_ERR_NOMEM; return -1; }
        *slot = v;
        return 0;
    }

    /* regular header */
    x->seen_regular = true;
    if (!zhs_lower_token_ok_(name, nlen)) {    /* uppercase / non-token */
        x->herr = ZH2_HERR_MALFORMED; return -1;
    }
    if (is_conn_specific(name, nlen)) { x->herr = ZH2_HERR_MALFORMED; return -1; }
    if (nm_eq(name, nlen, "te") && !(vlen == 8 && memcmp(value, "trailers", 8) == 0)) {
        x->herr = ZH2_HERR_MALFORMED; return -1;
    }
    if (x->trailer) return 0;                  /* trailer values are discarded */

    int r = zhs_hdrs_add_(&x->headers, name, nlen, value, vlen, x->lim, false);
    if (r == ZCIO_ERR_NOMEM) { x->herr = ZCIO_ERR_NOMEM; return -1; }
    if (r != ZCIO_OK)        { x->herr = ZH2_HERR_MALFORMED; return -1; } /* a cap */
    return 0;
}

static void hdrctx_free(zh2_hdrctx *x) {
    free(x->method); free(x->scheme); free(x->path); free(x->authority);
    zhs_hdrs_free_(&x->headers);
    memset(x, 0, sizeof *x);
}

/* ========================================================================= *
 *  Dispatch
 * ========================================================================= */

static int zh2_respond(zcio_http_req *req, int status,
                       const zcio_http_header *hdrs, size_t nhdrs,
                       const void *body, size_t body_len);

/* Run the handler on a completed request and free its input storage. The
 * response has been queued into the stream by respond_fn by the time this
 * returns; a no-body response leaves the stream fully sent and is reaped. */
static void h2_dispatch(zh2_conn *c, zh2_stream *st) {
    if (st->dispatched) return;
    st->dispatched = true;

    /* NUL-terminate the body for text convenience (not counted in len). */
    if (zhs_buf_reserve_(&st->req.body, 1) == ZCIO_OK)
        st->req.body.data[st->req.body.len] = 0;

    st->req.version   = 2;
    st->req.secure    = c->secure;
    st->req.srv       = c->srv;
    st->req.owner     = st;
    st->req.stream_id = (int64_t)st->id;
    st->req.responded = false;
    st->req.respond_fn = zh2_respond;

    (void)zhs_dispatch_(c->srv, &st->req);   /* h2 never detaches (ws is h1) */

    /* Input storage no longer needed; respond_fn already copied the body it
     * queues. Response framing lives in st (resp_body), not in req. */
    zhs_req_reset_(&st->req);

    if (st->send_done && st->end_stream_recv) {
        size_t idx;
        if (find_index(c, st->id, &idx)) stream_close(c, idx);
    }
}

/* Decode the reassembled header block and act on it. Consumes/clears the
 * reassembly state. On any allocation failure sets c->oom. */
static void h2_finish_headers(zh2_conn *c) {
    zh2_hdrctx x;
    memset(&x, 0, sizeof x);
    x.lim     = c->lim;
    x.trailer = c->hdr_trailer;

    int dr = zhp_decode_(c->dec, ZHS_PTR(&c->hdr_block), ZHS_AVAIL(&c->hdr_block),
                         c->lim->max_header_bytes, h2_emit, &x);

    /* Snapshot + clear reassembly state (subsequent frames are now allowed). */
    uint32_t    id      = c->hdr_id;
    zh2_stream *st      = c->hdr_stream;
    int         refuse  = c->hdr_refuse;
    bool        trailer = c->hdr_trailer;
    bool        end     = c->hdr_end_stream;
    c->hdr_active = false; c->hdr_stream = NULL; c->hdr_id = 0;
    c->hdr_refuse = 0; c->hdr_trailer = false; c->hdr_end_stream = false;
    c->cont_count = 0;
    zhs_buf_reset_(&c->hdr_block);

    if (x.herr == ZCIO_ERR_NOMEM || dr == ZCIO_ERR_NOMEM) {
        c->oom = true; hdrctx_free(&x); return;
    }
    /* An HPACK failure that did not come from our emit is a connection-level
     * COMPRESSION_ERROR; the dynamic table is now unusable. */
    if (dr != ZCIO_OK && x.herr == 0) {
        conn_error(c, ZH2_E_COMPRESSION_ERROR); hdrctx_free(&x); return;
    }
    if (x.herr == ZH2_HERR_MALFORMED) {        /* malformed request: stream error */
        if (st) rst_stream(c, st, ZH2_E_PROTOCOL_ERROR);
        else    q_rst(c, id, refuse ? (uint32_t)refuse : ZH2_E_PROTOCOL_ERROR);
        hdrctx_free(&x); return;
    }
    if (refuse) {                              /* concurrency / lifetime / closing */
        q_rst(c, id, (uint32_t)refuse);
        hdrctx_free(&x); return;
    }
    if (!st) { q_rst(c, id, ZH2_E_REFUSED_STREAM); hdrctx_free(&x); return; }

    if (trailer) {                             /* trailing HEADERS: must end stream */
        if (!end) { rst_stream(c, st, ZH2_E_PROTOCOL_ERROR); hdrctx_free(&x); return; }
        st->end_stream_recv = true;
        hdrctx_free(&x);
        h2_dispatch(c, st);
        return;
    }

    /* Mandatory request pseudo-headers (RFC 9113 sec. 8.3.1; no CONNECT). */
    if (!x.method || !x.scheme || !x.path ||
        !zhs_token_ok_(x.method, strlen(x.method))) {
        rst_stream(c, st, ZH2_E_PROTOCOL_ERROR); hdrctx_free(&x); return;
    }

    st->req.method = x.method; x.method = NULL;   /* transfer ownership */

    char *path = NULL, *query = NULL;
    int pr = zhs_decode_target_(x.path, strlen(x.path), c->lim, &path, &query);
    if (pr != ZCIO_OK) {
        if (pr == ZCIO_ERR_NOMEM) c->oom = true;
        else rst_stream(c, st, ZH2_E_PROTOCOL_ERROR);   /* frees st (owns method) */
        hdrctx_free(&x);
        return;
    }
    st->req.path  = path;
    st->req.query = query;

    /* Authority: :authority (userinfo stripped) else Host header. */
    if (x.authority) {
        const char *at = strchr(x.authority, '@');
        st->req.authority = zcio_strdup_(at ? at + 1 : x.authority);
        if (!st->req.authority) { c->oom = true; hdrctx_free(&x); return; }
    } else {
        const char *host = zhs_hdrs_get_(&x.headers, "host");
        if (host) {
            st->req.authority = zcio_strdup_(host);
            if (!st->req.authority) { c->oom = true; hdrctx_free(&x); return; }
        }
    }

    st->req.is_head = strcmp(st->req.method, "HEAD") == 0;
    st->req.headers = x.headers;                  /* transfer ownership */
    memset(&x.headers, 0, sizeof x.headers);

    st->got_headers      = true;
    st->end_stream_recv  = end;
    hdrctx_free(&x);

    if (end) h2_dispatch(c, st);
}

/* ========================================================================= *
 *  Header-block accumulation (HEADERS + CONTINUATION)
 * ========================================================================= */

/* Append a header-block fragment, enforcing the byte cap. Returns 0, or -1
 * after raising a connection error / OOM. */
static int hdr_accumulate(zh2_conn *c, const uint8_t *frag, size_t fraglen) {
    /* Compressed accumulation cap: the decoded size is already bounded by
     * max_header_bytes inside zhp_decode_; a little slack covers per-field
     * HPACK overhead. A flood pushes far past this. */
    size_t cap = c->lim->max_header_bytes;
    cap = (cap > SIZE_MAX - 4096) ? SIZE_MAX : cap + 4096;
    if (fraglen > cap - c->hdr_block.len) {   /* c->hdr_block.len <= cap holds */
        conn_error(c, ZH2_E_ENHANCE_YOUR_CALM);
        return -1;
    }
    if (zhs_buf_append_(&c->hdr_block, frag, fraglen) != ZCIO_OK) {
        c->oom = true; return -1;
    }
    return 0;
}

/* ========================================================================= *
 *  Frame handlers
 * ========================================================================= */

static void h2_on_headers(zh2_conn *c, uint8_t flags, uint32_t id,
                          const uint8_t *payload, uint32_t len) {
    if (id == 0) { conn_error(c, ZH2_E_PROTOCOL_ERROR); return; }

    /* Strip PADDED + PRIORITY to isolate the header-block fragment. */
    const uint8_t *p = payload;
    size_t rem = len;
    uint8_t pad = 0;
    if (flags & ZH2_FL_PADDED) {
        if (rem < 1) { conn_error(c, ZH2_E_PROTOCOL_ERROR); return; }
        pad = p[0]; p++; rem--;
    }
    if (flags & ZH2_FL_PRIORITY) {
        if (rem < 5) { conn_error(c, ZH2_E_PROTOCOL_ERROR); return; }
        p += 5; rem -= 5;
    }
    if (pad > rem) { conn_error(c, ZH2_E_PROTOCOL_ERROR); return; }
    size_t fraglen = rem - pad;

    zh2_stream *st = find_stream(c, id);
    int  refuse  = 0;
    bool trailer = false;

    if (!st) {                                 /* new stream */
        if ((id & 1u) == 0 || id <= c->last_client_id) {
            conn_error(c, ZH2_E_PROTOCOL_ERROR); return;
        }
        c->last_client_id = id;
        c->total_streams++;
        if (c->closing || c->peer_goaway) {
            refuse = ZH2_E_REFUSED_STREAM;
        } else if (c->lim->max_requests_per_conn &&
                   c->total_streams > c->lim->max_requests_per_conn) {
            q_goaway(c, ZH2_E_NO_ERROR);       /* lifetime cap: wind down */
            c->closing = true;
            refuse = ZH2_E_REFUSED_STREAM;
        } else if (c->open_count >= c->lim->max_streams) {
            refuse = ZH2_E_REFUSED_STREAM;     /* MAX_CONCURRENT_STREAMS */
        }
        if (!refuse) {
            st = h2_stream_new(c, id);
            if (!st) { c->oom = true; return; }
        }
    } else {                                   /* existing stream -> trailers */
        if (st->end_stream_recv) { conn_error(c, ZH2_E_STREAM_CLOSED); return; }
        if (!st->got_headers)    { conn_error(c, ZH2_E_PROTOCOL_ERROR); return; }
        trailer = true;
    }

    /* Begin reassembly. We decode even a refused stream's block to keep the
     * connection-wide HPACK dynamic table in sync. */
    c->hdr_active     = true;
    c->hdr_id         = id;
    c->hdr_stream     = st;                    /* NULL when refused */
    c->hdr_refuse     = refuse;
    c->hdr_trailer    = trailer;
    c->hdr_end_stream = (flags & ZH2_FL_END_STREAM) != 0;
    c->cont_count     = 0;
    zhs_buf_reset_(&c->hdr_block);

    if (hdr_accumulate(c, p, fraglen) != 0) return;
    if (flags & ZH2_FL_END_HEADERS) h2_finish_headers(c);
}

static void h2_on_continuation(zh2_conn *c, uint8_t flags,
                               const uint8_t *payload, uint32_t len) {
    /* Caller guaranteed hdr_active && stream == hdr_id. */
    if (++c->cont_count > ZH2_CONT_MAX) { conn_error(c, ZH2_E_ENHANCE_YOUR_CALM); return; }
    if (hdr_accumulate(c, payload, len) != 0) return;
    if (flags & ZH2_FL_END_HEADERS) h2_finish_headers(c);
}

static void h2_on_data(zh2_conn *c, uint8_t flags, uint32_t id,
                       const uint8_t *payload, uint32_t len) {
    if (id == 0) { conn_error(c, ZH2_E_PROTOCOL_ERROR); return; }
    if ((int64_t)len > c->recv_window) { conn_error(c, ZH2_E_FLOW_CONTROL_ERROR); return; }

    zh2_stream *st = find_stream(c, id);
    if (!st) {
        recv_consume(c, NULL, len, false);     /* replenish connection window */
        if (id > c->last_client_id) conn_error(c, ZH2_E_PROTOCOL_ERROR); /* idle */
        return;                                /* else: already-closed stream */
    }
    if (st->end_stream_recv || !st->got_headers) {
        conn_error(c, ZH2_E_STREAM_CLOSED); return;
    }
    if ((int64_t)len > st->recv_window) {
        rst_stream(c, st, ZH2_E_FLOW_CONTROL_ERROR);
        recv_consume(c, NULL, len, false);
        return;
    }

    /* Strip padding. */
    const uint8_t *p = payload;
    size_t after = len;
    uint8_t pad = 0;
    if (flags & ZH2_FL_PADDED) {
        if (after < 1) { conn_error(c, ZH2_E_PROTOCOL_ERROR); return; }
        pad = p[0]; p++; after--;
    }
    if (pad > after) { conn_error(c, ZH2_E_PROTOCOL_ERROR); return; }
    size_t dlen = after - pad;

    /* Body cap (overflow-safe: body.len <= max_body_bytes is invariant). */
    if (dlen > c->lim->max_body_bytes - st->req.body.len) {
        rst_stream(c, st, ZH2_E_ENHANCE_YOUR_CALM);
        recv_consume(c, NULL, len, false);
        return;
    }
    if (dlen && zhs_buf_append_(&st->req.body, p, dlen) != ZCIO_OK) {
        c->oom = true; return;
    }

    bool end = (flags & ZH2_FL_END_STREAM) != 0;
    recv_consume(c, st, len, !end);
    if (end) { st->end_stream_recv = true; h2_dispatch(c, st); }
}

static void h2_on_rst_stream(zh2_conn *c, uint32_t id, uint32_t len) {
    if (len != 4) { conn_error(c, ZH2_E_FRAME_SIZE_ERROR); return; }
    if (id == 0)  { conn_error(c, ZH2_E_PROTOCOL_ERROR);   return; }
    size_t idx;
    if (find_index(c, id, &idx)) {
        zh2_stream *st = c->streams[idx];
        if (!st->responded) c->rapid_reset++;   /* reset before we answered */
        stream_close(c, idx);
        if (c->rapid_reset > c->lim->max_streams)
            conn_error(c, ZH2_E_ENHANCE_YOUR_CALM);   /* CVE-2023-44487 */
    } else if (id > c->last_client_id) {
        conn_error(c, ZH2_E_PROTOCOL_ERROR);     /* RST on an idle stream */
    }
    /* else: already-closed stream -> ignore */
}

static void h2_on_settings(zh2_conn *c, uint8_t flags, uint32_t id,
                           const uint8_t *payload, uint32_t len,
                           unsigned *settings_this_feed) {
    if (id != 0) { conn_error(c, ZH2_E_PROTOCOL_ERROR); return; }
    if (flags & ZH2_FL_ACK) {
        if (len != 0) conn_error(c, ZH2_E_FRAME_SIZE_ERROR);  /* RFC 9113 6.5 */
        return;                                               /* our SETTINGS ACKed */
    }
    if (len % 6 != 0) { conn_error(c, ZH2_E_FRAME_SIZE_ERROR); return; }
    if (++*settings_this_feed > ZH2_SETTINGS_PER_FEED) {
        conn_error(c, ZH2_E_ENHANCE_YOUR_CALM); return;       /* SETTINGS flood */
    }

    for (uint32_t off = 0; off < len; off += 6) {
        uint16_t sid = rd16(payload + off);
        uint32_t val = rd32(payload + off + 2);
        switch (sid) {
        case ZH2_S_ENABLE_PUSH:
            if (val > 1) { conn_error(c, ZH2_E_PROTOCOL_ERROR); return; }
            break;
        case ZH2_S_INITIAL_WINDOW_SIZE:
            if (val > ZH2_MAX_WINDOW) { conn_error(c, ZH2_E_FLOW_CONTROL_ERROR); return; }
            /* Re-target every open stream's send window by the delta. */
            {
                int64_t delta = (int64_t)val - (int64_t)c->peer_initial_window;
                for (size_t i = 0; i < c->nstreams; i++) {
                    c->streams[i]->send_window += delta;
                    if (c->streams[i]->send_window > ZH2_MAX_WINDOW) {
                        conn_error(c, ZH2_E_FLOW_CONTROL_ERROR); return;
                    }
                }
                c->peer_initial_window = val;
            }
            break;
        case ZH2_S_MAX_FRAME_SIZE:
            if (val < 16384 || val > 16777215) { conn_error(c, ZH2_E_PROTOCOL_ERROR); return; }
            c->peer_max_frame = val;
            break;
        case ZH2_S_HEADER_TABLE_SIZE:      /* affects our (stateless) encoder: ignore */
        case ZH2_S_MAX_CONCURRENT_STREAMS: /* limits streams we open: we open none    */
        case ZH2_S_MAX_HEADER_LIST_SIZE:   /* advisory                                */
        default:                           /* unknown settings ignored (RFC 9113 6.5) */
            break;
        }
    }
    q_settings_ack(c);
}

static void h2_on_ping(zh2_conn *c, uint8_t flags, uint32_t id,
                       const uint8_t *payload, uint32_t len,
                       unsigned *pings_this_feed) {
    if (id != 0)  { conn_error(c, ZH2_E_PROTOCOL_ERROR);   return; }
    if (len != 8) { conn_error(c, ZH2_E_FRAME_SIZE_ERROR); return; }
    if (flags & ZH2_FL_ACK) return;              /* reply to our ping: ignore */
    if (++*pings_this_feed > ZH2_PING_PER_FEED ||
        ZHS_AVAIL(c->out) > c->lim->max_out_bytes) {
        conn_error(c, ZH2_E_ENHANCE_YOUR_CALM); return;   /* PING flood */
    }
    q_ping_ack(c, payload);
}

static void h2_on_window_update(zh2_conn *c, uint32_t id,
                                const uint8_t *payload, uint32_t len) {
    if (len != 4) { conn_error(c, ZH2_E_FRAME_SIZE_ERROR); return; }
    uint32_t incr = rd32(payload) & 0x7fffffffu;

    if (id == 0) {
        if (incr == 0) { conn_error(c, ZH2_E_PROTOCOL_ERROR); return; }
        c->send_window += (int64_t)incr;
        if (c->send_window > ZH2_MAX_WINDOW) conn_error(c, ZH2_E_FLOW_CONTROL_ERROR);
        return;
    }
    zh2_stream *st = find_stream(c, id);
    if (incr == 0) {
        if (st) rst_stream(c, st, ZH2_E_PROTOCOL_ERROR);
        else if (id > c->last_client_id) conn_error(c, ZH2_E_PROTOCOL_ERROR);
        return;
    }
    if (st) {
        st->send_window += (int64_t)incr;
        if (st->send_window > ZH2_MAX_WINDOW) rst_stream(c, st, ZH2_E_FLOW_CONTROL_ERROR);
    } else if (id > c->last_client_id) {
        conn_error(c, ZH2_E_PROTOCOL_ERROR);     /* WINDOW_UPDATE on idle stream */
    }
    /* else: already-closed stream -> ignore */
}

static void h2_on_goaway(zh2_conn *c, uint32_t id, uint32_t len) {
    if (id != 0)  { conn_error(c, ZH2_E_PROTOCOL_ERROR);   return; }
    if (len < 8)  { conn_error(c, ZH2_E_FRAME_SIZE_ERROR); return; }
    c->peer_goaway = true;   /* finish in-flight; refuse to open new streams */
}

/* ========================================================================= *
 *  Feed
 * ========================================================================= */

/* Consume as much of the client preface as is present. Returns false if more
 * bytes are still needed; sets a connection error on mismatch. */
static bool consume_preface(zh2_conn *c, zhs_buf *in) {
    while (c->preface_got < ZH2_PREFACE_LEN && ZHS_AVAIL(in) > 0) {
        if (*ZHS_PTR(in) != (uint8_t)ZH2_PREFACE[c->preface_got]) {
            conn_error(c, ZH2_E_PROTOCOL_ERROR);
            return false;
        }
        c->preface_got++;
        zhs_buf_consume_(in, 1);
    }
    if (c->preface_got < ZH2_PREFACE_LEN) return false;   /* need more */
    c->preface_done = true;
    return true;
}

int zh2_feed_(zh2_conn *c, zhs_buf *in) {
    if (c->oom) return zcio_fail_(ZCIO_ERR_NOMEM, "h2: out of memory");

    if (!c->preface_done) {
        if (!consume_preface(c, in)) {
            if (c->got_error) return ZH2_CLOSING;
            return ZH2_OK;                       /* mismatch handled / need more */
        }
    }

    unsigned pings = 0, settings = 0;

    while (!c->got_error && !c->oom) {
        if (ZHS_AVAIL(in) < ZH2_FRAME_HDR) break;        /* partial header */
        const uint8_t *h = ZHS_PTR(in);
        uint32_t len   = rd24(h);
        uint8_t  type  = h[3];
        uint8_t  flags = h[4];
        uint32_t sid   = rd32(h + 5) & 0x7fffffffu;

        if (len > ZH2_OUR_MAX_FRAME) { conn_error(c, ZH2_E_FRAME_SIZE_ERROR); break; }
        if (ZHS_AVAIL(in) < (size_t)ZH2_FRAME_HDR + len) break;   /* partial frame */

        const uint8_t *payload = h + ZH2_FRAME_HDR;

        /* The first frame after the preface MUST be SETTINGS (RFC 9113 3.4). */
        if (c->need_settings) {
            if (type != ZH2_FT_SETTINGS) { conn_error(c, ZH2_E_PROTOCOL_ERROR); break; }
            c->need_settings = false;
        }

        /* A header block in progress may only be followed by CONTINUATION on
         * the same stream; anything else is a connection error. */
        if (c->hdr_active) {
            if (type != ZH2_FT_CONTINUATION || sid != c->hdr_id) {
                conn_error(c, ZH2_E_PROTOCOL_ERROR); break;
            }
        } else if (type == ZH2_FT_CONTINUATION) {
            conn_error(c, ZH2_E_PROTOCOL_ERROR); break;
        }

        switch (type) {
        case ZH2_FT_DATA:          h2_on_data(c, flags, sid, payload, len); break;
        case ZH2_FT_HEADERS:       h2_on_headers(c, flags, sid, payload, len); break;
        case ZH2_FT_PRIORITY:      /* accept + ignore; RFC 9113 §6.3 */
            if (sid == 0) conn_error(c, ZH2_E_PROTOCOL_ERROR);
            else if (len != 5) conn_error(c, ZH2_E_FRAME_SIZE_ERROR);
            break;
        case ZH2_FT_RST_STREAM:    h2_on_rst_stream(c, sid, len); break;
        case ZH2_FT_SETTINGS:      h2_on_settings(c, flags, sid, payload, len, &settings); break;
        case ZH2_FT_PUSH_PROMISE:  conn_error(c, ZH2_E_PROTOCOL_ERROR); break; /* client MUST NOT push */
        case ZH2_FT_PING:          h2_on_ping(c, flags, sid, payload, len, &pings); break;
        case ZH2_FT_GOAWAY:        h2_on_goaway(c, sid, len); break;
        case ZH2_FT_WINDOW_UPDATE: h2_on_window_update(c, sid, payload, len); break;
        case ZH2_FT_CONTINUATION:  h2_on_continuation(c, flags, payload, len); break;
        default:                   break;   /* unknown frame types are ignored */
        }

        zhs_buf_consume_(in, (size_t)ZH2_FRAME_HDR + len);
    }

    if (c->oom) return zcio_fail_(ZCIO_ERR_NOMEM, "h2: out of memory");
    return (c->closing || c->got_error) ? ZH2_CLOSING : ZH2_OK;
}

/* ========================================================================= *
 *  Response encoding (respond_fn) + pump
 * ========================================================================= */

/* HPACK-encode one response header with a forced-lowercase name (HTTP/2 names
 * must be lowercase; the respond policy layer does not lowercase them). */
static int h2_encode_header(zhs_buf *fb, const char *name, const char *value) {
    char stackbuf[64];
    size_t nlen = strlen(name);
    char *low = stackbuf;
    if (nlen >= sizeof stackbuf) {
        low = (char *)zcio_xmalloc(nlen + 1);
        if (!low) return ZCIO_ERR_NOMEM;
    }
    for (size_t i = 0; i < nlen; i++) {
        char ch = name[i];
        low[i] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
    }
    low[nlen] = '\0';
    int r = zhp_encode_(fb, low, value ? value : "");
    if (low != stackbuf) free(low);
    return r;
}

/* Wire-format hook installed on every h2 request. Encodes the field block,
 * emits HEADERS (+ CONTINUATION when it exceeds MAX_FRAME_SIZE), and stashes
 * the body for zh2_pump_ to move out under flow control. */
static int zh2_respond(zcio_http_req *req, int status,
                       const zcio_http_header *hdrs, size_t nhdrs,
                       const void *body, size_t body_len) {
    zh2_stream *st = (zh2_stream *)req->owner;
    zh2_conn   *c  = st->conn;
    if (st->responded) return zcio_fail_(ZCIO_ERR, "h2: double respond");

    /* Encode :status + the final (already-filtered) header set. */
    zhs_buf fb = {0};
    int r = zhp_encode_status_(&fb, status);
    for (size_t i = 0; r == ZCIO_OK && i < nhdrs; i++) {
        if (!hdrs[i].key) continue;
        r = h2_encode_header(&fb, hdrs[i].key, hdrs[i].value);
    }
    if (r != ZCIO_OK) { zhs_buf_free_(&fb); c->oom = true; return r; }

    /* Bodies on HEAD / 204 / 304 / 1xx are suppressed (RFC 9110). */
    bool has_body = body && body_len > 0 && !req->is_head &&
                    status >= 200 && status != 204 && status != 304;

    /* Fragment the field block across HEADERS + CONTINUATION frames. */
    size_t off = 0, total = fb.len;
    uint32_t maxf = c->peer_max_frame ? c->peer_max_frame : ZH2_DEFAULT_MAX_FRAME;
    bool first = true;
    do {
        size_t chunk = total - off;
        if (chunk > maxf) chunk = maxf;
        bool last = (off + chunk == total);
        uint8_t type = first ? ZH2_FT_HEADERS : ZH2_FT_CONTINUATION;
        uint8_t flags = 0;
        if (last)  flags |= ZH2_FL_END_HEADERS;
        if (first && !has_body) flags |= ZH2_FL_END_STREAM;
        if (h2_frame(c, (uint32_t)chunk, type, flags, st->id, fb.data + off) != ZCIO_OK) {
            zhs_buf_free_(&fb); c->oom = true; return ZCIO_ERR_NOMEM;
        }
        off += chunk;
        first = false;
    } while (off < total);
    zhs_buf_free_(&fb);

    st->resp_headers_done = true;
    st->responded = true;
    req->responded = true;

    if (has_body) {
        if (zhs_buf_append_(&st->resp_body, body, body_len) != ZCIO_OK) {
            c->oom = true; return ZCIO_ERR_NOMEM;
        }
        st->resp_end_after_body = true;
    } else {
        st->send_done = true;              /* END_STREAM already on HEADERS */
    }
    return ZCIO_OK;
}

void zh2_pump_(zh2_conn *c) {
    if (!c || c->oom) return;

    for (size_t i = 0; i < c->nstreams; ) {
        zh2_stream *st = c->streams[i];

        if (st->resp_headers_done && !st->send_done) {
            size_t total = st->resp_body.len;   /* resp_body is never consumed */
            while (st->body_off < total) {
                int64_t swin = st->send_window < 0 ? 0 : st->send_window;
                int64_t cwin = c->send_window   < 0 ? 0 : c->send_window;
                int64_t win  = swin < cwin ? swin : cwin;
                if (win <= 0) break;             /* blocked on flow control */

                size_t out_used = ZHS_AVAIL(c->out);
                if (out_used >= c->lim->max_out_bytes) break;            /* backpressure */
                size_t out_budget = c->lim->max_out_bytes - out_used;
                if (out_budget <= ZH2_FRAME_HDR) break;

                size_t chunk = total - st->body_off;
                if (chunk > (uint64_t)win)      chunk = (size_t)win;
                if (chunk > c->peer_max_frame)  chunk = c->peer_max_frame;
                if (chunk > out_budget - ZH2_FRAME_HDR) chunk = out_budget - ZH2_FRAME_HDR;
                if (chunk == 0) break;

                bool last = (st->body_off + chunk == total);
                uint8_t flags = (last && st->resp_end_after_body) ? ZH2_FL_END_STREAM : 0;
                if (h2_frame(c, (uint32_t)chunk, ZH2_FT_DATA, flags, st->id,
                             st->resp_body.data + st->body_off) != ZCIO_OK) {
                    c->oom = true; return;
                }
                st->body_off    += chunk;
                st->send_window -= (int64_t)chunk;
                c->send_window  -= (int64_t)chunk;
                if (last) st->send_done = true;
            }
        }

        if (st->send_done && st->end_stream_recv) { stream_close(c, i); continue; }
        i++;
    }
}

/* ========================================================================= *
 *  Lifecycle
 * ========================================================================= */

zh2_conn *zh2_new_(struct zcio_http_server *srv, const zhs_limits *lim,
                   bool secure, zhs_buf *out) {
    zh2_conn *c = (zh2_conn *)zcio_xcalloc(1, sizeof *c);
    if (!c) { zcio_fail_(ZCIO_ERR_NOMEM, "h2: out of memory"); return NULL; }
    c->srv = srv; c->lim = lim; c->secure = secure; c->out = out;
    c->dec = zhp_dec_new_(ZHP_DEC_TABLE_MAX);
    if (!c->dec) { free(c); zcio_fail_(ZCIO_ERR_NOMEM, "h2: out of memory"); return NULL; }

    c->recv_window = ZH2_CONN_WINDOW;
    c->send_window = ZH2_CONN_WINDOW;
    c->peer_initial_window = ZH2_DEFAULT_INIT_WINDOW;
    c->peer_max_frame      = ZH2_DEFAULT_MAX_FRAME;
    c->need_settings = true;

    /* Server connection preface: our SETTINGS (RFC 9113 sec. 3.4). */
    uint32_t hlist = lim->max_header_bytes > 0xffffffffu
                   ? 0xffffffffu : (uint32_t)lim->max_header_bytes;
    uint8_t s[30];
    wr16(s + 0,  ZH2_S_HEADER_TABLE_SIZE);      wr32(s + 2,  ZHP_DEC_TABLE_MAX);
    wr16(s + 6,  ZH2_S_MAX_CONCURRENT_STREAMS); wr32(s + 8,  lim->max_streams);
    wr16(s + 12, ZH2_S_INITIAL_WINDOW_SIZE);    wr32(s + 14, ZH2_OUR_INITIAL_WINDOW);
    wr16(s + 18, ZH2_S_MAX_FRAME_SIZE);         wr32(s + 20, ZH2_OUR_MAX_FRAME);
    wr16(s + 24, ZH2_S_MAX_HEADER_LIST_SIZE);   wr32(s + 26, hlist);
    if (h2_frame(c, sizeof s, ZH2_FT_SETTINGS, 0, 0, s) != ZCIO_OK) {
        zhp_dec_free_(c->dec); free(c);
        zcio_fail_(ZCIO_ERR_NOMEM, "h2: out of memory");
        return NULL;
    }
    return c;
}

bool zh2_idle_(const zh2_conn *c) {
    if (!c) return true;
    if (c->got_error) return true;   /* erroring out: loop closes after out drains */
    if (c->hdr_active) return false;
    return c->nstreams == 0;
}

void zh2_graceful_(zh2_conn *c) {
    if (!c) return;
    q_goaway(c, ZH2_E_NO_ERROR);
    c->closing = true;               /* refuse new streams; finish in-flight */
}

void zh2_free_(zh2_conn *c) {
    if (!c) return;
    if (c->dec) zhp_dec_free_(c->dec);
    for (size_t i = 0; i < c->nstreams; i++) {
        zhs_buf_free_(&c->streams[i]->resp_body);
        zhs_req_reset_(&c->streams[i]->req);
        free(c->streams[i]);
    }
    free(c->streams);
    zhs_buf_free_(&c->hdr_block);
    free(c);
}
