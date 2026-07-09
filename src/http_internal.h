/* src/http_internal.h - private contracts between the HTTP server modules.
 * Not installed; not part of the public ABI.
 *
 * The server is layered as sans-I/O state machines glued by one event loop:
 *
 *   http_server.c  event loop, listeners, conn table, deadlines, dispatch,
 *                  respond policy (auto headers, filtering), graceful stop
 *   h1.c           HTTP/1.1 request parser + response serializer (hardened)
 *   h2.c           HTTP/2 framing, streams, flow control, flood guards
 *   hpack.c        HPACK decode (dyn table) / stateless encode + Huffman
 *   h3.c           HTTP/3 over OpenSSL QUIC (>= 3.5); stubs otherwise
 *   qpack.c        QPACK static-table-only decode/encode
 *   ws.c           RFC 6455 framing, both roles; detaches conns from the loop
 *   http_util.c    shared buffers, header lists, limits, validation helpers
 *
 * Modules NEVER touch sockets: h1/h2 consume a zhs_buf of input bytes and
 * append wire bytes to a zhs_buf of output; the loop moves bytes between
 * those buffers and the (possibly TLS) zcio_stream. h3 is the exception —
 * OpenSSL owns the UDP socket; h3.c exposes fd/timeout/process hooks instead.
 *
 * Security ground rules for every module (enforced, not aspirational):
 *   - single-pass, linear-time parsing; no recursion on attacker input
 *   - every length is bounds-checked against zhs_limits BEFORE allocation
 *   - all integer arithmetic on wire values is overflow-checked
 *   - header storage is a bounded array (no hashing to flood)
 *   - on protocol error: emit the mandated error response/frame, then close
 */
#ifndef ZCIO_HTTP_INTERNAL_H
#define ZCIO_HTTP_INTERNAL_H

#include "zcio/types.h"
#include "zcio/stream.h"
#include "zcio/http.h"
#include "zcio/http_server.h"
#include "internal.h"

/* ========================================================================= *
 *  Shared growable byte buffer (http_util.c)
 * ========================================================================= */

/* Readable region is [off, len); append grows the tail. Consuming advances
 * `off` (O(1)); the buffer compacts opportunistically so a long-lived
 * connection cannot accrete an unbounded dead prefix. */
typedef struct zhs_buf {
    uint8_t *data;
    size_t   off;
    size_t   len;
    size_t   cap;
} zhs_buf;

#define ZHS_AVAIL(b) ((b)->len - (b)->off)
#define ZHS_PTR(b)   ((b)->data + (b)->off)

int  zhs_buf_reserve_(zhs_buf *b, size_t extra);            /* ZCIO_OK/NOMEM  */
int  zhs_buf_append_(zhs_buf *b, const void *src, size_t n);
int  zhs_buf_append_str_(zhs_buf *b, const char *s);
int  zhs_buf_append_u8_(zhs_buf *b, uint8_t v);
void zhs_buf_consume_(zhs_buf *b, size_t n);                /* n <= ZHS_AVAIL */
void zhs_buf_reset_(zhs_buf *b);                            /* keep alloc     */
void zhs_buf_free_(zhs_buf *b);

/* ========================================================================= *
 *  Resolved limits (http_util.c)
 * ========================================================================= */

typedef struct zhs_limits {
    size_t   max_header_bytes;      /* 32768   */
    size_t   max_headers;           /* 128     */
    size_t   max_body_bytes;        /* 64 MiB  */
    size_t   max_url_bytes;         /* 8192    */
    uint32_t max_streams;           /* 128     */
    uint32_t max_requests_per_conn; /* 1024    */
    uint32_t max_connections;       /* 1024    */
    size_t   max_out_bytes;         /* 4 MiB   */
    int      header_timeout_ms;     /* 10000   */
    int      idle_timeout_ms;       /* 60000   */
    int      write_timeout_ms;      /* 30000   */
    int      drain_timeout_ms;      /* 5000    */
} zhs_limits;

/* Fill from cfg with defaults for zero fields. */
void zhs_limits_resolve_(zhs_limits *lim, const zcio_http_server_config *cfg);

/* ========================================================================= *
 *  Bounded header list (http_util.c)
 * ========================================================================= */

typedef struct zhs_hdr  { char *name; char *value; } zhs_hdr;
typedef struct zhs_hdrs { zhs_hdr *v; size_t n; size_t cap; size_t bytes; } zhs_hdrs;

/* Copy-in add. Enforces lim->max_headers and lim->max_header_bytes (name+value
 * lengths accumulate into ->bytes). lower_name forces the stored name to
 * lowercase (h1 path; h2/h3 names arrive lowercase already or are rejected).
 * ZCIO_OK, ZCIO_ERR_PROTOCOL (a cap), or ZCIO_ERR_NOMEM. */
int         zhs_hdrs_add_(zhs_hdrs *h, const char *name, size_t nlen,
                          const char *value, size_t vlen,
                          const zhs_limits *lim, bool lower_name);
const char *zhs_hdrs_get_(const zhs_hdrs *h, const char *name);   /* ci, first */
size_t      zhs_hdrs_count_(const zhs_hdrs *h, const char *name); /* ci        */
void        zhs_hdrs_free_(zhs_hdrs *h);

/* ========================================================================= *
 *  Validation / formatting helpers (http_util.c)
 * ========================================================================= */

bool zhs_token_ok_(const char *s, size_t n);   /* RFC 9110 tchar+, n > 0      */
bool zhs_value_ok_(const char *s, size_t n);   /* no CTL/DEL except HTAB      */
bool zhs_lower_token_ok_(const char *s, size_t n); /* tchar and no uppercase  */

/* Incremental UTF-8 validation (Hoehrmann DFA). state starts at ACCEPT; feed
 * each byte; ACCEPT = complete-so-far, REJECT = invalid (sticky), any other
 * value = mid-codepoint. */
#define ZHS_UTF8_ACCEPT 0u
#define ZHS_UTF8_REJECT 12u
uint32_t zhs_utf8_step_(uint32_t state, uint8_t byte);
bool     zhs_utf8_valid_(const void *s, size_t n); /* complete string          */

/* Percent-decode + remove-dot-segments an origin-form request target.
 * Splits at '?'. Rejects: empty/relative targets, decoded NUL/CTL bytes,
 * malformed %XX, targets longer than lim->max_url_bytes. Linear time.
 * On ZCIO_OK, *path_out (malloc'd, starts with '/') and *query_out (malloc'd
 * raw query without '?', or NULL) are set. Accepts "*" (OPTIONS) verbatim. */
int zhs_decode_target_(const char *raw, size_t rawlen, const zhs_limits *lim,
                       char **path_out, char **query_out);

/* "Sun, 06 Nov 1994 08:49:37 GMT" for the current wall clock. */
void zhs_http_date_(char out[32]);

/* Reason phrase for a status code ("OK", "Not Found", ... "" if unknown). */
const char *zhs_status_text_(int status);

/* ========================================================================= *
 *  The request object (storage owned by the protocol module)
 * ========================================================================= */

struct zcio_http_req {
    /* wire facts */
    int      version;     /* 1, 2, 3 */
    bool     secure;      /* arrived over TLS/QUIC */
    bool     is_head;     /* method == HEAD (response body suppressed) */
    bool     ws_upgrade;  /* h1: validated RFC 6455 upgrade request */
    char    *method;      /* malloc'd */
    char    *path;        /* malloc'd; decoded + normalized, or "*" */
    char    *query;       /* malloc'd or NULL */
    char    *authority;   /* malloc'd Host / :authority (no userinfo) or NULL */
    zhs_hdrs headers;     /* names lowercased; pseudo-headers NOT included */
    zhs_buf  body;        /* complete, capped; NUL byte appended after len */

    /* plumbing */
    struct zcio_http_server *srv;
    void    *owner;       /* zh1_conn* / zh2_conn* / zh3 per-request ctx */
    int64_t  stream_id;   /* h2/h3 stream id; 0 for h1 */
    bool     responded;

    /* Wire-format hook installed by the owning module. `hdrs` is the FINAL,
     * already-validated + merged header set from the respond policy layer.
     * The module adds protocol framing (status/pseudo-header, Content-Length
     * or DATA framing, keep-alive vs close) and queues bytes on its out buf. */
    int (*respond_fn)(struct zcio_http_req *req, int status,
                      const zcio_http_header *hdrs, size_t nhdrs,
                      const void *body, size_t body_len);
};

/* Free every owned field and zero the struct (plumbing included). */
void zhs_req_reset_(zcio_http_req *req);

/* ========================================================================= *
 *  Services http_server.c provides to the protocol modules
 * ========================================================================= */

/* Run the user handler on a completed request: guarantees exactly one
 * response (500 fallback if the handler neither responded nor detached for
 * websocket). Does NOT reset/free `req`. If the connection was detached by
 * zcio_ws_accept during the call, returns 1 (the module must stop touching
 * its buffers and report closure upward); otherwise 0. */
int zhs_dispatch_(struct zcio_http_server *srv, zcio_http_req *req);

/* WebSocket detach (called by ws.c from inside a handler): write `resp`
 * (the 101) plus any bytes already queued on the connection's out buffer to
 * the transport synchronously (restoring a blocking timeout), remove the
 * connection from the loop, and hand over the stream. NULL on failure (the
 * connection is then closed by the server). h1 connections only.
 *
 * `*leftover`/`*leftover_len` (when non-NULL) receive any bytes the connection
 * had already buffered PAST the upgrade request (a client that pipelined its
 * first WebSocket frames onto the handshake). The pointer aliases connection
 * memory freed after dispatch, so the caller must COPY it before returning. */
zcio_stream *zhs_detach_for_upgrade_(zcio_http_req *req,
                                     const void *resp, size_t resp_len,
                                     const uint8_t **leftover, size_t *leftover_len);

/* ========================================================================= *
 *  HTTP/1.1 (h1.c)
 * ========================================================================= */

typedef struct zh1_conn zh1_conn;

enum {
    ZH1_F_SECURE   = 1u << 0,  /* connection is TLS-wrapped */
    ZH1_F_REDIRECT = 1u << 1,  /* redirect-listener mode: 301 every request to
                                * https://host[:port]target, never dispatch */
};

/* `out` is the connection's output buffer (owned by the loop, stable address).
 * `user` is the loop's per-connection context (retrieved via zh1_user_). */
zh1_conn *zh1_new_(struct zcio_http_server *srv, const zhs_limits *lim,
                   uint32_t flags, zhs_buf *out, void *user);

/* Feed/parse: consumes from `in`, dispatches completed requests, writes
 * responses (including its own error responses: 400/413/431/501/505) to out.
 * Returns:
 *   ZH1_NEED_MORE  - consumed all it could; wait for more input
 *   ZH1_DISPATCHED - >= 1 request handled this call (loop should try to write)
 *   ZH1_CLOSE      - close the connection once out drains
 *   ZH1_DETACHED   - connection was detached (websocket); stop entirely
 *   negative       - hard error; close immediately
 * A request whose headers are complete but whose body still streams in keeps
 * returning NEED_MORE until the body cap or Content-Length is satisfied. */
enum { ZH1_NEED_MORE = 0, ZH1_DISPATCHED = 1, ZH1_CLOSE = 2, ZH1_DETACHED = 3 };
int   zh1_feed_(zh1_conn *c, zhs_buf *in);

bool  zh1_idle_(const zh1_conn *c);     /* between requests                  */
bool  zh1_mid_headers_(const zh1_conn *c); /* reading request head (slowloris
                                            * deadline applies)              */
bool  zh1_receiving_(const zh1_conn *c);   /* a request (head or body) is in
                                            * flight: absolute receive deadline */
void  zh1_graceful_(zh1_conn *c);       /* Connection: close after current   */
void *zh1_user_(zh1_conn *c);
void  zh1_free_(zh1_conn *c);

/* ========================================================================= *
 *  HPACK (hpack.c) - shared Huffman + integers reused by QPACK
 * ========================================================================= */

typedef struct zhp_dec zhp_dec;         /* decoder w/ dynamic table (opaque)  */

/* Our advertised SETTINGS_HEADER_TABLE_SIZE; the decoder honors dynamic-table
 * size updates only up to this cap. */
#define ZHP_DEC_TABLE_MAX 4096

zhp_dec *zhp_dec_new_(size_t max_table_bytes);
void     zhp_dec_free_(zhp_dec *d);

typedef int (*zhp_emit_fn)(void *u, const char *name, size_t nlen,
                           const char *value, size_t vlen);

/* Decode one COMPLETE header block (post-CONTINUATION reassembly). Enforces:
 * prefixed-integer cap (ZHP_INT_MAX), Huffman validity (incl. EOS/padding
 * rules), dynamic-table consistency, and `max_decoded_bytes` on the sum of
 * decoded name+value lengths (the RFC 9113 header-list-size guard). The emit
 * callback returning nonzero aborts decoding with that value.
 * ZCIO_OK | ZCIO_ERR_PROTOCOL | ZCIO_ERR_NOMEM. */
int zhp_decode_(zhp_dec *d, const uint8_t *block, size_t len,
                size_t max_decoded_bytes, zhp_emit_fn emit, void *u);

/* Stateless encoding: literal-without-indexing, static-table name refs where
 * available, no Huffman. (Deliberate: an encoder with no dynamic state cannot
 * be desynchronized.) */
int zhp_encode_(zhs_buf *out, const char *name, const char *value);
int zhp_encode_status_(zhs_buf *out, int status); /* ":status" via static tbl */

/* HPACK primitives shared with QPACK. Integers cap at ZHP_INT_MAX. */
#define ZHP_INT_MAX ((uint64_t)1 << 24)
/* Decode a prefix-int whose first byte is p[0] & mask(prefix_bits). Returns
 * bytes consumed (>= 1) or ZCIO_ERR_PROTOCOL (truncated/overflow). */
int zhp_int_decode_(const uint8_t *p, size_t n, unsigned prefix_bits, uint64_t *out);
/* Encode v with `flags` OR'd into the first byte's high bits. */
int zhp_int_encode_(zhs_buf *out, unsigned prefix_bits, uint8_t flags, uint64_t v);
/* Huffman-decode (RFC 7541 App. B). Rejects overlong padding / EOS symbol /
 * output beyond max_out. */
int zhp_huff_decode_(const uint8_t *in, size_t n, zhs_buf *out, size_t max_out);

/* ========================================================================= *
 *  HTTP/2 (h2.c)
 * ========================================================================= */

typedef struct zh2_conn zh2_conn;

/* Writes the server SETTINGS frame to out immediately. The client preface
 * ("PRI * HTTP/2.0...") is consumed by the first zh2_feed_ calls. */
zh2_conn *zh2_new_(struct zcio_http_server *srv, const zhs_limits *lim,
                   bool secure, zhs_buf *out);

/* Parse every complete frame available in `in`, dispatching completed
 * requests. All h2 error handling (RST_STREAM, GOAWAY + close) is internal.
 * Returns:
 *   ZH2_OK      - keep going
 *   ZH2_CLOSING - GOAWAY queued; close once out drains and streams finish
 *   negative    - hard error; close immediately */
enum { ZH2_OK = 0, ZH2_CLOSING = 1 };
int  zh2_feed_(zh2_conn *c, zhs_buf *in);

/* Move pending response DATA to out as peer flow-control windows and the
 * max_out_bytes cap allow. The loop calls this whenever out drains. */
void zh2_pump_(zh2_conn *c);

bool zh2_idle_(const zh2_conn *c);   /* no open streams, nothing pending      */
void zh2_graceful_(zh2_conn *c);     /* queue GOAWAY(NO_ERROR); refuse new    */
void zh2_free_(zh2_conn *c);

/* ========================================================================= *
 *  QPACK, static table only (qpack.c)
 * ========================================================================= */

/* Decode a complete request header block. We advertise dynamic-table capacity
 * 0, so a Required-Insert-Count != 0 (or any dynamic reference) is a protocol
 * error. Same emit/caps contract as zhp_decode_. */
int zqp_decode_(const uint8_t *block, size_t len, size_t max_decoded_bytes,
                zhp_emit_fn emit, void *u);

/* Encoded field section prefix (RIC 0, base 0) + stateless field lines. */
int zqp_prefix_encode_(zhs_buf *out);
int zqp_encode_(zhs_buf *out, const char *name, const char *value);
int zqp_encode_status_(zhs_buf *out, int status);

/* ========================================================================= *
 *  HTTP/3 over OpenSSL QUIC (h3.c) - stubbed to UNSUPPORTED without
 *  ZCIO_TLS_OPENSSL or with OpenSSL < 3.5
 * ========================================================================= */

typedef struct zh3_srv zh3_srv;

/* Binds the UDP socket, builds the QUIC listener (from cfg tls material or a
 * self-signed cert), advertises ALPN "h3". NULL + zcio_last_error on failure
 * or when unsupported. */
zh3_srv *zh3_new_(struct zcio_http_server *srv, const zcio_http_server_config *cfg,
                  const zhs_limits *lim, int port);

int  zh3_fd_(zh3_srv *h);            /* UDP fd for the poll set               */
int  zh3_timeout_ms_(zh3_srv *h);    /* next QUIC timer deadline, -1 = none   */
int  zh3_process_(zh3_srv *h);       /* accept conns/streams, read, dispatch,
                                      * handle timers. >=0 ok, <0 fatal       */
void zh3_graceful_(zh3_srv *h);      /* HTTP/3 GOAWAY + begin conn shutdown   */
bool zh3_idle_(const zh3_srv *h);    /* all connections fully closed          */
void zh3_free_(zh3_srv *h);

#endif /* ZCIO_HTTP_INTERNAL_H */
