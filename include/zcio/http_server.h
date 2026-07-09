/* zcio/http_server.h - minimal, hardened HTTP server (HTTP/1.1, /2, /3).
 *
 * One server object listens for HTTP/1.1 and HTTP/2 on a TCP port (plaintext
 * or TLS with ALPN selection) and, optionally, HTTP/3 on the same UDP port via
 * the OpenSSL QUIC stack (OpenSSL >= 3.5). Which protocol versions are offered
 * is a config setting (`versions` bitmask) — the wire negotiation (ALPN,
 * HTTP/2 prior-knowledge preface sniffing, QUIC) is handled internally.
 *
 * Design: a single-threaded, non-blocking event loop. zcio_http_server_poll()
 * runs one iteration (accept, TLS handshake progress, parse, dispatch, write);
 * zcio_http_server_run() loops until zcio_http_server_stop() is called. The
 * request handler runs synchronously inside poll — keep it short, or hand
 * long-lived work to your own threads after copying what you need.
 *
 * Algorithmic security: every parser is single-pass and linear-time over
 * bounded input. All limits below are enforced *before* memory is committed:
 * header size/count caps, body cap, URL cap, per-connection output cap,
 * slowloris header deadlines, idle timeouts, HTTP/2 CONTINUATION/PING/SETTINGS
 * /RST flood guards (rapid-reset), HPACK/QPACK integer + Huffman bounds, and
 * strict request-smuggling defenses (no TE+CL mixing, no obs-fold, no bare-LF
 * line endings, single Host, strict chunked framing). Header storage is a
 * bounded linear array — no hash tables to flood.
 *
 * Auto-HTTPS: with TLS configured, `redirect_port` opens a plaintext listener
 * that answers every request with a 301 to the https:// equivalent (and never
 * serves content). `hsts` stamps Strict-Transport-Security on TLS responses;
 * when HTTP/3 is enabled, TLS responses advertise it via Alt-Svc.
 *
 * Graceful exit: zcio_http_server_stop() is async-signal-safe (it sets a flag
 * and pokes a wake pipe). The loop then stops accepting, sends GOAWAY on
 * HTTP/2 and HTTP/3 connections, finishes in-flight exchanges with
 * `Connection: close` on HTTP/1.1, and drains until `drain_timeout_ms`.
 */
#ifndef ZCIO_HTTP_SERVER_H
#define ZCIO_HTTP_SERVER_H

#include "zcio/types.h"
#include "zcio/tls.h"
#include "zcio/http.h" /* zcio_http_header */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zcio_http_server zcio_http_server;
typedef struct zcio_http_req    zcio_http_req;

/* Protocol versions the server offers (config bitmask). */
typedef ZCIO_ENUM(zcio_http_versions, uint32_t) {
    ZCIO_HTTP1_1 = 1u << 0,
    ZCIO_HTTP2   = 1u << 1,
    ZCIO_HTTP3   = 1u << 2,
} zcio_http_versions;

/* Request handler. Runs synchronously inside poll(). It must either call
 * zcio_http_respond() or zcio_ws_accept() (see zcio/ws.h) before returning;
 * otherwise the server answers 500 on its behalf. `req` is only valid for the
 * duration of the call — copy anything you need to keep. */
typedef void (*zcio_http_handler)(zcio_http_req *req, void *user);

/* Server configuration. Zero-init then set what you need; every 0/NULL field
 * has a safe default (defaults in brackets). */
typedef struct zcio_http_server_config {
    int      port;         /* TCP port for h1/h2; UDP port for h3. 0 = ephemeral
                            * (read back with zcio_http_server_port).          */
    const char *bind_host; /* interface to bind: NULL/""/"*" = all interfaces;
                            * else dotted quad or name resolved to IPv4 (e.g.
                            * "localhost" for a loopback-only control plane).
                            * Applies to the h1/h2 and redirect listeners; the
                            * HTTP/3 UDP socket still binds all interfaces.    */
    uint32_t versions;     /* zcio_http_versions bitmask [ZCIO_HTTP1_1]        */

    /* --- TLS / HTTPS --------------------------------------------------- *
     * Precedence: `tls` if non-NULL (BORROWED; the server sets ALPN on it),
     * else cert_file+key_file, else — only if `versions` includes HTTP3 or
     * `require_tls` — a self-signed localhost certificate. With no TLS at
     * all, HTTP/1.1 is served plaintext and HTTP/2 requires the client's
     * prior-knowledge preface. HTTP/3 always requires TLS (QUIC).           */
    zcio_tls_ctx *tls;
    const char   *cert_file;   /* PEM chain  */
    const char   *key_file;    /* PEM key    */
    bool          require_tls; /* generate a self-signed cert if none given  */

    /* --- auto-HTTPS upgrade ------------------------------------------- */
    int         redirect_port; /* >0: plaintext listener 301-redirecting to
                                * https://host:port (0 = no redirect listener) */
    bool        hsts;          /* add Strict-Transport-Security on TLS resps  */
    const char *host;          /* public hostname for redirects; default: the
                                * request's own Host header                   */

    /* --- limits (0 = default) ------------------------------------------ */
    size_t   max_header_bytes;      /* request line + all headers   [32 KiB]  */
    size_t   max_headers;           /* header count                 [128]     */
    size_t   max_body_bytes;        /* request body                 [64 MiB]  */
    size_t   max_url_bytes;         /* request target               [8 KiB]   */
    uint32_t max_streams;           /* h2/h3 concurrent streams     [128]     */
    uint32_t max_requests_per_conn; /* keep-alive / total streams   [1024]    */
    uint32_t max_connections;       /* concurrent TCP conns         [1024]    */
    size_t   max_out_bytes;         /* per-conn queued output cap   [4 MiB]   */
    int      header_timeout_ms;     /* slowloris guard              [10000]   */
    int      idle_timeout_ms;       /* keep-alive idle              [60000]   */
    int      write_timeout_ms;      /* slow-read guard              [30000]   */
    int      drain_timeout_ms;      /* graceful-stop drain          [5000]    */
} zcio_http_server_config;

/* --- lifecycle ----------------------------------------------------------- */

/* Bind listeners and return a running (but not yet polling) server, or NULL
 * (zcio_last_error() explains). `cfg` is copied; `cfg->tls` stays borrowed. */
ZCIO_API ZCIO_NODISCARD zcio_http_server *
zcio_http_server_start(const zcio_http_server_config *cfg,
                       zcio_http_handler handler, void *user);

/* One event-loop iteration: waits up to timeout_ms (-1 = until activity) for
 * socket/QUIC events, then accepts, handshakes, parses, dispatches, writes.
 * Returns >0 if any work was done, 0 on timeout, <0 (negated zcio_result) on
 * fatal server error. Returns ZCIO_ERR_EOF once fully stopped and drained. */
ZCIO_API int zcio_http_server_poll(zcio_http_server *s, int timeout_ms);

/* Loop poll() until stop() completes the graceful drain. ZCIO_OK on clean
 * shutdown, or the first fatal error. */
ZCIO_API int zcio_http_server_run(zcio_http_server *s);

/* Begin graceful shutdown: stop accepting, GOAWAY h2/h3, `Connection: close`
 * h1, drain in-flight work up to drain_timeout_ms. Async-signal-safe and
 * thread-safe; callable from a signal handler while run() is blocked. */
ZCIO_API void zcio_http_server_stop(zcio_http_server *s);

/* The TCP port actually bound (useful with cfg.port == 0). */
ZCIO_API int zcio_http_server_port(const zcio_http_server *s);

/* Hard-release everything (force-closes any remaining connection). NULL-safe.
 * Never call while another thread is inside poll()/run(). */
ZCIO_API void zcio_http_server_free(zcio_http_server *s);

/* --- request accessors (valid only inside the handler) ------------------ */

ZCIO_API const char *zcio_http_req_method(const zcio_http_req *r);  /* "GET"  */
/* Percent-decoded, dot-segment-normalized path ("/a/b"). Control bytes and
 * embedded NUL are rejected before the handler ever runs. */
ZCIO_API const char *zcio_http_req_path(const zcio_http_req *r);
ZCIO_API const char *zcio_http_req_query(const zcio_http_req *r);   /* raw, "" if none */
ZCIO_API int         zcio_http_req_version(const zcio_http_req *r); /* 1, 2, 3 */
ZCIO_API bool        zcio_http_req_secure(const zcio_http_req *r);  /* over TLS/QUIC */

/* Case-insensitive single-header lookup (first match), or NULL. Names are
 * stored lowercased. Bounded linear scan (max_headers entries). */
ZCIO_API const char *zcio_http_req_header(const zcio_http_req *r, const char *name);
ZCIO_API size_t      zcio_http_req_header_count(const zcio_http_req *r);
ZCIO_API int         zcio_http_req_header_at(const zcio_http_req *r, size_t i,
                                             const char **name, const char **value);

/* Complete request body (already length-capped). NUL-terminated for text
 * convenience; *len excludes the terminator. */
ZCIO_API const void *zcio_http_req_body(const zcio_http_req *r, size_t *len);

/* --- responding ---------------------------------------------------------- */

/* Send a complete response. Content-Length/framing, Date, and the configured
 * security headers (HSTS, Alt-Svc) are added automatically; hop-by-hop and
 * connection-specific headers in `headers` are filtered out, and any header
 * containing CR/LF/NUL is rejected (ZCIO_ERR_INVALID_ARG). Bodies on HEAD /
 * 204 / 304 are suppressed per RFC 9110. Exactly one respond per request. */
ZCIO_API int zcio_http_respond(zcio_http_req *r, int status,
                               const zcio_http_header *headers, size_t nheaders,
                               const void *body, size_t body_len);

#ifdef __cplusplus
}
#endif

#endif /* ZCIO_HTTP_SERVER_H */
