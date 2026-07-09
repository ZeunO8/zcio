/* zcio/ws.h - RFC 6455 WebSocket client and server endpoints.
 *
 * Server side: inside a zcio_http_server handler, zcio_http_req_is_ws_upgrade()
 * detects a well-formed upgrade request and zcio_ws_accept() completes the
 * 101 handshake, DETACHING the connection from the server's event loop — the
 * returned zcio_ws owns the underlying stream from then on and is used
 * synchronously (typically from a thread of your own). HTTP/1.1 only; over
 * h2/h3 the upgrade accessor returns false and the request is served normally.
 *
 * Client side: zcio_ws_connect() dials ws:// or wss://, performs the opening
 * handshake (Sec-WebSocket-Key/-Accept verified), and follows an auto-HTTPS
 * upgrade: a 301/302/307/308 redirect from ws:// to wss:// (or https://) is
 * re-dialed over TLS automatically; a wss:// -> ws:// downgrade is refused.
 *
 * Framing security (both roles): client-to-server frames MUST be masked and
 * server-to-client frames MUST NOT be (violations close with 1002); RSV bits
 * are rejected (no extensions are negotiated); control frames are <= 125
 * bytes and never fragmented; text messages and close reasons are validated
 * as UTF-8; message reassembly is capped by max_msg_bytes. Masking keys and
 * handshake nonces come from the OS entropy source.
 *
 * Graceful close: zcio_ws_close() sends a Close frame and waits (bounded) for
 * the peer's echo per RFC 6455 §7. zcio_ws_free() performs the same best-
 * effort close if the session is still open, then releases everything.
 */
#ifndef ZCIO_WS_H
#define ZCIO_WS_H

#include "zcio/types.h"
#include "zcio/http.h"        /* zcio_http_header */
#include "zcio/http_server.h" /* zcio_http_req    */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zcio_ws zcio_ws;

typedef ZCIO_ENUM(zcio_ws_type, int32_t) {
    ZCIO_WS_TEXT   = 1,   /* UTF-8 validated */
    ZCIO_WS_BINARY = 2,
} zcio_ws_type;

/* One complete (defragmented) message. data is malloc'd and NUL-terminated
 * for text convenience; len excludes the terminator. */
typedef struct zcio_ws_msg {
    zcio_ws_type type;
    void        *data;
    size_t       len;
} zcio_ws_msg;
ZCIO_API void zcio_ws_msg_free(zcio_ws_msg *m);

/* ------------------------------- client --------------------------------- */

/* Dial `url` ("ws://h[:p]/path" or "wss://..."), send the opening handshake
 * with optional extra headers, verify the 101 + Sec-WebSocket-Accept. Follows
 * up to 3 redirects, upgrading ws->wss automatically and refusing wss->ws
 * downgrades. Returns NULL on failure (zcio_last_error() explains). */
ZCIO_API ZCIO_NODISCARD zcio_ws *
zcio_ws_connect(const char *url, const zcio_http_header *headers, size_t nheaders);

/* ------------------------------- server --------------------------------- */

/* True iff the request is a well-formed RFC 6455 upgrade (GET, HTTP/1.1,
 * Upgrade: websocket, Connection: upgrade, valid 16-byte key, version 13). */
ZCIO_API bool zcio_http_req_is_ws_upgrade(const zcio_http_req *r);

/* Complete the 101 handshake and detach the connection from the HTTP server.
 * On success the request is considered responded and the returned zcio_ws
 * owns the connection. On failure returns NULL and the connection is closed.
 * Call only when zcio_http_req_is_ws_upgrade() is true. */
ZCIO_API ZCIO_NODISCARD zcio_ws *zcio_ws_accept(zcio_http_req *r);

/* -------------------------------- I/O ------------------------------------ */

/* Send one complete message as a single (unfragmented) frame. ZCIO_WS_TEXT
 * payloads must be valid UTF-8 (checked). */
ZCIO_API int zcio_ws_send(zcio_ws *ws, zcio_ws_type type, const void *data, size_t len);
ZCIO_API int zcio_ws_send_text(zcio_ws *ws, const char *text);

/* Receive the next complete data message, transparently answering pings and
 * finishing a peer-initiated close handshake. Returns ZCIO_OK with *out
 * filled (caller frees via zcio_ws_msg_free), ZCIO_ERR_TIMEOUT if nothing
 * complete arrived in timeout_ms (-1 = block), ZCIO_ERR_EOF once the session
 * is closed, or another negated zcio_result on error. */
ZCIO_API int zcio_ws_recv(zcio_ws *ws, zcio_ws_msg *out, int timeout_ms);

/* Unsolicited ping (payload <= 125 bytes). Pong replies are consumed by
 * zcio_ws_recv. */
ZCIO_API int zcio_ws_ping(zcio_ws *ws, const void *data, size_t len);

/* Initiate (or complete) the closing handshake: send Close(code, reason) and
 * wait briefly for the echo. Safe to call more than once. */
ZCIO_API int zcio_ws_close(zcio_ws *ws, uint16_t code, const char *reason);

/* Close code received from the peer (0 if none yet). */
ZCIO_API uint16_t zcio_ws_close_code(const zcio_ws *ws);

/* Cap on a reassembled incoming message (default 16 MiB). */
ZCIO_API void zcio_ws_set_max_msg_bytes(zcio_ws *ws, size_t cap);

/* Per-op read/write timeout for send/recv-internals (default 30000 ms). */
ZCIO_API void zcio_ws_set_timeout(zcio_ws *ws, int timeout_ms);

/* Graceful best-effort close (if still open) + release. NULL-safe. */
ZCIO_API void zcio_ws_free(zcio_ws *ws);

#ifdef __cplusplus
}
#endif

#endif /* ZCIO_WS_H */
