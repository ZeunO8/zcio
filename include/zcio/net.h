/* zcio/net.h - TCP, UDP, and UDP-multicast endpoints as zcio_streams.
 *
 * Ports tcp_client/server/stream, udp_client/server/stream, and the multicast
 * sender/receiver. Each endpoint exposes a zcio_stream for byte I/O plus the
 * connection-management verbs the originals had (accept, wait, upgrade-TLS).
 *
 * TLS is optional: pass a zcio_tls_ctx (see zcio/tls.h) to the *_tls creators,
 * or NULL for plaintext. The core links no TLS library unless a backend is
 * compiled in. A zcio_tls_ctx passed to any creator is BORROWED, never freed by
 * the endpoint -- the caller owns it and may share one ctx across many
 * connections, then release it with zcio_tls_ctx_free.
 */
#ifndef ZCIO_NET_H
#define ZCIO_NET_H

#include "zcio/types.h"
#include "zcio/stream.h"
#include "zcio/tls.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zcio_tcp_client zcio_tcp_client;
typedef struct zcio_tcp_server zcio_tcp_server;
typedef struct zcio_tcp_conn   zcio_tcp_conn;   /* accepted/owned connection */
typedef struct zcio_udp_client zcio_udp_client;
typedef struct zcio_udp_server zcio_udp_server;
typedef struct zcio_udp_packet zcio_udp_packet; /* one received datagram peer */
typedef struct zcio_mcast_sender   zcio_mcast_sender;
typedef struct zcio_mcast_receiver zcio_mcast_receiver;

/* ----------------------------- TCP client ------------------------------- */
ZCIO_API ZCIO_NODISCARD zcio_tcp_client *zcio_tcp_client_connect(const char *host, int port);
ZCIO_API ZCIO_NODISCARD zcio_tcp_client *
zcio_tcp_client_connect_tls(const char *host, int port, zcio_tls_ctx *ctx, bool verify);
ZCIO_API void          zcio_tcp_client_free(zcio_tcp_client *c);
ZCIO_API zcio_stream  *zcio_tcp_client_stream(zcio_tcp_client *c); /* borrowed */
ZCIO_API int           zcio_tcp_client_tls_upgrade(zcio_tcp_client *c, zcio_tls_ctx *ctx);
ZCIO_API int           zcio_tcp_client_wait_readable(zcio_tcp_client *c, int timeout_ms);
ZCIO_API int           zcio_tcp_client_wait_writable(zcio_tcp_client *c, int timeout_ms);
ZCIO_API int           zcio_tcp_client_bytes_available(zcio_tcp_client *c);

/* ----------------------------- TCP server ------------------------------- */
ZCIO_API ZCIO_NODISCARD zcio_tcp_server *zcio_tcp_server_listen(int port);
ZCIO_API ZCIO_NODISCARD zcio_tcp_server *
zcio_tcp_server_listen_tls(int port, zcio_tls_ctx *ctx, bool non_blocking);
ZCIO_API void zcio_tcp_server_free(zcio_tcp_server *s);
/* Accept one client. Returns a borrowed connection (owned by the server map)
 * and its id via out_id, or NULL on timeout/error. */
ZCIO_API zcio_tcp_conn *zcio_tcp_server_accept(zcio_tcp_server *s, size_t *out_id, int timeout_ms);
ZCIO_API int            zcio_tcp_server_close_client(zcio_tcp_server *s, size_t id);

ZCIO_API zcio_stream *zcio_tcp_conn_stream(zcio_tcp_conn *c); /* borrowed */
ZCIO_API int          zcio_tcp_conn_wait_readable(zcio_tcp_conn *c, int timeout_ms);
ZCIO_API int          zcio_tcp_conn_wait_writable(zcio_tcp_conn *c, int timeout_ms);

/* ----------------------------- UDP client ------------------------------- */
ZCIO_API ZCIO_NODISCARD zcio_udp_client *zcio_udp_client_open(const char *host, int port);
ZCIO_API void         zcio_udp_client_free(zcio_udp_client *c);
ZCIO_API zcio_stream *zcio_udp_client_stream(zcio_udp_client *c); /* borrowed */

/* ----------------------------- UDP server ------------------------------- */
ZCIO_API ZCIO_NODISCARD zcio_udp_server *zcio_udp_server_bind(int port);
ZCIO_API void          zcio_udp_server_free(zcio_udp_server *s);
/* Receive one datagram. non_block + timeout_us mirror the original. Returns a
 * borrowed per-peer packet stream (owned by the server) or NULL. */
ZCIO_API zcio_udp_packet *
zcio_udp_server_receive(zcio_udp_server *s, bool non_block, unsigned timeout_us);
ZCIO_API zcio_stream *zcio_udp_packet_stream(zcio_udp_packet *p); /* borrowed */

/* --------------------------- UDP multicast ------------------------------ */
ZCIO_API ZCIO_NODISCARD zcio_mcast_sender   *zcio_mcast_sender_open(const char *group, int port);
ZCIO_API void         zcio_mcast_sender_free(zcio_mcast_sender *s);
ZCIO_API zcio_stream *zcio_mcast_sender_stream(zcio_mcast_sender *s); /* borrowed */

ZCIO_API ZCIO_NODISCARD zcio_mcast_receiver *zcio_mcast_receiver_open(const char *group, int port);
ZCIO_API void         zcio_mcast_receiver_free(zcio_mcast_receiver *r);
ZCIO_API zcio_stream *zcio_mcast_receiver_stream(zcio_mcast_receiver *r); /* borrowed */

#ifdef __cplusplus
}
#endif

#endif /* ZCIO_NET_H */
