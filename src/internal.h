/* src/internal.h - private helpers shared across zcio translation units.
 * Not installed; not part of the public ABI. */
#ifndef ZCIO_INTERNAL_H
#define ZCIO_INTERNAL_H

#include "zcio/types.h"
#include "zcio/stream.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* --- thread-local error reporting --------------------------------------- */
#if defined(_MSC_VER)
#  define ZCIO_THREAD __declspec(thread)
#else
#  define ZCIO_THREAD _Thread_local
#endif

/* Record a thread-local error message and return the given code. Usage:
 *     return zcio_fail(ZCIO_ERR_CONNECT, "connect to %s:%d failed", host, port);
 * The macro form ZCIO_FAIL passes through the code for convenience. */
int  zcio_fail_(zcio_result code, const char *fmt, ...);
void zcio_set_error_(const char *msg);

/* --- platform socket layer ---------------------------------------------- */
#if defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
typedef SOCKET zcio_socket;
#  define ZCIO_INVALID_SOCKET INVALID_SOCKET
#  define zcio_closesocket    closesocket
#  define ZCIO_SHUT_WR        SD_SEND
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <errno.h>
typedef int zcio_socket;
#  define ZCIO_INVALID_SOCKET (-1)
#  define zcio_closesocket    close
#  define ZCIO_SHUT_WR        SHUT_WR
#endif

/* One-time socket subsystem init (WSAStartup on Windows; no-op elsewhere). */
void zcio_socket_startup(void);
int  zcio_set_nonblocking(zcio_socket fd, bool on);

/* --- poll ---------------------------------------------------------------- *
 * Multi-fd readiness for the HTTP server event loop. POSIX poll(2) /
 * WSAPoll(); struct pollfd + POLLIN/POLLOUT come from <poll.h> / <winsock2.h>.
 * EINTR-safe (retries with the remaining timeout). Returns the poll() result:
 * >0 ready count, 0 timeout, <0 error. */
#if !defined(_WIN32)
#  include <poll.h>
#endif
int zcio_poll_(struct pollfd *fds, size_t nfds, int timeout_ms);

/* --- SIGPIPE suppression ------------------------------------------------ *
 * A send to a peer-closed socket must never raise SIGPIPE (which by default
 * kills the whole host process). Two complementary mechanisms:
 *   - ZCIO_SEND_FLAGS: OR into every send()/sendto() (MSG_NOSIGNAL on Linux).
 *   - zcio_socket_nosigpipe(fd): set SO_NOSIGPIPE right after socket() on
 *     macOS/BSD, where MSG_NOSIGNAL does not exist. No-op on Linux/Windows. */
#if defined(MSG_NOSIGNAL)
#  define ZCIO_SEND_FLAGS MSG_NOSIGNAL
#else
#  define ZCIO_SEND_FLAGS 0
#endif
void zcio_socket_nosigpipe(zcio_socket fd);

/* --- EINTR-safe blocking helpers ---------------------------------------- *
 * Wrap select() so a benign signal does not corrupt an otherwise-healthy
 * operation. Retries on EINTR while shrinking the remaining timeout so a
 * stream of signals cannot extend the deadline indefinitely.
 *   timeout_ms < 0  -> block indefinitely
 *   timeout_ms == 0 -> poll
 * Returns the select() result (>0 ready, 0 timeout, <0 error). */
int zcio_select_eintr(zcio_socket fd, bool want_read, bool want_write,
                      bool *out_read, bool *out_write, int timeout_ms);

/* --- tiny allocation helpers -------------------------------------------- */
static inline void *zcio_xmalloc(size_t n) { return malloc(n ? n : 1); }
static inline void *zcio_xcalloc(size_t n, size_t sz) { return calloc(n ? n : 1, sz ? sz : 1); }
char *zcio_strdup_(const char *s);  /* NULL-safe strdup using malloc */

/* --- clock / entropy (util.c) -------------------------------------------- */
uint64_t zcio_now_ms_(void);              /* monotonic milliseconds           */
int      zcio_rand_bytes_(void *dst, size_t n); /* OS entropy; ZCIO_OK or ERR */

/* --- raw-fd TCP stream (tcp.c) -------------------------------------------- *
 * Wrap an already-connected, non-blocking socket in the standard "tcp" stream
 * (stream owns and closes the fd). timeout_ms > 0: each read/write waits up to
 * that long (select) before ZCIO_ERR_TIMEOUT. timeout_ms == 0: fully
 * non-blocking - no wait, ZCIO_ERR_WOULDBLOCK when the socket isn't ready
 * (this is what the HTTP server event loop uses). */
zcio_stream *zcio_tcp_stream_from_fd_(zcio_socket fd, int timeout_ms);
/* Adjust the timeout on a stream made by the tcp layer (any "tcp" stream).
 * ZCIO_OK or ZCIO_ERR_INVALID_ARG when the stream isn't a tcp socket stream. */
int zcio_tcp_stream_set_timeout_(zcio_stream *s, int timeout_ms);

/* Set the transport timeout on a socket stream OR reach through a TLS overlay
 * to its underlying socket stream (so a wss session honors its recv/send
 * timeout). ZCIO_OK or ZCIO_ERR_INVALID_ARG. Implemented in tls.c. */
int zcio_stream_set_timeout_(zcio_stream *s, int timeout_ms);

#endif /* ZCIO_INTERNAL_H */
