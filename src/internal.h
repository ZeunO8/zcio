/* src/internal.h - private helpers shared across zcio translation units.
 * Not installed; not part of the public ABI. */
#ifndef ZCIO_INTERNAL_H
#define ZCIO_INTERNAL_H

#include "zcio/types.h"
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

/* --- tiny allocation helpers -------------------------------------------- */
static inline void *zcio_xmalloc(size_t n) { return malloc(n ? n : 1); }
static inline void *zcio_xcalloc(size_t n, size_t sz) { return calloc(n ? n : 1, sz ? sz : 1); }
char *zcio_strdup_(const char *s);  /* NULL-safe strdup using malloc */

#endif /* ZCIO_INTERNAL_H */
