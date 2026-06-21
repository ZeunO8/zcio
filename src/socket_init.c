/* src/socket_init.c - platform socket subsystem init + nonblocking helper +
 * SIGPIPE suppression + EINTR-safe select. */
#include "internal.h"

#if defined(_WIN32)
static bool g_wsa = false;
void zcio_socket_startup(void) {
    if (g_wsa) return;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) g_wsa = true;
}
int zcio_set_nonblocking(zcio_socket fd, bool on) {
    u_long mode = on ? 1 : 0;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? ZCIO_OK : ZCIO_ERR;
}
void zcio_socket_nosigpipe(zcio_socket fd) { (void)fd; /* N/A on Windows */ }
#else
#  include <time.h>
#  include <sys/select.h>
void zcio_socket_startup(void) { /* POSIX needs no global init */ }
int zcio_set_nonblocking(zcio_socket fd, bool on) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return ZCIO_ERR;
    if (on) flags |= O_NONBLOCK; else flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags) == 0 ? ZCIO_OK : ZCIO_ERR;
}
void zcio_socket_nosigpipe(zcio_socket fd) {
#  if defined(SO_NOSIGPIPE)   /* macOS / BSD: no MSG_NOSIGNAL, so set per-socket */
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
#  else
    (void)fd; /* Linux uses MSG_NOSIGNAL via ZCIO_SEND_FLAGS instead */
#  endif
}
#endif

/* Monotonic milliseconds for deadline tracking. */
static long long zcio_now_ms(void) {
#if defined(_WIN32)
    return (long long)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

int zcio_select_eintr(zcio_socket fd, bool want_read, bool want_write,
                      bool *out_read, bool *out_write, int timeout_ms) {
    long long deadline = (timeout_ms >= 0) ? zcio_now_ms() + timeout_ms : 0;
    for (;;) {
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        if (want_read)  FD_SET(fd, &rfds);
        if (want_write) FD_SET(fd, &wfds);

        struct timeval tv, *ptv = NULL;
        if (timeout_ms >= 0) {
            long long remaining = deadline - zcio_now_ms();
            if (remaining < 0) remaining = 0;
            tv.tv_sec  = (long)(remaining / 1000);
            tv.tv_usec = (long)((remaining % 1000) * 1000);
            ptv = &tv;
        }

        int rc = select((int)(fd + 1), want_read ? &rfds : NULL,
                        want_write ? &wfds : NULL, NULL, ptv);
#if !defined(_WIN32)
        if (rc < 0 && errno == EINTR) {
            if (timeout_ms < 0) continue;              /* infinite: just retry  */
            if (deadline - zcio_now_ms() > 0) continue; /* time left: retry      */
            rc = 0;                                     /* deadline passed: timeout */
        }
#endif
        if (out_read)  *out_read  = want_read  && FD_ISSET(fd, &rfds);
        if (out_write) *out_write = want_write && FD_ISSET(fd, &wfds);
        return rc;
    }
}
