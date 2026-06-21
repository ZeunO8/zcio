/* src/socket_init.c - platform socket subsystem init + nonblocking helper. */
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
#else
void zcio_socket_startup(void) { /* POSIX needs no global init */ }
int zcio_set_nonblocking(zcio_socket fd, bool on) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return ZCIO_ERR;
    if (on) flags |= O_NONBLOCK; else flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags) == 0 ? ZCIO_OK : ZCIO_ERR;
}
#endif
