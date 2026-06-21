/* internal_port.h - test helper: grab an OS-assigned free TCP port.
 * zcio's server sets no SO_REUSEADDR, so reusing a fixed port across back-to-back
 * runs collides in TIME_WAIT. Binding to port 0 and reading it back avoids that. */
#ifndef ZTEST_INTERNAL_PORT_H
#define ZTEST_INTERNAL_PORT_H

#include <string.h>
#if defined(_WIN32)
#  include <winsock2.h>
#else
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <unistd.h>
#endif

static inline int ztest_free_port(void) {
    int fd = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 39000;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof a) != 0) {
#if defined(_WIN32)
        closesocket(fd);
#else
        close(fd);
#endif
        return 39000;
    }
    socklen_t len = sizeof a;
    getsockname(fd, (struct sockaddr *)&a, &len);
    int port = ntohs(a.sin_port);
#if defined(_WIN32)
    closesocket(fd);
#else
    close(fd);
#endif
    return port;
}

#endif /* ZTEST_INTERNAL_PORT_H */
