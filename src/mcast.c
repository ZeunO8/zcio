/* src/mcast.c - UDP multicast sender/receiver as zcio_streams.
 *
 * Ports udpmc_sender (IP_MULTICAST_IF + sendto to group) and udpmc_receiver
 * (SO_REUSEADDR, bind, IP_ADD_MEMBERSHIP). */
#include "zcio/net.h"
#include "zcio/dns.h"
#include "internal.h"

#define MCAST_RECV_BUF 4096

/* ----------------------------- sender stream ---------------------------- */
typedef struct mcast_sctx {
    zcio_socket        fd;
    struct sockaddr_in group;
    bool               closed;
} mcast_sctx;

static int64_t mcast_send_write(void *c, const void *src, size_t n) {
    mcast_sctx *s = (mcast_sctx *)c;
    if (s->closed || s->fd == ZCIO_INVALID_SOCKET) return ZCIO_ERR_EOF;
    long long sent = sendto(s->fd, (const char *)src, (int)n, ZCIO_SEND_FLAGS,
                            (struct sockaddr *)&s->group, sizeof s->group);
    if (sent < 0) return ZCIO_ERR;
    return (int64_t)sent;
}

static int mcast_send_close(void *c) {
    mcast_sctx *s = (mcast_sctx *)c;
    if (!s->closed && s->fd != ZCIO_INVALID_SOCKET) {
        zcio_closesocket(s->fd);
        s->fd = ZCIO_INVALID_SOCKET;
        s->closed = true;
    }
    return ZCIO_OK;
}

static void mcast_send_destroy(void *c) {
    mcast_sctx *s = (mcast_sctx *)c;
    if (!s) return;
    if (!s->closed && s->fd != ZCIO_INVALID_SOCKET) zcio_closesocket(s->fd);
    free(s);
}

static const zcio_stream_vtable MCAST_SEND_VT = {
    .name = "mcast",
    .write = mcast_send_write,
    .close = mcast_send_close,
    .destroy = mcast_send_destroy,
};

struct zcio_mcast_sender {
    zcio_stream *stream;
};

zcio_mcast_sender *zcio_mcast_sender_open(const char *group, int port) {
    if (!group) { zcio_fail_(ZCIO_ERR_INVALID_ARG, "mcast_sender: NULL group"); return NULL; }
    char *ip = zcio_resolve_ipv4(group);
    if (!ip) return NULL;

    zcio_socket_startup();
    zcio_socket fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == ZCIO_INVALID_SOCKET) {
        free(ip);
        zcio_fail_(ZCIO_ERR, "mcast_sender: socket() failed");
        return NULL;
    }
    zcio_socket_nosigpipe(fd);

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof reuse);

    struct sockaddr_in gaddr;
    memset(&gaddr, 0, sizeof gaddr);
    gaddr.sin_family = AF_INET;
    gaddr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &gaddr.sin_addr) <= 0) {
        zcio_closesocket(fd); free(ip);
        zcio_fail_(ZCIO_ERR_INVALID_ARG, "mcast_sender: invalid group address");
        return NULL;
    }
    free(ip);

    struct in_addr local_iface;
    memset(&local_iface, 0, sizeof local_iface);
    local_iface.s_addr = htonl(INADDR_ANY);
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF,
               (const char *)&local_iface, sizeof local_iface);

    mcast_sctx *ctx = (mcast_sctx *)zcio_xcalloc(1, sizeof *ctx);
    if (!ctx) { zcio_closesocket(fd); zcio_fail_(ZCIO_ERR_NOMEM, "mcast_sender: oom"); return NULL; }
    ctx->fd = fd;
    ctx->group = gaddr;

    zcio_stream *st = zcio_stream_new(&MCAST_SEND_VT, ctx,
        ZCIO_STREAM_OWNS_CTX | ZCIO_STREAM_WRITABLE);
    if (!st) { mcast_send_destroy(ctx); zcio_fail_(ZCIO_ERR_NOMEM, "mcast_sender: oom"); return NULL; }

    zcio_mcast_sender *s = (zcio_mcast_sender *)zcio_xcalloc(1, sizeof *s);
    if (!s) { zcio_stream_free(st); zcio_fail_(ZCIO_ERR_NOMEM, "mcast_sender: oom"); return NULL; }
    s->stream = st;
    return s;
}

void zcio_mcast_sender_free(zcio_mcast_sender *s) {
    if (!s) return;
    zcio_stream_free(s->stream);
    free(s);
}

zcio_stream *zcio_mcast_sender_stream(zcio_mcast_sender *s) {
    return s ? s->stream : NULL;
}

/* ---------------------------- receiver stream --------------------------- */
typedef struct mcast_rctx {
    zcio_socket fd;
    bool        closed;
} mcast_rctx;

static int64_t mcast_recv_read(void *c, void *dst, size_t n) {
    mcast_rctx *r = (mcast_rctx *)c;
    if (r->closed || r->fd == ZCIO_INVALID_SOCKET) return ZCIO_ERR_EOF;
    struct sockaddr_in from;
    socklen_t flen = sizeof from;
    long long got;
    do {
        flen = sizeof from;
        got = recvfrom(r->fd, (char *)dst, (int)n, 0,
                       (struct sockaddr *)&from, &flen);
    } while (got < 0
#if !defined(_WIN32)
             && errno == EINTR
#endif
            );
    if (got > 0) return (int64_t)got;
    if (got == 0) return 0;
#if defined(_WIN32)
    if (WSAGetLastError() == WSAEWOULDBLOCK) return ZCIO_ERR_WOULDBLOCK;
#else
    if (errno == EAGAIN || errno == EWOULDBLOCK) return ZCIO_ERR_WOULDBLOCK;
#endif
    return ZCIO_ERR;
}

static int mcast_recv_close(void *c) {
    mcast_rctx *r = (mcast_rctx *)c;
    if (!r->closed && r->fd != ZCIO_INVALID_SOCKET) {
        zcio_closesocket(r->fd);
        r->fd = ZCIO_INVALID_SOCKET;
        r->closed = true;
    }
    return ZCIO_OK;
}

static void mcast_recv_destroy(void *c) {
    mcast_rctx *r = (mcast_rctx *)c;
    if (!r) return;
    if (!r->closed && r->fd != ZCIO_INVALID_SOCKET) zcio_closesocket(r->fd);
    free(r);
}

static const zcio_stream_vtable MCAST_RECV_VT = {
    .name = "mcast",
    .read = mcast_recv_read,
    .close = mcast_recv_close,
    .destroy = mcast_recv_destroy,
};

struct zcio_mcast_receiver {
    zcio_stream *stream;
};

zcio_mcast_receiver *zcio_mcast_receiver_open(const char *group, int port) {
    if (!group) { zcio_fail_(ZCIO_ERR_INVALID_ARG, "mcast_receiver: NULL group"); return NULL; }
    char *ip = zcio_resolve_ipv4(group);
    if (!ip) return NULL;

    zcio_socket_startup();
    zcio_socket fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == ZCIO_INVALID_SOCKET) {
        free(ip);
        zcio_fail_(ZCIO_ERR, "mcast_receiver: socket() failed");
        return NULL;
    }
    zcio_socket_nosigpipe(fd);
    zcio_set_nonblocking(fd, true);

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof reuse);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        zcio_closesocket(fd); free(ip);
        zcio_fail_(ZCIO_ERR, "mcast_receiver: bind(:%d) failed", port);
        return NULL;
    }

    int loopback = 1;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP,
               (const char *)&loopback, sizeof loopback);

    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof mreq);
    if (inet_pton(AF_INET, ip, &mreq.imr_multiaddr) <= 0) {
        zcio_closesocket(fd); free(ip);
        zcio_fail_(ZCIO_ERR_INVALID_ARG, "mcast_receiver: invalid group address");
        return NULL;
    }
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    free(ip);
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   (const char *)&mreq, sizeof mreq) < 0) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR, "mcast_receiver: IP_ADD_MEMBERSHIP failed");
        return NULL;
    }

    mcast_rctx *ctx = (mcast_rctx *)zcio_xcalloc(1, sizeof *ctx);
    if (!ctx) { zcio_closesocket(fd); zcio_fail_(ZCIO_ERR_NOMEM, "mcast_receiver: oom"); return NULL; }
    ctx->fd = fd;

    zcio_stream *st = zcio_stream_new(&MCAST_RECV_VT, ctx,
        ZCIO_STREAM_OWNS_CTX | ZCIO_STREAM_READABLE);
    if (!st) { mcast_recv_destroy(ctx); zcio_fail_(ZCIO_ERR_NOMEM, "mcast_receiver: oom"); return NULL; }

    zcio_mcast_receiver *r = (zcio_mcast_receiver *)zcio_xcalloc(1, sizeof *r);
    if (!r) { zcio_stream_free(st); zcio_fail_(ZCIO_ERR_NOMEM, "mcast_receiver: oom"); return NULL; }
    r->stream = st;
    return r;
}

void zcio_mcast_receiver_free(zcio_mcast_receiver *r) {
    if (!r) return;
    zcio_stream_free(r->stream);
    free(r);
}

zcio_stream *zcio_mcast_receiver_stream(zcio_mcast_receiver *r) {
    return r ? r->stream : NULL;
}
