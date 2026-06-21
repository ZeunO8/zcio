/* src/udp.c - UDP client/server/packet as zcio_streams.
 *
 * Ports udp_streambuf (sendto/recvfrom to a fixed peer), udp_client, and
 * udp_server (demux by source addr/port into per-peer buffered streams). */
#include "zcio/net.h"
#include "zcio/dns.h"
#include "internal.h"

#define UDP_RECV_BUF 4096

/* --------------------------- UDP client stream -------------------------- */
/* A datagram stream bound to a single peer: write -> sendto, read -> recvfrom.
 * Owns the fd. */
typedef struct udp_clictx {
    zcio_socket        fd;
    struct sockaddr_in peer;
    bool               closed;
} udp_clictx;

static int64_t udp_cli_read(void *c, void *dst, size_t n) {
    udp_clictx *s = (udp_clictx *)c;
    if (s->closed || s->fd == ZCIO_INVALID_SOCKET) return ZCIO_ERR_EOF;
    struct sockaddr_in from;
    socklen_t flen = sizeof from;
    long long got = recvfrom(s->fd, (char *)dst, (int)n, 0,
                             (struct sockaddr *)&from, &flen);
    if (got > 0) return (int64_t)got;
    if (got == 0) return 0;
#if defined(_WIN32)
    if (WSAGetLastError() == WSAEWOULDBLOCK) return ZCIO_ERR_WOULDBLOCK;
#else
    if (errno == EAGAIN || errno == EWOULDBLOCK) return ZCIO_ERR_WOULDBLOCK;
#endif
    return ZCIO_ERR;
}

static int64_t udp_cli_write(void *c, const void *src, size_t n) {
    udp_clictx *s = (udp_clictx *)c;
    if (s->closed || s->fd == ZCIO_INVALID_SOCKET) return ZCIO_ERR_EOF;
    long long sent = sendto(s->fd, (const char *)src, (int)n, 0,
                            (struct sockaddr *)&s->peer, sizeof s->peer);
    if (sent < 0) return ZCIO_ERR;
    return (int64_t)sent;
}

static int udp_cli_close(void *c) {
    udp_clictx *s = (udp_clictx *)c;
    if (!s->closed && s->fd != ZCIO_INVALID_SOCKET) {
        zcio_closesocket(s->fd);
        s->fd = ZCIO_INVALID_SOCKET;
        s->closed = true;
    }
    return ZCIO_OK;
}

static void udp_cli_destroy(void *c) {
    udp_clictx *s = (udp_clictx *)c;
    if (!s) return;
    if (!s->closed && s->fd != ZCIO_INVALID_SOCKET) zcio_closesocket(s->fd);
    free(s);
}

static const zcio_stream_vtable UDP_CLI_VT = {
    .name = "udp",
    .read = udp_cli_read,
    .write = udp_cli_write,
    .close = udp_cli_close,
    .destroy = udp_cli_destroy,
};

struct zcio_udp_client {
    zcio_stream *stream;
};

zcio_udp_client *zcio_udp_client_open(const char *host, int port) {
    if (!host) { zcio_fail_(ZCIO_ERR_INVALID_ARG, "udp_client: NULL host"); return NULL; }
    char *ip = zcio_resolve_ipv4(host);
    if (!ip) return NULL;

    zcio_socket_startup();
    zcio_socket fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == ZCIO_INVALID_SOCKET) {
        free(ip);
        zcio_fail_(ZCIO_ERR, "udp_client: socket() failed");
        return NULL;
    }

    udp_clictx *ctx = (udp_clictx *)zcio_xcalloc(1, sizeof *ctx);
    if (!ctx) {
        zcio_closesocket(fd); free(ip);
        zcio_fail_(ZCIO_ERR_NOMEM, "udp_client: out of memory");
        return NULL;
    }
    ctx->fd = fd;
    ctx->peer.sin_family = AF_INET;
    ctx->peer.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &ctx->peer.sin_addr) <= 0) {
        zcio_closesocket(fd); free(ctx); free(ip);
        zcio_fail_(ZCIO_ERR_INVALID_ARG, "udp_client: invalid address");
        return NULL;
    }
    free(ip);

    zcio_stream *st = zcio_stream_new(&UDP_CLI_VT, ctx,
        ZCIO_STREAM_OWNS_CTX | ZCIO_STREAM_READABLE | ZCIO_STREAM_WRITABLE);
    if (!st) {
        udp_cli_destroy(ctx);
        zcio_fail_(ZCIO_ERR_NOMEM, "udp_client: out of memory");
        return NULL;
    }

    zcio_udp_client *c = (zcio_udp_client *)zcio_xcalloc(1, sizeof *c);
    if (!c) { zcio_stream_free(st); zcio_fail_(ZCIO_ERR_NOMEM, "udp_client: out of memory"); return NULL; }
    c->stream = st;
    return c;
}

void zcio_udp_client_free(zcio_udp_client *c) {
    if (!c) return;
    zcio_stream_free(c->stream);
    free(c);
}

zcio_stream *zcio_udp_client_stream(zcio_udp_client *c) {
    return c ? c->stream : NULL;
}

/* ------------------------- UDP server / packet -------------------------- */
/* Per-peer buffered read stream. The server's receive() routes datagrams into
 * the matching peer's buffer; reads drain that buffer. Writes sendto the peer.
 * The fd is shared (owned by the server), so the stream does NOT close it. */
typedef struct udp_pktctx {
    zcio_socket        fd;          /* shared listening socket (not owned)   */
    struct sockaddr_in peer;
    char              *buf;         /* dynamic read buffer                   */
    size_t             buf_cap;
    size_t             buf_len;     /* bytes currently buffered              */
    size_t             buf_pos;     /* read cursor                           */
} udp_pktctx;

static int64_t udp_pkt_read(void *c, void *dst, size_t n) {
    udp_pktctx *p = (udp_pktctx *)c;
    size_t avail = p->buf_len - p->buf_pos;
    if (avail == 0) return 0;             /* nothing buffered: EOF-for-now    */
    size_t take = avail < n ? avail : n;
    memcpy(dst, p->buf + p->buf_pos, take);
    p->buf_pos += take;
    return (int64_t)take;
}

static int64_t udp_pkt_write(void *c, const void *src, size_t n) {
    udp_pktctx *p = (udp_pktctx *)c;
    if (p->fd == ZCIO_INVALID_SOCKET) return ZCIO_ERR_EOF;
    long long sent = sendto(p->fd, (const char *)src, (int)n, 0,
                            (struct sockaddr *)&p->peer, sizeof p->peer);
    if (sent < 0) return ZCIO_ERR;
    return (int64_t)sent;
}

static int64_t udp_pkt_available(void *c) {
    udp_pktctx *p = (udp_pktctx *)c;
    return (int64_t)(p->buf_len - p->buf_pos);
}

static void udp_pkt_destroy(void *c) {
    udp_pktctx *p = (udp_pktctx *)c;
    if (!p) return;
    free(p->buf);
    free(p);
}

static const zcio_stream_vtable UDP_PKT_VT = {
    .name = "udp",
    .read = udp_pkt_read,
    .write = udp_pkt_write,
    .available = udp_pkt_available,
    .destroy = udp_pkt_destroy,
};

struct zcio_udp_packet {
    udp_pktctx  *ctx;     /* aliases stream->ctx                            */
    zcio_stream *stream;  /* owns ctx                                       */
};

/* growable array of peers keyed by (addr,port); receive() is O(peers) only on
 * a new peer, O(1) amortized for an existing one via linear match. Kept simple
 * to mirror the original std::map demux. */
struct zcio_udp_server {
    zcio_socket        fd;
    zcio_udp_packet  **peers;
    size_t             peers_len;
    size_t             peers_cap;
    unsigned           rcvtimeo_us;   /* cached SO_RCVTIMEO setting          */
    bool               rcvtimeo_set;
};

zcio_udp_server *zcio_udp_server_bind(int port) {
    zcio_socket_startup();
    zcio_socket fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == ZCIO_INVALID_SOCKET) {
        zcio_fail_(ZCIO_ERR, "udp_server: socket() failed");
        return NULL;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR, "udp_server: bind(:%d) failed", port);
        return NULL;
    }
    zcio_udp_server *s = (zcio_udp_server *)zcio_xcalloc(1, sizeof *s);
    if (!s) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR_NOMEM, "udp_server: out of memory");
        return NULL;
    }
    s->fd = fd;
    return s;
}

void zcio_udp_server_free(zcio_udp_server *s) {
    if (!s) return;
    for (size_t i = 0; i < s->peers_len; ++i) {
        if (s->peers[i]) {
            zcio_stream_free(s->peers[i]->stream);
            free(s->peers[i]);
        }
    }
    free(s->peers);
    if (s->fd != ZCIO_INVALID_SOCKET) zcio_closesocket(s->fd);
    free(s);
}

/* Find existing peer (linear) or create + append a new one. */
static zcio_udp_packet *server_peer(zcio_udp_server *s, const struct sockaddr_in *from) {
    for (size_t i = 0; i < s->peers_len; ++i) {
        zcio_udp_packet *pk = s->peers[i];
        if (pk && pk->ctx->peer.sin_addr.s_addr == from->sin_addr.s_addr &&
            pk->ctx->peer.sin_port == from->sin_port)
            return pk;
    }
    /* create */
    udp_pktctx *ctx = (udp_pktctx *)zcio_xcalloc(1, sizeof *ctx);
    if (!ctx) return NULL;
    ctx->fd = s->fd;
    ctx->peer = *from;
    zcio_stream *st = zcio_stream_new(&UDP_PKT_VT, ctx,
        ZCIO_STREAM_OWNS_CTX | ZCIO_STREAM_READABLE | ZCIO_STREAM_WRITABLE);
    if (!st) { free(ctx); return NULL; }
    zcio_udp_packet *pk = (zcio_udp_packet *)zcio_xcalloc(1, sizeof *pk);
    if (!pk) { zcio_stream_free(st); return NULL; }
    pk->ctx = ctx;
    pk->stream = st;

    if (s->peers_len >= s->peers_cap) {
        size_t ncap = s->peers_cap ? s->peers_cap * 2 : 8;
        zcio_udp_packet **np = (zcio_udp_packet **)realloc(s->peers, ncap * sizeof *np);
        if (!np) { zcio_stream_free(st); free(pk); return NULL; }
        s->peers = np;
        s->peers_cap = ncap;
    }
    s->peers[s->peers_len++] = pk;
    return pk;
}

zcio_udp_packet *
zcio_udp_server_receive(zcio_udp_server *s, bool non_block, unsigned timeout_us) {
    if (!s) { zcio_fail_(ZCIO_ERR_INVALID_ARG, "udp_receive: NULL server"); return NULL; }

    if (non_block && (!s->rcvtimeo_set || s->rcvtimeo_us != timeout_us)) {
#if defined(_WIN32)
        DWORD to = timeout_us / 1000;
        setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof to);
#else
        struct timeval to;
        to.tv_sec = 0;
        to.tv_usec = (int)timeout_us;
        setsockopt(s->fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof to);
#endif
        s->rcvtimeo_us = timeout_us;
        s->rcvtimeo_set = true;
    }

    char buffer[UDP_RECV_BUF];
    struct sockaddr_in from;
    memset(&from, 0, sizeof from);
    socklen_t flen = sizeof from;
    long long got = recvfrom(s->fd, buffer, sizeof buffer, 0,
                             (struct sockaddr *)&from, &flen);
    if (got <= 0) return NULL; /* timeout / error / empty */

    zcio_udp_packet *pk = server_peer(s, &from);
    if (!pk) { zcio_fail_(ZCIO_ERR_NOMEM, "udp_receive: out of memory"); return NULL; }

    /* route bytes into the peer buffer (reset cursor, grow as needed) */
    udp_pktctx *ctx = pk->ctx;
    size_t need = (size_t)got;
    if (ctx->buf_cap < need) {
        char *nb = (char *)realloc(ctx->buf, need);
        if (!nb) { zcio_fail_(ZCIO_ERR_NOMEM, "udp_receive: out of memory"); return NULL; }
        ctx->buf = nb;
        ctx->buf_cap = need;
    }
    memcpy(ctx->buf, buffer, need);
    ctx->buf_len = need;
    ctx->buf_pos = 0;
    return pk;
}

zcio_stream *zcio_udp_packet_stream(zcio_udp_packet *p) {
    return p ? p->stream : NULL;
}
