/* src/tcp.c - TCP client/server/conn as zcio_streams.
 *
 * Ports tcp_streambuf (select-with-timeout recv/send), tcp_client (connect),
 * and tcp_server (listen/accept). Each socket is exposed through an internal
 * "socket stream" vtable holding the fd; TLS, when requested, wraps that plain
 * stream via zcio_tls_wrap and the wrapped stream is what callers see. */
#include "zcio/net.h"
#include "zcio/dns.h"
#include "internal.h"

#define TCP_DEFAULT_TIMEOUT_MS 30000
#define TCP_BACKLOG            5

#if !defined(_WIN32)
#  include <sys/ioctl.h>
#endif

/* ----------------------------- select helper ---------------------------- */
/* Mirrors the original wait_for_socket: returns >0 if the requested condition
 * is ready, 0 on timeout, <0 on error. */
typedef struct sock_wait {
    bool readable;
    bool writable;
    bool excepted;
    int  rc; /* select() return code */
} sock_wait;

static sock_wait tcp_wait(zcio_socket fd, int timeout_ms, bool want_read, bool want_write) {
    fd_set rs, ws, es;
    FD_ZERO(&rs); FD_ZERO(&ws); FD_ZERO(&es);
    if (want_read)  FD_SET(fd, &rs);
    if (want_write) FD_SET(fd, &ws);
    FD_SET(fd, &es);

    struct timeval tv;
    struct timeval *tvp = NULL;
    if (timeout_ms >= 0) {
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        tvp = &tv;
    }
    int res = select((int)(fd + 1), &rs, &ws, &es, tvp);
    sock_wait out = {0};
    out.rc = res;
    if (res > 0) {
        out.readable = FD_ISSET(fd, &rs) != 0;
        out.writable = FD_ISSET(fd, &ws) != 0;
        out.excepted = FD_ISSET(fd, &es) != 0;
    }
    return out;
}

/* --------------------------- socket stream ctx -------------------------- */
typedef struct tcp_sockctx {
    zcio_socket fd;
    int         timeout_ms;
    bool        closed;
    bool        eof;
} tcp_sockctx;

static int64_t tcp_s_read(void *c, void *dst, size_t n) {
    tcp_sockctx *s = (tcp_sockctx *)c;
    if (s->closed || s->fd == ZCIO_INVALID_SOCKET) return ZCIO_ERR_EOF;
    sock_wait w = tcp_wait(s->fd, s->timeout_ms, true, false);
    if (w.rc < 0)  return ZCIO_ERR;
    if (w.rc == 0) return ZCIO_ERR_TIMEOUT;
    if (!w.readable) return ZCIO_ERR_TIMEOUT;

    long long got = recv(s->fd, (char *)dst, (int)n, 0);
    if (got > 0) return (int64_t)got;
    if (got == 0) { s->eof = true; return 0; } /* peer closed */
#if defined(_WIN32)
    if (WSAGetLastError() == WSAEWOULDBLOCK) return ZCIO_ERR_WOULDBLOCK;
#else
    if (errno == EAGAIN || errno == EWOULDBLOCK) return ZCIO_ERR_WOULDBLOCK;
#endif
    s->eof = true;
    return ZCIO_ERR_EOF;
}

static int64_t tcp_s_write(void *c, const void *src, size_t n) {
    tcp_sockctx *s = (tcp_sockctx *)c;
    if (s->closed || s->fd == ZCIO_INVALID_SOCKET) return ZCIO_ERR_EOF;
    sock_wait w = tcp_wait(s->fd, s->timeout_ms, false, true);
    if (w.rc < 0)  return ZCIO_ERR;
    if (w.rc == 0) return ZCIO_ERR_TIMEOUT;
    if (!w.writable) return ZCIO_ERR_TIMEOUT;

    long long sent = send(s->fd, (const char *)src, (int)n, 0);
    if (sent > 0) return (int64_t)sent;
    return ZCIO_ERR;
}

static int64_t tcp_s_seek(void *c, int64_t off, zcio_seek_origin origin, zcio_seek_which which) {
    (void)c; (void)off; (void)origin; (void)which;
    return ZCIO_ERR_UNSUPPORTED;
}

static int64_t tcp_s_available(void *c) {
    tcp_sockctx *s = (tcp_sockctx *)c;
    if (s->fd == ZCIO_INVALID_SOCKET) return 0;
#if defined(_WIN32)
    u_long count = 0;
    if (ioctlsocket(s->fd, FIONREAD, &count) != 0) return ZCIO_ERR;
    return (int64_t)count;
#else
    int count = 0;
    if (ioctl(s->fd, FIONREAD, &count) < 0) return ZCIO_ERR;
    return (int64_t)count;
#endif
}

static bool tcp_s_eof(void *c) { return ((tcp_sockctx *)c)->eof; }

static int tcp_s_close(void *c) {
    tcp_sockctx *s = (tcp_sockctx *)c;
    if (s->closed || s->fd == ZCIO_INVALID_SOCKET) return ZCIO_OK;
    shutdown(s->fd, ZCIO_SHUT_WR);
    zcio_closesocket(s->fd);
    s->fd = ZCIO_INVALID_SOCKET;
    s->closed = true;
    return ZCIO_OK;
}

static void tcp_s_destroy(void *c) {
    tcp_sockctx *s = (tcp_sockctx *)c;
    if (!s) return;
    if (!s->closed && s->fd != ZCIO_INVALID_SOCKET) {
        shutdown(s->fd, ZCIO_SHUT_WR);
        zcio_closesocket(s->fd);
    }
    free(s);
}

static const zcio_stream_vtable TCP_VT = {
    .name = "tcp",
    .read = tcp_s_read,
    .write = tcp_s_write,
    .seek = tcp_s_seek,
    .close = tcp_s_close,
    .destroy = tcp_s_destroy,
    .available = tcp_s_available,
    .eof = tcp_s_eof,
};

/* Build a plaintext socket stream that owns the fd. Returns NULL on OOM. */
static zcio_stream *tcp_make_plain_stream(zcio_socket fd) {
    tcp_sockctx *ctx = (tcp_sockctx *)zcio_xcalloc(1, sizeof *ctx);
    if (!ctx) return NULL;
    ctx->fd = fd;
    ctx->timeout_ms = TCP_DEFAULT_TIMEOUT_MS;
    zcio_stream *st = zcio_stream_new(&TCP_VT, ctx,
        ZCIO_STREAM_OWNS_CTX | ZCIO_STREAM_READABLE | ZCIO_STREAM_WRITABLE);
    if (!st) { free(ctx); return NULL; }
    return st;
}

/* ------------------------------- connect -------------------------------- */
/* Returns a connected fd or ZCIO_INVALID_SOCKET (error message left). */
static zcio_socket tcp_do_connect(const char *host, int port) {
    char *ip = zcio_resolve_ipv4(host);
    if (!ip) return ZCIO_INVALID_SOCKET; /* zcio_resolve_ipv4 set the error */

    zcio_socket_startup();
    zcio_socket fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == ZCIO_INVALID_SOCKET) {
        free(ip);
        zcio_fail_(ZCIO_ERR_CONNECT, "tcp: socket() failed");
        return ZCIO_INVALID_SOCKET;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR_CONNECT, "tcp: invalid address %s", ip);
        free(ip);
        return ZCIO_INVALID_SOCKET;
    }
    free(ip);

    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0)
        return fd;

    /* In-progress (non-blocking sockets); wait up to 15s. The original blocks
     * via the default socket but tolerates EINPROGRESS, so we mirror it. */
#if defined(_WIN32)
    int err = WSAGetLastError();
    bool inprog = (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS);
#else
    bool inprog = (errno == EINPROGRESS);
#endif
    if (inprog) {
        sock_wait w = tcp_wait(fd, 15000, false, true);
        if (w.rc > 0 && w.writable) {
            int so_error = 0;
            socklen_t len = sizeof so_error;
            getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&so_error, &len);
            if (so_error == 0) return fd;
            zcio_closesocket(fd);
            zcio_fail_(ZCIO_ERR_CONNECT, "tcp: connect to %s:%d failed", host, port);
            return ZCIO_INVALID_SOCKET;
        }
        zcio_closesocket(fd);
        zcio_fail_(w.rc == 0 ? ZCIO_ERR_TIMEOUT : ZCIO_ERR_CONNECT,
                   "tcp: connect to %s:%d %s", host, port,
                   w.rc == 0 ? "timed out" : "select failed");
        return ZCIO_INVALID_SOCKET;
    }
    zcio_closesocket(fd);
    zcio_fail_(ZCIO_ERR_CONNECT, "tcp: connect to %s:%d failed immediately", host, port);
    return ZCIO_INVALID_SOCKET;
}

/* ------------------------------ TCP client ------------------------------ */
struct zcio_tcp_client {
    zcio_socket   fd;          /* mirror of underlying fd for wait/avail ops */
    zcio_stream  *stream;      /* plain or TLS-wrapped, owns the socket ctx  */
    zcio_tls_ctx *tls_ctx;     /* BORROWED; caller owns it (reusable)        */
};

static zcio_tcp_client *
tcp_client_make(const char *host, int port, zcio_tls_ctx *ctx, bool verify) {
    if (!host) { zcio_fail_(ZCIO_ERR_INVALID_ARG, "tcp_client: NULL host"); return NULL; }
    zcio_socket fd = tcp_do_connect(host, port);
    if (fd == ZCIO_INVALID_SOCKET) return NULL;

    zcio_stream *plain = tcp_make_plain_stream(fd);
    if (!plain) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR_NOMEM, "tcp_client: out of memory");
        return NULL;
    }

    zcio_stream *use = plain;
    if (ctx) {
        zcio_stream *wrapped = zcio_tls_wrap(ctx, plain, false, verify);
        if (!wrapped) {
            zcio_stream_free(plain); /* destroys ctx -> closes fd */
            zcio_fail_(ZCIO_ERR_TLS, "tcp_client: TLS handshake to %s failed", host);
            return NULL;
        }
        use = wrapped;
    }

    zcio_tcp_client *c = (zcio_tcp_client *)zcio_xcalloc(1, sizeof *c);
    if (!c) {
        zcio_stream_free(use);
        zcio_fail_(ZCIO_ERR_NOMEM, "tcp_client: out of memory");
        return NULL;
    }
    c->fd = fd;
    c->stream = use;
    c->tls_ctx = ctx;
    return c;
}

zcio_tcp_client *zcio_tcp_client_connect(const char *host, int port) {
    return tcp_client_make(host, port, NULL, false);
}

zcio_tcp_client *
zcio_tcp_client_connect_tls(const char *host, int port, zcio_tls_ctx *ctx, bool verify) {
    return tcp_client_make(host, port, ctx, verify);
}

void zcio_tcp_client_free(zcio_tcp_client *c) {
    if (!c) return;
    zcio_stream_free(c->stream);
    /* tls_ctx is borrowed: the caller owns it and may reuse it. */
    free(c);
}

zcio_stream *zcio_tcp_client_stream(zcio_tcp_client *c) {
    return c ? c->stream : NULL;
}

int zcio_tcp_client_tls_upgrade(zcio_tcp_client *c, zcio_tls_ctx *ctx) {
    if (!c || !ctx) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "tls_upgrade: NULL arg");
    if (c->tls_ctx) return zcio_fail_(ZCIO_ERR, "tls_upgrade: already secured");
    zcio_stream *wrapped = zcio_tls_wrap(ctx, c->stream, false, true);
    if (!wrapped) return zcio_fail_(ZCIO_ERR_TLS, "tls_upgrade: handshake failed");
    c->stream = wrapped;
    c->tls_ctx = ctx;
    return ZCIO_OK;
}

int zcio_tcp_client_wait_readable(zcio_tcp_client *c, int timeout_ms) {
    if (!c) return ZCIO_ERR_INVALID_ARG;
    sock_wait w = tcp_wait(c->fd, timeout_ms, true, false);
    return w.readable ? 1 : 0;
}

int zcio_tcp_client_wait_writable(zcio_tcp_client *c, int timeout_ms) {
    if (!c) return ZCIO_ERR_INVALID_ARG;
    sock_wait w = tcp_wait(c->fd, timeout_ms, false, true);
    return w.writable ? 1 : 0;
}

int zcio_tcp_client_bytes_available(zcio_tcp_client *c) {
    if (!c) return ZCIO_ERR_INVALID_ARG;
#if defined(_WIN32)
    u_long count = 0;
    if (ioctlsocket(c->fd, FIONREAD, &count) != 0) return ZCIO_ERR;
    return (int)count;
#else
    int count = 0;
    if (ioctl(c->fd, FIONREAD, &count) < 0) return ZCIO_ERR;
    return count;
#endif
}

/* ------------------------------ TCP conn -------------------------------- */
struct zcio_tcp_conn {
    zcio_socket  fd;
    zcio_stream *stream;
};

/* O(1)-indexed slot array entry. */
typedef struct conn_slot {
    size_t          id;
    zcio_tcp_conn  *conn;   /* NULL if free/closed */
} conn_slot;

/* ------------------------------ TCP server ------------------------------ */
struct zcio_tcp_server {
    zcio_socket   listen_fd;
    zcio_tls_ctx *tls_ctx;     /* BORROWED; caller owns it (reusable)       */
    bool          non_blocking;
    size_t        next_id;     /* monotonically increasing client id        */
    conn_slot    *slots;       /* growable array indexed by id              */
    size_t        slots_len;   /* allocated length (== next_id high-water)  */
    size_t        slots_cap;
};

static zcio_tcp_server *
tcp_server_make(int port, zcio_tls_ctx *ctx, bool non_blocking) {
    zcio_socket_startup();
    zcio_socket fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == ZCIO_INVALID_SOCKET) {
        zcio_fail_(ZCIO_ERR, "tcp_server: socket() failed");
        return NULL;
    }
    if (zcio_set_nonblocking(fd, true) != ZCIO_OK) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR, "tcp_server: set non-blocking failed");
        return NULL;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR, "tcp_server: bind(:%d) failed", port);
        return NULL;
    }
    if (listen(fd, TCP_BACKLOG) != 0) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR, "tcp_server: listen() failed");
        return NULL;
    }

    zcio_tcp_server *s = (zcio_tcp_server *)zcio_xcalloc(1, sizeof *s);
    if (!s) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR_NOMEM, "tcp_server: out of memory");
        return NULL;
    }
    s->listen_fd = fd;
    s->tls_ctx = ctx;
    s->non_blocking = non_blocking;
    s->next_id = 0;
    return s;
}

zcio_tcp_server *zcio_tcp_server_listen(int port) {
    return tcp_server_make(port, NULL, true);
}

zcio_tcp_server *
zcio_tcp_server_listen_tls(int port, zcio_tls_ctx *ctx, bool non_blocking) {
    return tcp_server_make(port, ctx, non_blocking);
}

void zcio_tcp_server_free(zcio_tcp_server *s) {
    if (!s) return;
    for (size_t i = 0; i < s->slots_len; ++i) {
        if (s->slots[i].conn) {
            zcio_stream_free(s->slots[i].conn->stream);
            free(s->slots[i].conn);
        }
    }
    free(s->slots);
    if (s->listen_fd != ZCIO_INVALID_SOCKET) {
        shutdown(s->listen_fd, ZCIO_SHUT_WR);
        zcio_closesocket(s->listen_fd);
    }
    /* tls_ctx is borrowed: the caller owns it and may reuse it. */
    free(s);
}

/* Append conn at slot index `id`; grow array as needed. O(1) amortized. */
static int server_store(zcio_tcp_server *s, size_t id, zcio_tcp_conn *conn) {
    if (id >= s->slots_cap) {
        size_t ncap = s->slots_cap ? s->slots_cap * 2 : 8;
        while (ncap <= id) ncap *= 2;
        conn_slot *ns = (conn_slot *)realloc(s->slots, ncap * sizeof *ns);
        if (!ns) return ZCIO_ERR_NOMEM;
        for (size_t i = s->slots_cap; i < ncap; ++i) { ns[i].id = i; ns[i].conn = NULL; }
        s->slots = ns;
        s->slots_cap = ncap;
    }
    if (id >= s->slots_len) s->slots_len = id + 1;
    s->slots[id].id = id;
    s->slots[id].conn = conn;
    return ZCIO_OK;
}

zcio_tcp_conn *zcio_tcp_server_accept(zcio_tcp_server *s, size_t *out_id, int timeout_ms) {
    if (!s) { zcio_fail_(ZCIO_ERR_INVALID_ARG, "accept: NULL server"); return NULL; }

    sock_wait w = tcp_wait(s->listen_fd, timeout_ms, true, false);
    if (w.rc <= 0) return NULL; /* timeout or error: no message (poll-style) */
    if (!w.readable) return NULL;

    struct sockaddr_in caddr;
    memset(&caddr, 0, sizeof caddr);
    socklen_t clen = sizeof caddr;
    zcio_socket cfd = accept(s->listen_fd, (struct sockaddr *)&caddr, &clen);
    if (cfd == ZCIO_INVALID_SOCKET) return NULL;

    /* Accepted socket inherits non-blocking on some platforms; force blocking
     * semantics off so our select()+recv loop governs timeouts. */
    zcio_set_nonblocking(cfd, false);

    zcio_stream *plain = tcp_make_plain_stream(cfd);
    if (!plain) {
        zcio_closesocket(cfd);
        zcio_fail_(ZCIO_ERR_NOMEM, "accept: out of memory");
        return NULL;
    }

    zcio_stream *use = plain;
    if (s->tls_ctx) {
        zcio_stream *wrapped = zcio_tls_wrap(s->tls_ctx, plain, true, false);
        if (!wrapped) {
            zcio_stream_free(plain);
            zcio_fail_(ZCIO_ERR_TLS, "accept: TLS handshake failed");
            return NULL;
        }
        use = wrapped;
    }

    zcio_tcp_conn *conn = (zcio_tcp_conn *)zcio_xcalloc(1, sizeof *conn);
    if (!conn) {
        zcio_stream_free(use);
        zcio_fail_(ZCIO_ERR_NOMEM, "accept: out of memory");
        return NULL;
    }
    conn->fd = cfd;
    conn->stream = use;

    size_t id = s->next_id++;
    if (server_store(s, id, conn) != ZCIO_OK) {
        zcio_stream_free(use);
        free(conn);
        zcio_fail_(ZCIO_ERR_NOMEM, "accept: out of memory");
        return NULL;
    }
    if (out_id) *out_id = id;
    return conn;
}

int zcio_tcp_server_close_client(zcio_tcp_server *s, size_t id) {
    if (!s) return ZCIO_ERR_INVALID_ARG;
    if (id >= s->slots_len || !s->slots[id].conn)
        return zcio_fail_(ZCIO_ERR_INVALID_ARG, "close_client: unknown id %zu", id);
    zcio_tcp_conn *conn = s->slots[id].conn;
    zcio_stream_free(conn->stream);
    free(conn);
    s->slots[id].conn = NULL;
    return ZCIO_OK;
}

zcio_stream *zcio_tcp_conn_stream(zcio_tcp_conn *c) {
    return c ? c->stream : NULL;
}

int zcio_tcp_conn_wait_readable(zcio_tcp_conn *c, int timeout_ms) {
    if (!c) return ZCIO_ERR_INVALID_ARG;
    sock_wait w = tcp_wait(c->fd, timeout_ms, true, false);
    return w.readable ? 1 : 0;
}

int zcio_tcp_conn_wait_writable(zcio_tcp_conn *c, int timeout_ms) {
    if (!c) return ZCIO_ERR_INVALID_ARG;
    sock_wait w = tcp_wait(c->fd, timeout_ms, false, true);
    return w.writable ? 1 : 0;
}
