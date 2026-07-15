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
    bool rd = false, wr = false;
    int res = zcio_select_eintr(fd, want_read, want_write, &rd, &wr, timeout_ms);
    sock_wait out = {0};
    out.rc = res;
    if (res > 0) {
        out.readable = rd;
        out.writable = wr;
        out.excepted = false;
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
    /* timeout 0 = fully non-blocking: skip the wait and let recv() surface
     * EWOULDBLOCK below (the HTTP server event loop drives readiness). */
    if (s->timeout_ms != 0) {
        sock_wait w = tcp_wait(s->fd, s->timeout_ms, true, false);
        if (w.rc < 0)  return ZCIO_ERR;
        if (w.rc == 0) return ZCIO_ERR_TIMEOUT;
        if (!w.readable) return ZCIO_ERR_TIMEOUT;
    }

    long long got;
    do {
        got = recv(s->fd, (char *)dst, (int)n, 0);
    } while (got < 0
#if defined(_WIN32)
             && WSAGetLastError() == WSAEINTR
#else
             && errno == EINTR
#endif
            );
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
    if (s->timeout_ms != 0) { /* 0 = non-blocking; see tcp_s_read */
        sock_wait w = tcp_wait(s->fd, s->timeout_ms, false, true);
        if (w.rc < 0)  return ZCIO_ERR;
        if (w.rc == 0) return ZCIO_ERR_TIMEOUT;
        if (!w.writable) return ZCIO_ERR_TIMEOUT;
    }

    long long sent;
    do {
        sent = send(s->fd, (const char *)src, (int)n, ZCIO_SEND_FLAGS);
    } while (sent < 0
#if defined(_WIN32)
             && WSAGetLastError() == WSAEINTR
#else
             && errno == EINTR
#endif
            );
    if (sent > 0) return (int64_t)sent;
    if (sent == 0) return 0; /* nothing sent this call; not a hard error */
#if defined(_WIN32)
    {
        int werr = WSAGetLastError();
        if (werr == WSAEWOULDBLOCK) return ZCIO_ERR_WOULDBLOCK;
        if (werr == WSAECONNRESET || werr == WSAECONNABORTED) {
            s->eof = true;
            return ZCIO_ERR_EOF;
        }
    }
#else
    if (errno == EAGAIN || errno == EWOULDBLOCK) return ZCIO_ERR_WOULDBLOCK;
    if (errno == EPIPE || errno == ECONNRESET) {
        s->eof = true;
        return ZCIO_ERR_EOF;
    }
#endif
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

/* Internal (see internal.h): wrap an already-connected fd; the stream owns and
 * closes it. timeout_ms == 0 makes every op non-blocking (WOULDBLOCK). */
zcio_stream *zcio_tcp_stream_from_fd_(zcio_socket fd, int timeout_ms) {
    zcio_stream *st = tcp_make_plain_stream(fd);
    if (!st) return NULL;
    ((tcp_sockctx *)st->ctx)->timeout_ms = timeout_ms;
    return st;
}

int zcio_tcp_stream_set_timeout_(zcio_stream *s, int timeout_ms) {
    if (!s || s->vt != &TCP_VT || !s->ctx)
        return zcio_fail_(ZCIO_ERR_INVALID_ARG, "set_timeout: not a tcp stream");
    ((tcp_sockctx *)s->ctx)->timeout_ms = timeout_ms;
    return ZCIO_OK;
}

/* ------------------------------- connect -------------------------------- */
#define TCP_DEFAULT_CONNECT_TIMEOUT_MS 15000

/* Returns a connected fd or ZCIO_INVALID_SOCKET (error message left).
 * connect_timeout_ms <= 0 selects the default.
 *
 * Dual-stack: resolves BOTH A and AAAA records (getaddrinfo AF_UNSPEC) and
 * tries each candidate in the order the resolver returned (glibc/BSD/Apple
 * resolvers already apply RFC 6724 destination-address ordering, so this is
 * a reasonable happy-eyeballs approximation without full RFC 8305
 * parallelism). Previously this resolved A-only (zcio_resolve_ipv4) and
 * connected via a single AF_INET socket, which fails outright with zero
 * fallback on an IPv6-only network: there's no A record to find (NAT64/
 * DNS64 synthesizes AAAA from A for IPv6-only clients, not the reverse), so
 * the connect never even reaches the socket layer. IPv6-only is the default
 * on several major cellular carriers today and is an explicit Apple App
 * Store review requirement for exactly this reason -- confirmed live: a
 * QUANTIX iOS client on cellular couldn't reach ANY exchange host at all,
 * while the same build worked fine in Simulator (dual-stack Mac Wi-Fi). */
static zcio_socket tcp_do_connect(const char *host, int port, int connect_timeout_ms) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof port_str, "%d", port);

    struct addrinfo *result = NULL;
    int gai_rc = getaddrinfo(host, port_str, &hints, &result);
    if (gai_rc != 0 || !result) {
        zcio_fail_(ZCIO_ERR_DNS, "tcp: getaddrinfo(%s) failed: %s", host, gai_strerror(gai_rc));
        return ZCIO_INVALID_SOCKET;
    }

    zcio_socket_startup();
    int cto = connect_timeout_ms > 0 ? connect_timeout_ms
                                     : TCP_DEFAULT_CONNECT_TIMEOUT_MS;

    zcio_socket fd = ZCIO_INVALID_SOCKET;
    const char *last_err = "no address candidates";
    bool last_err_timeout = false;
    for (struct addrinfo *p = result; p; p = p->ai_next) {
        zcio_socket cand = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (cand == ZCIO_INVALID_SOCKET) { last_err = "socket() failed"; continue; }
        zcio_socket_nosigpipe(cand);
        /* Non-blocking BEFORE connect so the EINPROGRESS + select path below
         * is live (a blocking socket would silently use the kernel default
         * timeout). Left non-blocking; per-op tcp_wait() governs read/write
         * timeouts, consistent with tcp_s_read/tcp_s_write EWOULDBLOCK
         * handling. */
        zcio_set_nonblocking(cand, true);

        if (connect(cand, p->ai_addr, (socklen_t)p->ai_addrlen) == 0) { fd = cand; break; }

#if defined(_WIN32)
        int err = WSAGetLastError();
        bool inprog = (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS);
#else
        bool inprog = (errno == EINPROGRESS);
#endif
        if (!inprog) {
            zcio_closesocket(cand);
            last_err = "connect failed immediately";
            last_err_timeout = false;
            continue;
        }

        sock_wait w = tcp_wait(cand, cto, false, true);
        if (w.rc > 0 && w.writable) {
            int so_error = 0;
            socklen_t len = sizeof so_error;
            getsockopt(cand, SOL_SOCKET, SO_ERROR, (char *)&so_error, &len);
            if (so_error == 0) { fd = cand; break; }
            zcio_closesocket(cand);
            last_err = "connect failed";
            last_err_timeout = false;
            continue;
        }
        zcio_closesocket(cand);
        last_err = w.rc == 0 ? "timed out" : "select failed";
        last_err_timeout = (w.rc == 0);
    }
    freeaddrinfo(result);

    if (fd == ZCIO_INVALID_SOCKET) {
        zcio_fail_(last_err_timeout ? ZCIO_ERR_TIMEOUT : ZCIO_ERR_CONNECT,
                   "tcp: connect to %s:%d failed (%s)", host, port, last_err);
    }
    return fd;
}

/* ------------------------------ TCP client ------------------------------ */
struct zcio_tcp_client {
    zcio_socket   fd;          /* mirror of underlying fd for wait/avail ops */
    zcio_stream  *stream;      /* plain or TLS-wrapped, owns the socket ctx  */
    zcio_tls_ctx *tls_ctx;     /* BORROWED; caller owns it (reusable)        */
};

static zcio_tcp_client *
tcp_client_make(const char *host, int port, zcio_tls_ctx *ctx, bool verify,
                int connect_timeout_ms, int io_timeout_ms) {
    if (!host) { zcio_fail_(ZCIO_ERR_INVALID_ARG, "tcp_client: NULL host"); return NULL; }
    zcio_socket fd = tcp_do_connect(host, port, connect_timeout_ms);
    if (fd == ZCIO_INVALID_SOCKET) return NULL;

    zcio_stream *plain = tcp_make_plain_stream(fd);
    if (!plain) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR_NOMEM, "tcp_client: out of memory");
        return NULL;
    }
    /* Preset the per-op transport timeout BEFORE any TLS wrap so the handshake
     * itself honors the caller's deadline. io_timeout_ms <= 0 keeps default. */
    if (io_timeout_ms > 0)
        ((tcp_sockctx *)plain->ctx)->timeout_ms = io_timeout_ms;

    zcio_stream *use = plain;
    if (ctx) {
        zcio_stream *wrapped = zcio_tls_wrap(ctx, plain, false, verify);
        if (!wrapped) {
            /* zcio_tls_wrap already called zcio_fail_ with the specific
             * reason (cert verification failure detail, handshake alert,
             * ...) -- preserve it instead of clobbering with a bare "TLS
             * handshake failed" that hides which of those it actually was.
             * (Same bug class as ws.c's zcio_ws_connect() -- see that fix.) */
            char underlying[192];
            snprintf(underlying, sizeof underlying, "%s", zcio_last_error());
            zcio_stream_free(plain); /* destroys ctx -> closes fd */
            zcio_fail_(ZCIO_ERR_TLS, "tcp_client: TLS handshake to %s failed: %s", host, underlying);
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
    return tcp_client_make(host, port, NULL, false, 0, 0);
}

zcio_tcp_client *
zcio_tcp_client_connect_tls(const char *host, int port, zcio_tls_ctx *ctx, bool verify) {
    return tcp_client_make(host, port, ctx, verify, 0, 0);
}

/* Internal (see internal.h): connect with explicit connect/IO timeouts. */
zcio_tcp_client *
zcio_tcp_client_connect_opts_(const char *host, int port, zcio_tls_ctx *ctx,
                              bool verify, int connect_timeout_ms, int io_timeout_ms) {
    return tcp_client_make(host, port, ctx, verify, connect_timeout_ms, io_timeout_ms);
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
    /* Free-list of reclaimed ids (slots whose conn was closed). accept()
     * reuses these before bumping next_id, bounding slot-array growth so a
     * churn of connect/close cannot grow memory without limit. */
    size_t       *free_ids;
    size_t        free_len;
    size_t        free_cap;
};

/* Wrap an already-listening socket in a server object (shared tail of the
 * make/adopt paths). Takes ownership of fd. */
static zcio_tcp_server *
tcp_server_wrap(zcio_socket fd, zcio_tls_ctx *ctx, bool non_blocking) {
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

static zcio_tcp_server *
tcp_server_make(const char *host, int port, zcio_tls_ctx *ctx, bool non_blocking) {
    zcio_socket_startup();

    /* Bind scope: NULL/""/"*" = all interfaces; anything else is a dotted
     * quad or a name resolved to one (e.g. "localhost" -> 127.0.0.1). */
    struct in_addr bind_addr;
    bind_addr.s_addr = INADDR_ANY;
    if (host && *host && strcmp(host, "*") != 0) {
        if (inet_pton(AF_INET, host, &bind_addr) != 1) {
            char *ip = zcio_resolve_ipv4(host);
            int ok = ip && inet_pton(AF_INET, ip, &bind_addr) == 1;
            free(ip);
            if (!ok) {
                zcio_fail_(ZCIO_ERR_DNS, "tcp_server: cannot resolve bind host '%s'", host);
                return NULL;
            }
        }
    }

    zcio_socket fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == ZCIO_INVALID_SOCKET) {
        zcio_fail_(ZCIO_ERR, "tcp_server: socket() failed");
        return NULL;
    }
    zcio_socket_nosigpipe(fd);
    if (zcio_set_nonblocking(fd, true) != ZCIO_OK) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR, "tcp_server: set non-blocking failed");
        return NULL;
    }

    /* Allow rebinding a port still lingering in TIME_WAIT from a prior process,
     * matching the UDP/multicast paths and the original iostreams server. */
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&reuse, sizeof reuse);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr = bind_addr;
    addr.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR, "tcp_server: bind(%s:%d) failed",
                   (host && *host) ? host : "*", port);
        return NULL;
    }
    if (listen(fd, TCP_BACKLOG) != 0) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR, "tcp_server: listen() failed");
        return NULL;
    }

    return tcp_server_wrap(fd, ctx, non_blocking);
}

zcio_tcp_server *zcio_tcp_server_listen(int port) {
    return tcp_server_make(NULL, port, NULL, true);
}

zcio_tcp_server *zcio_tcp_server_listen_host(const char *host, int port) {
    return tcp_server_make(host, port, NULL, true);
}

zcio_tcp_server *
zcio_tcp_server_listen_tls(int port, zcio_tls_ctx *ctx, bool non_blocking) {
    return tcp_server_make(NULL, port, ctx, non_blocking);
}

zcio_tcp_server *
zcio_tcp_server_listen_host_tls(const char *host, int port,
                                zcio_tls_ctx *ctx, bool non_blocking) {
    return tcp_server_make(host, port, ctx, non_blocking);
}

zcio_tcp_server *
zcio_tcp_server_adopt(intptr_t listen_fd, zcio_tls_ctx *ctx, bool non_blocking) {
    zcio_socket_startup();
    zcio_socket fd = (zcio_socket)listen_fd;
    if (fd == ZCIO_INVALID_SOCKET) {
        zcio_fail_(ZCIO_ERR_INVALID_ARG, "tcp_server: adopt of invalid socket");
        return NULL;
    }
    zcio_socket_nosigpipe(fd);
    if (zcio_set_nonblocking(fd, true) != ZCIO_OK) {
        /* NOT closed: an fd we could not adopt stays owned by the caller. */
        zcio_fail_(ZCIO_ERR, "tcp_server: set non-blocking failed");
        return NULL;
    }
    return tcp_server_wrap(fd, ctx, non_blocking);
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
    free(s->free_ids);
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

/* Pop a reclaimed id if one is available; return true and write *out. */
static bool server_pop_free_id(zcio_tcp_server *s, size_t *out) {
    if (s->free_len == 0) return false;
    *out = s->free_ids[--s->free_len];
    return true;
}

zcio_tcp_conn *zcio_tcp_server_accept(zcio_tcp_server *s, size_t *out_id, int timeout_ms) {
    if (!s) { zcio_fail_(ZCIO_ERR_INVALID_ARG, "accept: NULL server"); return NULL; }

    sock_wait w = tcp_wait(s->listen_fd, timeout_ms, true, false);
    if (w.rc <= 0) return NULL; /* timeout or error: no message (poll-style) */
    if (!w.readable) return NULL;

    struct sockaddr_in caddr;
    memset(&caddr, 0, sizeof caddr);
    socklen_t clen = sizeof caddr;
    zcio_socket cfd;
    do {
        clen = sizeof caddr;
        cfd = accept(s->listen_fd, (struct sockaddr *)&caddr, &clen);
    } while (cfd == ZCIO_INVALID_SOCKET
#if defined(_WIN32)
             && WSAGetLastError() == WSAEINTR
#else
             && errno == EINTR
#endif
            );
    if (cfd == ZCIO_INVALID_SOCKET) return NULL;
    zcio_socket_nosigpipe(cfd);

    /* Leave the accepted socket non-blocking; the per-op tcp_wait() select
     * (EINTR-safe) governs read/write timeouts and tcp_s_read/tcp_s_write
     * already handle EWOULDBLOCK. */
    zcio_set_nonblocking(cfd, true);

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

    size_t id;
    if (!server_pop_free_id(s, &id)) id = s->next_id++;
    if (server_store(s, id, conn) != ZCIO_OK) {
        zcio_stream_free(use);
        free(conn);
        zcio_fail_(ZCIO_ERR_NOMEM, "accept: out of memory");
        return NULL;
    }
    if (out_id) *out_id = id;
    return conn;
}

/* Closes and frees the client identified by `id`. CONTRACT: after this call the
 * zcio_tcp_conn* previously returned by accept() for this id is freed (dangling);
 * the caller must not use it again. The id is recycled by a later accept(). */
int zcio_tcp_server_close_client(zcio_tcp_server *s, size_t id) {
    if (!s) return ZCIO_ERR_INVALID_ARG;
    if (id >= s->slots_len || !s->slots[id].conn)
        return zcio_fail_(ZCIO_ERR_INVALID_ARG, "close_client: unknown id %zu", id);
    zcio_tcp_conn *conn = s->slots[id].conn;
    zcio_stream_free(conn->stream);
    free(conn);
    s->slots[id].conn = NULL;

    /* Reclaim the id for reuse. If the free-list push fails (OOM), simply drop
     * the id: the slot stays NULL and next_id-allocated ids remain valid. */
    if (s->free_len >= s->free_cap) {
        size_t ncap = s->free_cap ? s->free_cap * 2 : 8;
        size_t *nf = (size_t *)realloc(s->free_ids, ncap * sizeof *nf);
        if (nf) { s->free_ids = nf; s->free_cap = ncap; }
    }
    if (s->free_len < s->free_cap) s->free_ids[s->free_len++] = id;
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
