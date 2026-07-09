/* src/http_server.c - the HTTP server event-loop spine + respond policy.
 *
 * A single-threaded, non-blocking event loop over poll(2)/WSAPoll: it owns the
 * listen sockets, the connection table, the deadline clocks and the graceful
 * drain; the per-protocol sans-I/O state machines (h1.c / h2.c / h3.c) do the
 * actual parsing/serialization. This TU moves bytes between each connection's
 * input/output zhs_buf and its (possibly TLS-wrapped) zcio_stream, and it
 * implements the two services the protocol modules call up into: zhs_dispatch_
 * (run the user handler with a guaranteed single response) and
 * zhs_detach_for_upgrade_ (hand a connection to ws.c).
 *
 * Ownership map:
 *   - The server owns every `conn` (heap) in srv->conns[]; conn_free releases
 *     the protocol object, both buffers, and the stream (which itself owns and
 *     closes the fd). A detached (WebSocket) conn has stream == NULL: ws.c owns
 *     the stream now, so conn_free must not touch it.
 *   - A tls ctx the server created itself (self-signed / from files) is owned
 *     and freed on destroy; a borrowed cfg->tls is never freed.
 *   - cfg is copied; the three caller string fields we retain (host, cert_file,
 *     key_file) are duplicated so the caller may free the originals.
 */
#include "http_internal.h"
#include "zcio/zcio.h"   /* zcio_init() */

#include <stdatomic.h>

#if !defined(_WIN32)
#  include <signal.h>
#endif

#define READ_SCRATCH   65536
#define LISTEN_BACKLOG 128

/* HTTP/2 client connection preface prefix; enough to recognize prior-knowledge
 * h2 on a plaintext socket without reading the whole 24-byte magic. */
static const char H2_PREFACE[] = "PRI * HTTP/2.0";
#define H2_PREFACE_LEN 14u

/* ========================================================================= *
 *  Connection object
 * ========================================================================= */

typedef enum { CONN_UNKNOWN = 0, CONN_H1, CONN_H2 } conn_proto;

typedef struct conn {
    struct zcio_http_server *srv;
    zcio_socket  fd;          /* mirror of the stream's fd, for the poll set   */
    zcio_stream *stream;      /* plain or TLS overlay; NULL once detached      */
    zhs_buf      in;          /* bytes read off the wire, awaiting the parser  */
    zhs_buf      out;         /* bytes the parser queued, awaiting the wire    */

    conn_proto   proto;
    zh1_conn    *h1;
    zh2_conn    *h2;

    bool         secure;      /* arrived over TLS                              */
    bool         tls_pending; /* TLS handshake not yet complete                */
    bool         redirect;    /* plaintext auto-HTTPS redirect listener conn   */
    bool         peer_eof;    /* read hit EOF/error: close once out drains     */
    bool         want_close;  /* protocol asked to close once out drains       */
    bool         dead;        /* remove from the loop this iteration           */
    bool         detached;    /* handed to ws.c: do NOT free the stream        */

    uint64_t     created_ms;  /* accept time (handshake/preface slowloris)     */
    uint64_t     activity_ms; /* last >0-byte read/write                       */
    bool         timing_head; /* currently timing an h1 request head           */
    uint64_t     head_start_ms;
} conn;

/* ========================================================================= *
 *  Server object
 * ========================================================================= */

struct zcio_http_server {
    zcio_http_server_config cfg;      /* shallow copy; strings below re-owned  */
    char              *host_owned;    /* dup of cfg.host (or NULL)             */
    char              *bind_owned;    /* dup of cfg.bind_host (or NULL)        */
    char              *cert_owned;    /* dup of cfg.cert_file (or NULL)        */
    char              *key_owned;     /* dup of cfg.key_file (or NULL)         */
    uint32_t           versions;      /* resolved (defaults to HTTP1_1)        */
    zcio_http_handler  handler;
    void              *user;
    zhs_limits         lim;

    zcio_socket  listen_fd;           /* h1/h2 TCP listener                    */
    zcio_socket  redirect_fd;         /* plaintext 301 listener, or INVALID    */
    zh3_srv     *h3;                  /* HTTP/3 over QUIC, or NULL             */
    int          bound_port;          /* the TCP port actually bound           */

    zcio_socket  wake_r;              /* self-pipe read end (POSIX) / socket   */
    zcio_socket  wake_w;              /* self-pipe write end (POSIX) / socket  */

    zcio_tls_ctx *tls;                /* effective server ctx, or NULL         */
    bool          tls_owned;          /* free tls on destroy iff true          */

    conn       **conns;               /* live connections (heap conn*)         */
    size_t       nconns;
    size_t       cap_conns;

    struct pollfd *pollset;           /* reusable poll fd array                */
    size_t         pollset_cap;

    _Atomic bool  stop_flag;          /* set by zcio_http_server_stop()        */
    bool          stopping;           /* graceful drain in progress            */
    bool          stopped;            /* fully drained: poll() returns EOF     */
    uint64_t      drain_deadline_ms;

    bool          upgrade_detached;   /* set by detach during a dispatch       */
};

/* ========================================================================= *
 *  Small helpers
 * ========================================================================= */

static bool out_pending(const conn *c) { return ZHS_AVAIL(&c->out) > 0; }

/* case-insensitive equality of NUL-terminated strings. */
static bool ci_eq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        int ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return false;
    }
    return *a == '\0' && *b == '\0';
}

/* Take the smaller non-negative timeout; a negative operand means "no bound". */
static int to_min(int cur, int cand) {
    if (cand < 0) return cur;
    if (cur < 0)  return cand;
    return cand < cur ? cand : cur;
}

/* ========================================================================= *
 *  Request accessors
 * ========================================================================= */

const char *zcio_http_req_method(const zcio_http_req *r) {
    return r && r->method ? r->method : "";
}
const char *zcio_http_req_path(const zcio_http_req *r) {
    return r && r->path ? r->path : "";
}
const char *zcio_http_req_query(const zcio_http_req *r) {
    return r && r->query ? r->query : "";
}
int zcio_http_req_version(const zcio_http_req *r) { return r ? r->version : 0; }
bool zcio_http_req_secure(const zcio_http_req *r) { return r ? r->secure : false; }

const char *zcio_http_req_header(const zcio_http_req *r, const char *name) {
    return r ? zhs_hdrs_get_(&r->headers, name) : NULL;
}
size_t zcio_http_req_header_count(const zcio_http_req *r) {
    return r ? r->headers.n : 0;
}
int zcio_http_req_header_at(const zcio_http_req *r, size_t i,
                            const char **name, const char **value) {
    if (!r || i >= r->headers.n)
        return zcio_fail_(ZCIO_ERR_INVALID_ARG, "http: header index out of range");
    if (name)  *name  = r->headers.v[i].name;
    if (value) *value = r->headers.v[i].value;
    return ZCIO_OK;
}

const void *zcio_http_req_body(const zcio_http_req *r, size_t *len) {
    if (!r || !r->body.data) { if (len) *len = 0; return ""; }
    if (len) *len = ZHS_AVAIL(&r->body);   /* body is never consumed: off == 0 */
    return ZHS_PTR(&r->body);
}

/* ========================================================================= *
 *  Respond policy (public zcio_http_respond)
 * ========================================================================= */

/* Hop-by-hop / connection-specific headers plus the ones the server stamps
 * itself: a caller may not smuggle these into the final response. */
static bool respond_filtered(const char *name) {
    static const char *DROP[] = {
        "connection", "keep-alive", "proxy-connection", "transfer-encoding",
        "upgrade", "te", "trailer", "content-length", "date", "server",
    };
    for (size_t i = 0; i < sizeof DROP / sizeof DROP[0]; i++)
        if (ci_eq(name, DROP[i])) return true;
    return false;
}

int zcio_http_respond(zcio_http_req *r, int status,
                      const zcio_http_header *headers, size_t nheaders,
                      const void *body, size_t body_len) {
    if (!r || !r->respond_fn)
        return zcio_fail_(ZCIO_ERR_INVALID_ARG, "respond: invalid request");
    if (r->responded)
        return zcio_fail_(ZCIO_ERR_INVALID_ARG, "respond: already responded");
    if (status < 100 || status > 599)
        return zcio_fail_(ZCIO_ERR_INVALID_ARG, "respond: status %d out of range", status);

    /* Reject any header carrying CR/LF/NUL or a non-token name (response-
     * splitting defense) before we commit to building anything. */
    for (size_t i = 0; i < nheaders; i++) {
        const char *k = headers[i].key;
        const char *v = headers[i].value ? headers[i].value : "";
        if (!k || !zhs_token_ok_(k, strlen(k)))
            return zcio_fail_(ZCIO_ERR_INVALID_ARG, "respond: invalid header name");
        if (!zhs_value_ok_(v, strlen(v)))
            return zcio_fail_(ZCIO_ERR_INVALID_ARG, "respond: invalid header value");
    }

    /* Build the final header set: surviving caller headers + Date + Server +
     * (HSTS) + (Alt-Svc). Up to 4 headers are appended. */
    if (nheaders > SIZE_MAX / sizeof(zcio_http_header) - 4)
        return zcio_fail_(ZCIO_ERR_NOMEM, "respond: too many headers");
    zcio_http_header *fin =
        (zcio_http_header *)zcio_xmalloc((nheaders + 4) * sizeof *fin);
    if (!fin) return zcio_fail_(ZCIO_ERR_NOMEM, "respond: out of memory");

    size_t n = 0;
    for (size_t i = 0; i < nheaders; i++) {
        if (respond_filtered(headers[i].key)) continue;   /* drop hop-by-hop  */
        fin[n].key   = headers[i].key;
        fin[n].value = headers[i].value ? headers[i].value : "";
        n++;
    }

    char date[32];
    zhs_http_date_(date);
    fin[n].key = "date";   fin[n].value = date;      n++;
    fin[n].key = "server"; fin[n].value = "zcio";    n++;

    const zcio_http_server *srv = r->srv;
    if (srv && srv->cfg.hsts && r->secure) {
        fin[n].key = "strict-transport-security";
        fin[n].value = "max-age=31536000";
        n++;
    }
    char altsvc[48];
    if (srv && (srv->versions & ZCIO_HTTP3) && r->secure) {
        snprintf(altsvc, sizeof altsvc, "h3=\":%d\"", srv->bound_port);
        fin[n].key = "alt-svc"; fin[n].value = altsvc; n++;
    }

    /* Commit: mark responded now so a respond_fn failure cannot become a
     * double response via the dispatch 500 fallback. Body suppression for
     * HEAD/204/304 is the owning module's framing responsibility. */
    r->responded = true;
    int rc = r->respond_fn(r, status, fin, n, body, body_len);
    free(fin);
    return rc;
}

/* ========================================================================= *
 *  Services for the protocol modules
 * ========================================================================= */

/* Private accessor for h1.c redirect mode (the server struct is opaque to it).
 * Not part of the pinned http_internal.h contract; see the note in h1.c. */
const char *zhs_redirect_host_(struct zcio_http_server *srv) {
    return srv ? srv->cfg.host : NULL;
}

int zhs_dispatch_(struct zcio_http_server *srv, zcio_http_req *req) {
    req->srv = srv;
    srv->upgrade_detached = false;
    srv->handler(req, srv->user);

    /* A WebSocket accept detached the connection mid-handler: the request is
     * considered responded and the loop must stop managing this conn. */
    if (srv->upgrade_detached) return 1;

    /* Guarantee exactly one response: synthesize 500 if the handler produced
     * neither a response nor a detach. */
    if (!req->responded)
        (void)zcio_http_respond(req, 500, NULL, 0,
                                "Internal Server Error", 21);
    return 0;
}

zcio_stream *zhs_detach_for_upgrade_(zcio_http_req *req,
                                     const void *resp, size_t resp_len,
                                     const uint8_t **leftover, size_t *leftover_len) {
    /* WebSocket upgrade is h1-only: owner is the zh1_conn, whose loop-side
     * context (zh1_user_) is our conn. */
    if (!req || req->version != 1 || !req->owner) {
        zcio_fail_(ZCIO_ERR_UNSUPPORTED, "ws detach: not an h1 request");
        return NULL;
    }
    conn *c = (conn *)zh1_user_((zh1_conn *)req->owner);
    if (!c || !c->stream) return NULL;
    if (leftover) { *leftover = NULL; *leftover_len = 0; }

    /* Restore a blocking write timeout so the synchronous 101 + queued-output
     * flush cannot spin on WOULDBLOCK. Effective over TLS too (unwraps the
     * overlay to the transport). */
    zcio_stream *s = c->stream;
    (void)zcio_stream_set_timeout_(s, c->srv->lim.write_timeout_ms);

    int64_t w = zcio_write_full(s, resp, resp_len);
    if (w < 0 || (size_t)w != resp_len) {
        zcio_fail_(ZCIO_ERR, "ws detach: failed to write 101");
        return NULL;   /* leave the conn intact; the loop closes it normally */
    }
    size_t queued = ZHS_AVAIL(&c->out);
    if (queued) {
        w = zcio_write_full(s, ZHS_PTR(&c->out), queued);
        if (w < 0 || (size_t)w != queued) {
            zcio_fail_(ZCIO_ERR, "ws detach: failed to drain output");
            return NULL;
        }
        zhs_buf_consume_(&c->out, queued);
    }

    /* Hand back any bytes buffered past the upgrade request (a client that
     * pipelined its first WebSocket frames). Aliases c->in, which conn_free
     * releases after dispatch — ws.c copies it out before returning. */
    if (leftover && ZHS_AVAIL(&c->in) > 0) {
        *leftover = ZHS_PTR(&c->in);
        *leftover_len = ZHS_AVAIL(&c->in);
    }

    /* Ownership of the stream (and its fd) passes to ws.c. Detach the conn from
     * the loop: NULL the stream so conn_free never touches it. */
    c->stream = NULL;
    c->detached = true;
    c->srv->upgrade_detached = true;
    return s;
}

/* ========================================================================= *
 *  Connection lifecycle
 * ========================================================================= */

static void conn_free(conn *c) {
    if (!c) return;
    if (c->h1) zh1_free_(c->h1);
    if (c->h2) zh2_free_(c->h2);
    zhs_buf_free_(&c->in);
    zhs_buf_free_(&c->out);
    if (c->stream) zcio_stream_free(c->stream);  /* NULL after ws detach */
    free(c);
}

static int server_add_conn(zcio_http_server *srv, conn *c) {
    if (srv->nconns == srv->cap_conns) {
        size_t ncap = srv->cap_conns ? srv->cap_conns * 2 : 16;
        conn **nc = (conn **)realloc(srv->conns, ncap * sizeof *nc);
        if (!nc) return ZCIO_ERR_NOMEM;
        srv->conns = nc;
        srv->cap_conns = ncap;
    }
    srv->conns[srv->nconns++] = c;
    return ZCIO_OK;
}

/* Build a conn around an accepted fd. On failure the fd/stream is released and
 * NULL is returned (the fd is never leaked). */
static conn *conn_create(zcio_http_server *srv, zcio_socket fd, bool redirect) {
    conn *c = (conn *)zcio_xcalloc(1, sizeof *c);
    if (!c) { zcio_closesocket(fd); return NULL; }
    c->srv = srv;
    c->fd = fd;
    c->created_ms = c->activity_ms = c->head_start_ms = zcio_now_ms_();
    c->redirect = redirect;

    zcio_stream *plain = zcio_tcp_stream_from_fd_(fd, 0);  /* fully non-blocking */
    if (!plain) { zcio_closesocket(fd); free(c); return NULL; }
    c->stream = plain;

    if (redirect) {
        /* Plaintext 301 listener: h1 in redirect mode, never dispatched. */
        c->proto = CONN_H1;
        c->h1 = zh1_new_(srv, &srv->lim, ZH1_F_REDIRECT, &c->out, c);
        if (!c->h1) { conn_free(c); return NULL; }
    } else if (srv->tls) {
        /* wrap_nb leaves `plain` untouched on failure -> we free it here. */
        zcio_stream *w = zcio_tls_wrap_nb(srv->tls, plain, true, false);
        if (!w) { conn_free(c); return NULL; }
        c->stream = w;
        c->secure = true;
        c->tls_pending = true;   /* proto chosen from ALPN once handshake done */
    }
    /* else: plaintext main listener; proto chosen by preface sniffing. */

    if (server_add_conn(srv, c) != ZCIO_OK) { conn_free(c); return NULL; }
    return c;
}

/* Choose h1/h2 for a TLS conn from the negotiated ALPN. */
static void conn_select_proto_tls(conn *c) {
    const char *alpn = zcio_tls_stream_alpn(c->stream);
    if (alpn && strcmp(alpn, "h2") == 0) {
        if (!(c->srv->versions & ZCIO_HTTP2)) { c->dead = true; return; }
        c->h2 = zh2_new_(c->srv, &c->srv->lim, c->secure, &c->out);
        if (!c->h2) { c->dead = true; return; }
        c->proto = CONN_H2;
    } else {
        if (!(c->srv->versions & ZCIO_HTTP1_1)) { c->dead = true; return; }
        c->h1 = zh1_new_(c->srv, &c->srv->lim,
                         c->secure ? ZH1_F_SECURE : 0u, &c->out, c);
        if (!c->h1) { c->dead = true; return; }
        c->proto = CONN_H1;
    }
}

/* Plaintext protocol sniff. Returns true once a protocol is chosen (or the
 * conn is marked dead); false means "need more bytes, wait". */
static bool conn_select_proto_plain(conn *c) {
    size_t avail = ZHS_AVAIL(&c->in);
    if (avail == 0) return false;

    if (c->srv->versions & ZCIO_HTTP2) {
        size_t look = avail < H2_PREFACE_LEN ? avail : H2_PREFACE_LEN;
        if (memcmp(ZHS_PTR(&c->in), H2_PREFACE, look) == 0) {
            if (avail < H2_PREFACE_LEN) return false;   /* matches so far */
            c->h2 = zh2_new_(c->srv, &c->srv->lim, c->secure, &c->out);
            if (!c->h2) { c->dead = true; return true; }
            c->proto = CONN_H2;
            return true;
        }
    }
    if (!(c->srv->versions & ZCIO_HTTP1_1)) { c->dead = true; return true; }
    c->h1 = zh1_new_(c->srv, &c->srv->lim,
                     c->secure ? ZH1_F_SECURE : 0u, &c->out, c);
    if (!c->h1) { c->dead = true; return true; }
    c->proto = CONN_H1;
    return true;
}

/* Stamp head_start_ms at the first byte of a request and hold it for the whole
 * receive (head AND body), so conn_deadline_ms can bound the entire request
 * against an absolute deadline rather than a per-read idle timer. */
static void conn_update_head_timing(conn *c, uint64_t now) {
    if (c->proto == CONN_H1 && c->h1 && zh1_receiving_(c->h1)) {
        if (!c->timing_head) { c->timing_head = true; c->head_start_ms = now; }
    } else {
        c->timing_head = false;
    }
}

/* Feed queued input to the protocol state machine, translating its return code
 * into conn flags. Sets *work when a request was dispatched. */
static void conn_feed(conn *c, int *work) {
    if (c->proto == CONN_UNKNOWN && !conn_select_proto_plain(c)) return;
    if (c->dead) return;

    if (c->proto == CONN_H1) {
        int r = zh1_feed_(c->h1, &c->in);
        switch (r) {
            case ZH1_NEED_MORE:  break;
            case ZH1_DISPATCHED: (*work)++; break;
            case ZH1_CLOSE:      c->want_close = true; break;
            case ZH1_DETACHED:   c->dead = true; return;  /* stream now ws.c's */
            default:             c->dead = true; return;  /* hard error */
        }
    } else if (c->proto == CONN_H2) {
        int r = zh2_feed_(c->h2, &c->in);
        if (r < 0) { c->dead = true; return; }
        if (r == ZH2_CLOSING) c->want_close = true;
        zh2_pump_(c->h2);           /* move any ready DATA to the out buffer */
        (*work)++;
    }
}

static void conn_flush(conn *c, uint64_t now, int *work) {
    while (ZHS_AVAIL(&c->out)) {
        int64_t w = zcio_write(c->stream, ZHS_PTR(&c->out), ZHS_AVAIL(&c->out));
        if (w > 0) {
            zhs_buf_consume_(&c->out, (size_t)w);
            c->activity_ms = now;
            (*work)++;
        } else if (w == ZCIO_ERR_WOULDBLOCK) {
            break;                                   /* keep the remainder */
        } else {
            c->dead = true;                          /* write error: close */
            break;
        }
    }
}

/* One connection's slice of a poll iteration. */
static void conn_process(conn *c, short revents, int *work) {
    uint64_t now = zcio_now_ms_();

    if (revents & (POLLERR | POLLNVAL)) c->peer_eof = true;

    /* Drive the TLS handshake on readable OR writable: its flights move in both
     * directions and a blocked outbound flight only clears via POLLOUT. */
    if (c->tls_pending) {
        if (revents & (POLLIN | POLLOUT)) {
            int hr = zcio_tls_handshake(c->stream);
            if (hr == ZCIO_OK) {
                c->tls_pending = false;
                c->activity_ms = now;
                conn_select_proto_tls(c);
            } else if (hr != ZCIO_ERR_WOULDBLOCK) {
                c->dead = true;
            }
        }
    } else if (revents & POLLIN) {
        {
            uint8_t scratch[READ_SCRATCH];
            int64_t r = zcio_read(c->stream, scratch, sizeof scratch);
            if (r > 0) {
                if (zhs_buf_append_(&c->in, scratch, (size_t)r) != ZCIO_OK)
                    c->dead = true;
                else { c->activity_ms = now; (*work)++; }
            } else if (r == 0 || r != ZCIO_ERR_WOULDBLOCK) {
                c->peer_eof = true;                  /* EOF or read error */
            }
        }
    }

    if (!c->dead && !c->tls_pending) {
        conn_feed(c, work);
        conn_update_head_timing(c, now);
    }
    /* h2 may have more to send once its window opens or output drains. */
    if (!c->dead && c->proto == CONN_H2 && (revents & POLLOUT))
        zh2_pump_(c->h2);
    if (!c->dead && out_pending(c))
        conn_flush(c, now, work);

    /* Close decisions. Detach was already handled (dead + stream NULL). */
    if (!c->detached) {
        if (c->want_close && !out_pending(c)) c->dead = true;
        if (c->peer_eof) {
            if (!out_pending(c)) c->dead = true;
            else c->want_close = true;               /* flush, then close */
        }
    }
}

/* Earliest deadline that applies to `c`, or UINT64_MAX for none. */
static uint64_t conn_deadline_ms(const conn *c) {
    const zhs_limits *L = &c->srv->lim;
    if (c->dead) return UINT64_MAX;
    if (c->tls_pending || c->proto == CONN_UNKNOWN)
        return c->created_ms + (uint64_t)L->header_timeout_ms;
    if (out_pending(c))
        return c->activity_ms + (uint64_t)L->write_timeout_ms;
    /* A request in flight is bound by an ABSOLUTE deadline from its first byte:
     * header_timeout while still reading the head (tight slowloris guard), then
     * idle_timeout as the total body budget. Because head_start_ms does not move
     * once the request begins, a body trickled one byte per (idle_timeout-1)ms
     * cannot keep the connection alive indefinitely. */
    if (c->proto == CONN_H1 && c->h1 && zh1_receiving_(c->h1)) {
        uint64_t budget = zh1_mid_headers_(c->h1)
                        ? (uint64_t)L->header_timeout_ms
                        : (uint64_t)L->idle_timeout_ms;
        return c->head_start_ms + budget;
    }
    return c->activity_ms + (uint64_t)L->idle_timeout_ms;   /* keep-alive idle */
}

/* True once a connection has nothing left in flight (safe to close on drain). */
static bool conn_drained(const conn *c) {
    if (out_pending(c)) return false;
    if (c->proto == CONN_H1) return !c->h1 || zh1_idle_(c->h1);
    if (c->proto == CONN_H2) return !c->h2 || zh2_idle_(c->h2);
    return true;   /* UNKNOWN / mid-handshake: nothing dispatched yet */
}

static void server_remove_dead(zcio_http_server *srv) {
    size_t k = 0;
    for (size_t i = 0; i < srv->nconns; i++) {
        conn *c = srv->conns[i];
        if (c->dead) conn_free(c);
        else srv->conns[k++] = c;
    }
    srv->nconns = k;
}

/* ========================================================================= *
 *  Listeners / accept
 * ========================================================================= */

/* Create a non-blocking TCP listener. Deliberately no SO_REUSEADDR: matches the
 * server's documented behavior (fresh ephemeral ports across restarts).
 * bind_host: NULL/""/"*" bind all interfaces; else a dotted quad or a name
 * resolved to IPv4 (same convention as zcio_tcp_server_listen_host). */
static zcio_socket make_listener(const char *bind_host, int port, int *out_port) {
    zcio_socket_startup();

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (!bind_host || !bind_host[0] || (bind_host[0] == '*' && !bind_host[1])) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, bind_host, &addr.sin_addr) != 1) {
        char *ip = zcio_resolve_ipv4(bind_host);
        if (!ip) return ZCIO_INVALID_SOCKET; /* resolve_ipv4 set the error */
        int ok = inet_pton(AF_INET, ip, &addr.sin_addr) == 1;
        free(ip);
        if (!ok) {
            zcio_fail_(ZCIO_ERR, "http: cannot bind host '%s'", bind_host);
            return ZCIO_INVALID_SOCKET;
        }
    }

    zcio_socket fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == ZCIO_INVALID_SOCKET) {
        zcio_fail_(ZCIO_ERR, "http: socket() failed");
        return ZCIO_INVALID_SOCKET;
    }
    zcio_socket_nosigpipe(fd);
    if (zcio_set_nonblocking(fd, true) != ZCIO_OK) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR, "http: set non-blocking failed");
        return ZCIO_INVALID_SOCKET;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR, "http: bind(:%d) failed", port);
        return ZCIO_INVALID_SOCKET;
    }
    if (listen(fd, LISTEN_BACKLOG) != 0) {
        zcio_closesocket(fd);
        zcio_fail_(ZCIO_ERR, "http: listen() failed");
        return ZCIO_INVALID_SOCKET;
    }
    if (out_port) {
        struct sockaddr_in bound;
        socklen_t blen = sizeof bound;
        if (getsockname(fd, (struct sockaddr *)&bound, &blen) == 0)
            *out_port = (int)ntohs(bound.sin_port);
    }
    return fd;
}

static void accept_loop(zcio_http_server *srv, zcio_socket lfd, bool redirect,
                        int *work) {
    for (;;) {
        struct sockaddr_storage sa;
        socklen_t slen = sizeof sa;
        zcio_socket cfd = accept(lfd, (struct sockaddr *)&sa, &slen);
        if (cfd == ZCIO_INVALID_SOCKET) {
#if !defined(_WIN32)
            if (errno == EINTR) continue;
#endif
            break;   /* drained (WOULDBLOCK) or a transient error */
        }
        zcio_socket_nosigpipe(cfd);
        zcio_set_nonblocking(cfd, true);
        if (srv->nconns >= srv->lim.max_connections) {
            zcio_closesocket(cfd);       /* over the cap: refuse */
            continue;
        }
        if (conn_create(srv, cfd, redirect)) (*work)++;
    }
}

/* ========================================================================= *
 *  Wake mechanism (interrupt poll from stop())
 * ========================================================================= */

#if defined(_WIN32)
/* A loopback UDP socket connected to itself: WSAPoll only watches SOCKETs, so a
 * pipe won't do. stop() sends one byte; the loop drains it. */
static int make_wake(zcio_http_server *srv) {
    zcio_socket u = socket(AF_INET, SOCK_DGRAM, 0);
    if (u == ZCIO_INVALID_SOCKET) return ZCIO_ERR;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(u, (struct sockaddr *)&a, sizeof a) != 0) { zcio_closesocket(u); return ZCIO_ERR; }
    socklen_t alen = sizeof a;
    if (getsockname(u, (struct sockaddr *)&a, &alen) != 0) { zcio_closesocket(u); return ZCIO_ERR; }
    if (connect(u, (struct sockaddr *)&a, alen) != 0) { zcio_closesocket(u); return ZCIO_ERR; }
    zcio_set_nonblocking(u, true);
    srv->wake_r = srv->wake_w = u;
    return ZCIO_OK;
}
static void free_wake(zcio_http_server *srv) {
    if (srv->wake_r != ZCIO_INVALID_SOCKET) zcio_closesocket(srv->wake_r);
    srv->wake_r = srv->wake_w = ZCIO_INVALID_SOCKET;
}
static void wake_poke(zcio_http_server *srv) {
    char b = 1;
    send(srv->wake_w, &b, 1, 0);
}
static void wake_drain(zcio_http_server *srv) {
    char buf[64];
    while (recv(srv->wake_r, buf, sizeof buf, 0) > 0) { }
}
#else
static int make_wake(zcio_http_server *srv) {
    int fds[2];
    if (pipe(fds) != 0) return ZCIO_ERR;
    zcio_set_nonblocking((zcio_socket)fds[0], true);
    zcio_set_nonblocking((zcio_socket)fds[1], true);
    srv->wake_r = fds[0];
    srv->wake_w = fds[1];
    return ZCIO_OK;
}
static void free_wake(zcio_http_server *srv) {
    if (srv->wake_r != ZCIO_INVALID_SOCKET) close(srv->wake_r);
    if (srv->wake_w != ZCIO_INVALID_SOCKET) close(srv->wake_w);
    srv->wake_r = srv->wake_w = ZCIO_INVALID_SOCKET;
}
static void wake_poke(zcio_http_server *srv) {
    char b = 1;
    ssize_t n = write(srv->wake_w, &b, 1);   /* async-signal-safe */
    (void)n;
}
static void wake_drain(zcio_http_server *srv) {
    char buf[64];
    while (read(srv->wake_r, buf, sizeof buf) > 0) { }
}
#endif

/* ========================================================================= *
 *  Graceful stop
 * ========================================================================= */

static void begin_stop(zcio_http_server *srv) {
    /* Stop accepting: close both listeners. */
    if (srv->listen_fd != ZCIO_INVALID_SOCKET) {
        zcio_closesocket(srv->listen_fd);
        srv->listen_fd = ZCIO_INVALID_SOCKET;
    }
    if (srv->redirect_fd != ZCIO_INVALID_SOCKET) {
        zcio_closesocket(srv->redirect_fd);
        srv->redirect_fd = ZCIO_INVALID_SOCKET;
    }
    for (size_t i = 0; i < srv->nconns; i++) {
        conn *c = srv->conns[i];
        if (c->proto == CONN_H1 && c->h1) zh1_graceful_(c->h1);
        else if (c->proto == CONN_H2 && c->h2) zh2_graceful_(c->h2);
    }
    if (srv->h3) zh3_graceful_(srv->h3);
    srv->stopping = true;
    srv->drain_deadline_ms = zcio_now_ms_() + (uint64_t)srv->lim.drain_timeout_ms;
}

/* ========================================================================= *
 *  Event loop
 * ========================================================================= */

static int ensure_pollset(zcio_http_server *srv, size_t need) {
    if (need <= srv->pollset_cap) return ZCIO_OK;
    size_t ncap = srv->pollset_cap ? srv->pollset_cap : 16;
    while (ncap < need) ncap *= 2;
    struct pollfd *np = (struct pollfd *)realloc(srv->pollset, ncap * sizeof *np);
    if (!np) return ZCIO_ERR_NOMEM;
    srv->pollset = np;
    srv->pollset_cap = ncap;
    return ZCIO_OK;
}

int zcio_http_server_poll(zcio_http_server *s, int timeout_ms) {
    if (!s) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "poll: NULL server");
    if (s->stopped) return ZCIO_ERR_EOF;

    if (atomic_load_explicit(&s->stop_flag, memory_order_acquire) && !s->stopping)
        begin_stop(s);

    /* --- build the poll set: special fds first, then one per connection --- */
    size_t nc = s->nconns;
    if (ensure_pollset(s, nc + 4) != ZCIO_OK)
        return zcio_fail_(ZCIO_ERR_NOMEM, "poll: out of memory");

    struct pollfd *p = s->pollset;
    size_t np = 0;
    int idx_listen = -1, idx_redirect = -1, idx_wake = -1;

    if (!s->stopping && s->listen_fd != ZCIO_INVALID_SOCKET) {
        p[np].fd = s->listen_fd; p[np].events = POLLIN; p[np].revents = 0;
        idx_listen = (int)np++;
    }
    if (!s->stopping && s->redirect_fd != ZCIO_INVALID_SOCKET) {
        p[np].fd = s->redirect_fd; p[np].events = POLLIN; p[np].revents = 0;
        idx_redirect = (int)np++;
    }
    p[np].fd = s->wake_r; p[np].events = POLLIN; p[np].revents = 0;
    idx_wake = (int)np++;
    if (s->h3) {
        p[np].fd = zh3_fd_(s->h3); p[np].events = POLLIN; p[np].revents = 0;
        np++;   /* h3 is polled for input; its timers run every iteration */
    }
    size_t nspecial = np;
    for (size_t i = 0; i < nc; i++) {
        conn *c = s->conns[i];
        p[np].fd = c->fd;
        /* Watch writability while output is queued OR the TLS handshake is in
         * flight (its outbound flight may block on a full send buffer, which
         * only clears via POLLOUT — without it the handshake stalls to the
         * header deadline). */
        p[np].events = (short)(POLLIN |
            ((out_pending(c) || c->tls_pending) ? POLLOUT : 0));
        p[np].revents = 0;
        np++;
    }

    /* --- timeout: min(caller, next deadline, h3 timer) --- */
    uint64_t now = zcio_now_ms_();
    uint64_t dl = UINT64_MAX;
    for (size_t i = 0; i < nc; i++) {
        uint64_t cd = conn_deadline_ms(s->conns[i]);
        if (cd < dl) dl = cd;
    }
    if (s->stopping && s->drain_deadline_ms < dl) dl = s->drain_deadline_ms;
    int to = timeout_ms;
    if (dl != UINT64_MAX) {
        int64_t d = (int64_t)(dl - now);
        if (d < 0) d = 0;
        to = to_min(to, (int)(d > INT32_MAX ? INT32_MAX : d));
    }
    if (s->h3) to = to_min(to, zh3_timeout_ms_(s->h3));

    int rc = zcio_poll_(p, np, to);
    if (rc < 0) return zcio_fail_(ZCIO_ERR, "poll: poll() failed");

    int work = 0;
    now = zcio_now_ms_();

    /* --- service ready fds --- */
    if (rc > 0) {
        if (idx_wake >= 0 && (p[idx_wake].revents & POLLIN)) wake_drain(s);
        if (idx_listen >= 0 && (p[idx_listen].revents & (POLLIN | POLLERR)))
            accept_loop(s, s->listen_fd, false, &work);
        if (idx_redirect >= 0 && (p[idx_redirect].revents & (POLLIN | POLLERR)))
            accept_loop(s, s->redirect_fd, true, &work);
    }
    /* h3 drives its own timers even on a bare timeout. */
    if (s->h3) {
        if (zh3_process_(s->h3) < 0) { zh3_free_(s->h3); s->h3 = NULL; }
        else work++;
    }

    /* Connections (poll entries are 1:1 with s->conns[0..nc)). */
    for (size_t i = 0; i < nc; i++)
        conn_process(s->conns[i], rc > 0 ? p[nspecial + i].revents : 0, &work);

    /* Deadline sweep. */
    for (size_t i = 0; i < nc; i++) {
        conn *c = s->conns[i];
        if (!c->dead && now >= conn_deadline_ms(c)) c->dead = true;
    }

    /* --- drain bookkeeping --- */
    if (s->stopping) {
        for (size_t i = 0; i < s->nconns; i++)
            if (conn_drained(s->conns[i])) s->conns[i]->dead = true;
        if (now >= s->drain_deadline_ms)
            for (size_t i = 0; i < s->nconns; i++) s->conns[i]->dead = true;
    }

    server_remove_dead(s);

    if (s->stopping && s->nconns == 0 && (!s->h3 || zh3_idle_(s->h3))) {
        s->stopped = true;
        return ZCIO_ERR_EOF;
    }
    return work > 0 ? work : 0;
}

int zcio_http_server_run(zcio_http_server *s) {
    if (!s) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "run: NULL server");
    for (;;) {
        int r = zcio_http_server_poll(s, -1);
        if (r == ZCIO_ERR_EOF) return ZCIO_OK;
        if (r < 0) return r;
    }
}

void zcio_http_server_stop(zcio_http_server *s) {
    if (!s) return;
    /* async-signal-safe: set a flag and poke the wake fd; the loop does the
     * rest on its own thread. */
    atomic_store_explicit(&s->stop_flag, true, memory_order_release);
    wake_poke(s);
}

int zcio_http_server_port(const zcio_http_server *s) {
    return s ? s->bound_port : ZCIO_ERR_INVALID_ARG;
}

/* ========================================================================= *
 *  TLS resolution + start / free
 * ========================================================================= */

/* Resolve the effective server TLS ctx per http_server.h precedence and, when
 * present, advertise ALPN for the enabled versions. Returns ZCIO_OK (tls may
 * stay NULL for a plaintext server) or a negated result. */
static int resolve_tls(zcio_http_server *srv) {
    const zcio_http_server_config *cfg = &srv->cfg;
    if (cfg->tls) {                          /* borrowed: never freed by us */
        srv->tls = cfg->tls;
        srv->tls_owned = false;
    } else if (srv->cert_owned && srv->key_owned) {
        srv->tls = zcio_tls_server_ctx_files(srv->cert_owned, srv->key_owned);
        if (!srv->tls) return ZCIO_ERR_TLS;
        srv->tls_owned = true;
    } else if (cfg->require_tls || (srv->versions & ZCIO_HTTP3)) {
        srv->tls = zcio_tls_server_ctx();    /* self-signed localhost */
        if (!srv->tls) return ZCIO_ERR_TLS;
        srv->tls_owned = true;
    }

    if (srv->tls) {
        const char *protos[2];
        size_t n = 0;
        if (srv->versions & ZCIO_HTTP2)   protos[n++] = "h2";
        if (srv->versions & ZCIO_HTTP1_1) protos[n++] = "http/1.1";
        if (n) (void)zcio_tls_ctx_set_alpn(srv->tls, protos, n);
    }
    return ZCIO_OK;
}

zcio_http_server *zcio_http_server_start(const zcio_http_server_config *cfg,
                                         zcio_http_handler handler, void *user) {
    zcio_init();
    if (!handler) { zcio_fail_(ZCIO_ERR_INVALID_ARG, "start: NULL handler"); return NULL; }

    zcio_http_server *s = (zcio_http_server *)zcio_xcalloc(1, sizeof *s);
    if (!s) { zcio_fail_(ZCIO_ERR_NOMEM, "start: out of memory"); return NULL; }
    s->handler = handler;
    s->user = user;
    s->listen_fd = s->redirect_fd = ZCIO_INVALID_SOCKET;
    s->wake_r = s->wake_w = ZCIO_INVALID_SOCKET;
    atomic_store_explicit(&s->stop_flag, false, memory_order_relaxed);

    if (cfg) s->cfg = *cfg;                  /* shallow copy */
    s->versions = (cfg && cfg->versions) ? cfg->versions : ZCIO_HTTP1_1;
    zhs_limits_resolve_(&s->lim, cfg);

    /* Re-own the caller string fields so cfg's originals may be freed. */
    if (cfg) {
        s->host_owned = zcio_strdup_(cfg->host);
        s->bind_owned = zcio_strdup_(cfg->bind_host);
        s->cert_owned = zcio_strdup_(cfg->cert_file);
        s->key_owned  = zcio_strdup_(cfg->key_file);
        if ((cfg->host && !s->host_owned) ||
            (cfg->bind_host && !s->bind_owned) ||
            (cfg->cert_file && !s->cert_owned) ||
            (cfg->key_file && !s->key_owned)) {
            zcio_fail_(ZCIO_ERR_NOMEM, "start: out of memory");
            goto fail;
        }
    }
    s->cfg.host = s->host_owned;
    s->cfg.bind_host = s->bind_owned;
    s->cfg.cert_file = s->cert_owned;
    s->cfg.key_file = s->key_owned;

    if (resolve_tls(s) != ZCIO_OK) goto fail;

    if (make_wake(s) != ZCIO_OK) { zcio_fail_(ZCIO_ERR, "start: wake pipe failed"); goto fail; }

    s->listen_fd = make_listener(s->cfg.bind_host, s->cfg.port, &s->bound_port);
    if (s->listen_fd == ZCIO_INVALID_SOCKET) goto fail;

    if (s->cfg.redirect_port > 0) {
        s->redirect_fd = make_listener(s->cfg.bind_host, s->cfg.redirect_port, NULL);
        if (s->redirect_fd == ZCIO_INVALID_SOCKET) goto fail;
    }

    /* HTTP/3 shares the TCP port number on UDP; zh3_new_ owns the UDP socket
     * and self-skips (NULL) when QUIC is unavailable. */
    if (s->versions & ZCIO_HTTP3) {
        s->h3 = zh3_new_(s, &s->cfg, &s->lim, s->bound_port);
        if (!s->h3) goto fail;   /* HTTP3 was requested but cannot be served */
    }

    return s;
fail:
    zcio_http_server_free(s);
    return NULL;
}

void zcio_http_server_free(zcio_http_server *s) {
    if (!s) return;
    for (size_t i = 0; i < s->nconns; i++) conn_free(s->conns[i]);
    free(s->conns);
    free(s->pollset);
    if (s->h3) zh3_free_(s->h3);
    if (s->listen_fd != ZCIO_INVALID_SOCKET) zcio_closesocket(s->listen_fd);
    if (s->redirect_fd != ZCIO_INVALID_SOCKET) zcio_closesocket(s->redirect_fd);
    free_wake(s);
    if (s->tls && s->tls_owned) zcio_tls_ctx_free(s->tls);  /* borrowed: never */
    free(s->host_owned);
    free(s->bind_owned);
    free(s->cert_owned);
    free(s->key_owned);
    free(s);
}
