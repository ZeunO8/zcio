/* HTTP/2 loopback coverage. Starts a real zcio_http_server (plaintext, h1+h2)
 * on an ephemeral port in a background thread, then drives it as a raw HTTP/2
 * prior-knowledge client over a plain TCP socket: connection preface + SETTINGS,
 * a GET as an HPACK-encoded HEADERS frame, and verification of the server
 * SETTINGS, the :status 200 response HEADERS, and the DATA body. A second case
 * asserts that an UPPERCASE header name is rejected (RST_STREAM / GOAWAY).
 *
 * The client reuses the library's internal HPACK codec (zhp_encode_/zhp_decode_)
 * and zhs_buf, so the test target compiles with -Isrc and includes
 * "http_internal.h". Frame parsing is kept order-tolerant and time-bounded. */
#include "ztest.h"
#include "zcio/zcio.h"
#include "zcio/net.h"
#include "zthread.h"
#include "internal_port.h"
#include "http_internal.h"   /* zhp_*, zhs_buf, zcio_tcp_stream_set_timeout_ */

#include <stdio.h>
#include <string.h>

#define PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"   /* 24 bytes */

/* --- frame type/flag constants (mirrored from the wire) ------------------ */
enum { FT_DATA = 0, FT_HEADERS = 1, FT_RST = 3, FT_SETTINGS = 4,
       FT_PING = 6, FT_GOAWAY = 7, FT_WINDOW_UPDATE = 8, FT_CONTINUATION = 9 };
enum { FL_END_STREAM = 0x1, FL_ACK = 0x1, FL_END_HEADERS = 0x4 };

/* --- server plumbing ----------------------------------------------------- */

static void h2_handler(zcio_http_req *r, void *user) {
    (void)user;
    const char *body = "hello h2";
    zcio_http_respond(r, 200, NULL, 0, body, 8);
}

typedef struct { zcio_http_server *srv; } srv_ctx;

static void *server_thread(void *p) {
    srv_ctx *sc = (srv_ctx *)p;
    zcio_http_server_run(sc->srv);   /* returns once stop() drains the loop */
    return NULL;
}

static zcio_http_server *start_h2_server(int *port_out) {
    zcio_http_server_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.port            = 0;                            /* ephemeral */
    cfg.versions        = (uint32_t)(ZCIO_HTTP1_1 | ZCIO_HTTP2);
    cfg.header_timeout_ms = 2000;
    cfg.idle_timeout_ms   = 2000;
    cfg.write_timeout_ms  = 2000;
    cfg.drain_timeout_ms  = 500;
    zcio_http_server *srv = zcio_http_server_start(&cfg, h2_handler, NULL);
    if (srv) *port_out = zcio_http_server_port(srv);
    return srv;
}

/* --- little-endian-free wire helpers ------------------------------------- */

static uint32_t rd24(const uint8_t *p) {
    return (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | (uint32_t)p[2];
}
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8  | (uint32_t)p[3];
}

/* Write one frame (9-byte header + payload). Returns 0 on success. */
static int wr_frame(zcio_stream *s, uint32_t len, uint8_t type, uint8_t flags,
                    uint32_t sid, const void *payload) {
    uint8_t h[9];
    h[0] = (uint8_t)(len >> 16); h[1] = (uint8_t)(len >> 8); h[2] = (uint8_t)len;
    h[3] = type; h[4] = flags;
    h[5] = (uint8_t)(sid >> 24); h[6] = (uint8_t)(sid >> 16);
    h[7] = (uint8_t)(sid >> 8);  h[8] = (uint8_t)sid;
    if (zcio_write_full(s, h, 9) != 9) return -1;
    if (len && zcio_write_full(s, payload, len) != (int64_t)len) return -1;
    return 0;
}

/* Send the client preface: 24-byte magic + an (empty) SETTINGS frame. */
static int send_preface(zcio_stream *s) {
    if (zcio_write_full(s, PREFACE, 24) != 24) return -1;
    return wr_frame(s, 0, FT_SETTINGS, 0, 0, NULL);
}

/* --- HPACK status capture ------------------------------------------------ */

typedef struct { char status[16]; } dec_ctx;

static int status_emit(void *u, const char *name, size_t nl,
                       const char *val, size_t vl) {
    dec_ctx *d = (dec_ctx *)u;
    if (nl == 7 && memcmp(name, ":status", 7) == 0) {
        size_t n = vl < sizeof d->status - 1 ? vl : sizeof d->status - 1;
        memcpy(d->status, val, n);
        d->status[n] = '\0';
    }
    return 0;
}

/* --- collected server responses ------------------------------------------ */

typedef struct {
    bool     saw_settings;   /* server SETTINGS (non-ACK) */
    bool     saw_headers;    /* response HEADERS on stream 1 */
    char     status[16];
    bool     saw_data_end;   /* DATA with END_STREAM on stream 1 */
    bool     saw_rst;
    bool     saw_goaway;
    uint8_t  body[256];
    size_t   body_len;
} h2res;

/* Read + parse frames until a full response, an error frame, or a timeout.
 * Order-tolerant: SETTINGS/ACK/WINDOW_UPDATE are consumed and ignored. */
static void collect(zcio_stream *s, h2res *res) {
    static uint8_t buf[65536];
    size_t have = 0;

    for (int guard = 0; guard < 512; guard++) {
        if ((res->saw_headers && res->saw_data_end) || res->saw_rst || res->saw_goaway)
            break;

        /* Ensure a full frame header, then a full frame, is buffered. */
        while (have < 9) {
            int64_t n = zcio_read(s, buf + have, sizeof buf - have);
            if (n <= 0) return;                 /* timeout / EOF */
            have += (size_t)n;
        }
        uint32_t len   = rd24(buf);
        uint8_t  type  = buf[3];
        uint8_t  flags = buf[4];
        uint32_t sid   = rd32(buf + 5) & 0x7fffffffu;
        if (len > sizeof buf - 9) return;       /* absurd; bail */
        while (have < (size_t)9 + len) {
            int64_t n = zcio_read(s, buf + have, sizeof buf - have);
            if (n <= 0) return;
            have += (size_t)n;
        }
        const uint8_t *payload = buf + 9;

        switch (type) {
        case FT_SETTINGS:
            if (!(flags & FL_ACK)) {
                res->saw_settings = true;
                (void)wr_frame(s, 0, FT_SETTINGS, FL_ACK, 0, NULL); /* be polite */
            }
            break;
        case FT_HEADERS:
            if (sid == 1) {
                dec_ctx dc; memset(&dc, 0, sizeof dc);
                zhp_dec *d = zhp_dec_new_(ZHP_DEC_TABLE_MAX);
                if (d) {
                    (void)zhp_decode_(d, payload, len, 65536, status_emit, &dc);
                    zhp_dec_free_(d);
                }
                res->saw_headers = true;
                memcpy(res->status, dc.status, sizeof res->status);
                if (flags & FL_END_STREAM) res->saw_data_end = true;
            }
            break;
        case FT_DATA:
            if (sid == 1) {
                size_t n = len;
                if (n > sizeof res->body - res->body_len) n = sizeof res->body - res->body_len;
                memcpy(res->body + res->body_len, payload, n);
                res->body_len += n;
                if (flags & FL_END_STREAM) res->saw_data_end = true;
            }
            break;
        case FT_RST:    res->saw_rst = true; break;
        case FT_GOAWAY: res->saw_goaway = true; break;
        default: break; /* WINDOW_UPDATE, PING, etc.: ignore */
        }

        size_t consumed = (size_t)9 + len;
        memmove(buf, buf + consumed, have - consumed);
        have -= consumed;
    }
}

/* Build the GET pseudo-header field block into fb. */
static int build_get_block(zhs_buf *fb, const char *authority) {
    int r = ZCIO_OK;
    if (r == ZCIO_OK) r = zhp_encode_(fb, ":method", "GET");
    if (r == ZCIO_OK) r = zhp_encode_(fb, ":scheme", "http");
    if (r == ZCIO_OK) r = zhp_encode_(fb, ":path", "/");
    if (r == ZCIO_OK) r = zhp_encode_(fb, ":authority", authority);
    return r;
}

/* ========================================================================= */

ZTEST(h2_get_response_cycle) {
    zcio_init();
    int port = 0;
    zcio_http_server *srv = start_h2_server(&port);
    ZCHECK(srv != NULL);
    if (!srv) return;

    srv_ctx sc = { .srv = srv };
    zthread_t th;
    zthread_start(&th, server_thread, &sc);
    zthread_sleep_ms(50);

    zcio_tcp_client *cli = zcio_tcp_client_connect("127.0.0.1", port);
    ZCHECK(cli != NULL);
    if (cli) {
        zcio_stream *s = zcio_tcp_client_stream(cli);
        zcio_tcp_stream_set_timeout_(s, 3000);

        char authority[64];
        snprintf(authority, sizeof authority, "127.0.0.1:%d", port);
        zhs_buf fb = {0};
        ZCHECK(build_get_block(&fb, authority) == ZCIO_OK);

        ZCHECK(send_preface(s) == 0);
        ZCHECK(wr_frame(s, (uint32_t)fb.len, FT_HEADERS,
                        FL_END_HEADERS | FL_END_STREAM, 1, fb.data) == 0);
        zhs_buf_free_(&fb);

        h2res res; memset(&res, 0, sizeof res);
        collect(s, &res);

        ZCHECK(res.saw_settings);                 /* server connection preface */
        ZCHECK(res.saw_headers);
        ZCHECK_STR(res.status, "200");
        ZCHECK(res.saw_data_end);
        ZCHECK_EQ(res.body_len, 8);
        if (res.body_len == 8) ZCHECK(memcmp(res.body, "hello h2", 8) == 0);

        zcio_tcp_client_free(cli);
    }

    zcio_http_server_stop(srv);
    zthread_join(th);
    zcio_http_server_free(srv);
}

ZTEST(h2_uppercase_header_rejected) {
    zcio_init();
    int port = 0;
    zcio_http_server *srv = start_h2_server(&port);
    ZCHECK(srv != NULL);
    if (!srv) return;

    srv_ctx sc = { .srv = srv };
    zthread_t th;
    zthread_start(&th, server_thread, &sc);
    zthread_sleep_ms(50);

    zcio_tcp_client *cli = zcio_tcp_client_connect("127.0.0.1", port);
    ZCHECK(cli != NULL);
    if (cli) {
        zcio_stream *s = zcio_tcp_client_stream(cli);
        zcio_tcp_stream_set_timeout_(s, 3000);

        char authority[64];
        snprintf(authority, sizeof authority, "127.0.0.1:%d", port);
        zhs_buf fb = {0};
        ZCHECK(build_get_block(&fb, authority) == ZCIO_OK);
        /* "X-Test" is not a static-table name, so zhp_encode_ emits it as a
         * literal preserving case -> an uppercase HTTP/2 header name. */
        ZCHECK(zhp_encode_(&fb, "X-Test", "bad") == ZCIO_OK);

        ZCHECK(send_preface(s) == 0);
        ZCHECK(wr_frame(s, (uint32_t)fb.len, FT_HEADERS,
                        FL_END_HEADERS | FL_END_STREAM, 1, fb.data) == 0);
        zhs_buf_free_(&fb);

        h2res res; memset(&res, 0, sizeof res);
        collect(s, &res);

        ZCHECK(res.saw_rst || res.saw_goaway);    /* stream/connection error */

        zcio_tcp_client_free(cli);
    }

    zcio_http_server_stop(srv);
    zthread_join(th);
    zcio_http_server_free(srv);
}

ZTEST_MAIN()
