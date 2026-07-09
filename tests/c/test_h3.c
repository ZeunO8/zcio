/* test_h3.c - HTTP/3 end-to-end + lifecycle test.
 *
 * HTTP/3 is only available when the library was built against OpenSSL >= 3.5
 * with QUIC (otherwise zh3_new_ returns UNSUPPORTED and the server refuses to
 * offer it). We detect availability the honest way: try to start a server that
 * offers ONLY HTTP/3 over TLS; if zcio_http_server_start returns NULL, HTTP/3
 * is unavailable on this build and we self-skip (print a note, pass).
 *
 * When it IS available (OpenSSL >= 3.5) we do a genuine end-to-end exchange:
 * drive the zcio server with a real OpenSSL QUIC client that negotiates ALPN
 * "h3", sends an HTTP/3 HEADERS frame whose field section is QPACK-encoded by
 * the library's own zqp_encode_, and verifies the server dispatches the
 * request and answers 200 with the expected body (QPACK-decoded on the client
 * with zqp_decode_). Then we exercise graceful stop. On older OpenSSL the
 * client path is compiled out and we fall back to a lifecycle-only smoke test.
 */
#include "ztest.h"
#include "zcio/zcio.h"
#include "zcio/http_server.h"
#include "http_internal.h"     /* zhs_buf + zqp_* (library internals; -Isrc) */
#include "zthread.h"
#include "internal_port.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/opensslv.h>
#if defined(ZCIO_TLS_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x30500000L
#  define ZCIO_H3_CLIENT 1
#  include <openssl/ssl.h>
#  include <openssl/err.h>
#  if defined(_WIN32)
#    include <winsock2.h>
#    include <ws2tcpip.h>
#  else
#    include <sys/socket.h>
#    include <netinet/in.h>
#    include <arpa/inet.h>
#    include <unistd.h>
#  endif
#endif

/* Handler: answer every request 200 with a distinctive body. */
static volatile int g_hits = 0;
static void h3_handler(zcio_http_req *req, void *user) {
    (void)user;
    g_hits++;
    zcio_http_respond(req, 200, NULL, 0, "hello-h3", 8);
}

typedef struct {
    zcio_http_server *s;
    volatile int      stop;
    volatile int      polls;
} h3_poll_ctx;

static void *h3_poll_loop(void *p) {
    h3_poll_ctx *c = (h3_poll_ctx *)p;
    while (!c->stop) {
        int r = zcio_http_server_poll(c->s, 20);
        c->polls++;
        if (r < 0) break;   /* ZCIO_ERR_EOF (drained) or a fatal error */
    }
    return NULL;
}

#if defined(ZCIO_H3_CLIENT)
/* --- minimal HTTP/3 client glue over OpenSSL QUIC ----------------------- */

/* RFC 9000 §16 variable-length integer (encode; small values only needed). */
static void h3_vput(zhs_buf *b, uint64_t v) {
    if (v < 0x40) {
        zhs_buf_append_u8_(b, (uint8_t)v);
    } else if (v < 0x4000) {
        zhs_buf_append_u8_(b, 0x40 | (uint8_t)(v >> 8));
        zhs_buf_append_u8_(b, (uint8_t)v);
    } else {
        zhs_buf_append_u8_(b, 0x80 | (uint8_t)(v >> 24));
        zhs_buf_append_u8_(b, (uint8_t)(v >> 16));
        zhs_buf_append_u8_(b, (uint8_t)(v >> 8));
        zhs_buf_append_u8_(b, (uint8_t)v);
    }
}
/* Decode a varint at *p (rem bytes left); advance *p/*rem, set *ok. */
static uint64_t h3_vget(const uint8_t **p, size_t *rem, int *ok) {
    if (*rem < 1) { *ok = 0; return 0; }
    uint8_t b0 = **p;
    size_t len = (size_t)1 << (b0 >> 6);
    if (*rem < len) { *ok = 0; return 0; }
    uint64_t v = b0 & 0x3f;
    for (size_t i = 1; i < len; i++) v = (v << 8) | (*p)[i];
    *p += len; *rem -= len; *ok = 1;
    return v;
}

static int g_status = 0;
static int h3_emit(void *u, const char *n, size_t nl, const char *v, size_t vl) {
    (void)u; (void)vl;
    if (nl == 7 && memcmp(n, ":status", 7) == 0) g_status = atoi(v);
    return 0;
}

/* Returns 1 on a verified 200/"hello-h3" exchange, 0 otherwise. */
static int h3_client_fetch(int port) {
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (!ctx) return 0;
    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); return 0; }

    static const unsigned char alpn[] = { 2, 'h', '3' };
    SSL_set_alpn_protos(ssl, alpn, sizeof alpn);
    SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);   /* self-signed server cert */
    SSL_set1_host(ssl, "localhost");

    int fd = (int)socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        SSL_free(ssl); SSL_CTX_free(ctx);
#if !defined(_WIN32)
        close(fd);
#endif
        return 0;
    }
    SSL_set_fd(ssl, fd);
    SSL_set_blocking_mode(ssl, 1);

    int ok = 0;
    if (SSL_connect(ssl) == 1) {
        /* client control stream: type 0x00 + empty SETTINGS(0x04). */
        SSL *ctl = SSL_new_stream(ssl, SSL_STREAM_FLAG_UNI);
        if (ctl) {
            unsigned char c[3] = { 0x00, 0x04, 0x00 };
            size_t w;
            SSL_write_ex(ctl, c, sizeof c, &w);
        }

        /* request bidi stream: HEADERS frame (QPACK field section). */
        zhs_buf fields = {0};
        zqp_prefix_encode_(&fields);
        zqp_encode_(&fields, ":method", "GET");
        zqp_encode_(&fields, ":scheme", "https");
        zqp_encode_(&fields, ":authority", "localhost");
        zqp_encode_(&fields, ":path", "/");
        zhs_buf frame = {0};
        h3_vput(&frame, 0x01);
        h3_vput(&frame, ZHS_AVAIL(&fields));
        zhs_buf_append_(&frame, ZHS_PTR(&fields), ZHS_AVAIL(&fields));

        SSL *req = SSL_new_stream(ssl, 0);
        if (req) {
            size_t w;
            SSL_write_ex(req, frame.data, frame.len, &w);
            SSL_stream_conclude(req, 0);

            /* read the full response, then parse HTTP/3 frames. */
            zhs_buf in = {0};
            unsigned char tmp[4096];
            size_t n;
            for (;;) {
                int rr = SSL_read_ex(req, tmp, sizeof tmp, &n);
                if (rr == 1 && n > 0) { zhs_buf_append_(&in, tmp, n); continue; }
                int e = SSL_get_error(req, rr);
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) continue;
                break; /* ZERO_RETURN / reset / error => end of stream */
            }

            const uint8_t *p = in.data;
            size_t rem = in.len;
            char body[64] = {0};
            size_t blen = 0;
            while (rem >= 2) {
                int vok = 0;
                uint64_t t = h3_vget(&p, &rem, &vok); if (!vok) break;
                uint64_t L = h3_vget(&p, &rem, &vok); if (!vok) break;
                if (L > rem) break;
                if (t == 0x01) {
                    zqp_decode_(p, (size_t)L, 65536, h3_emit, NULL);
                } else if (t == 0x00) {
                    blen = (size_t)L < sizeof body - 1 ? (size_t)L : sizeof body - 1;
                    memcpy(body, p, blen);
                }
                p += L; rem -= (size_t)L;
            }
            ok = (g_status == 200 && blen == 8 && memcmp(body, "hello-h3", 8) == 0);
            zhs_buf_free_(&in);
            SSL_free(req);
        }
        zhs_buf_free_(&fields);
        zhs_buf_free_(&frame);
        if (ctl) SSL_free(ctl);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
#if !defined(_WIN32)
    close(fd);
#endif
    return ok;
}
#endif /* ZCIO_H3_CLIENT */

ZTEST(h3_server) {
    zcio_init();

    zcio_http_server_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.port              = ztest_free_port();
    cfg.versions          = ZCIO_HTTP3;
    cfg.require_tls       = true;      /* self-signed cert if none given */
    cfg.header_timeout_ms = 2000;
    cfg.idle_timeout_ms   = 3000;
    cfg.write_timeout_ms  = 2000;
    cfg.drain_timeout_ms  = 500;

    zcio_http_server *s = zcio_http_server_start(&cfg, h3_handler, NULL);
    if (!s) {
        fprintf(stderr, "  (skipped: HTTP/3 unavailable: %s)\n", zcio_last_error());
        return; /* not a failure */
    }

    h3_poll_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.s = s;
    zthread_t th;
    if (zthread_start(&th, h3_poll_loop, &ctx) != 0) {
        ZCHECK(0);
        zcio_http_server_free(s);
        return;
    }

#if defined(ZCIO_H3_CLIENT)
    /* Genuine end-to-end request over real QUIC + HTTP/3 + QPACK. */
    int ok = h3_client_fetch(cfg.port);
    ZCHECK(ok);
    ZCHECK(g_hits >= 1);        /* the server actually dispatched the request */
#else
    zthread_sleep_ms(150);      /* older OpenSSL: lifecycle-only smoke test  */
#endif

    zcio_http_server_stop(s);   /* graceful, thread-safe shutdown request     */
    zthread_sleep_ms(150);
    ctx.stop = 1;
    zthread_join(th);
    ZCHECK(ctx.polls > 0);
    zcio_http_server_free(s);
}

ZTEST_MAIN()
