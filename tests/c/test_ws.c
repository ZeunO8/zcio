/* test_ws.c - WebSocket (RFC 6455) coverage against an in-process loopback.
 *
 * A zcio_http_server (HTTP/1.1, plaintext, ephemeral port) runs on its own
 * thread. Its handler detects the upgrade, calls zcio_ws_accept, and hands the
 * detached session to a per-connection echo thread that mirrors every message
 * back until the peer closes. From the main thread we drive the client side:
 * connect, TEXT/BINARY echo round-trips, a ping, and a graceful close. A second
 * test performs a raw handshake with the RFC 6455 §1.3 sample key to pin the
 * SHA-1/Base64 Sec-WebSocket-Accept computation to its published value.
 */
#include "ztest.h"
#include "zthread.h"
#include "internal_port.h"

#include "zcio/zcio.h"
#include "zcio/ws.h"
#include "zcio/http_server.h"
#include "zcio/net.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* --------------------------- server-side echo -------------------------- */

static zthread_t g_echo;
static int       g_echo_started;

static void *ws_echo_thread(void *p) {
    zcio_ws *ws = (zcio_ws *)p;
    for (;;) {
        zcio_ws_msg m;
        if (zcio_ws_recv(ws, &m, -1) != ZCIO_OK) break; /* EOF / close / error */
        zcio_ws_send(ws, m.type, m.data, m.len);
        zcio_ws_msg_free(&m);
    }
    zcio_ws_free(ws);
    return NULL;
}

static void ws_handler(zcio_http_req *r, void *user) {
    (void)user;
    if (zcio_http_req_is_ws_upgrade(r)) {
        zcio_ws *ws = zcio_ws_accept(r);
        if (ws) {
            if (zthread_start(&g_echo, ws_echo_thread, ws) == 0) g_echo_started = 1;
            else zcio_ws_free(ws);
        }
        return;
    }
    zcio_http_respond(r, 404, NULL, 0, NULL, 0);
}

static void *run_thread(void *p) {
    zcio_http_server_run((zcio_http_server *)p);
    return NULL;
}

static zcio_http_server *start_server(int port) {
    zcio_http_server_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.port             = port;
    cfg.versions         = ZCIO_HTTP1_1;
    cfg.header_timeout_ms = 2000;
    cfg.idle_timeout_ms   = 2000;
    cfg.drain_timeout_ms  = 500;
    return zcio_http_server_start(&cfg, ws_handler, NULL);
}

/* --------------------------- raw-handshake aid ------------------------- */

/* Case-insensitive header lookup in a raw HTTP head; malloc'd value or NULL. */
static char *extract_hdr(const char *buf, const char *name) {
    size_t nl = strlen(name);
    const char *line = buf;
    while (line && *line) {
        const char *eol = strstr(line, "\r\n");
        const char *le = eol ? eol : line + strlen(line);
        const char *colon = (const char *)memchr(line, ':', (size_t)(le - line));
        if (colon && (size_t)(colon - line) == nl) {
            bool m = true;
            for (size_t i = 0; i < nl; i++)
                if (tolower((unsigned char)line[i]) != tolower((unsigned char)name[i])) { m = false; break; }
            if (m) {
                const char *v = colon + 1;
                while (v < le && (*v == ' ' || *v == '\t')) v++;
                size_t vl = (size_t)(le - v);
                char *out = (char *)malloc(vl + 1);
                if (!out) return NULL;
                memcpy(out, v, vl);
                out[vl] = '\0';
                return out;
            }
        }
        if (!eol) break;
        line = eol + 2;
    }
    return NULL;
}

/* ------------------------------- tests --------------------------------- */

ZTEST(ws_accept_key_rfc6455) {
    zcio_init();
    g_echo_started = 0;
    int port = ztest_free_port();
    zcio_http_server *srv = start_server(port);
    ZCHECK(srv != NULL);
    if (!srv) return;
    zthread_t rt;
    zthread_start(&rt, run_thread, srv);

    zcio_tcp_client *cli = zcio_tcp_client_connect("127.0.0.1", port);
    ZCHECK(cli != NULL);
    if (cli) {
        zcio_stream *s = zcio_tcp_client_stream(cli);
        /* RFC 6455 §1.3 sample key -> "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=". */
        static const char *kHandshake =
            "GET / HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n";
        zcio_write_full(s, kHandshake, strlen(kHandshake));

        char buf[2048];
        size_t total = 0;
        buf[0] = '\0';
        while (total < sizeof buf - 1) {
            int64_t r = zcio_read(s, buf + total, sizeof buf - 1 - total);
            if (r <= 0) break;
            total += (size_t)r;
            buf[total] = '\0';
            if (strstr(buf, "\r\n\r\n")) break;
        }

        ZCHECK(strstr(buf, " 101 ") != NULL);
        char *accept = extract_hdr(buf, "sec-websocket-accept");
        ZCHECK(accept != NULL);
        if (accept) {
            ZCHECK_STR(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
            free(accept);
        }
        zcio_tcp_client_free(cli); /* EOF -> server echo thread ends */
    }

    zcio_http_server_stop(srv);
    zthread_join(rt);
    if (g_echo_started) zthread_join(g_echo);
    zcio_http_server_free(srv);
}

ZTEST(ws_echo_loopback) {
    zcio_init();
    g_echo_started = 0;
    int port = ztest_free_port();
    zcio_http_server *srv = start_server(port);
    ZCHECK(srv != NULL);
    if (!srv) return;
    zthread_t rt;
    zthread_start(&rt, run_thread, srv);

    char url[64];
    snprintf(url, sizeof url, "ws://127.0.0.1:%d/", port);
    zcio_ws *ws = zcio_ws_connect(url, NULL, 0);
    ZCHECK(ws != NULL);

    if (ws) {
        /* TEXT round-trip. */
        static const char *text = "hello websocket \xE2\x9C\x93"; /* incl. a UTF-8 checkmark */
        ZCHECK_EQ(zcio_ws_send_text(ws, text), ZCIO_OK);
        zcio_ws_msg m;
        int r = zcio_ws_recv(ws, &m, 3000);
        ZCHECK_EQ(r, ZCIO_OK);
        if (r == ZCIO_OK) {
            ZCHECK_EQ(m.type, ZCIO_WS_TEXT);
            ZCHECK_EQ(m.len, strlen(text));
            ZCHECK(m.data && strcmp((const char *)m.data, text) == 0);
            zcio_ws_msg_free(&m);
        }

        /* BINARY round-trip (includes NULs and high bytes). */
        static const unsigned char bin[] = { 0x00, 0x01, 0x02, 0xFD, 0x00, 0xFF };
        ZCHECK_EQ(zcio_ws_send(ws, ZCIO_WS_BINARY, bin, sizeof bin), ZCIO_OK);
        r = zcio_ws_recv(ws, &m, 3000);
        ZCHECK_EQ(r, ZCIO_OK);
        if (r == ZCIO_OK) {
            ZCHECK_EQ(m.type, ZCIO_WS_BINARY);
            ZCHECK_EQ(m.len, sizeof bin);
            ZCHECK(m.data && memcmp(m.data, bin, sizeof bin) == 0);
            zcio_ws_msg_free(&m);
        }

        /* Unsolicited ping (the echo peer's recv answers it with a pong). */
        ZCHECK_EQ(zcio_ws_ping(ws, "pi", 2), ZCIO_OK);

        /* Graceful close: expect the peer to echo code 1000. */
        ZCHECK_EQ(zcio_ws_close(ws, 1000, "bye"), ZCIO_OK);
        ZCHECK_EQ(zcio_ws_close_code(ws), 1000);
        zcio_ws_free(ws);
    }

    zcio_http_server_stop(srv);
    zthread_join(rt);
    if (g_echo_started) zthread_join(g_echo);
    zcio_http_server_free(srv);
}

ZTEST_MAIN()
