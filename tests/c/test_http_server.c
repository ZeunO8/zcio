/* HTTP/1.1 server loopback: start a real non-blocking server on an ephemeral
 * port, run its event loop on a background thread, and drive it with the
 * existing HTTP client (zcio_http_get / zcio_http_request) plus raw TCP for the
 * cases the client can't express (pipelining, a smuggling-style malformed
 * request). Short timeouts keep the test from hanging CI. */
#include "ztest.h"
#include "zcio/zcio.h"
#include "zcio/http_server.h"   /* not pulled in by the umbrella header */
#include "zthread.h"
#include "internal_port.h"
#include <stdio.h>
#include <string.h>

/* Handler: 404 for /notfound, echo the body for POST, otherwise echo
 * "METHOD PATH" so every response body is trivially checkable. */
static void handler(zcio_http_req *req, void *user) {
    (void)user;
    const char *m = zcio_http_req_method(req);
    const char *p = zcio_http_req_path(req);
    if (strcmp(p, "/notfound") == 0) {
        zcio_http_respond(req, 404, NULL, 0, "nope", 4);
        return;
    }
    if (strcmp(m, "POST") == 0) {
        size_t n = 0;
        const void *b = zcio_http_req_body(req, &n);
        zcio_http_respond(req, 200, NULL, 0, b, n);
        return;
    }
    char buf[256];
    int len = snprintf(buf, sizeof buf, "%s %s", m, p);
    zcio_http_respond(req, 200, NULL, 0, buf, (size_t)len);
}

static void *run_thread(void *p) {
    zcio_http_server_run((zcio_http_server *)p);
    return NULL;
}

/* Two keep-alive requests written back-to-back on one connection; both must be
 * answered on the same socket. */
static void check_pipeline(int port) {
    zcio_tcp_client *cli = zcio_tcp_client_connect("127.0.0.1", port);
    ZCHECK(cli != NULL);
    if (!cli) return;
    zcio_stream *s = zcio_tcp_client_stream(cli);

    const char *reqs =
        "GET /a HTTP/1.1\r\nHost: x\r\n\r\n"
        "GET /b HTTP/1.1\r\nHost: x\r\n\r\n";
    int64_t w = zcio_write_full(s, reqs, strlen(reqs));
    ZCHECK_EQ(w, (int64_t)strlen(reqs));

    char buf[4096];
    size_t total = 0;
    bool got_a = false, got_b = false;
    for (int reads = 0; reads < 40 && total < sizeof buf - 1; reads++) {
        int64_t r = zcio_read(s, buf + total, sizeof buf - 1 - total);
        if (r <= 0) break;
        total += (size_t)r;
        buf[total] = '\0';
        got_a = strstr(buf, "GET /a") != NULL;
        got_b = strstr(buf, "GET /b") != NULL;
        if (got_a && got_b) break;   /* stop before an extra blocking read */
    }
    ZCHECK(got_a);
    ZCHECK(got_b);

    int cnt = 0;
    for (const char *q = buf; (q = strstr(q, "HTTP/1.1 200")) != NULL; q += 12) cnt++;
    ZCHECK_EQ(cnt, 2);

    zcio_tcp_client_free(cli);
}

/* Send a raw request and assert the response begins with `expect` (e.g.
 * "HTTP/1.1 400"). These exercise smuggling-style inputs the high-level client
 * cannot express; every one must be rejected and the connection closed. */
static void check_raw_status(int port, const char *raw, const char *expect) {
    zcio_tcp_client *cli = zcio_tcp_client_connect("127.0.0.1", port);
    ZCHECK(cli != NULL);
    if (!cli) return;
    zcio_stream *s = zcio_tcp_client_stream(cli);

    zcio_write_full(s, raw, strlen(raw));

    char buf[1024];
    size_t total = 0;
    for (int reads = 0; reads < 40 && total < sizeof buf - 1; reads++) {
        int64_t r = zcio_read(s, buf + total, sizeof buf - 1 - total);
        if (r <= 0) break;   /* Connection: close -> EOF once the response ships */
        total += (size_t)r;
        buf[total] = '\0';
    }
    size_t el = strlen(expect);
    ZCHECK(total >= el && memcmp(buf, expect, el) == 0);
    zcio_tcp_client_free(cli);
}

ZTEST(http_server_loopback) {
    zcio_init();

    zcio_http_server_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.port            = 0;              /* ephemeral: read back below */
    cfg.versions        = ZCIO_HTTP1_1;
    cfg.idle_timeout_ms = 400;            /* keep-alive conns close quickly */
    cfg.header_timeout_ms = 2000;
    cfg.write_timeout_ms  = 2000;
    cfg.drain_timeout_ms  = 500;

    zcio_http_server *srv = zcio_http_server_start(&cfg, handler, NULL);
    ZCHECK(srv != NULL);
    if (!srv) return;

    int port = zcio_http_server_port(srv);
    ZCHECK(port > 0);

    zthread_t th;
    zthread_start(&th, run_thread, srv);
    zthread_sleep_ms(50);                 /* let the loop reach poll() */

    char url[64], nf[80];
    snprintf(url, sizeof url, "http://127.0.0.1:%d/", port);
    snprintf(nf, sizeof nf, "http://127.0.0.1:%d/notfound", port);

    /* Connection: close makes the client see EOF immediately (no idle wait). */
    zcio_http_header close_hdr = { .key = "Connection", .value = "close" };

    /* Plain GET 200 via zcio_http_get (terminates on the idle-timeout close). */
    {
        zcio_http_response r = zcio_http_get(url);
        ZCHECK_EQ(r.status, 200);
        ZCHECK(r.body && r.body_size == 5 && memcmp(r.body, "GET /", 5) == 0);
        zcio_http_response_free(&r);
    }

    /* Custom 404 status + body. */
    {
        zcio_http_response r = zcio_http_request("GET", nf, &close_hdr, 1, NULL, 0);
        ZCHECK_EQ(r.status, 404);
        ZCHECK(r.body && r.body_size == 4 && memcmp(r.body, "nope", 4) == 0);
        zcio_http_response_free(&r);
    }

    /* HEAD: no body, but the Content-Length of the would-be GET is present. */
    {
        zcio_http_response r = zcio_http_request("HEAD", url, &close_hdr, 1, NULL, 0);
        ZCHECK_EQ(r.status, 200);
        ZCHECK_EQ(r.body_size, 0);
        ZCHECK(r.headers_json &&
               strstr(r.headers_json, "\"content-length\":\"6\"") != NULL);
        zcio_http_response_free(&r);
    }

    /* POST with a body echoed back verbatim. */
    {
        zcio_http_response r = zcio_http_request("POST", url, &close_hdr, 1, "hello", 5);
        ZCHECK_EQ(r.status, 200);
        ZCHECK(r.body && r.body_size == 5 && memcmp(r.body, "hello", 5) == 0);
        zcio_http_response_free(&r);
    }

    check_pipeline(port);
    /* bare-LF request line (no CR) — smuggling vector. */
    check_raw_status(port, "GET / HTTP/1.1\nHost: x\r\n\r\n", "HTTP/1.1 400");
    /* Transfer-Encoding + Content-Length together — request smuggling. */
    check_raw_status(port,
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        "Content-Length: 5\r\n\r\n0\r\n\r\n", "HTTP/1.1 400");
    /* Transfer-Encoding: chunked on HTTP/1.0 — undefined; TE-desync vector. */
    check_raw_status(port,
        "POST / HTTP/1.0\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "HTTP/1.1 400");
    /* Duplicate Content-Length (even identical values) — rejected. */
    check_raw_status(port,
        "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
        "HTTP/1.1 400");

    /* Graceful stop from this (non-loop) thread, then join the loop thread. */
    zcio_http_server_stop(srv);
    zthread_join(th);
    zcio_http_server_free(srv);
}

ZTEST_MAIN()
