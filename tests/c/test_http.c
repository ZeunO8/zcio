/* HTTP client coverage against an in-process loopback server (no live network).
 * A pthread runs a tiny zcio TCP server that answers one request with a fixed
 * HTTP/1.1 200 response, then closes the connection so the client sees EOF. */
#include "ztest.h"
#include "zcio/zcio.h"
#include "zthread.h"
#include "internal_port.h"
#include <stdio.h>
#include <time.h>

typedef struct { int port; int ready; int requests; } srv_arg;

static const char *kResponse =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "hello";

/* Answers `requests` successive connections, one canned 200 response each. */
static void *http_server(void *p) {
    srv_arg *a = (srv_arg *)p;
    zcio_tcp_server *srv = zcio_tcp_server_listen(a->port);
    if (!srv) { a->ready = -1; return NULL; }
    a->ready = 1;
    for (int i = 0; i < a->requests; i++) {
        size_t id = 0;
        zcio_tcp_conn *conn = zcio_tcp_server_accept(srv, &id, 4000);
        if (!conn) break;
        zcio_stream *s = zcio_tcp_conn_stream(conn);
        char req[2048];
        zcio_read(s, req, sizeof req);            /* consume the request */
        zcio_write_full(s, kResponse, strlen(kResponse));
        zcio_tcp_server_close_client(srv, id);     /* signal EOF to the client */
    }
    zthread_sleep_ms(50);
    zcio_tcp_server_free(srv);
    return NULL;
}

static void check_ok(zcio_http_response *r) {
    ZCHECK_EQ(r->status, 200);
    ZCHECK(r->headers_json != NULL);
    ZCHECK(r->body != NULL && r->body_size == 5);
    if (r->body) ZCHECK(memcmp(r->body, "hello", 5) == 0);
    zcio_http_response_free(r);
}

ZTEST(http_all_verbs_loopback) {
    zcio_init();
    srv_arg arg = { .port = ztest_free_port(), .ready = 0, .requests = 5 };
    zthread_t th;
    zthread_start(&th, http_server, &arg);
    while (arg.ready == 0) zthread_sleep_ms(2);
    if (arg.ready < 0) { zthread_join(th); ZCHECK(0); return; }

    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%d/", arg.port);

    zcio_http_response g = zcio_http_get(url);            check_ok(&g);
    zcio_http_response p = zcio_http_post(url, "x", 1);   check_ok(&p);
    zcio_http_response u = zcio_http_put(url, "y", 1);    check_ok(&u);
    zcio_http_response d = zcio_http_delete(url);         check_ok(&d);
    zcio_http_header hdr = { .key = "X-Test", .value = "1" };
    zcio_http_response q = zcio_http_request("PATCH", url, &hdr, 1, "z", 1);
    check_ok(&q);

    zthread_join(th);
}

/* Keep-alive server: answers one request with a Content-Length response but
 * holds the connection OPEN for `hold_ms` before closing. The client must
 * frame the response by Content-Length and return immediately — not wait for
 * EOF (the pre-1.3.1 behavior, which stalled until the peer's idle close). */
typedef struct { int port; int ready; int hold_ms; const char *response; } ka_arg;

static void *keepalive_server(void *p) {
    ka_arg *a = (ka_arg *)p;
    zcio_tcp_server *srv = zcio_tcp_server_listen(a->port);
    if (!srv) { a->ready = -1; return NULL; }
    a->ready = 1;
    size_t id = 0;
    zcio_tcp_conn *conn = zcio_tcp_server_accept(srv, &id, 4000);
    if (conn) {
        zcio_stream *s = zcio_tcp_conn_stream(conn);
        char req[2048];
        zcio_read(s, req, sizeof req);
        zcio_write_full(s, a->response, strlen(a->response));
        zthread_sleep_ms(a->hold_ms);              /* keep-alive: no close yet */
        zcio_tcp_server_close_client(srv, id);
    }
    zcio_tcp_server_free(srv);
    return NULL;
}

ZTEST(http_keepalive_content_length) {
    zcio_init();
    ka_arg arg = { .port = ztest_free_port(), .ready = 0, .hold_ms = 8000,
                   .response = kResponse };
    zthread_t th;
    zthread_start(&th, keepalive_server, &arg);
    while (arg.ready == 0) zthread_sleep_ms(2);
    if (arg.ready < 0) { zthread_join(th); ZCHECK(0); return; }

    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%d/", arg.port);

    time_t t0 = time(NULL);
    zcio_http_response g = zcio_http_get(url);
    time_t elapsed = time(NULL) - t0;
    check_ok(&g);
    ZCHECK(elapsed < 4); /* returned on framing, not on the 8 s idle close */
    zthread_join(th);
}

ZTEST(http_chunked_body) {
    zcio_init();
    ka_arg arg = { .port = ztest_free_port(), .ready = 0, .hold_ms = 8000,
                   .response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\r\nhello\r\n"
        "6\r\n worof\r\n"      /* deliberately not 'world' — bytes are opaque */
        "0\r\n\r\n" };
    zthread_t th;
    zthread_start(&th, keepalive_server, &arg);
    while (arg.ready == 0) zthread_sleep_ms(2);
    if (arg.ready < 0) { zthread_join(th); ZCHECK(0); return; }

    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%d/", arg.port);

    time_t t0 = time(NULL);
    zcio_http_response r = zcio_http_get(url);
    time_t elapsed = time(NULL) - t0;
    ZCHECK_EQ(r.status, 200);
    ZCHECK(r.body != NULL && r.body_size == 11);
    if (r.body) ZCHECK(memcmp(r.body, "hello worof", 11) == 0);
    ZCHECK(elapsed < 4);
    zcio_http_response_free(&r);
    zthread_join(th);
}

/* Per-request deadline, stalled mid-body: the server sends headers plus 5 of a
 * promised 100 body bytes, then goes silent while holding the connection. The
 * caller's overall timeout_ms must bound the call — without it the read blocks
 * for the 30 s per-op transport default. */
ZTEST(http_deadline_stalled_body) {
    zcio_init();
    ka_arg arg = { .port = ztest_free_port(), .ready = 0, .hold_ms = 8000,
                   .response =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 100\r\n"
        "\r\n"
        "hello" };
    zthread_t th;
    zthread_start(&th, keepalive_server, &arg);
    while (arg.ready == 0) zthread_sleep_ms(2);
    if (arg.ready < 0) { zthread_join(th); ZCHECK(0); return; }

    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%d/", arg.port);

    zcio_http_opts opts = { .timeout_ms = 500 };
    time_t t0 = time(NULL);
    zcio_http_response r = zcio_http_request_opts("GET", url, NULL, 0, NULL, 0, &opts);
    time_t elapsed = time(NULL) - t0;
    ZCHECK_EQ(r.status, 0);
    ZCHECK(elapsed < 4);
    zcio_http_response_free(&r);
    zthread_join(th);
}

/* Per-request deadline, server never sends a byte after accepting. */
ZTEST(http_deadline_silent_server) {
    zcio_init();
    ka_arg arg = { .port = ztest_free_port(), .ready = 0, .hold_ms = 8000,
                   .response = "" };
    zthread_t th;
    zthread_start(&th, keepalive_server, &arg);
    while (arg.ready == 0) zthread_sleep_ms(2);
    if (arg.ready < 0) { zthread_join(th); ZCHECK(0); return; }

    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%d/", arg.port);

    zcio_http_opts opts = { .connect_timeout_ms = 2000, .timeout_ms = 500 };
    time_t t0 = time(NULL);
    zcio_http_response r = zcio_http_request_opts("GET", url, NULL, 0, NULL, 0, &opts);
    time_t elapsed = time(NULL) - t0;
    ZCHECK_EQ(r.status, 0);
    ZCHECK(elapsed < 4);
    zcio_http_response_free(&r);
    zthread_join(th);
}

/* Multi-request server for session tests: counts distinct ACCEPTED connections
 * (not requests) — a reused keep-alive connection should accept ONCE and serve
 * every request off that same socket. `close_after` requests, the server
 * closes the connection (simulating an idle-timeout/restart) so the NEXT
 * session call must reconnect; 0 = never close early. */
typedef struct {
    int port, ready;
    int requests;       /* total requests to serve before returning */
    int close_after;    /* close the connection after this many requests on it; 0 = don't */
    int accept_count;   /* out: how many distinct TCP connections were accepted */
} sess_arg;

static void *session_server(void *p) {
    sess_arg *a = (sess_arg *)p;
    zcio_tcp_server *srv = zcio_tcp_server_listen(a->port);
    if (!srv) { a->ready = -1; return NULL; }
    a->ready = 1;
    int served = 0;
    while (served < a->requests) {
        size_t id = 0;
        zcio_tcp_conn *conn = zcio_tcp_server_accept(srv, &id, 4000);
        if (!conn) break;
        a->accept_count++;
        zcio_stream *s = zcio_tcp_conn_stream(conn);
        int on_this_conn = 0;
        for (;;) {
            char req[2048];
            int64_t n = zcio_read(s, req, sizeof req);
            if (n <= 0) break;                 /* client dropped the connection */
            zcio_write_full(s, kResponse, strlen(kResponse));
            served++; on_this_conn++;
            if (served >= a->requests) break;
            if (a->close_after > 0 && on_this_conn >= a->close_after) break;
        }
        zcio_tcp_server_close_client(srv, id);
    }
    zthread_sleep_ms(50);
    zcio_tcp_server_free(srv);
    return NULL;
}

/* Three requests over one session must reuse the SAME underlying connection —
 * the server sees exactly one accept, not three. */
ZTEST(http_session_reuses_connection) {
    zcio_init();
    sess_arg arg = { .port = ztest_free_port(), .ready = 0, .requests = 3, .close_after = 0 };
    zthread_t th;
    zthread_start(&th, session_server, &arg);
    while (arg.ready == 0) zthread_sleep_ms(2);
    if (arg.ready < 0) { zthread_join(th); ZCHECK(0); return; }

    char base[64];
    snprintf(base, sizeof base, "http://127.0.0.1:%d", arg.port);
    zcio_http_session *sess = zcio_http_session_create(base);
    ZCHECK(sess != NULL);
    if (!sess) { zthread_join(th); return; }

    for (int i = 0; i < 3; i++) {
        zcio_http_response r = zcio_http_session_request(sess, "GET", "/", NULL, 0, NULL, 0, NULL);
        check_ok(&r);
    }
    zcio_http_session_free(sess);
    zthread_join(th);
    ZCHECK_EQ(arg.accept_count, 1);
}

/* Server closes after the first request (simulating its own idle timeout).
 * The session must transparently reconnect for the second call rather than
 * surfacing a failure — the caller only sees two successful responses, but
 * the server saw two distinct accepts. */
ZTEST(http_session_reconnects_after_server_close) {
    zcio_init();
    sess_arg arg = { .port = ztest_free_port(), .ready = 0, .requests = 2, .close_after = 1 };
    zthread_t th;
    zthread_start(&th, session_server, &arg);
    while (arg.ready == 0) zthread_sleep_ms(2);
    if (arg.ready < 0) { zthread_join(th); ZCHECK(0); return; }

    char base[64];
    snprintf(base, sizeof base, "http://127.0.0.1:%d", arg.port);
    zcio_http_session *sess = zcio_http_session_create(base);
    ZCHECK(sess != NULL);
    if (!sess) { zthread_join(th); return; }

    zcio_http_response r1 = zcio_http_session_request(sess, "GET", "/", NULL, 0, NULL, 0, NULL);
    check_ok(&r1);
    zcio_http_response r2 = zcio_http_session_request(sess, "GET", "/", NULL, 0, NULL, 0, NULL);
    check_ok(&r2);

    zcio_http_session_free(sess);
    zthread_join(th);
    ZCHECK_EQ(arg.accept_count, 2);
}

ZTEST(http_get_bad_host) {
    zcio_init();
    /* unresolvable host: must return a zeroed response (status 0), not crash */
    zcio_http_response r = zcio_http_get("http://no.such.host.invalid.zcio.test./x");
    ZCHECK_EQ(r.status, 0);
    zcio_http_response_free(&r); /* must be safe on the zeroed struct */
}

ZTEST_MAIN()
