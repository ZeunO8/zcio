/* HTTP client coverage against an in-process loopback server (no live network).
 * A pthread runs a tiny zcio TCP server that answers one request with a fixed
 * HTTP/1.1 200 response, then closes the connection so the client sees EOF. */
#include "ztest.h"
#include "zcio/zcio.h"
#include "internal_port.h"
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>

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
    usleep(50 * 1000);
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
    pthread_t th;
    pthread_create(&th, NULL, http_server, &arg);
    while (arg.ready == 0) usleep(2 * 1000);
    if (arg.ready < 0) { pthread_join(th, NULL); ZCHECK(0); return; }

    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%d/", arg.port);

    zcio_http_response g = zcio_http_get(url);            check_ok(&g);
    zcio_http_response p = zcio_http_post(url, "x", 1);   check_ok(&p);
    zcio_http_response u = zcio_http_put(url, "y", 1);    check_ok(&u);
    zcio_http_response d = zcio_http_delete(url);         check_ok(&d);
    zcio_http_header hdr = { .key = "X-Test", .value = "1" };
    zcio_http_response q = zcio_http_request("PATCH", url, &hdr, 1, "z", 1);
    check_ok(&q);

    pthread_join(th, NULL);
}

ZTEST(http_get_bad_host) {
    zcio_init();
    /* unresolvable host: must return a zeroed response (status 0), not crash */
    zcio_http_response r = zcio_http_get("http://no.such.host.invalid.zcio.test./x");
    ZCHECK_EQ(r.status, 0);
    zcio_http_response_free(&r); /* must be safe on the zeroed struct */
}

ZTEST_MAIN()
