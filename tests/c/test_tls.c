/* TLS loopback: self-signed server cert + client (no verify), exchanged over a
 * real socket, driving the custom-BIO-over-zcio_stream handshake in both
 * directions. Skips cleanly when no TLS backend is compiled in. */
#include "ztest.h"
#include "zcio/zcio.h"
#include <pthread.h>
#include <unistd.h>

#define TLS_PORT 39931

typedef struct {
    zcio_tcp_server *srv;
    int ok;
} server_arg;

static void *server_thread(void *p) {
    server_arg *a = (server_arg *)p;
    size_t id = 0;
    zcio_tcp_conn *conn = zcio_tcp_server_accept(a->srv, &id, 4000);
    if (!conn) { a->ok = 0; return NULL; }
    zcio_stream *ss = zcio_tcp_conn_stream(conn);
    char buf[32] = {0};
    int64_t got = zcio_read_full(ss, buf, 5);
    if (got == 5 && memcmp(buf, "hello", 5) == 0) {
        zcio_write_full(ss, "world", 5);
        a->ok = 1;
    } else {
        a->ok = 0;
    }
    return NULL;
}

ZTEST(tls_loopback_roundtrip) {
    zcio_init();
    if (!zcio_tls_available()) {
        fprintf(stderr, "  (skipped: TLS backend is '%s')\n", zcio_tls_backend_name());
        return; /* not a failure */
    }

    zcio_tls_ctx *sctx = zcio_tls_server_ctx();
    ZCHECK(sctx != NULL);
    if (!sctx) return;

    zcio_tcp_server *srv = zcio_tcp_server_listen_tls(TLS_PORT, sctx, false);
    ZCHECK(srv != NULL);
    if (!srv) { zcio_tls_ctx_free(sctx); return; }

    server_arg arg = { .srv = srv, .ok = -1 };
    pthread_t th;
    pthread_create(&th, NULL, server_thread, &arg);

    /* tiny grace so accept() is waiting before we connect */
    usleep(50 * 1000);

    zcio_tls_ctx *cctx = zcio_tls_client_ctx("localhost");
    zcio_tcp_client *cli = zcio_tcp_client_connect_tls("127.0.0.1", TLS_PORT, cctx, false);
    ZCHECK(cli != NULL);
    if (cli) {
        zcio_stream *cs = zcio_tcp_client_stream(cli);
        /* already-secured guard: upgrading an already-TLS client must fail
         * fast (not re-handshake), exercising zcio_tcp_client_tls_upgrade. */
        ZCHECK(zcio_tcp_client_tls_upgrade(cli, cctx) < 0);
        ZCHECK_EQ(zcio_write_full(cs, "hello", 5), 5);
        char buf[8] = {0};
        int64_t got = zcio_read_full(cs, buf, 5);
        ZCHECK_EQ(got, 5);
        ZCHECK_STR(buf, "world");
        zcio_tcp_client_free(cli);
    }

    pthread_join(th, NULL);
    ZCHECK_EQ(arg.ok, 1);

    zcio_tcp_server_free(srv);
    zcio_tls_ctx_free(sctx);
    zcio_tls_ctx_free(cctx);
}

ZTEST_MAIN()
