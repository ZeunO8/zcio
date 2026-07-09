/* Port of tcp_tests.cpp / udp_tests.cpp essentials: loopback round-trips. */
#include "ztest.h"
#include "zcio/zcio.h"

/* Pick a high port unlikely to collide. */
#define TEST_TCP_PORT 39871
#define TEST_UDP_PORT 39872

ZTEST(tcp_loopback_roundtrip) {
    zcio_init();
    zcio_tcp_server *srv = zcio_tcp_server_listen(TEST_TCP_PORT);
    ZCHECK(srv != NULL);
    if (!srv) return;

    zcio_tcp_client *cli = zcio_tcp_client_connect("127.0.0.1", TEST_TCP_PORT);
    ZCHECK(cli != NULL);
    if (!cli) { zcio_tcp_server_free(srv); return; }

    size_t id = 0;
    zcio_tcp_conn *conn = zcio_tcp_server_accept(srv, &id, 2000);
    ZCHECK(conn != NULL);
    if (conn) {
        zcio_stream *cs = zcio_tcp_client_stream(cli);
        zcio_stream *ss = zcio_tcp_conn_stream(conn);
        const char *msg = "ping-zcio";
        ZCHECK_EQ(zcio_write_full(cs, msg, strlen(msg)), (long long)strlen(msg));
        char buf[32] = {0};
        int64_t got = zcio_read_full(ss, buf, strlen(msg));
        ZCHECK_EQ(got, (long long)strlen(msg));
        ZCHECK_STR(buf, msg);
    }
    zcio_tcp_client_free(cli);
    zcio_tcp_server_free(srv);
}

ZTEST(tcp_listen_host_scoped) {
    zcio_init();
    /* Loopback-scoped listener accepts loopback clients. */
    zcio_tcp_server *srv = zcio_tcp_server_listen_host("127.0.0.1", TEST_TCP_PORT + 2);
    ZCHECK(srv != NULL);
    if (srv) {
        zcio_tcp_client *cli = zcio_tcp_client_connect("127.0.0.1", TEST_TCP_PORT + 2);
        ZCHECK(cli != NULL);
        if (cli) {
            size_t id = 0;
            zcio_tcp_conn *conn = zcio_tcp_server_accept(srv, &id, 2000);
            ZCHECK(conn != NULL);
            zcio_tcp_client_free(cli);
        }
        zcio_tcp_server_free(srv);
    }
    /* "localhost" resolves; NULL/"*" keep the INADDR_ANY behavior. */
    zcio_tcp_server *lo = zcio_tcp_server_listen_host("localhost", TEST_TCP_PORT + 3);
    ZCHECK(lo != NULL);
    zcio_tcp_server_free(lo);
    /* Unresolvable bind host fails cleanly. */
    zcio_tcp_server *bad =
        zcio_tcp_server_listen_host("no.such.host.invalid.zcio.test.", TEST_TCP_PORT + 4);
    ZCHECK(bad == NULL);
}

ZTEST(udp_loopback_roundtrip) {
    zcio_init();
    zcio_udp_server *srv = zcio_udp_server_bind(TEST_UDP_PORT);
    ZCHECK(srv != NULL);
    if (!srv) return;
    zcio_udp_client *cli = zcio_udp_client_open("127.0.0.1", TEST_UDP_PORT);
    ZCHECK(cli != NULL);
    if (cli) {
        zcio_stream *cs = zcio_udp_client_stream(cli);
        const char *msg = "udp-hello";
        zcio_write_full(cs, msg, strlen(msg));
        zcio_udp_packet *pkt = zcio_udp_server_receive(srv, false, 1000000);
        ZCHECK(pkt != NULL);
        if (pkt) {
            zcio_stream *ps = zcio_udp_packet_stream(pkt);
            char buf[32] = {0};
            int64_t got = zcio_read(ps, buf, strlen(msg));
            ZCHECK(got > 0);
        }
        zcio_udp_client_free(cli);
    }
    zcio_udp_server_free(srv);
}

ZTEST_MAIN()
