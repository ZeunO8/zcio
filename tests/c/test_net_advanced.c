/* Advanced networking coverage: multiple TCP clients, close_client by id,
 * wait_readable/writable, bytes_available, and UDP multi-peer demux. */
#include "ztest.h"
#include "zcio/zcio.h"
#include "internal_port.h"

ZTEST(tcp_two_clients_and_close) {
    zcio_init();
    int port = ztest_free_port();
    zcio_tcp_server *srv = zcio_tcp_server_listen(port);
    ZCHECK(srv != NULL);
    if (!srv) return;

    zcio_tcp_client *a = zcio_tcp_client_connect("127.0.0.1", port);
    zcio_tcp_client *b = zcio_tcp_client_connect("127.0.0.1", port);
    ZCHECK(a != NULL && b != NULL);

    size_t id_a = 0, id_b = 0;
    zcio_tcp_conn *ca = zcio_tcp_server_accept(srv, &id_a, 2000);
    zcio_tcp_conn *cb = zcio_tcp_server_accept(srv, &id_b, 2000);
    ZCHECK(ca != NULL && cb != NULL);
    ZCHECK(id_a != id_b);

    if (a && ca) {
        zcio_stream *cs = zcio_tcp_client_stream(a);
        zcio_stream *ss = zcio_tcp_conn_stream(ca);
        zcio_write_full(cs, "AAAA", 4);
        ZCHECK(zcio_tcp_conn_wait_readable(ca, 2000) >= 0);
        char buf[5] = {0};
        ZCHECK_EQ(zcio_read_full(ss, buf, 4), 4);
        ZCHECK_STR(buf, "AAAA");
        /* reply on the conn so the client side becomes readable */
        ZCHECK(zcio_tcp_conn_wait_writable(ca, 2000) >= 0);
        zcio_write_full(ss, "ackk", 4);
        ZCHECK(zcio_tcp_client_wait_readable(a, 2000) >= 0);
        char rep[5] = {0};
        ZCHECK_EQ(zcio_read_full(cs, rep, 4), 4);
        ZCHECK_STR(rep, "ackk");
    }

    /* close just client a by id; b must still work */
    ZCHECK_EQ(zcio_tcp_server_close_client(srv, id_a), ZCIO_OK);

    if (b && cb) {
        zcio_stream *cs = zcio_tcp_client_stream(b);
        zcio_stream *ss = zcio_tcp_conn_stream(cb);
        ZCHECK(zcio_tcp_client_wait_writable(b, 2000) >= 0);
        zcio_write_full(cs, "BBBB", 4);
        char buf[5] = {0};
        ZCHECK_EQ(zcio_read_full(ss, buf, 4), 4);
        ZCHECK_STR(buf, "BBBB");
        (void)zcio_tcp_client_bytes_available(b);
    }

    zcio_tcp_client_free(a);
    zcio_tcp_client_free(b);
    zcio_tcp_server_free(srv);
}

ZTEST(udp_two_peers_demux) {
    zcio_init();
    int port = ztest_free_port();
    zcio_udp_server *srv = zcio_udp_server_bind(port);
    ZCHECK(srv != NULL);
    if (!srv) return;

    zcio_udp_client *a = zcio_udp_client_open("127.0.0.1", port);
    zcio_udp_client *b = zcio_udp_client_open("127.0.0.1", port);
    ZCHECK(a != NULL && b != NULL);
    if (a) zcio_write_full(zcio_udp_client_stream(a), "from-a", 6);
    if (b) zcio_write_full(zcio_udp_client_stream(b), "from-b", 6);

    int packets = 0;
    for (int i = 0; i < 4 && packets < 2; i++) {
        zcio_udp_packet *p = zcio_udp_server_receive(srv, false, 1000000);
        if (!p) break;
        char buf[16] = {0};
        int64_t got = zcio_read(zcio_udp_packet_stream(p), buf, sizeof buf);
        if (got >= 6) packets++;
    }
    ZCHECK(packets >= 1); /* at least one datagram demuxed */

    if (a) zcio_udp_client_free(a);
    if (b) zcio_udp_client_free(b);
    zcio_udp_server_free(srv);
}

ZTEST_MAIN()
