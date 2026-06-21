/* Regression tests for the v1.0 hardening fixes. */
#include "ztest.h"
#include "zcio/zcio.h"
#include "internal_port.h"

/* read_str must reject an attacker-controlled oversized length instead of
 * allocating/over-reading. We forge a buffer whose u64 length prefix is huge. */
ZTEST(serial_read_str_rejects_huge_length) {
    unsigned char buf[16] = {0};
    uint64_t huge = 0xFFFFFFFFFFFFFFFFull; /* UINT64_MAX */
    memcpy(buf, &huge, sizeof huge);
    zcio_serial *r = zcio_serial_new_buffer(buf, sizeof buf, false);
    size_t len = 123;
    char *s = zcio_serial_read_str(r, &len);
    ZCHECK(s == NULL); /* rejected, not a multi-exabyte malloc */
    zcio_serial_free(r);

    /* A length that exceeds the remaining buffer is also rejected. */
    unsigned char buf2[16] = {0};
    uint64_t big = 1000000; /* far more than the 8 bytes that remain */
    memcpy(buf2, &big, sizeof big);
    zcio_serial *r2 = zcio_serial_new_buffer(buf2, sizeof buf2, false);
    ZCHECK(zcio_serial_read_str(r2, NULL) == NULL);
    zcio_serial_free(r2);
}

/* Buffer-mode write past capacity must report the honest count (0), not lie. */
ZTEST(serial_buffer_write_overflow_honest) {
    unsigned char buf[4];
    zcio_serial *w = zcio_serial_new_buffer(buf, sizeof buf, false);
    ZCHECK_EQ(zcio_serial_write_bytes(w, "ABCDEFGH", 8), 0); /* doesn't fit -> 0 */
    /* a fitting write still works */
    ZCHECK_EQ(zcio_serial_write_bytes(w, "XY", 2), 2);
    zcio_serial_free(w);
}

/* zcio_copy(limit = SIZE_MAX) must copy until EOF (previously returned 0). */
ZTEST(stream_copy_until_eof) {
    zcio_ring *ring = zcio_ring_new(64, true); /* non-blocking so reads end at EOF */
    zcio_ring_write(ring, "until-eof-copy", 14);
    zcio_stream *src = zcio_ring_as_stream(ring, true);
    char back[32] = {0};
    zcio_stream *dst = zcio_memory_stream(back, sizeof back);
    int64_t n = zcio_copy(dst, src, SIZE_MAX);
    ZCHECK_EQ(n, 14);
    ZCHECK(memcmp(back, "until-eof-copy", 14) == 0);
    zcio_stream_free(dst);
    zcio_stream_free(src);
}

/* SIGPIPE regression: writing to a peer that has closed must return an error,
 * NOT deliver SIGPIPE and kill the process. If the fix regresses, this test
 * crashes with signal 13 instead of failing an assertion. */
ZTEST(tcp_write_to_closed_peer_survives) {
    zcio_init();
    int port = ztest_free_port();
    zcio_tcp_server *srv = zcio_tcp_server_listen(port);
    ZCHECK(srv != NULL);
    if (!srv) return;
    zcio_tcp_client *cli = zcio_tcp_client_connect("127.0.0.1", port);
    ZCHECK(cli != NULL);
    if (!cli) { zcio_tcp_server_free(srv); return; }
    size_t id = 0;
    zcio_tcp_conn *conn = zcio_tcp_server_accept(srv, &id, 2000);
    ZCHECK(conn != NULL);

    /* close the server side entirely so the client's peer is gone */
    zcio_tcp_server_free(srv);

    /* Write repeatedly; one of these hits the dead peer. The point is we are
     * still alive afterward (no SIGPIPE termination) and get a non-positive
     * result on failure. */
    zcio_stream *cs = zcio_tcp_client_stream(cli);
    int64_t last = 1;
    char chunk[4096];
    memset(chunk, 'x', sizeof chunk);
    for (int i = 0; i < 50 && last > 0; i++) last = zcio_write(cs, chunk, sizeof chunk);
    ZCHECK(last <= 0);          /* eventually reported as error/closed */
    ZCHECK(1);                  /* reached here => no SIGPIPE crash */
    zcio_tcp_client_free(cli);
}

ZTEST_MAIN()
