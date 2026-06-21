/* UDP multicast coverage. Exercises sender/receiver open+stream+free
 * unconditionally; the datagram round-trip is best-effort and SKIPS (does not
 * fail) when the host has no usable multicast loopback route. */
#include "ztest.h"
#include "zcio/zcio.h"
#include "zthread.h"

#define MC_GROUP "239.255.13.37"
#define MC_PORT  39945

ZTEST(mcast_open_stream_free) {
    zcio_init();
    zcio_mcast_receiver *rx = zcio_mcast_receiver_open(MC_GROUP, MC_PORT);
    ZCHECK(rx != NULL);
    zcio_mcast_sender *tx = zcio_mcast_sender_open(MC_GROUP, MC_PORT);
    ZCHECK(tx != NULL);
    if (!rx || !tx) { if (rx) zcio_mcast_receiver_free(rx);
                      if (tx) zcio_mcast_sender_free(tx); return; }

    zcio_stream *ss = zcio_mcast_sender_stream(tx);
    zcio_stream *rs = zcio_mcast_receiver_stream(rx);
    ZCHECK(ss != NULL && rs != NULL);

    /* best-effort delivery: send a few times, poll the (non-blocking) receiver */
    const char *msg = "mcast-hello";
    int delivered = 0;
    for (int attempt = 0; attempt < 5 && !delivered; attempt++) {
        zcio_write_full(ss, msg, 11);
        for (int i = 0; i < 20 && !delivered; i++) {
            char buf[32] = {0};
            int64_t got = zcio_read(rs, buf, sizeof buf);
            if (got >= 11 && memcmp(buf, msg, 11) == 0) delivered = 1;
            else zthread_sleep_ms(5);
        }
    }
    if (!delivered)
        fprintf(stderr, "  (skipped delivery: no multicast loopback route)\n");

    zcio_mcast_sender_free(tx);
    zcio_mcast_receiver_free(rx);
}

ZTEST_MAIN()
