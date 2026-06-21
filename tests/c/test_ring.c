/* Port of ringbuf_advanced_tests.cpp essentials. */
#include "ztest.h"
#include "zcio/zcio.h"

ZTEST(ring_basic_fifo) {
    zcio_ring *r = zcio_ring_new(64, false);
    const char *msg = "abcdefgh";
    ZCHECK_EQ(zcio_ring_write(r, msg, 8), 8);
    ZCHECK_EQ(zcio_ring_available_read(r), 8);
    char out[8] = {0};
    ZCHECK_EQ(zcio_ring_read(r, out, 8), 8);
    ZCHECK(memcmp(out, msg, 8) == 0);
    ZCHECK_EQ(zcio_ring_available_read(r), 0);
    zcio_ring_free(r);
}

ZTEST(ring_wraparound) {
    zcio_ring *r = zcio_ring_new(16, false);
    char in[10], out[10];
    for (int i = 0; i < 10; i++) in[i] = (char)('A' + i);
    /* push/pop repeatedly to force the head/tail past the wrap point */
    for (int iter = 0; iter < 8; iter++) {
        ZCHECK_EQ(zcio_ring_write(r, in, 10), 10);
        ZCHECK_EQ(zcio_ring_read(r, out, 10), 10);
        ZCHECK(memcmp(in, out, 10) == 0);
    }
    zcio_ring_free(r);
}

ZTEST(ring_nonblocking_partial) {
    zcio_ring *r = zcio_ring_new(8, true); /* capacity 8, 1 reserved -> 7 usable */
    char in[100];
    memset(in, 'x', sizeof in);
    int64_t w = zcio_ring_write(r, in, sizeof in);
    ZCHECK(w > 0 && w < (int64_t)sizeof in); /* couldn't fit all, non-blocking */
    zcio_ring_free(r);
}

ZTEST(ring_as_stream) {
    zcio_ring *ring = zcio_ring_new(128, false);
    zcio_stream *s = zcio_ring_as_stream(ring, true); /* take ownership */
    ZCHECK_STR(zcio_stream_name(s), "ring");
    const char *m = "stream-over-ring";
    ZCHECK_EQ(zcio_write(s, m, strlen(m)), (long long)strlen(m));
    char out[32] = {0};
    ZCHECK_EQ(zcio_read(s, out, strlen(m)), (long long)strlen(m));
    ZCHECK_STR(out, m);
    zcio_stream_free(s); /* frees ring too */
}

ZTEST_MAIN()
