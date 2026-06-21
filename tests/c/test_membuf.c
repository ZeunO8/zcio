/* Port of streambuf_tests.cpp essentials (memory + counting). */
#include "ztest.h"
#include "zcio/zcio.h"

ZTEST(memory_stream_rw_and_seek) {
    char buf[32];
    zcio_stream *s = zcio_memory_stream(buf, sizeof buf);
    const char *m = "0123456789";
    ZCHECK_EQ(zcio_write(s, m, 10), 10);
    zcio_seek(s, 0, ZCIO_SEEK_SET, ZCIO_SEEK_READ);
    char out[11] = {0};
    ZCHECK_EQ(zcio_read(s, out, 10), 10);
    ZCHECK_STR(out, m);
    /* seek read cursor back to 5 and read the tail */
    zcio_seek(s, 5, ZCIO_SEEK_SET, ZCIO_SEEK_READ);
    char tail[6] = {0};
    ZCHECK_EQ(zcio_read(s, tail, 5), 5);
    ZCHECK_STR(tail, "56789");
    zcio_stream_free(s);
}

ZTEST(memory_stream_bounds) {
    char buf[4];
    zcio_stream *s = zcio_memory_stream(buf, sizeof buf);
    /* write more than capacity -> clamped */
    ZCHECK_EQ(zcio_write(s, "ABCDEFGH", 8), 4);
    zcio_stream_free(s);
}

ZTEST(counting_stream_totals) {
    zcio_stream *s = zcio_counting_stream(NULL, 0);
    zcio_write(s, "hello", 5);
    zcio_write(s, " world", 6);
    ZCHECK_EQ(zcio_counting_bytes_written(s), 11);
    zcio_stream_free(s);
}

ZTEST_MAIN()
