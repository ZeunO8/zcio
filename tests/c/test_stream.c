/* Generic stream-verb coverage: copy, available, eof, seek, flush, close,
 * name, and the ring-as-stream / counting paths. */
#include "ztest.h"
#include "zcio/zcio.h"

ZTEST(stream_copy_ring_to_memory) {
    zcio_ring *ring = zcio_ring_new(64, false);
    zcio_ring_write(ring, "payload-via-copy", 16);
    zcio_stream *src = zcio_ring_as_stream(ring, true); /* owns ring */

    char back[64] = {0};
    zcio_stream *dst = zcio_memory_stream(back, sizeof back);

    int64_t n = zcio_copy(dst, src, 16);
    ZCHECK_EQ(n, 16);
    ZCHECK(memcmp(back, "payload-via-copy", 16) == 0);

    zcio_stream_free(dst);
    zcio_stream_free(src); /* frees ring */
}

ZTEST(stream_available_and_name) {
    zcio_ring *ring = zcio_ring_new(64, false);
    zcio_stream *s = zcio_ring_as_stream(ring, true);
    ZCHECK_STR(zcio_stream_name(s), "ring");
    zcio_write(s, "abcd", 4);
    ZCHECK_EQ(zcio_available(s), 4);
    ZCHECK(!zcio_stream_eof(s));
    zcio_stream_free(s);
}

ZTEST(stream_seek_and_flush_memory) {
    char buf[16] = {0};
    zcio_stream *s = zcio_memory_stream(buf, sizeof buf);
    zcio_write(s, "0123456789", 10);
    ZCHECK_EQ(zcio_flush(s), ZCIO_OK);
    /* rewind read cursor, read tail half */
    ZCHECK_EQ(zcio_seek(s, 5, ZCIO_SEEK_SET, ZCIO_SEEK_READ), 5);
    char out[6] = {0};
    ZCHECK_EQ(zcio_read(s, out, 5), 5);
    ZCHECK_STR(out, "56789");
    /* cur-relative seek of the write cursor */
    ZCHECK_EQ(zcio_seek(s, 0, ZCIO_SEEK_SET, ZCIO_SEEK_WRITE), 0);
    ZCHECK_EQ(zcio_close(s), ZCIO_OK);
    zcio_stream_free(s);
}

ZTEST(stream_counting_totals) {
    char buf[32];
    zcio_stream *s = zcio_counting_stream(buf, sizeof buf);
    zcio_write(s, "hello", 5);
    zcio_seek(s, 0, ZCIO_SEEK_SET, ZCIO_SEEK_READ);
    char tmp[5];
    zcio_read(s, tmp, 5);
    ZCHECK_EQ(zcio_counting_bytes_written(s), 5);
    ZCHECK_EQ(zcio_counting_bytes_read(s), 5);
    zcio_stream_free(s);
}

ZTEST(stream_ring_header_size_attach) {
    /* exercise zcio_ring_header_size + attach over a shared block */
    size_t hdr = zcio_ring_header_size();
    ZCHECK(hdr > 0);
    size_t total = hdr + 32;
    void *mem = malloc(total);
    zcio_ring *r = zcio_ring_attach(mem, total, false);
    ZCHECK(r != NULL);
    ZCHECK_EQ(zcio_ring_write(r, "hi", 2), 2);
    ZCHECK_EQ(zcio_ring_available_read(r), 2);
    ZCHECK(zcio_ring_available_write(r) > 0);
    zcio_ring_free(r); /* attached: does not free mem */
    free(mem);
}

ZTEST_MAIN()
