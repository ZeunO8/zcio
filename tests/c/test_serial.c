/* Port of serial_tests.cpp / serial_advanced_tests.cpp essentials. */
#include "ztest.h"
#include "zcio/zcio.h"

ZTEST(serial_buffer_roundtrip_scalars) {
    unsigned char buf[256];
    zcio_serial *w = zcio_serial_new_buffer(buf, sizeof buf, false);
    zcio_serial_write_i32(w, -12345);
    zcio_serial_write_u64(w, 0xDEADBEEFCAFEull);
    zcio_serial_write_f64(w, 3.14159);
    zcio_serial_free(w);

    zcio_serial *r = zcio_serial_new_buffer(buf, sizeof buf, false);
    ZCHECK_EQ(zcio_serial_read_i32(r), -12345);
    ZCHECK_EQ(zcio_serial_read_u64(r), 0xDEADBEEFCAFEull);
    ZCHECK(zcio_serial_read_f64(r) == 3.14159);
    zcio_serial_free(r);
}

ZTEST(serial_count_mode) {
    zcio_serial *c = zcio_serial_new_count();
    zcio_serial_write_i32(c, 1);
    zcio_serial_write_u8(c, 2);
    zcio_serial_write_f64(c, 2.0);
    ZCHECK_EQ(zcio_serial_write_pos(c), 4 + 1 + 8);
    zcio_serial_free(c);
}

ZTEST(serial_string_roundtrip) {
    unsigned char buf[128];
    zcio_serial *w = zcio_serial_new_buffer(buf, sizeof buf, false);
    const char *msg = "hello zcio";
    zcio_serial_write_str(w, msg, strlen(msg));
    zcio_serial_free(w);

    zcio_serial *r = zcio_serial_new_buffer(buf, sizeof buf, false);
    size_t len = 0;
    char *got = zcio_serial_read_str(r, &len);
    ZCHECK_EQ(len, (long long)strlen(msg));
    ZCHECK_STR(got, msg);
    zcio_free(got);
    zcio_serial_free(r);
}

ZTEST(serial_bitstream_over_ring) {
    zcio_ring *ring = zcio_ring_new(4096, false);
    zcio_stream *s = zcio_ring_as_stream(ring, false);
    zcio_serial *w = zcio_serial_new(s, true, false);
    /* write a known bit pattern */
    bool pattern[12] = {1,0,1,1,0,0,1,0, 1,1,1,0};
    for (int i = 0; i < 12; i++) zcio_serial_write_bit(w, pattern[i]);
    zcio_serial_synchronize(w);
    zcio_serial_free(w);

    zcio_serial *r = zcio_serial_new(s, true, false);
    for (int i = 0; i < 12; i++) {
        ZCHECK_EQ(zcio_serial_read_bit(r) ? 1 : 0, pattern[i] ? 1 : 0);
    }
    zcio_serial_free(r);
    zcio_stream_free(s);
    zcio_ring_free(ring);
}

ZTEST_MAIN()
