/* Advanced serializer coverage: bit arrays, byte ops, positioning, status
 * flags, count mode, read/write length. Ports serial_advanced_tests.cpp. */
#include "ztest.h"
#include "zcio/zcio.h"

ZTEST(serial_byte_and_bytes) {
    unsigned char buf[64];
    zcio_serial *w = zcio_serial_new_buffer(buf, sizeof buf, false);
    zcio_serial_write_byte(w, 0xAB);
    zcio_serial_write_bytes(w, "raw", 3);
    ZCHECK_EQ(zcio_serial_write_pos(w), 4);
    zcio_serial_free(w);

    zcio_serial *r = zcio_serial_new_buffer(buf, sizeof buf, false);
    ZCHECK_EQ(zcio_serial_read_byte(r), 0xAB);
    char tmp[4] = {0};
    ZCHECK_EQ(zcio_serial_read_bytes(r, tmp, 3), 3);
    ZCHECK_STR(tmp, "raw");
    zcio_serial_free(r);
}

ZTEST(serial_bit_array_roundtrip) {
    /* bit-stream serial over a ring; pack 13 bits then read them back */
    zcio_ring *ring = zcio_ring_new(256, false);
    zcio_stream *s = zcio_ring_as_stream(ring, false);
    uint8_t in[13] = {1,0,1,1, 0,0,1,0, 1,1,1,0, 1};
    zcio_serial *w = zcio_serial_new(s, true, false);
    zcio_serial_write_bits(w, in, 0, 13);
    zcio_serial_synchronize(w);
    zcio_serial_free(w);

    uint8_t out[13] = {0};
    zcio_serial *r = zcio_serial_new(s, true, false);
    zcio_serial_read_bits(r, out, 0, 13);
    for (int i = 0; i < 13; i++) ZCHECK_EQ(out[i], in[i]);
    zcio_serial_free(r);
    zcio_stream_free(s);
    zcio_ring_free(ring);
}

ZTEST(serial_all_scalars) {
    unsigned char buf[128];
    zcio_serial *w = zcio_serial_new_buffer(buf, sizeof buf, false);
    zcio_serial_write_i8(w, -5);   zcio_serial_write_u8(w, 250);
    zcio_serial_write_i16(w, -1000); zcio_serial_write_u16(w, 60000);
    zcio_serial_write_i32(w, -100000); zcio_serial_write_u32(w, 4000000000u);
    zcio_serial_write_i64(w, -9000000000ll); zcio_serial_write_u64(w, 18000000000ull);
    zcio_serial_write_f32(w, 1.5f); zcio_serial_write_f64(w, 3.25);
    zcio_serial_free(w);

    zcio_serial *r = zcio_serial_new_buffer(buf, sizeof buf, false);
    ZCHECK_EQ(zcio_serial_read_i8(r), -5);
    ZCHECK_EQ(zcio_serial_read_u8(r), 250);
    ZCHECK_EQ(zcio_serial_read_i16(r), -1000);
    ZCHECK_EQ(zcio_serial_read_u16(r), 60000);
    ZCHECK_EQ(zcio_serial_read_i32(r), -100000);
    ZCHECK_EQ(zcio_serial_read_u32(r), 4000000000u);
    ZCHECK_EQ(zcio_serial_read_i64(r), -9000000000ll);
    ZCHECK_EQ(zcio_serial_read_u64(r), 18000000000ull);
    ZCHECK(zcio_serial_read_f32(r) == 1.5f);
    ZCHECK(zcio_serial_read_f64(r) == 3.25);
    zcio_serial_free(r);
}

ZTEST(serial_positioning) {
    unsigned char buf[64];
    zcio_serial *w = zcio_serial_new_buffer(buf, sizeof buf, false);
    zcio_serial_write_i32(w, 1);
    zcio_serial_write_i32(w, 2);
    ZCHECK_EQ(zcio_serial_write_pos(w), 8);
    zcio_serial_set_write_pos(w, 0);
    zcio_serial_write_i32(w, 99);
    ZCHECK_EQ(zcio_serial_write_len(w), (int64_t)sizeof buf);
    zcio_serial_free(w);

    zcio_serial *r = zcio_serial_new_buffer(buf, sizeof buf, false);
    ZCHECK_EQ(zcio_serial_read_i32(r), 99);
    ZCHECK_EQ(zcio_serial_read_pos(r), 4);
    zcio_serial_set_read_pos(r, 4);
    ZCHECK_EQ(zcio_serial_read_i32(r), 2);
    ZCHECK_EQ(zcio_serial_read_len(r), (int64_t)sizeof buf);
    zcio_serial_free(r);
}

ZTEST(serial_count_mode_sizing) {
    zcio_serial *c = zcio_serial_new_count();
    zcio_serial_write_i32(c, 0);     /* 4 */
    zcio_serial_write_f64(c, 0.0);   /* 8 */
    zcio_serial_write_str(c, "abc", 3); /* 8 (u64 len) + 3 */
    ZCHECK_EQ(zcio_serial_write_pos(c), 4 + 8 + 8 + 3);
    zcio_serial_free(c);
}

ZTEST(serial_read_status_flags) {
    unsigned char buf[8];
    zcio_serial *w = zcio_serial_new_buffer(buf, sizeof buf, false);
    zcio_serial_write_i16(w, 7);
    zcio_serial_free(w);

    zcio_serial *r = zcio_serial_new_buffer(buf, sizeof buf, false);
    ZCHECK_EQ(zcio_serial_read_i16(r), 7);
    ZCHECK(!zcio_serial_short_read(r));
    char big[100];
    zcio_serial_read_bytes(r, big, sizeof big);  /* overread the 8-byte buffer */
    ZCHECK(zcio_serial_read_eof(r) || zcio_serial_read_empty(r));
    (void)zcio_serial_last_read(r);
    zcio_serial_clear_read(r);
    ZCHECK(!zcio_serial_read_eof(r));
    zcio_serial_free(r);
}

ZTEST_MAIN()
