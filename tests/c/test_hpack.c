/* test_hpack.c - HPACK (RFC 7541) + QPACK (RFC 9204) codec tests.
 *
 * Exercises the internal codecs directly (the target adds -Isrc): prefixed
 * integers (incl. boundary/overflow/truncation), the shared Huffman decoder
 * against the RFC examples and its EOS/padding rejections, full HPACK request
 * blocks with dynamic-table reuse across two decodes on one decoder, and the
 * QPACK static-table decode/encode paths. */
#include "ztest.h"
#include "http_internal.h"

/* ------------------------------ collector -------------------------------- */
/* zhp_emit_fn sink: copies each emitted (name,value) as NUL-terminated text. */
#define MAXH 16
typedef struct {
    char   names[MAXH][128];
    char   vals[MAXH][256];
    size_t n;
} collector;

static int collect(void *u, const char *name, size_t nlen,
                   const char *value, size_t vlen) {
    collector *c = (collector *)u;
    if (c->n >= MAXH) return -1;
    if (nlen >= sizeof c->names[0]) nlen = sizeof c->names[0] - 1;
    if (vlen >= sizeof c->vals[0])  vlen = sizeof c->vals[0] - 1;
    memcpy(c->names[c->n], name, nlen);  c->names[c->n][nlen] = '\0';
    memcpy(c->vals[c->n],  value, vlen); c->vals[c->n][vlen]  = '\0';
    c->n++;
    return 0;
}

/* ============================ prefixed integers ========================== */

static void rt_int(unsigned prefix, uint64_t val) {
    zhs_buf b = {0};
    ZCHECK(zhp_int_encode_(&b, prefix, 0x00, val) == ZCIO_OK);
    uint64_t out = 0;
    int c = zhp_int_decode_(b.data, b.len, prefix, &out);
    ZCHECK_EQ(c, (long long)b.len);   /* consumes exactly the encoded octets */
    ZCHECK_EQ(out, val);
    zhs_buf_free_(&b);
}

ZTEST(int_roundtrip) {
    for (unsigned pfx = 1; pfx <= 8; pfx++) {
        rt_int(pfx, 0);
        rt_int(pfx, 1);
        rt_int(pfx, ((uint64_t)1 << pfx) - 2);  /* just below prefix-max      */
        rt_int(pfx, ((uint64_t)1 << pfx) - 1);  /* == prefix-max: all-ones     */
        rt_int(pfx, ((uint64_t)1 << pfx));       /* one continuation octet      */
        rt_int(pfx, 1337);
        rt_int(pfx, 100000);
        rt_int(pfx, ZHP_INT_MAX);                /* cap boundary (accepted)     */
    }
}

/* RFC 7541 C.1.1 / C.1.2 / C.1.3 wire vectors. */
ZTEST(int_rfc_vectors) {
    uint64_t out = 0;
    /* C.1.1: 10 in a 5-bit prefix -> 0x0a */
    const uint8_t v1[] = { 0x0a };
    ZCHECK_EQ(zhp_int_decode_(v1, sizeof v1, 5, &out), 1);
    ZCHECK_EQ(out, 10);
    /* C.1.2: 1337 in a 5-bit prefix -> 1f 9a 0a */
    const uint8_t v2[] = { 0x1f, 0x9a, 0x0a };
    ZCHECK_EQ(zhp_int_decode_(v2, sizeof v2, 5, &out), 3);
    ZCHECK_EQ(out, 1337);
    /* C.1.3: 42 at an octet boundary (8-bit prefix) -> 0x2a */
    const uint8_t v3[] = { 0x2a };
    ZCHECK_EQ(zhp_int_decode_(v3, sizeof v3, 8, &out), 1);
    ZCHECK_EQ(out, 42);

    /* And the encoder reproduces C.1.2 exactly. */
    zhs_buf b = {0};
    ZCHECK(zhp_int_encode_(&b, 5, 0x00, 1337) == ZCIO_OK);
    ZCHECK_EQ(b.len, 3);
    ZCHECK(b.len == 3 && b.data[0] == 0x1f && b.data[1] == 0x9a && b.data[2] == 0x0a);
    zhs_buf_free_(&b);
}

ZTEST(int_rejects) {
    uint64_t out = 0;
    /* Truncated: prefix-max with no continuation octet. */
    const uint8_t t1[] = { 0xff };                 /* 8-bit prefix all-ones */
    ZCHECK(zhp_int_decode_(t1, sizeof t1, 8, &out) < 0);
    /* Truncated: continuation bit set but the block ends. */
    const uint8_t t2[] = { 0x1f, 0x80 };
    ZCHECK(zhp_int_decode_(t2, sizeof t2, 5, &out) < 0);
    /* Overlong (zero-padded) continuation run. */
    const uint8_t t3[] = { 0x1f, 0x80, 0x80, 0x80, 0x80, 0x80 };
    ZCHECK(zhp_int_decode_(t3, sizeof t3, 5, &out) < 0);
    /* Empty input. */
    ZCHECK(zhp_int_decode_(t1, 0, 7, &out) < 0);

    /* A value one past the cap must be rejected on decode. */
    zhs_buf b = {0};
    ZCHECK(zhp_int_encode_(&b, 5, 0x00, ZHP_INT_MAX + 1) == ZCIO_OK);
    ZCHECK(zhp_int_decode_(b.data, b.len, 5, &out) < 0);
    zhs_buf_free_(&b);
}

/* ================================ Huffman ================================ */

static void huff_ok(const uint8_t *in, size_t n, const char *expect) {
    zhs_buf b = {0};
    int r = zhp_huff_decode_(in, n, &b, 4096);
    ZCHECK_EQ(r, ZCIO_OK);
    ZCHECK_EQ(b.len, (long long)strlen(expect));
    ZCHECK(b.len == strlen(expect) && memcmp(b.data, expect, b.len) == 0);
    zhs_buf_free_(&b);
}

static void huff_bad(const uint8_t *in, size_t n) {
    zhs_buf b = {0};
    ZCHECK(zhp_huff_decode_(in, n, &b, 4096) != ZCIO_OK);
    zhs_buf_free_(&b);
}

ZTEST(huffman_decode) {
    /* RFC 7541 C.4.1 value. */
    const uint8_t www[] = { 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
                            0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    huff_ok(www, sizeof www, "www.example.com");
    /* RFC 7541 C.4.2 value. */
    const uint8_t nc[] = { 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf };
    huff_ok(nc, sizeof nc, "no-cache");
    /* Single symbol '0' (00000) + 3 one-bits of valid padding. */
    const uint8_t zero_pad[] = { 0x07 };
    huff_ok(zero_pad, sizeof zero_pad, "0");
}

ZTEST(huffman_rejects) {
    /* Padding that is not all-ones: '0' (00000) then 000. */
    const uint8_t bad_pad[] = { 0x00 };
    huff_bad(bad_pad, sizeof bad_pad);
    /* Padding longer than 7 bits: '0'+3 one-bits then a whole 0xff octet. */
    const uint8_t long_pad[] = { 0x07, 0xff };
    huff_bad(long_pad, sizeof long_pad);
    /* The EOS symbol (>=30 one-bits) must never decode to a value. */
    const uint8_t eos[] = { 0xff, 0xff, 0xff, 0xff };
    huff_bad(eos, sizeof eos);
}

ZTEST(huffman_max_out) {
    const uint8_t www[] = { 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a,
                            0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    zhs_buf b = {0};
    /* "www.example.com" is 15 bytes; a cap of 5 must be rejected. */
    ZCHECK(zhp_huff_decode_(www, sizeof www, &b, 5) != ZCIO_OK);
    zhs_buf_free_(&b);
}

/* ============================ HPACK block decode ========================= */

ZTEST(hpack_request_c3_dynamic) {
    zhp_dec *d = zhp_dec_new_(ZHP_DEC_TABLE_MAX);
    ZCHECK(d != NULL);
    if (!d) return;

    /* RFC 7541 C.3.1 - first request; inserts :authority into the dyn table. */
    const uint8_t r1[] = {
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
        0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
    };
    collector c1 = {0};
    ZCHECK_EQ(zhp_decode_(d, r1, sizeof r1, 65536, collect, &c1), ZCIO_OK);
    ZCHECK_EQ(c1.n, 4);
    ZCHECK_STR(c1.names[0], ":method");    ZCHECK_STR(c1.vals[0], "GET");
    ZCHECK_STR(c1.names[1], ":scheme");    ZCHECK_STR(c1.vals[1], "http");
    ZCHECK_STR(c1.names[2], ":path");      ZCHECK_STR(c1.vals[2], "/");
    ZCHECK_STR(c1.names[3], ":authority"); ZCHECK_STR(c1.vals[3], "www.example.com");

    /* RFC 7541 C.3.2 - second request on the SAME decoder: 0xbe pulls the
     * :authority entry back out of the dynamic table (index 62). */
    const uint8_t r2[] = {
        0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f,
        0x2d, 0x63, 0x61, 0x63, 0x68, 0x65
    };
    collector c2 = {0};
    ZCHECK_EQ(zhp_decode_(d, r2, sizeof r2, 65536, collect, &c2), ZCIO_OK);
    ZCHECK_EQ(c2.n, 5);
    ZCHECK_STR(c2.names[3], ":authority");    ZCHECK_STR(c2.vals[3], "www.example.com");
    ZCHECK_STR(c2.names[4], "cache-control"); ZCHECK_STR(c2.vals[4], "no-cache");

    zhp_dec_free_(d);
}

ZTEST(hpack_request_c4_huffman) {
    zhp_dec *d = zhp_dec_new_(ZHP_DEC_TABLE_MAX);
    ZCHECK(d != NULL);
    if (!d) return;
    /* RFC 7541 C.4.1 - Huffman-coded :authority value. */
    const uint8_t r[] = {
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5,
        0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff
    };
    collector c = {0};
    ZCHECK_EQ(zhp_decode_(d, r, sizeof r, 65536, collect, &c), ZCIO_OK);
    ZCHECK_EQ(c.n, 4);
    ZCHECK_STR(c.names[3], ":authority"); ZCHECK_STR(c.vals[3], "www.example.com");
    zhp_dec_free_(d);
}

ZTEST(hpack_index_zero_rejected) {
    zhp_dec *d = zhp_dec_new_(ZHP_DEC_TABLE_MAX);
    ZCHECK(d != NULL);
    if (!d) return;
    const uint8_t bad[] = { 0x80 };   /* indexed header field, index 0 */
    collector c = {0};
    ZCHECK(zhp_decode_(d, bad, sizeof bad, 65536, collect, &c) < 0);
    zhp_dec_free_(d);
}

ZTEST(hpack_encode_roundtrip) {
    zhs_buf b = {0};
    ZCHECK(zhp_encode_(&b, "content-type", "text/html") == ZCIO_OK); /* static name ref */
    ZCHECK(zhp_encode_(&b, "x-custom", "abc") == ZCIO_OK);           /* literal name    */
    ZCHECK(zhp_encode_status_(&b, 200) == ZCIO_OK);

    zhp_dec *d = zhp_dec_new_(ZHP_DEC_TABLE_MAX);
    collector c = {0};
    ZCHECK_EQ(zhp_decode_(d, b.data, b.len, 65536, collect, &c), ZCIO_OK);
    ZCHECK_EQ(c.n, 3);
    ZCHECK_STR(c.names[0], "content-type"); ZCHECK_STR(c.vals[0], "text/html");
    ZCHECK_STR(c.names[1], "x-custom");     ZCHECK_STR(c.vals[1], "abc");
    ZCHECK_STR(c.names[2], ":status");      ZCHECK_STR(c.vals[2], "200");
    zhp_dec_free_(d);
    zhs_buf_free_(&b);
}

/* ================================= QPACK ================================= */

ZTEST(qpack_rejects_nonzero_ric) {
    /* Required Insert Count = 1 (nonzero) => protocol error. */
    const uint8_t blk[] = { 0x01, 0x00 };
    collector c = {0};
    ZCHECK(zqp_decode_(blk, sizeof blk, 65536, collect, &c) < 0);
    ZCHECK_EQ(c.n, 0);
}

ZTEST(qpack_static_indexed_line) {
    /* prefix (RIC 0, Base 0) + indexed field line, static index 25 (:status 200). */
    const uint8_t blk[] = { 0x00, 0x00, 0xd9 };
    collector c = {0};
    ZCHECK_EQ(zqp_decode_(blk, sizeof blk, 65536, collect, &c), ZCIO_OK);
    ZCHECK_EQ(c.n, 1);
    ZCHECK_STR(c.names[0], ":status"); ZCHECK_STR(c.vals[0], "200");
}

ZTEST(qpack_literal_static_name_ref) {
    /* prefix + literal-with-name-reference: static name index 1 (:path),
     * T=1, then literal value "/foo". First byte 0x50 | 1 = 0x51. */
    const uint8_t blk[] = { 0x00, 0x00, 0x51, 0x04, '/', 'f', 'o', 'o' };
    collector c = {0};
    ZCHECK_EQ(zqp_decode_(blk, sizeof blk, 65536, collect, &c), ZCIO_OK);
    ZCHECK_EQ(c.n, 1);
    ZCHECK_STR(c.names[0], ":path"); ZCHECK_STR(c.vals[0], "/foo");
}

ZTEST(qpack_rejects_dynamic_ref) {
    /* Indexed field line with T=0 (dynamic table) must be rejected. */
    const uint8_t blk[] = { 0x00, 0x00, 0x80 };   /* 1 T=0 index 0 */
    collector c = {0};
    ZCHECK(zqp_decode_(blk, sizeof blk, 65536, collect, &c) < 0);
}

ZTEST(qpack_encode_roundtrip) {
    zhs_buf b = {0};
    ZCHECK(zqp_prefix_encode_(&b) == ZCIO_OK);
    ZCHECK(zqp_encode_(&b, "content-type", "text/plain") == ZCIO_OK); /* static name */
    ZCHECK(zqp_encode_(&b, "x-custom-header", "value123") == ZCIO_OK);/* literal name */
    ZCHECK(zqp_encode_status_(&b, 200) == ZCIO_OK);                    /* indexed line */
    ZCHECK(zqp_encode_status_(&b, 418) == ZCIO_OK);                    /* name-ref fallback */

    collector c = {0};
    ZCHECK_EQ(zqp_decode_(b.data, b.len, 65536, collect, &c), ZCIO_OK);
    ZCHECK_EQ(c.n, 4);
    ZCHECK_STR(c.names[0], "content-type");    ZCHECK_STR(c.vals[0], "text/plain");
    ZCHECK_STR(c.names[1], "x-custom-header"); ZCHECK_STR(c.vals[1], "value123");
    ZCHECK_STR(c.names[2], ":status");         ZCHECK_STR(c.vals[2], "200");
    ZCHECK_STR(c.names[3], ":status");         ZCHECK_STR(c.vals[3], "418");
    zhs_buf_free_(&b);
}

ZTEST_MAIN()
