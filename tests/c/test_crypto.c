/* SHA-256 (FIPS vectors), Ed25519 (RFC 8032 vector + roundtrip/tamper), and
 * the hex codec. Pure computation — no network. */
#include "ztest.h"
#include "zcio/zcio.h"
#include "zcio/crypto.h"
#include <string.h>

static void expect_hex(const uint8_t *bytes, size_t n, const char *want) {
    char got[2 * 64 + 1];
    zcio_hex_encode(bytes, n, got);
    ZCHECK(strcmp(got, want) == 0);
}

ZTEST(sha256_vectors) {
    uint8_t d[ZCIO_SHA256_LEN];

    zcio_sha256("", 0, d);
    expect_hex(d, sizeof d,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    zcio_sha256("abc", 3, d);
    expect_hex(d, sizeof d,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    zcio_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
    expect_hex(d, sizeof d,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

/* One million 'a' bytes, streamed in ragged chunks — exercises buffering. */
ZTEST(sha256_streaming_million) {
    zcio_sha256_ctx c;
    zcio_sha256_init(&c);
    char chunk[997];
    memset(chunk, 'a', sizeof chunk);
    size_t left = 1000000;
    while (left) {
        size_t take = left < sizeof chunk ? left : sizeof chunk;
        zcio_sha256_update(&c, chunk, take);
        left -= take;
    }
    uint8_t d[ZCIO_SHA256_LEN];
    zcio_sha256_final(&c, d);
    expect_hex(d, sizeof d,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

/* RFC 8032, Ed25519 TEST 1 (empty message). */
ZTEST(ed25519_rfc8032_vector) {
    uint8_t seed[32], want_pub[32], want_sig[64];
    ZCHECK_EQ(zcio_hex_decode(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        seed, sizeof seed), 32);
    ZCHECK_EQ(zcio_hex_decode(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        want_pub, sizeof want_pub), 32);
    ZCHECK_EQ(zcio_hex_decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        want_sig, sizeof want_sig), 64);

    uint8_t pub[32], priv[64], sig[64];
    zcio_ed25519_keypair_from_seed(pub, priv, seed);
    ZCHECK(memcmp(pub, want_pub, 32) == 0);

    zcio_ed25519_sign(sig, "", 0, pub, priv);
    ZCHECK(memcmp(sig, want_sig, 64) == 0);
    ZCHECK_EQ(zcio_ed25519_verify(sig, "", 0, pub), 1);
}

ZTEST(ed25519_roundtrip_and_tamper) {
    uint8_t pub[32], priv[64], seed[32];
    ZCHECK_EQ(zcio_ed25519_keypair(pub, priv, seed), ZCIO_OK);

    /* Seed determinism: rebuilding from the returned seed gives the same key. */
    uint8_t pub2[32], priv2[64];
    zcio_ed25519_keypair_from_seed(pub2, priv2, seed);
    ZCHECK(memcmp(pub, pub2, 32) == 0);

    const char *msg = "the artifact bytes stand in for a shared library";
    uint8_t sig[64];
    zcio_ed25519_sign(sig, msg, strlen(msg), pub, priv);
    ZCHECK_EQ(zcio_ed25519_verify(sig, msg, strlen(msg), pub), 1);

    /* Flip one message byte -> reject. */
    char bad[80];
    snprintf(bad, sizeof bad, "%s", msg);
    bad[3] ^= 1;
    ZCHECK_EQ(zcio_ed25519_verify(sig, bad, strlen(bad), pub), 0);

    /* Flip one signature byte -> reject. */
    sig[10] ^= 1;
    ZCHECK_EQ(zcio_ed25519_verify(sig, msg, strlen(msg), pub), 0);
    sig[10] ^= 1;

    /* Wrong key -> reject. */
    uint8_t pub3[32], priv3[64];
    ZCHECK_EQ(zcio_ed25519_keypair(pub3, priv3, NULL), ZCIO_OK);
    ZCHECK_EQ(zcio_ed25519_verify(sig, msg, strlen(msg), pub3), 0);
}

ZTEST(hex_codec) {
    uint8_t out[8];
    ZCHECK_EQ(zcio_hex_decode("00ff10AB", out, sizeof out), 4);
    ZCHECK(out[0] == 0x00 && out[1] == 0xff && out[2] == 0x10 && out[3] == 0xab);

    char enc[9];
    zcio_hex_encode(out, 4, enc);
    ZCHECK(strcmp(enc, "00ff10ab") == 0);

    ZCHECK_EQ(zcio_hex_decode("abc", out, sizeof out), -1);   /* odd length  */
    ZCHECK_EQ(zcio_hex_decode("zz", out, sizeof out), -1);    /* bad digits  */
    ZCHECK_EQ(zcio_hex_decode("0011223344556677aa", out, sizeof out), -1); /* overflow */
}

ZTEST_MAIN()
