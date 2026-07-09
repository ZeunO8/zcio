/* src/crypto.c - SHA-256 (FIPS 180-4) + Ed25519 wrappers + hex codec.
 *
 * SHA-256 is implemented here (compact, byte-oriented). Ed25519 dispatches to
 * the vendored orlp/ed25519 implementation (src/vendor/ed25519/, zlib license)
 * with key material seeded from zcio's OS entropy helper.
 */
#include "zcio/crypto.h"
#include "internal.h"

#include <string.h>

#include "vendor/ed25519/ed25519.h"

/* ------------------------------- SHA-256 -------------------------------- */

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(zcio_sha256_ctx *c, const uint8_t p[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16)
             | ((uint32_t)p[i*4+2] << 8) |  (uint32_t)p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i-15], 7) ^ ROTR(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROTR(w[i-2], 17) ^ ROTR(w[i-2], 19)  ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
    uint32_t e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g;  c->state[7] += h;
}

void zcio_sha256_init(zcio_sha256_ctx *c) {
    c->state[0] = 0x6a09e667; c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372; c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f; c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab; c->state[7] = 0x5be0cd19;
    c->bitlen = 0;
    c->buflen = 0;
}

void zcio_sha256_update(zcio_sha256_ctx *c, const void *data, size_t n) {
    const uint8_t *p = (const uint8_t *)data;
    c->bitlen += (uint64_t)n * 8;
    while (n > 0) {
        size_t take = 64 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        n -= take;
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
}

void zcio_sha256_final(zcio_sha256_ctx *c, uint8_t out[ZCIO_SHA256_LEN]) {
    uint64_t bits = c->bitlen;
    uint8_t pad = 0x80;
    zcio_sha256_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 56)
        zcio_sha256_update(c, &zero, 1);
    uint8_t len[8];
    for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - i * 8));
    /* bypass bitlen accounting for the length block */
    memcpy(c->buf + 56, len, 8);
    sha256_block(c, c->buf);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->state[i] >> 24);
        out[i*4+1] = (uint8_t)(c->state[i] >> 16);
        out[i*4+2] = (uint8_t)(c->state[i] >> 8);
        out[i*4+3] = (uint8_t)(c->state[i]);
    }
    memset(c, 0, sizeof *c);
}

void zcio_sha256(const void *data, size_t n, uint8_t out[ZCIO_SHA256_LEN]) {
    zcio_sha256_ctx c;
    zcio_sha256_init(&c);
    zcio_sha256_update(&c, data, n);
    zcio_sha256_final(&c, out);
}

/* ------------------------------- Ed25519 -------------------------------- */

int zcio_ed25519_keypair(uint8_t pub[ZCIO_ED25519_PUBKEY_LEN],
                         uint8_t priv[ZCIO_ED25519_PRIVKEY_LEN],
                         uint8_t seed_out[ZCIO_ED25519_SEED_LEN]) {
    uint8_t seed[ZCIO_ED25519_SEED_LEN];
    int r = zcio_rand_bytes_(seed, sizeof seed);
    if (r != ZCIO_OK)
        return zcio_fail_(ZCIO_ERR, "ed25519: OS entropy unavailable");
    ed25519_create_keypair(pub, priv, seed);
    if (seed_out) memcpy(seed_out, seed, sizeof seed);
    memset(seed, 0, sizeof seed);
    return ZCIO_OK;
}

void zcio_ed25519_keypair_from_seed(uint8_t pub[ZCIO_ED25519_PUBKEY_LEN],
                                    uint8_t priv[ZCIO_ED25519_PRIVKEY_LEN],
                                    const uint8_t seed[ZCIO_ED25519_SEED_LEN]) {
    ed25519_create_keypair(pub, priv, seed);
}

void zcio_ed25519_sign(uint8_t sig[ZCIO_ED25519_SIG_LEN],
                       const void *msg, size_t n,
                       const uint8_t pub[ZCIO_ED25519_PUBKEY_LEN],
                       const uint8_t priv[ZCIO_ED25519_PRIVKEY_LEN]) {
    ed25519_sign(sig, (const unsigned char *)msg, n, pub, priv);
}

int zcio_ed25519_verify(const uint8_t sig[ZCIO_ED25519_SIG_LEN],
                        const void *msg, size_t n,
                        const uint8_t pub[ZCIO_ED25519_PUBKEY_LEN]) {
    return ed25519_verify(sig, (const unsigned char *)msg, n, pub);
}

/* ------------------------------ hex codec ------------------------------- */

void zcio_hex_encode(const void *data, size_t n, char *out) {
    static const char *d = "0123456789abcdef";
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < n; i++) {
        out[i*2]   = d[p[i] >> 4];
        out[i*2+1] = d[p[i] & 0x0f];
    }
    out[n*2] = '\0';
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int zcio_hex_decode(const char *hex, void *out, size_t cap) {
    if (!hex) return -1;
    size_t len = strlen(hex);
    if (len % 2 != 0 || len / 2 > cap) return -1;
    uint8_t *p = (uint8_t *)out;
    for (size_t i = 0; i < len; i += 2) {
        int hi = hex_nibble(hex[i]), lo = hex_nibble(hex[i+1]);
        if (hi < 0 || lo < 0) return -1;
        p[i/2] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(len / 2);
}
