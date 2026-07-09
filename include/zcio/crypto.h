/* zcio/crypto.h - minimal crypto primitives for artifact integrity.
 *
 * Self-contained (no OpenSSL or platform TLS dependency), so they are
 * available on every zcio target including mobile builds whose HTTP backends
 * bypass the TLS layer entirely.
 *
 *   - SHA-256: one-shot and streaming (FIPS 180-4).
 *   - Ed25519: keypair / sign / verify (RFC 8032), vendored from orlp/ed25519
 *     (zlib license, see src/vendor/ed25519/). Private keys are the 64-byte
 *     expanded form derived from a 32-byte seed; keep the seed to recreate a
 *     keypair deterministically.
 *   - Hex codec helpers for manifests and CLI plumbing.
 */
#ifndef ZCIO_CRYPTO_H
#define ZCIO_CRYPTO_H

#include "zcio/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------- SHA-256 -------------------------------- */

#define ZCIO_SHA256_LEN 32

typedef struct zcio_sha256_ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} zcio_sha256_ctx;

ZCIO_API void zcio_sha256_init  (zcio_sha256_ctx *c);
ZCIO_API void zcio_sha256_update(zcio_sha256_ctx *c, const void *data, size_t n);
ZCIO_API void zcio_sha256_final (zcio_sha256_ctx *c, uint8_t out[ZCIO_SHA256_LEN]);

/* One-shot convenience. */
ZCIO_API void zcio_sha256(const void *data, size_t n, uint8_t out[ZCIO_SHA256_LEN]);

/* ------------------------------- Ed25519 -------------------------------- */

#define ZCIO_ED25519_PUBKEY_LEN  32
#define ZCIO_ED25519_PRIVKEY_LEN 64  /* expanded; derived from a 32-byte seed */
#define ZCIO_ED25519_SEED_LEN    32
#define ZCIO_ED25519_SIG_LEN     64

/* Fresh keypair from OS entropy. Returns ZCIO_OK or a negated zcio_result
 * (entropy failure). When `seed_out` is non-NULL the generating seed is also
 * returned so the caller may persist it instead of the expanded key. */
ZCIO_API int zcio_ed25519_keypair(uint8_t pub[ZCIO_ED25519_PUBKEY_LEN],
                                  uint8_t priv[ZCIO_ED25519_PRIVKEY_LEN],
                                  uint8_t seed_out[ZCIO_ED25519_SEED_LEN]);

/* Deterministic keypair from a 32-byte seed. */
ZCIO_API void zcio_ed25519_keypair_from_seed(uint8_t pub[ZCIO_ED25519_PUBKEY_LEN],
                                             uint8_t priv[ZCIO_ED25519_PRIVKEY_LEN],
                                             const uint8_t seed[ZCIO_ED25519_SEED_LEN]);

ZCIO_API void zcio_ed25519_sign(uint8_t sig[ZCIO_ED25519_SIG_LEN],
                                const void *msg, size_t n,
                                const uint8_t pub[ZCIO_ED25519_PUBKEY_LEN],
                                const uint8_t priv[ZCIO_ED25519_PRIVKEY_LEN]);

/* 1 = valid, 0 = invalid. */
ZCIO_API int zcio_ed25519_verify(const uint8_t sig[ZCIO_ED25519_SIG_LEN],
                                 const void *msg, size_t n,
                                 const uint8_t pub[ZCIO_ED25519_PUBKEY_LEN]);

/* ------------------------------ hex codec ------------------------------- */

/* Encode n bytes as lowercase hex into out (needs 2n+1 bytes; NUL-terminated). */
ZCIO_API void zcio_hex_encode(const void *data, size_t n, char *out);

/* Decode a hex string (case-insensitive, even length) into out (capacity cap).
 * Returns the decoded byte count, or -1 on malformed input / overflow. */
ZCIO_API int zcio_hex_decode(const char *hex, void *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* ZCIO_CRYPTO_H */
