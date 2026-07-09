# Vendored: orlp/ed25519

Source: https://github.com/orlp/ed25519 (zlib license — see license.txt).

Altered from the original distribution (per license clause 2):
- Subset only: `seed.c` (OS entropy — zcio supplies its own via
  `zcio_rand_bytes_`), `add_scalar.c`, and `key_exchange.c` are omitted.
- Compiled with `ED25519_NO_SEED` so the omitted seeder is never declared.

API notes: `private_key` is the 64-byte expanded form produced by
`ed25519_create_keypair` from a 32-byte seed; signatures are 64 bytes,
public keys 32 bytes.
