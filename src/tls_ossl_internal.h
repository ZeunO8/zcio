/* src/tls_ossl_internal.h - OpenSSL-backend internals shared with h3.c.
 * Only meaningful when ZCIO_TLS_OPENSSL is defined. Not installed. */
#ifndef ZCIO_TLS_OSSL_INTERNAL_H
#define ZCIO_TLS_OSSL_INTERNAL_H

#if defined(ZCIO_TLS_OPENSSL)

#include <openssl/ssl.h>

/* Generate a self-signed localhost RSA-2048 certificate (CN=localhost,
 * SAN DNS:localhost,IP:127.0.0.1) and install cert+key on `ssl_ctx`.
 * Returns 1 on success, 0 on failure (OpenSSL error queue populated).
 * Shared by the TLS-over-TCP server context and the QUIC (h3) listener. */
int zcio_ossl_selfsign_install_(SSL_CTX *ssl_ctx);

#endif /* ZCIO_TLS_OPENSSL */

#endif /* ZCIO_TLS_OSSL_INTERNAL_H */
