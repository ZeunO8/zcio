/* src/tls_none.c - the "none" TLS stub backend.
 *
 * Compiled ONLY when no real TLS backend is selected. Every context creator
 * fails with ZCIO_ERR_UNSUPPORTED and wrap() returns NULL, so a build without
 * TLS still links and runs -- attempts to use TLS report a clear error.
 *
 * This TU provides zcio_tls_install_default_backend() (called from zcio_init).
 */
#include "zcio/tls.h"
#include "internal.h"

/* The opaque type still needs a definition somewhere this TU references it; the
 * "none" backend never creates one, so a minimal placeholder suffices. */
struct zcio_tls_ctx {
    int unused;
};

static zcio_tls_ctx *none_client_ctx(const char *host) {
    (void)host;
    zcio_fail_(ZCIO_ERR_UNSUPPORTED, "TLS not compiled in");
    return NULL;
}

static zcio_tls_ctx *none_server_ctx(void) {
    zcio_fail_(ZCIO_ERR_UNSUPPORTED, "TLS not compiled in");
    return NULL;
}

static zcio_tls_ctx *none_server_ctx_files(const char *cert, const char *key) {
    (void)cert;
    (void)key;
    zcio_fail_(ZCIO_ERR_UNSUPPORTED, "TLS not compiled in");
    return NULL;
}

static void none_ctx_free(zcio_tls_ctx *ctx) {
    (void)ctx;
}

static zcio_stream *none_wrap(zcio_tls_ctx *ctx, zcio_stream *plain,
                              bool is_server, bool verify) {
    (void)ctx;
    (void)plain;
    (void)is_server;
    (void)verify;
    zcio_fail_(ZCIO_ERR_UNSUPPORTED, "TLS not compiled in");
    return NULL;
}

static const zcio_tls_backend g_none_backend = {
    .name             = "none",
    .client_ctx       = none_client_ctx,
    .server_ctx       = none_server_ctx,
    .server_ctx_files = none_server_ctx_files,
    .ctx_free         = none_ctx_free,
    .wrap             = none_wrap,
};

void zcio_tls_install_default_backend(void) {
    zcio_tls_set_backend(&g_none_backend);
}
