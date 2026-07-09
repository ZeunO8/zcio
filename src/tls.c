/* src/tls.c - TLS backend registry and dispatch.
 *
 * Always compiled. Holds the single registered backend and forwards the public
 * zcio_tls_* verbs to it. The concrete zcio_tls_ctx struct is private to each
 * backend; this file only ever passes the opaque pointer through.
 *
 * It deliberately does NOT define zcio_tls_install_default_backend(): exactly
 * one selected backend TU (tls_none.c or tls_openssl.c) provides that symbol,
 * which zcio_init() calls to register itself via zcio_tls_set_backend().
 */
#include "zcio/tls.h"
#include "internal.h"

static const zcio_tls_backend *g_backend = NULL;

void zcio_tls_set_backend(const zcio_tls_backend *b) {
    g_backend = b;
}

const zcio_tls_backend *zcio_tls_get_backend(void) {
    return g_backend;
}

bool zcio_tls_available(void) {
    /* A real backend is anything other than the "none" stub. */
    if (!g_backend || !g_backend->name) return false;
    return strcmp(g_backend->name, "none") != 0;
}

const char *zcio_tls_backend_name(void) {
    return (g_backend && g_backend->name) ? g_backend->name : "none";
}

zcio_tls_ctx *zcio_tls_client_ctx(const char *host) {
    if (!g_backend || !g_backend->client_ctx) {
        zcio_fail_(ZCIO_ERR_UNSUPPORTED, "no TLS backend registered");
        return NULL;
    }
    return g_backend->client_ctx(host);
}

zcio_tls_ctx *zcio_tls_server_ctx(void) {
    if (!g_backend || !g_backend->server_ctx) {
        zcio_fail_(ZCIO_ERR_UNSUPPORTED, "no TLS backend registered");
        return NULL;
    }
    return g_backend->server_ctx();
}

zcio_tls_ctx *zcio_tls_server_ctx_files(const char *cert_path, const char *key_path) {
    if (!g_backend || !g_backend->server_ctx_files) {
        zcio_fail_(ZCIO_ERR_UNSUPPORTED, "no TLS backend registered");
        return NULL;
    }
    return g_backend->server_ctx_files(cert_path, key_path);
}

void zcio_tls_ctx_free(zcio_tls_ctx *ctx) {
    if (g_backend && g_backend->ctx_free)
        g_backend->ctx_free(ctx);
}

zcio_stream *zcio_tls_wrap(zcio_tls_ctx *ctx, zcio_stream *plain, bool is_server, bool verify) {
    if (!g_backend || !g_backend->wrap) {
        zcio_fail_(ZCIO_ERR_UNSUPPORTED, "no TLS backend registered");
        return NULL;
    }
    return g_backend->wrap(ctx, plain, is_server, verify);
}

/* --- optional extensions (ALPN / non-blocking handshake) ----------------- */

int zcio_tls_ctx_set_alpn(zcio_tls_ctx *ctx, const char *const *protos, size_t n) {
    if (!g_backend || !g_backend->ctx_set_alpn)
        return zcio_fail_(ZCIO_ERR_UNSUPPORTED, "TLS backend has no ALPN support");
    return g_backend->ctx_set_alpn(ctx, protos, n);
}

zcio_stream *zcio_tls_wrap_nb(zcio_tls_ctx *ctx, zcio_stream *plain,
                              bool is_server, bool verify) {
    if (!g_backend || !g_backend->wrap_nb) {
        zcio_fail_(ZCIO_ERR_UNSUPPORTED, "TLS backend has no non-blocking wrap");
        return NULL;
    }
    return g_backend->wrap_nb(ctx, plain, is_server, verify);
}

int zcio_tls_handshake(zcio_stream *tls) {
    if (!g_backend || !g_backend->handshake)
        return zcio_fail_(ZCIO_ERR_UNSUPPORTED, "TLS backend has no handshake pump");
    return g_backend->handshake(tls);
}

const char *zcio_tls_stream_alpn(zcio_stream *tls) {
    if (!g_backend || !g_backend->stream_alpn) return NULL;
    return g_backend->stream_alpn(tls);
}

/* Set a transport timeout on either a bare socket stream or a TLS overlay
 * (reaching through to its underlying socket stream). Lives here so it can
 * consult the TLS backend without the tcp layer knowing about TLS. */
int zcio_stream_set_timeout_(zcio_stream *s, int timeout_ms) {
    if (zcio_tcp_stream_set_timeout_(s, timeout_ms) == ZCIO_OK)
        return ZCIO_OK;
    if (g_backend && g_backend->stream_transport) {
        zcio_stream *t = g_backend->stream_transport(s);
        if (t) return zcio_tcp_stream_set_timeout_(t, timeout_ms);
    }
    return zcio_fail_(ZCIO_ERR_INVALID_ARG, "set_timeout: unsupported stream");
}
