/* zcio/tls.h - pluggable TLS backend.
 *
 * The core has zero TLS dependencies. A backend (OpenSSL by default, or "none")
 * is selected at build time and registered through this interface. A
 * zcio_tls_ctx is an opaque per-role configuration (client or server) that gets
 * handed to the net layer to wrap a socket's zcio_stream in a TLS overlay.
 *
 * Backends implement zcio_tls_backend and install it via zcio_tls_set_backend.
 * Whichever backend the build selects self-registers in zcio_init().
 */
#ifndef ZCIO_TLS_H
#define ZCIO_TLS_H

#include "zcio/types.h"
#include "zcio/stream.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zcio_tls_ctx zcio_tls_ctx;

/* True if a real TLS backend (not the "none" stub) is compiled in. */
ZCIO_API bool        zcio_tls_available(void);
ZCIO_API const char *zcio_tls_backend_name(void);

/* Create a client context that will verify `host` (SNI + cert hostname). */
ZCIO_API ZCIO_NODISCARD zcio_tls_ctx *zcio_tls_client_ctx(const char *host);
/* Server context with a generated self-signed cert (matches ssl_factory). */
ZCIO_API ZCIO_NODISCARD zcio_tls_ctx *zcio_tls_server_ctx(void);
/* Server context from PEM cert/key file paths. */
ZCIO_API ZCIO_NODISCARD zcio_tls_ctx *
zcio_tls_server_ctx_files(const char *cert_path, const char *key_path);
ZCIO_API void zcio_tls_ctx_free(zcio_tls_ctx *ctx);

/* --- backend registration (for implementers / alternative backends) ----- */

/* A TLS backend turns a plaintext byte stream (already-connected socket stream)
 * into an encrypted stream, performing the handshake. `is_server` selects the
 * accept vs connect handshake. `verify` toggles peer verification (client). */
typedef struct zcio_tls_backend {
    const char *name;
    zcio_tls_ctx *(*client_ctx)(const char *host);
    zcio_tls_ctx *(*server_ctx)(void);
    zcio_tls_ctx *(*server_ctx_files)(const char *cert, const char *key);
    void          (*ctx_free)(zcio_tls_ctx *ctx);
    /* Wrap `plain` with TLS using `ctx`. Returns a new stream that owns the
     * handshake/session; on failure returns NULL and leaves `plain` untouched. */
    zcio_stream  *(*wrap)(zcio_tls_ctx *ctx, zcio_stream *plain, bool is_server, bool verify);
} zcio_tls_backend;

ZCIO_API void                    zcio_tls_set_backend(const zcio_tls_backend *b);
ZCIO_API const zcio_tls_backend *zcio_tls_get_backend(void);

/* Wrap a connected plaintext stream in TLS using ctx. Borrows nothing on
 * failure; on success the returned stream takes over `plain`. */
ZCIO_API ZCIO_NODISCARD zcio_stream *
zcio_tls_wrap(zcio_tls_ctx *ctx, zcio_stream *plain, bool is_server, bool verify);

#ifdef __cplusplus
}
#endif

#endif /* ZCIO_TLS_H */
