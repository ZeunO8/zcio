/* src/tls_openssl.c - OpenSSL-backed TLS, layered over a zcio_stream.
 *
 * Compiled ONLY when ZCIO_TLS=openssl. The defining feature of this backend is
 * that TLS records ride over an EXISTING zcio_stream (the plaintext transport),
 * not a raw fd. We do this with a custom OpenSSL BIO whose bread/bwrite call
 * zcio_read/zcio_write on the underlying stream, so TLS composes over any
 * transport (TCP, archive entry, in-memory pipe, ...).
 *
 * Ported from iostreams/src/ssl_factory.cpp (cert generation, file loading) and
 * iostreams/src/tcp_streambuf.cpp (SSL_read/write + WANT_READ/WANT_WRITE loop).
 *
 * Targets OpenSSL 1.1+ and 3.x (BIO_meth_new / SSL_CTX_get0_param exist there).
 */
#include "zcio/tls.h"
#include "internal.h"

#include <limits.h>

#ifndef _WIN32
#include <pthread.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>

/* --- opaque context: a per-role SSL_CTX plus the verify host (client) ------ */
struct zcio_tls_ctx {
    SSL_CTX *ctx;
    char    *host;  /* strdup'd; used for SNI on the client. NULL for server. */
};

/* --- last OpenSSL error -> thread-local message ----------------------------*/
static void tls_set_ossl_error(const char *what) {
    unsigned long e = ERR_get_error();
    char buf[256];
    if (e) {
        ERR_error_string_n(e, buf, sizeof buf);
        zcio_fail_(ZCIO_ERR_TLS, "%s: %s", what, buf);
    } else {
        zcio_fail_(ZCIO_ERR_TLS, "%s", what);
    }
}

/* ===========================================================================
 * Custom BIO that drives I/O through a zcio_stream.
 * ===========================================================================*/

/* Each SSL gets a BIO whose "app data" is the underlying plaintext stream. */
static BIO_METHOD *g_bio_method = NULL;

static int zcio_bio_write(BIO *b, const char *data, int len) {
    zcio_stream *plain = (zcio_stream *)BIO_get_data(b);
    BIO_clear_retry_flags(b);
    if (!plain || len < 0) return -1;
    if (len == 0) return 0;
    int64_t w = zcio_write(plain, data, (size_t)len);
    if (w > 0) return (int)w;
    if (w == ZCIO_ERR_WOULDBLOCK) {
        BIO_set_retry_write(b);
        return -1;
    }
    /* 0 (sink full / closed) or any other error: signal a hard write failure. */
    return -1;
}

static int zcio_bio_read(BIO *b, char *data, int len) {
    zcio_stream *plain = (zcio_stream *)BIO_get_data(b);
    BIO_clear_retry_flags(b);
    if (!plain || len < 0) return -1;
    if (len == 0) return 0;
    int64_t r = zcio_read(plain, data, (size_t)len);
    if (r > 0) return (int)r;
    if (r == 0) return 0; /* EOF: SSL turns this into a clean/dirty shutdown */
    if (r == ZCIO_ERR_WOULDBLOCK) {
        BIO_set_retry_read(b);
        return -1;
    }
    return -1;
}

static long zcio_bio_ctrl(BIO *b, int cmd, long num, void *ptr) {
    (void)b;
    (void)num;
    (void)ptr;
    switch (cmd) {
        case BIO_CTRL_FLUSH:
            return 1; /* nothing buffered here; the stream flushes itself */
        case BIO_CTRL_PUSH:
        case BIO_CTRL_POP:
            return 0;
        default:
            return 0;
    }
}

static int zcio_bio_create(BIO *b) {
    BIO_set_init(b, 1);
    BIO_set_data(b, NULL);
    BIO_set_flags(b, 0);
    return 1;
}

static int zcio_bio_destroy(BIO *b) {
    /* We do NOT own the zcio_stream here; the wrapped stream's destroy() frees
     * the plaintext stream. Just detach. */
    if (b) BIO_set_data(b, NULL);
    return 1;
}

/* Build the BIO method exactly once and publish it in g_bio_method. */
static void zcio_bio_method_init(void) {
    int type = BIO_get_new_index() | BIO_TYPE_SOURCE_SINK;
    BIO_METHOD *m = BIO_meth_new(type, "zcio_stream");
    if (!m) return; /* g_bio_method stays NULL; callers report the failure */
    BIO_meth_set_write(m, zcio_bio_write);
    BIO_meth_set_read(m, zcio_bio_read);
    BIO_meth_set_ctrl(m, zcio_bio_ctrl);
    BIO_meth_set_create(m, zcio_bio_create);
    BIO_meth_set_destroy(m, zcio_bio_destroy);
    g_bio_method = m;
}

static BIO_METHOD *zcio_bio_method(void) {
#ifndef _WIN32
    /* Thread-safe one-time init: avoids a data race / leak when two threads
     * create their first TLS stream concurrently. */
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, zcio_bio_method_init);
#else
    /* Windows fallback: lazy init (matches the original behavior). */
    if (!g_bio_method) zcio_bio_method_init();
#endif
    return g_bio_method;
}

/* ===========================================================================
 * Wrapped TLS stream: vtable + backing state.
 * ===========================================================================*/

typedef struct tls_stream {
    SSL         *ssl;
    BIO         *bio;    /* the zcio_stream BIO; owned by ssl after SSL_set_bio */
    zcio_stream *plain;  /* owned: freed on destroy */
    bool         shut;   /* close_notify already sent; shutdown runs once       */
} tls_stream;

static int64_t tls_strm_read(void *vctx, void *dst, size_t n) {
    tls_stream *t = (tls_stream *)vctx;
    if (n == 0) return 0;
    if (n > INT_MAX) n = INT_MAX;
    for (;;) {
        int r = SSL_read(t->ssl, dst, (int)n);
        if (r > 0) return r;
        int err = SSL_get_error(t->ssl, r);
        switch (err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                /* Underlying BIO is blocking unless the transport returned
                 * WOULDBLOCK; in that case propagate. Loop to retry otherwise. */
                if (BIO_should_retry(t->bio)) continue;
                return ZCIO_ERR_WOULDBLOCK;
            case SSL_ERROR_ZERO_RETURN:
                return 0; /* clean TLS close_notify */
            case SSL_ERROR_SYSCALL:
                if (r == 0) return 0; /* EOF without close_notify */
                return zcio_fail_(ZCIO_ERR_TLS, "SSL_read: transport error");
            default:
                tls_set_ossl_error("SSL_read");
                return ZCIO_ERR_TLS;
        }
    }
}

static int64_t tls_strm_write(void *vctx, const void *src, size_t n) {
    tls_stream *t = (tls_stream *)vctx;
    if (n == 0) return 0;
    if (n > INT_MAX) n = INT_MAX;
    for (;;) {
        int w = SSL_write(t->ssl, src, (int)n);
        if (w > 0) return w;
        int err = SSL_get_error(t->ssl, w);
        switch (err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                if (BIO_should_retry(t->bio)) continue;
                return ZCIO_ERR_WOULDBLOCK;
            case SSL_ERROR_ZERO_RETURN:
                return zcio_fail_(ZCIO_ERR_EOF, "SSL_write: connection closed");
            case SSL_ERROR_SYSCALL:
                return zcio_fail_(ZCIO_ERR_TLS, "SSL_write: transport error");
            default:
                tls_set_ossl_error("SSL_write");
                return ZCIO_ERR_TLS;
        }
    }
}

static int tls_strm_flush(void *vctx) {
    tls_stream *t = (tls_stream *)vctx;
    return zcio_flush(t->plain);
}

static int tls_strm_close(void *vctx) {
    tls_stream *t = (tls_stream *)vctx;
    if (t->ssl && !t->shut) {
        int ret = SSL_shutdown(t->ssl);
        if (ret == 0) SSL_shutdown(t->ssl); /* bidirectional close_notify */
        t->shut = true;
    }
    return zcio_close(t->plain);
}

static void tls_strm_destroy(void *vctx) {
    tls_stream *t = (tls_stream *)vctx;
    if (!t) return;
    if (t->ssl) {
        /* Best-effort close_notify; ignore result during teardown. Skip if
         * tls_strm_close already sent it. */
        if (!t->shut) SSL_shutdown(t->ssl);
        SSL_free(t->ssl); /* also frees the BIO attached via SSL_set_bio */
    }
    if (t->plain) zcio_stream_free(t->plain); /* take ownership of plain */
    free(t);
}

static const zcio_stream_vtable g_tls_vtable = {
    .name    = "tls",
    .read    = tls_strm_read,
    .write   = tls_strm_write,
    .seek    = NULL,
    .flush   = tls_strm_flush,
    .close   = tls_strm_close,
    .destroy = tls_strm_destroy,
    .available = NULL,
    .eof       = NULL,
};

/* ===========================================================================
 * Context creators (ported from ssl_factory.cpp).
 * ===========================================================================*/

static zcio_tls_ctx *ossl_client_ctx(const char *host) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        tls_set_ossl_error("SSL_CTX_new(client)");
        return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(ctx);

    if (host && *host) {
        X509_VERIFY_PARAM *param = SSL_CTX_get0_param(ctx);
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        X509_VERIFY_PARAM_set1_host(param, host, 0);
    }

    zcio_tls_ctx *c = (zcio_tls_ctx *)zcio_xcalloc(1, sizeof *c);
    if (!c) {
        SSL_CTX_free(ctx);
        zcio_fail_(ZCIO_ERR_NOMEM, "out of memory");
        return NULL;
    }
    c->ctx = ctx;
    c->host = zcio_strdup_(host); /* may be NULL; that's fine */
    return c;
}

static zcio_tls_ctx *ossl_server_ctx(void) {
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx) {
        tls_set_ossl_error("SSL_CTX_new(server)");
        return NULL;
    }

    const int kBits = 2048;
    const int kCertDuration = 365;

    RSA       *rsa     = NULL;
    BIGNUM    *bne     = NULL;
    X509      *x509    = NULL;
    EVP_PKEY  *pkey    = NULL;
    int        ok      = 0;
    int        ret;

    bne = BN_new();
    if (!bne) goto cleanup;
    ret = BN_set_word(bne, RSA_F4);
    if (ret != 1) goto cleanup;

    rsa = RSA_new();
    if (!rsa) goto cleanup;
    ret = RSA_generate_key_ex(rsa, kBits, bne, NULL);
    if (ret != 1) goto cleanup;

    pkey = EVP_PKEY_new();
    if (!pkey) goto cleanup;
    if (!EVP_PKEY_assign_RSA(pkey, rsa)) goto cleanup;
    rsa = NULL; /* ownership transferred to pkey */

    x509 = X509_new();
    if (!x509) goto cleanup;
    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 60L * 60 * 24 * kCertDuration);
    X509_set_pubkey(x509, pkey);

    {
        X509_NAME *name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (const unsigned char *)"localhost", -1, -1, 0);
        X509_set_issuer_name(x509, name);
    }

    {
        X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name,
                                                  "DNS:localhost,IP:127.0.0.1");
        if (ext) {
            X509_add_ext(x509, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }

    if (!X509_sign(x509, pkey, EVP_sha256())) goto cleanup;

    if (SSL_CTX_use_certificate(ssl_ctx, x509) != 1 ||
        SSL_CTX_use_PrivateKey(ssl_ctx, pkey) != 1) {
        goto cleanup;
    }
    ok = 1;

cleanup:
    if (bne)  BN_free(bne);
    if (rsa)  RSA_free(rsa);
    if (pkey) EVP_PKEY_free(pkey);
    if (x509) X509_free(x509);

    if (!ok) {
        tls_set_ossl_error("server cert generation");
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    zcio_tls_ctx *c = (zcio_tls_ctx *)zcio_xcalloc(1, sizeof *c);
    if (!c) {
        SSL_CTX_free(ssl_ctx);
        zcio_fail_(ZCIO_ERR_NOMEM, "out of memory");
        return NULL;
    }
    c->ctx = ssl_ctx;
    c->host = NULL;
    return c;
}

static zcio_tls_ctx *ossl_server_ctx_files(const char *cert, const char *key) {
    if (!cert || !key) {
        zcio_fail_(ZCIO_ERR_INVALID_ARG, "cert/key path required");
        return NULL;
    }
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        tls_set_ossl_error("SSL_CTX_new(server)");
        return NULL;
    }
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1) {
        tls_set_ossl_error("load certificate");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        tls_set_ossl_error("load private key");
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        tls_set_ossl_error("private key does not match certificate");
        SSL_CTX_free(ctx);
        return NULL;
    }

    zcio_tls_ctx *c = (zcio_tls_ctx *)zcio_xcalloc(1, sizeof *c);
    if (!c) {
        SSL_CTX_free(ctx);
        zcio_fail_(ZCIO_ERR_NOMEM, "out of memory");
        return NULL;
    }
    c->ctx = ctx;
    c->host = NULL;
    return c;
}

static void ossl_ctx_free(zcio_tls_ctx *ctx) {
    if (!ctx) return;
    if (ctx->ctx) SSL_CTX_free(ctx->ctx);
    free(ctx->host);
    free(ctx);
}

/* ===========================================================================
 * wrap(): build SSL over a custom BIO, handshake, return a TLS stream.
 * ===========================================================================*/

static zcio_stream *ossl_wrap(zcio_tls_ctx *ctx, zcio_stream *plain,
                              bool is_server, bool verify) {
    if (!ctx || !ctx->ctx || !plain) {
        zcio_fail_(ZCIO_ERR_INVALID_ARG, "tls wrap: missing ctx or stream");
        return NULL;
    }

    BIO_METHOD *meth = zcio_bio_method();
    if (!meth) {
        zcio_fail_(ZCIO_ERR_TLS, "BIO_meth_new failed");
        return NULL;
    }

    SSL *ssl = SSL_new(ctx->ctx);
    if (!ssl) {
        tls_set_ossl_error("SSL_new");
        return NULL;
    }

    BIO *bio = BIO_new(meth);
    if (!bio) {
        tls_set_ossl_error("BIO_new");
        SSL_free(ssl);
        return NULL;
    }
    BIO_set_data(bio, plain);
    /* SSL takes ownership of the BIO for both read and write. */
    SSL_set_bio(ssl, bio, bio);

    if (is_server) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
        if (!verify) {
            SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
        }
        if (ctx->host && *ctx->host) {
            /* SNI. Cast away const: the API stores a copy internally in 1.1+.
             * Returns 1 on success; treat failure as fatal so we never proceed
             * without the SNI/verify host the caller asked for. */
            if (SSL_set_tlsext_host_name(ssl, ctx->host) != 1) {
                tls_set_ossl_error("SSL_set_tlsext_host_name");
                SSL_free(ssl); /* frees bio; leaves plain untouched */
                return NULL;
            }
        }
    }

    /* Handshake with WANT_READ/WANT_WRITE retry, mirroring tcp_streambuf.cpp.
     * The underlying transport is expected to block (or report WOULDBLOCK,
     * which surfaces via BIO_should_retry); we loop while it asks to retry. */
    for (;;) {
        int hs = is_server ? SSL_accept(ssl) : SSL_connect(ssl);
        if (hs == 1) break; /* handshake complete */
        int err = SSL_get_error(ssl, hs);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            if (BIO_should_retry(bio)) continue;
            /* Non-blocking transport with nothing pending: cannot complete a
             * synchronous handshake here. Fail rather than spin. */
            zcio_fail_(ZCIO_ERR_TLS, "TLS handshake would block");
            SSL_free(ssl); /* frees bio; does NOT free plain */
            return NULL;
        }
        tls_set_ossl_error(is_server ? "SSL_accept" : "SSL_connect");
        SSL_free(ssl); /* frees bio; leaves plain untouched */
        return NULL;
    }

    /* Defense in depth: for a verifying client, require that the peer chain
     * actually validated. SSL_VERIFY_PEER usually aborts the handshake on
     * failure, but assert X509_V_OK explicitly so a misconfiguration can never
     * yield a "successful" handshake over an unverified peer. */
    if (!is_server && verify) {
        long vr = SSL_get_verify_result(ssl);
        if (vr != X509_V_OK) {
            zcio_fail_(ZCIO_ERR_TLS, "TLS certificate verification failed: %s",
                       X509_verify_cert_error_string(vr));
            SSL_free(ssl); /* frees bio; leaves plain untouched */
            return NULL;
        }
    }

    tls_stream *t = (tls_stream *)zcio_xcalloc(1, sizeof *t);
    if (!t) {
        SSL_free(ssl);
        zcio_fail_(ZCIO_ERR_NOMEM, "out of memory");
        return NULL;
    }
    t->ssl   = ssl;
    t->bio   = bio;
    t->plain = plain; /* ownership transferred on success */

    uint32_t flags = ZCIO_STREAM_OWNS_CTX | ZCIO_STREAM_READABLE | ZCIO_STREAM_WRITABLE;
    zcio_stream *s = zcio_stream_new(&g_tls_vtable, t, flags);
    if (!s) {
        /* Detach plain so it is NOT freed: caller still owns it on failure. */
        t->plain = NULL;
        SSL_free(ssl);
        free(t);
        zcio_fail_(ZCIO_ERR_NOMEM, "out of memory");
        return NULL;
    }
    return s;
}

/* ===========================================================================
 * Backend registration.
 * ===========================================================================*/

static const zcio_tls_backend g_openssl_backend = {
    .name             = "openssl",
    .client_ctx       = ossl_client_ctx,
    .server_ctx       = ossl_server_ctx,
    .server_ctx_files = ossl_server_ctx_files,
    .ctx_free         = ossl_ctx_free,
    .wrap             = ossl_wrap,
};

void zcio_tls_install_default_backend(void) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    /* Pre-1.1 explicit init. 1.1+ initialises lazily and these are no-ops. */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
#else
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                     OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#endif
    zcio_tls_set_backend(&g_openssl_backend);
}
