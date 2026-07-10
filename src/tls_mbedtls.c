/* src/tls_mbedtls.c - mbedTLS-backed TLS, layered over a zcio_stream.
 *
 * Compiled ONLY when ZCIO_TLS=mbedtls — the mobile-default backend: mbedTLS is
 * pure C, Apache-2.0, CMake-native and cross-compiles cleanly under the
 * Android NDK / iOS toolchains, which is exactly where the OpenSSL backend
 * can't follow (neither OS ships OpenSSL as a public system library).
 *
 * Mirrors tls_openssl.c's structure: TLS records ride over an EXISTING
 * zcio_stream via mbedtls_ssl_set_bio callbacks, so TLS composes over any
 * transport (TCP, in-memory pipe, ...). Semantics intentionally identical —
 * per-op transient errors (ZCIO_ERR_TIMEOUT / ZCIO_ERR_WOULDBLOCK) surface
 * as-is through reads/writes/handshakes rather than looping or hardening
 * into TLS errors.
 *
 * One structural difference from OpenSSL: mbedtls_ssl_config is NOT
 * reference-counted, while zcio's consumers (http.c, ws.c) free the
 * zcio_tls_ctx as soon as the connection is up and keep using the wrapped
 * stream. The ctx therefore carries its own refcount: every wrapped stream
 * holds a reference, and teardown happens when the last holder lets go.
 *
 * Client verification: mbedTLS has no per-connection authmode on the client
 * side, so the config runs VERIFY_OPTIONAL and wrap()'s `verify` flag is
 * enforced post-handshake via mbedtls_ssl_get_verify_result() — the same
 * defense-in-depth check tls_openssl.c does with SSL_get_verify_result().
 *
 * CA roots: unlike OpenSSL there is no set_default_verify_paths(); the
 * client ctx probes $ZCIO_CA_FILE / $ZCIO_CA_PATH, then the well-known
 * bundle locations (macOS /etc/ssl/cert.pem, Debian/RHEL/SUSE bundles,
 * Android's /system/etc/security/cacerts directory).
 */
#include "zcio/tls.h"
#include "internal.h"

#include <limits.h>
#include <stdatomic.h>
#include <string.h>
#include <stdlib.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/net_sockets.h>   /* MBEDTLS_ERR_NET_* (canonical BIO error codes) */
#include <psa/crypto.h>

#ifndef _WIN32
#include <pthread.h>
#else
#include <windows.h>
#endif

/* --- opaque context ------------------------------------------------------ */
struct zcio_tls_ctx {
    mbedtls_ssl_config       conf;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context drbg;
#ifndef _WIN32
    pthread_mutex_t          drbg_lock;
#else
    CRITICAL_SECTION         drbg_lock;
#endif
    bool  is_server;
    char *host;              /* client: SNI + hostname verification target */

    /* server credentials (generated self-signed or loaded from files) */
    mbedtls_x509_crt   srv_cert;
    mbedtls_pk_context srv_key;

    /* client CA roots */
    mbedtls_x509_crt ca;
    bool             ca_loaded;

    /* ALPN: NULL-terminated array of strdup'd strings; mbedtls keeps the
     * pointer for the conf's lifetime, so it lives here. */
    char **alpn;

    /* Streams outlive the caller's ctx handle (http.c frees the ctx right
     * after connect); every wrapped stream holds one reference. */
    atomic_int refs;
};

static void tls_set_mbed_error(const char *what, int ret) {
    char buf[128];
    mbedtls_strerror(ret, buf, sizeof buf);
    zcio_fail_(ZCIO_ERR_TLS, "%s: %s (-0x%04x)", what, buf, (unsigned)-ret);
}

/* drbg is not thread-safe; a server ctx is shared across concurrent accepted
 * handshakes, so serialize it. */
static int locked_drbg_random(void *p, unsigned char *out, size_t n) {
    zcio_tls_ctx *c = (zcio_tls_ctx *)p;
#ifndef _WIN32
    pthread_mutex_lock(&c->drbg_lock);
#else
    EnterCriticalSection(&c->drbg_lock);
#endif
    int r = mbedtls_ctr_drbg_random(&c->drbg, out, n);
#ifndef _WIN32
    pthread_mutex_unlock(&c->drbg_lock);
#else
    LeaveCriticalSection(&c->drbg_lock);
#endif
    return r;
}

/* --- ctx lifecycle ------------------------------------------------------- */

static zcio_tls_ctx *ctx_alloc(bool is_server) {
    zcio_tls_ctx *c = (zcio_tls_ctx *)zcio_xcalloc(1, sizeof *c);
    if (!c) {
        zcio_fail_(ZCIO_ERR_NOMEM, "out of memory");
        return NULL;
    }
    mbedtls_ssl_config_init(&c->conf);
    mbedtls_entropy_init(&c->entropy);
    mbedtls_ctr_drbg_init(&c->drbg);
    mbedtls_x509_crt_init(&c->srv_cert);
    mbedtls_pk_init(&c->srv_key);
    mbedtls_x509_crt_init(&c->ca);
#ifndef _WIN32
    pthread_mutex_init(&c->drbg_lock, NULL);
#else
    InitializeCriticalSection(&c->drbg_lock);
#endif
    c->is_server = is_server;
    atomic_store(&c->refs, 1);

    int ret = mbedtls_ctr_drbg_seed(&c->drbg, mbedtls_entropy_func, &c->entropy,
                                    (const unsigned char *)"zcio-tls", 8);
    if (ret != 0) {
        tls_set_mbed_error("ctr_drbg_seed", ret);
        /* fall through to teardown via unref */
        atomic_store(&c->refs, 1);
        return NULL;
    }
    return c;
}

static void ctx_teardown(zcio_tls_ctx *c) {
    if (c->alpn) {
        for (char **p = c->alpn; *p; p++) free(*p);
        free(c->alpn);
    }
    free(c->host);
    mbedtls_x509_crt_free(&c->ca);
    mbedtls_pk_free(&c->srv_key);
    mbedtls_x509_crt_free(&c->srv_cert);
    mbedtls_ssl_config_free(&c->conf);
    mbedtls_ctr_drbg_free(&c->drbg);
    mbedtls_entropy_free(&c->entropy);
#ifndef _WIN32
    pthread_mutex_destroy(&c->drbg_lock);
#else
    DeleteCriticalSection(&c->drbg_lock);
#endif
    free(c);
}

static void ctx_ref(zcio_tls_ctx *c)   { atomic_fetch_add(&c->refs, 1); }
static void ctx_unref(zcio_tls_ctx *c) {
    if (c && atomic_fetch_sub(&c->refs, 1) == 1) ctx_teardown(c);
}

/* --- default CA roots ---------------------------------------------------- */

/* Returns true if at least one usable root landed in `ca`. parse_file/path
 * return >0 for "N certs failed to parse" with the rest loaded — normal for
 * OS stores that mix formats — so >= 0 counts as success here. */
static bool load_default_cas(mbedtls_x509_crt *ca) {
    const char *env_file = getenv("ZCIO_CA_FILE");
    if (env_file && *env_file && mbedtls_x509_crt_parse_file(ca, env_file) >= 0)
        return true;
    const char *env_path = getenv("ZCIO_CA_PATH");
    if (env_path && *env_path && mbedtls_x509_crt_parse_path(ca, env_path) >= 0)
        return true;

    static const char *bundles[] = {
        "/etc/ssl/cert.pem",                    /* macOS (LibreSSL bundle)   */
        "/etc/ssl/certs/ca-certificates.crt",   /* Debian/Ubuntu/Alpine      */
        "/etc/pki/tls/certs/ca-bundle.crt",     /* RHEL/Fedora               */
        "/etc/ssl/ca-bundle.pem",               /* openSUSE                  */
    };
    for (size_t i = 0; i < sizeof bundles / sizeof bundles[0]; i++)
        if (mbedtls_x509_crt_parse_file(ca, bundles[i]) >= 0)
            return true;

    static const char *dirs[] = {
        "/system/etc/security/cacerts",         /* Android system store      */
        "/etc/ssl/certs",                       /* hashed-PEM directories    */
    };
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++)
        if (mbedtls_x509_crt_parse_path(ca, dirs[i]) >= 0 && ca->version != 0)
            return true;

    return ca->version != 0;
}

/* --- context creators ----------------------------------------------------- */

static zcio_tls_ctx *mtls_client_ctx(const char *host) {
    zcio_tls_ctx *c = ctx_alloc(false);
    if (!c) return NULL;

    int ret = mbedtls_ssl_config_defaults(&c->conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        tls_set_mbed_error("ssl_config_defaults(client)", ret);
        ctx_unref(c);
        return NULL;
    }
    mbedtls_ssl_conf_rng(&c->conf, locked_drbg_random, c);

    /* Per-wrap `verify` needs a per-connection decision, but authmode lives
     * on the shared config — run OPTIONAL and enforce post-handshake (see
     * file header). */
    mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);

    c->ca_loaded = load_default_cas(&c->ca);
    if (c->ca_loaded)
        mbedtls_ssl_conf_ca_chain(&c->conf, &c->ca, NULL);

    c->host = zcio_strdup_(host); /* may be NULL; that's fine */
    return c;
}

/* Generate + install a self-signed localhost cert (ECDSA P-256; mirrors the
 * OpenSSL backend's generated-cert server ctx). */
static int mtls_selfsign_install(zcio_tls_ctx *c) {
    mbedtls_x509write_cert w;
    unsigned char der[2048];
    int ret, ok = 0;

    mbedtls_x509write_crt_init(&w);

    ret = mbedtls_pk_setup(&c->srv_key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) { tls_set_mbed_error("pk_setup", ret); goto out; }
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(c->srv_key),
                              locked_drbg_random, c);
    if (ret != 0) { tls_set_mbed_error("ecp_gen_key", ret); goto out; }

    mbedtls_x509write_crt_set_subject_key(&w, &c->srv_key);
    mbedtls_x509write_crt_set_issuer_key(&w, &c->srv_key);
    if (mbedtls_x509write_crt_set_subject_name(&w, "CN=localhost") != 0 ||
        mbedtls_x509write_crt_set_issuer_name(&w, "CN=localhost") != 0) {
        zcio_fail_(ZCIO_ERR_TLS, "selfsign: set subject/issuer failed");
        goto out;
    }
    mbedtls_x509write_crt_set_md_alg(&w, MBEDTLS_MD_SHA256);
    {
        unsigned char serial[1] = { 1 };
        mbedtls_x509write_crt_set_serial_raw(&w, serial, sizeof serial);
    }
    /* Fixed window (like the OpenSSL backend's 365-day cert, this exists for
     * localhost/require_tls use where the client connects with verify=false;
     * a wide static window keeps generation deterministic and clock-proof). */
    ret = mbedtls_x509write_crt_set_validity(&w, "20240101000000", "20440101000000");
    if (ret != 0) { tls_set_mbed_error("set_validity", ret); goto out; }

    /* SubjectAltName: DNS:localhost + IP:127.0.0.1 (parity with OpenSSL). */
    {
        mbedtls_x509_san_list san_ip, san_dns;
        static const unsigned char loopback[4] = { 127, 0, 0, 1 };
        memset(&san_dns, 0, sizeof san_dns);
        memset(&san_ip, 0, sizeof san_ip);
        san_dns.node.type = MBEDTLS_X509_SAN_DNS_NAME;
        san_dns.node.san.unstructured_name.p   = (unsigned char *)"localhost";
        san_dns.node.san.unstructured_name.len = 9;
        san_dns.next = &san_ip;
        san_ip.node.type = MBEDTLS_X509_SAN_IP_ADDRESS;
        san_ip.node.san.unstructured_name.p   = (unsigned char *)loopback;
        san_ip.node.san.unstructured_name.len = sizeof loopback;
        san_ip.next = NULL;
        ret = mbedtls_x509write_crt_set_subject_alternative_name(&w, &san_dns);
        if (ret != 0) { tls_set_mbed_error("set_subject_alternative_name", ret); goto out; }
    }

    ret = mbedtls_x509write_crt_der(&w, der, sizeof der, locked_drbg_random, c);
    if (ret < 0) { tls_set_mbed_error("x509write_crt_der", ret); goto out; }
    /* mbedtls writes at the END of the buffer; ret is the DER length. */
    ret = mbedtls_x509_crt_parse_der(&c->srv_cert, der + sizeof der - ret, (size_t)ret);
    if (ret != 0) { tls_set_mbed_error("parse own cert", ret); goto out; }

    ok = 1;
out:
    mbedtls_x509write_crt_free(&w);
    return ok;
}

static zcio_tls_ctx *mtls_server_ctx_common(zcio_tls_ctx *c) {
    int ret = mbedtls_ssl_config_defaults(&c->conf, MBEDTLS_SSL_IS_SERVER,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        tls_set_mbed_error("ssl_config_defaults(server)", ret);
        ctx_unref(c);
        return NULL;
    }
    mbedtls_ssl_conf_rng(&c->conf, locked_drbg_random, c);
    mbedtls_ssl_conf_authmode(&c->conf, MBEDTLS_SSL_VERIFY_NONE);

    ret = mbedtls_ssl_conf_own_cert(&c->conf, &c->srv_cert, &c->srv_key);
    if (ret != 0) {
        tls_set_mbed_error("ssl_conf_own_cert", ret);
        ctx_unref(c);
        return NULL;
    }
    return c;
}

static zcio_tls_ctx *mtls_server_ctx(void) {
    zcio_tls_ctx *c = ctx_alloc(true);
    if (!c) return NULL;
    if (!mtls_selfsign_install(c)) {
        ctx_unref(c);
        return NULL;
    }
    return mtls_server_ctx_common(c);
}

static zcio_tls_ctx *mtls_server_ctx_files(const char *cert, const char *key) {
    if (!cert || !key) {
        zcio_fail_(ZCIO_ERR_INVALID_ARG, "cert/key path required");
        return NULL;
    }
    zcio_tls_ctx *c = ctx_alloc(true);
    if (!c) return NULL;

    int ret = mbedtls_x509_crt_parse_file(&c->srv_cert, cert);
    if (ret != 0) {
        tls_set_mbed_error("load certificate", ret);
        ctx_unref(c);
        return NULL;
    }
    ret = mbedtls_pk_parse_keyfile(&c->srv_key, key, NULL, locked_drbg_random, c);
    if (ret != 0) {
        tls_set_mbed_error("load private key", ret);
        ctx_unref(c);
        return NULL;
    }
    return mtls_server_ctx_common(c);
}

static void mtls_ctx_free(zcio_tls_ctx *ctx) {
    ctx_unref(ctx);
}

/* --- ALPN ----------------------------------------------------------------- */

static int mtls_ctx_set_alpn(zcio_tls_ctx *ctx, const char *const *protos, size_t n) {
    if (!ctx || (!protos && n))
        return zcio_fail_(ZCIO_ERR_INVALID_ARG, "alpn: missing ctx/protos");

    char **list = (char **)zcio_xcalloc(n + 1, sizeof *list);
    if (!list) return zcio_fail_(ZCIO_ERR_NOMEM, "alpn: out of memory");
    for (size_t i = 0; i < n; i++) {
        size_t len = protos[i] ? strlen(protos[i]) : 0;
        if (len == 0 || len > 255) {
            for (size_t j = 0; j < i; j++) free(list[j]);
            free(list);
            return zcio_fail_(ZCIO_ERR_INVALID_ARG, "alpn: bad protocol length");
        }
        list[i] = zcio_strdup_(protos[i]);
        if (!list[i]) {
            for (size_t j = 0; j < i; j++) free(list[j]);
            free(list);
            return zcio_fail_(ZCIO_ERR_NOMEM, "alpn: out of memory");
        }
    }

    /* mbedtls stores the array pointer (client: offer; server: preference
     * order, matching the OpenSSL backend's selection semantics). */
    int ret = n ? mbedtls_ssl_conf_alpn_protocols(&ctx->conf, (const char **)list)
                : 0;
    if (ret != 0) {
        for (size_t j = 0; j < n; j++) free(list[j]);
        free(list);
        tls_set_mbed_error("ssl_conf_alpn_protocols", ret);
        return ZCIO_ERR_TLS;
    }

    if (ctx->alpn) {
        for (char **p = ctx->alpn; *p; p++) free(*p);
        free(ctx->alpn);
    }
    ctx->alpn = list;
    return ZCIO_OK;
}

/* ===========================================================================
 * BIO callbacks + wrapped TLS stream.
 * ===========================================================================*/

/* Last transient (retryable) error the BIO saw on THIS thread — same
 * mechanism as tls_openssl.c's g_bio_transient_err (see that file's comment
 * for why timeouts must not loop or harden into TLS errors). */
static ZCIO_THREAD int g_bio_transient_err;

static int mtls_bio_send(void *pctx, const unsigned char *buf, size_t len) {
    zcio_stream *plain = (zcio_stream *)pctx;
    if (!plain) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if (len > INT_MAX) len = INT_MAX;
    int64_t w = zcio_write(plain, buf, len);
    if (w > 0) return (int)w;
    if (w == ZCIO_ERR_WOULDBLOCK || w == ZCIO_ERR_TIMEOUT) {
        g_bio_transient_err = (int)w;
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    return MBEDTLS_ERR_NET_SEND_FAILED;
}

static int mtls_bio_recv(void *pctx, unsigned char *buf, size_t len) {
    zcio_stream *plain = (zcio_stream *)pctx;
    if (!plain) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if (len > INT_MAX) len = INT_MAX;
    int64_t r = zcio_read(plain, buf, len);
    if (r > 0) return (int)r;
    if (r == 0) return 0; /* EOF: surfaces as MBEDTLS_ERR_SSL_CONN_EOF */
    if (r == ZCIO_ERR_WOULDBLOCK || r == ZCIO_ERR_TIMEOUT) {
        g_bio_transient_err = (int)r;
        return MBEDTLS_ERR_SSL_WANT_READ;
    }
    return MBEDTLS_ERR_NET_RECV_FAILED;
}

typedef struct tls_stream {
    mbedtls_ssl_context ssl;
    zcio_tls_ctx *tctx;   /* ref held: the conf must outlive the ssl */
    zcio_stream  *plain;  /* owned: freed on destroy */
    bool          shut;
    bool          verify;
    bool          hs_done;
    char          alpn[32];
} tls_stream;

static int64_t tls_strm_read(void *vctx, void *dst, size_t n) {
    tls_stream *t = (tls_stream *)vctx;
    if (n == 0) return 0;
    if (n > INT_MAX) n = INT_MAX;
    for (;;) {
        g_bio_transient_err = 0;
        int r = mbedtls_ssl_read(&t->ssl, (unsigned char *)dst, n);
        if (r > 0) return r;
        if (r == 0) return 0;
        switch (r) {
            case MBEDTLS_ERR_SSL_WANT_READ:
            case MBEDTLS_ERR_SSL_WANT_WRITE:
                if (g_bio_transient_err) return g_bio_transient_err;
                return ZCIO_ERR_WOULDBLOCK;
#ifdef MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
            case MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET:
                continue; /* TLS 1.3 housekeeping, not app data */
#endif
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                return 0; /* clean TLS close */
            case MBEDTLS_ERR_SSL_CONN_EOF:
                return 0; /* transport EOF without close_notify */
            default:
                tls_set_mbed_error("ssl_read", r);
                return ZCIO_ERR_TLS;
        }
    }
}

static int64_t tls_strm_write(void *vctx, const void *src, size_t n) {
    tls_stream *t = (tls_stream *)vctx;
    if (n == 0) return 0;
    if (n > INT_MAX) n = INT_MAX;
    for (;;) {
        g_bio_transient_err = 0;
        int w = mbedtls_ssl_write(&t->ssl, (const unsigned char *)src, n);
        if (w > 0) return w;
        switch (w) {
            case MBEDTLS_ERR_SSL_WANT_READ:
            case MBEDTLS_ERR_SSL_WANT_WRITE:
                if (g_bio_transient_err) return g_bio_transient_err;
                return ZCIO_ERR_WOULDBLOCK;
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            case MBEDTLS_ERR_SSL_CONN_EOF:
                return zcio_fail_(ZCIO_ERR_EOF, "ssl_write: connection closed");
            default:
                tls_set_mbed_error("ssl_write", w);
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
    if (!t->shut) {
        mbedtls_ssl_close_notify(&t->ssl); /* best effort */
        t->shut = true;
    }
    return zcio_close(t->plain);
}

static void tls_strm_destroy(void *vctx) {
    tls_stream *t = (tls_stream *)vctx;
    if (!t) return;
    if (!t->shut) mbedtls_ssl_close_notify(&t->ssl);
    mbedtls_ssl_free(&t->ssl);
    if (t->plain) zcio_stream_free(t->plain);
    ctx_unref(t->tctx);
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

/* --- wrap ------------------------------------------------------------------*/

static zcio_stream *mtls_make_stream(zcio_tls_ctx *ctx, zcio_stream *plain,
                                     bool is_server, bool verify) {
    if (!ctx || !plain) {
        zcio_fail_(ZCIO_ERR_INVALID_ARG, "tls wrap: missing ctx or stream");
        return NULL;
    }
    if (is_server != ctx->is_server) {
        zcio_fail_(ZCIO_ERR_INVALID_ARG, "tls wrap: role mismatch with ctx");
        return NULL;
    }

    tls_stream *t = (tls_stream *)zcio_xcalloc(1, sizeof *t);
    if (!t) {
        zcio_fail_(ZCIO_ERR_NOMEM, "out of memory");
        return NULL;
    }
    mbedtls_ssl_init(&t->ssl);
    int ret = mbedtls_ssl_setup(&t->ssl, &ctx->conf);
    if (ret != 0) {
        tls_set_mbed_error("ssl_setup", ret);
        mbedtls_ssl_free(&t->ssl);
        free(t);
        return NULL;
    }

    if (!is_server && ctx->host && *ctx->host) {
        /* SNI + hostname verification target (checked via verify_result). */
        ret = mbedtls_ssl_set_hostname(&t->ssl, ctx->host);
        if (ret != 0) {
            tls_set_mbed_error("ssl_set_hostname", ret);
            mbedtls_ssl_free(&t->ssl);
            free(t);
            return NULL;
        }
    }

    mbedtls_ssl_set_bio(&t->ssl, plain, mtls_bio_send, mtls_bio_recv, NULL);

    t->plain  = plain;   /* ownership transferred on success */
    t->tctx   = ctx;
    t->verify = !is_server && verify;
    ctx_ref(ctx);

    uint32_t flags = ZCIO_STREAM_OWNS_CTX | ZCIO_STREAM_READABLE | ZCIO_STREAM_WRITABLE;
    zcio_stream *s = zcio_stream_new(&g_tls_vtable, t, flags);
    if (!s) {
        t->plain = NULL; /* caller keeps ownership on failure */
        ctx_unref(ctx);
        mbedtls_ssl_free(&t->ssl);
        free(t);
        zcio_fail_(ZCIO_ERR_NOMEM, "out of memory");
        return NULL;
    }
    return s;
}

/* Defense in depth (mirrors ossl_post_handshake_check): a verifying client
 * requires a clean verify_result — the config runs VERIFY_OPTIONAL, so this
 * IS the enforcement point, not just a double-check. */
static int mtls_post_handshake_check(tls_stream *t) {
    if (!t->verify) return ZCIO_OK;
    uint32_t vr = mbedtls_ssl_get_verify_result(&t->ssl);
    if (vr != 0) {
        char why[256];
        int n = mbedtls_x509_crt_verify_info(why, sizeof why, "", vr);
        if (n <= 0) why[0] = '\0';
        /* verify_info appends a newline per flag; flatten for the message */
        for (char *p = why; *p; p++)
            if (*p == '\n') *p = ' ';
        return zcio_fail_(ZCIO_ERR_TLS,
                          "TLS certificate verification failed: %s", why);
    }
    return ZCIO_OK;
}

static int mtls_handshake_step(tls_stream *t) {
    if (t->hs_done) return ZCIO_OK;
    g_bio_transient_err = 0;
    int r = mbedtls_ssl_handshake(&t->ssl);
    if (r == 0) {
        int v = mtls_post_handshake_check(t);
        if (v != ZCIO_OK) return v;
        t->hs_done = true;
        return ZCIO_OK;
    }
    if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
        /* Transient transport conditions surface as retryable. */
        return g_bio_transient_err ? g_bio_transient_err : ZCIO_ERR_WOULDBLOCK;
    }
    tls_set_mbed_error("ssl_handshake", r);
    return ZCIO_ERR_TLS;
}

static zcio_stream *mtls_wrap(zcio_tls_ctx *ctx, zcio_stream *plain,
                              bool is_server, bool verify) {
    zcio_stream *s = mtls_make_stream(ctx, plain, is_server, verify);
    if (!s) return NULL;
    tls_stream *t = (tls_stream *)s->ctx;

    /* Blocking handshake: keep pumping while the transport reports transient
     * conditions (per-op timeouts on a blocking socket), same retry policy as
     * the OpenSSL backend's BIO_should_retry loop. A genuinely non-blocking
     * transport (WOULDBLOCK) cannot complete a synchronous handshake. */
    for (;;) {
        int r = mtls_handshake_step(t);
        if (r == ZCIO_OK) break;
        if (r == ZCIO_ERR_TIMEOUT) continue;
        if (r == ZCIO_ERR_WOULDBLOCK)
            zcio_fail_(ZCIO_ERR_TLS, "TLS handshake would block");
        t->plain = NULL; /* caller keeps the plaintext stream on failure */
        zcio_stream_free(s);
        return NULL;
    }
    return s;
}

static zcio_stream *mtls_wrap_nb(zcio_tls_ctx *ctx, zcio_stream *plain,
                                 bool is_server, bool verify) {
    return mtls_make_stream(ctx, plain, is_server, verify);
}

static int mtls_handshake(zcio_stream *s) {
    if (!s || s->vt != &g_tls_vtable || !s->ctx)
        return zcio_fail_(ZCIO_ERR_INVALID_ARG, "tls handshake: not a tls stream");
    return mtls_handshake_step((tls_stream *)s->ctx);
}

static zcio_stream *mtls_stream_transport(zcio_stream *s) {
    if (!s || s->vt != &g_tls_vtable || !s->ctx) return NULL;
    return ((tls_stream *)s->ctx)->plain;
}

static const char *mtls_stream_alpn(zcio_stream *s) {
    if (!s || s->vt != &g_tls_vtable || !s->ctx) return NULL;
    tls_stream *t = (tls_stream *)s->ctx;
    if (!t->hs_done) return NULL;
    if (t->alpn[0]) return t->alpn; /* cached */
    const char *proto = mbedtls_ssl_get_alpn_protocol(&t->ssl);
    if (!proto || !*proto) return NULL;
    size_t len = strlen(proto);
    if (len >= sizeof t->alpn) return NULL;
    memcpy(t->alpn, proto, len + 1);
    return t->alpn;
}

/* ===========================================================================
 * Backend registration.
 * ===========================================================================*/

static const zcio_tls_backend g_mbedtls_backend = {
    .name             = "mbedtls",
    .client_ctx       = mtls_client_ctx,
    .server_ctx       = mtls_server_ctx,
    .server_ctx_files = mtls_server_ctx_files,
    .ctx_free         = mtls_ctx_free,
    .wrap             = mtls_wrap,
    .ctx_set_alpn     = mtls_ctx_set_alpn,
    .wrap_nb          = mtls_wrap_nb,
    .handshake        = mtls_handshake,
    .stream_alpn      = mtls_stream_alpn,
    .stream_transport = mtls_stream_transport,
};

void zcio_tls_install_default_backend(void) {
    /* TLS 1.3 (and USE_PSA_CRYPTO builds generally) require the PSA core to
     * be initialised before the first handshake; idempotent and cheap. */
    psa_crypto_init();
    zcio_tls_set_backend(&g_mbedtls_backend);
}
