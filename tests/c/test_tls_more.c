/* TLS backend registry + context coverage beyond the handshake in test_tls.c:
 * available/backend_name, get/set_backend round-trip, and server_ctx_files via
 * an OpenSSL-CLI-generated key/cert (skips if generation is unavailable). */
#include "ztest.h"
#include "zcio/zcio.h"
#include <stdlib.h>
#include <stdio.h>
#if defined(__APPLE__)
#  include <TargetConditionals.h>
#endif

/* system() is marked unavailable in the iOS SDK (and there is no openssl CLI
 * on-device anyway) — resolve to "generation failed" so the skip path fires. */
static int run_cmd(const char *cmd) {
#if defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
    (void)cmd;
    return -1;
#else
    return system(cmd);
#endif
}

ZTEST(tls_backend_registry) {
    zcio_init();
    const zcio_tls_backend *b = zcio_tls_get_backend();
    ZCHECK(b != NULL);
    if (b) {
        ZCHECK(b->name != NULL);
        ZCHECK_STR(zcio_tls_backend_name(), b->name);
        /* set_backend round-trip: re-install the same backend, no change */
        zcio_tls_set_backend(b);
        ZCHECK(zcio_tls_get_backend() == b);
    }
    /* availability matches the build: backend name != "none" */
    if (zcio_tls_available())
        ZCHECK(strcmp(zcio_tls_backend_name(), "none") != 0);
}

ZTEST(tls_server_ctx_files) {
    zcio_init();
    if (!zcio_tls_available()) {
        fprintf(stderr, "  (skipped: TLS not compiled in)\n");
        return;
    }
    const char *key = "/tmp/zcio_test_key.pem";
    const char *crt = "/tmp/zcio_test_cert.pem";
    char cmd[512];
    snprintf(cmd, sizeof cmd,
        "openssl req -x509 -newkey rsa:2048 -nodes -days 1 "
        "-keyout %s -out %s -subj /CN=localhost >/dev/null 2>&1",
        key, crt);
    int rc = run_cmd(cmd);
    FILE *fk = fopen(key, "r");
    FILE *fc = fopen(crt, "r");
    int generated = (rc == 0 && fk && fc);
    if (fk) fclose(fk);
    if (fc) fclose(fc);
    if (!generated) {
        fprintf(stderr, "  (skipped: openssl CLI unavailable to make a cert)\n");
        return;
    }

    zcio_tls_ctx *ctx = zcio_tls_server_ctx_files(crt, key);
    ZCHECK(ctx != NULL);
    if (ctx) zcio_tls_ctx_free(ctx);
    remove(key);
    remove(crt);
}

ZTEST_MAIN()
