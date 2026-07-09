/* src/util.c - error reporting, allocation, init, version. */
#include "zcio/zcio.h"
#include "internal.h"
#include <stdarg.h>
#include <stdatomic.h>

/* Version is single-sourced from CMake (PROJECT_VERSION). The fallbacks keep a
 * non-CMake/IDE compile of this TU building. */
#ifndef ZCIO_VERSION_STR
#  define ZCIO_VERSION_STR "0.0.0"
#endif
#ifndef ZCIO_VER_MAJOR
#  define ZCIO_VER_MAJOR 0
#endif
#ifndef ZCIO_VER_MINOR
#  define ZCIO_VER_MINOR 0
#endif
#ifndef ZCIO_VER_PATCH
#  define ZCIO_VER_PATCH 0
#endif

static ZCIO_THREAD char g_err[512];

void zcio_set_error_(const char *msg) {
    if (!msg) { g_err[0] = '\0'; return; }
    snprintf(g_err, sizeof g_err, "%s", msg);
}

int zcio_fail_(zcio_result code, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_err, sizeof g_err, fmt, ap);
    va_end(ap);
    return (int)code;
}

const char *zcio_last_error(void) { return g_err; }

const char *zcio_result_str(zcio_result r) {
    switch (r) {
        case ZCIO_OK:              return "ok";
        case ZCIO_ERR:             return "error";
        case ZCIO_ERR_INVALID_ARG: return "invalid argument";
        case ZCIO_ERR_CONNECT:     return "connection failed";
        case ZCIO_ERR_TIMEOUT:     return "timed out";
        case ZCIO_ERR_EOF:         return "end of stream";
        case ZCIO_ERR_TLS:         return "tls error";
        case ZCIO_ERR_ARCHIVE:     return "archive error";
        case ZCIO_ERR_NOMEM:       return "out of memory";
        case ZCIO_ERR_UNSUPPORTED: return "unsupported";
        case ZCIO_ERR_WOULDBLOCK:  return "would block";
        case ZCIO_ERR_DNS:         return "dns failure";
        case ZCIO_ERR_PROTOCOL:    return "protocol error";
    }
    return "unknown";
}

char *zcio_strdup_(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

void zcio_free(void *p) { free(p); }

/* --- OS entropy ----------------------------------------------------------- *
 * Used for WebSocket masking keys / handshake nonces (RFC 6455 requires a
 * strong entropy source) without coupling the core to the TLS backend. */
#if defined(_WIN32)
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt.lib")
int zcio_rand_bytes_(void *dst, size_t n) {
    if (!dst && n) return ZCIO_ERR_INVALID_ARG;
    if (BCryptGenRandom(NULL, (PUCHAR)dst, (ULONG)n,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return zcio_fail_(ZCIO_ERR, "BCryptGenRandom failed");
    return ZCIO_OK;
}
#elif defined(__APPLE__) || defined(__ANDROID__) || \
      defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
/* arc4random_buf (<stdlib.h>): kernel-seeded CSPRNG, cannot fail, no per-call
 * size cap. It is the portable choice here: iOS SDKs ship no <sys/random.h>,
 * and bionic declares getentropy only from API 28 while arc4random_buf is
 * available from API 21. */
int zcio_rand_bytes_(void *dst, size_t n) {
    if (!dst && n) return ZCIO_ERR_INVALID_ARG;
    arc4random_buf(dst, n);
    return ZCIO_OK;
}
#else
#  include <unistd.h>
#  include <sys/random.h>   /* glibc 2.25+ / musl 1.1.20+ */
int zcio_rand_bytes_(void *dst, size_t n) {
    if (!dst && n) return ZCIO_ERR_INVALID_ARG;
    uint8_t *p = (uint8_t *)dst;
    while (n > 0) {
        /* getentropy caps a single request at 256 bytes. */
        size_t chunk = n > 256 ? 256 : n;
        if (getentropy(p, chunk) != 0)
            return zcio_fail_(ZCIO_ERR, "getentropy failed");
        p += chunk;
        n -= chunk;
    }
    return ZCIO_OK;
}
#endif

/* --- library init ------------------------------------------------------- */
extern void zcio_tls_install_default_backend(void); /* provided by tls backend TU */

/* Thread-safe one-time init via an atomic state machine, replacing the racy
 * check-then-set. States: 0 = uninit, 1 = in progress, 2 = done. The winner of
 * the CAS runs the body; concurrent callers spin until it reaches DONE. */
enum { ZCIO_INIT_NONE = 0, ZCIO_INIT_BUSY = 1, ZCIO_INIT_DONE = 2 };
static _Atomic int g_init_state = ZCIO_INIT_NONE;

void zcio_init(void) {
    int expected = ZCIO_INIT_NONE;
    if (atomic_compare_exchange_strong_explicit(
            &g_init_state, &expected, ZCIO_INIT_BUSY,
            memory_order_acq_rel, memory_order_acquire)) {
        zcio_socket_startup();
        zcio_tls_install_default_backend();
        atomic_store_explicit(&g_init_state, ZCIO_INIT_DONE, memory_order_release);
        return;
    }
    /* Lost the race (or already done): wait until the winner finishes. */
    while (atomic_load_explicit(&g_init_state, memory_order_acquire) != ZCIO_INIT_DONE)
        ; /* brief spin; init is fast and runs once per process */
}

/* Init is idempotent and process-wide; there is no safe per-call teardown
 * (socket_init owns WSACleanup on Windows), so shutdown is intentionally a
 * no-op here. Left in place for API compatibility. */
void zcio_shutdown(void) { }

const char *zcio_version_string(void) { return ZCIO_VERSION_STR; }
void zcio_version(int *maj, int *min, int *pat) {
    if (maj) *maj = ZCIO_VER_MAJOR;
    if (min) *min = ZCIO_VER_MINOR;
    if (pat) *pat = ZCIO_VER_PATCH;
}
