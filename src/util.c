/* src/util.c - error reporting, allocation, init, version. */
#include "zcio/zcio.h"
#include "internal.h"
#include <stdarg.h>

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

/* --- library init ------------------------------------------------------- */
extern void zcio_tls_install_default_backend(void); /* provided by tls backend TU */

static bool g_inited = false;

void zcio_init(void) {
    if (g_inited) return;
    g_inited = true;
    zcio_socket_startup();
    zcio_tls_install_default_backend();
}

void zcio_shutdown(void) { g_inited = false; }

const char *zcio_version_string(void) { return ZCIO_VERSION_STR; }
void zcio_version(int *maj, int *min, int *pat) {
    if (maj) *maj = ZCIO_VER_MAJOR;
    if (min) *min = ZCIO_VER_MINOR;
    if (pat) *pat = ZCIO_VER_PATCH;
}
