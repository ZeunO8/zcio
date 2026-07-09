/* zcio/http.h - minimal synchronous HTTP/1.1 client.
 *
 * Port of http_client/http_common. Builds requests over a zcio TCP (or TLS)
 * connection, parses the response, follows 3xx redirects. Headers are exposed
 * both as a parsed list and as a JSON blob (as the original C API did).
 */
#ifndef ZCIO_HTTP_H
#define ZCIO_HTTP_H

#include "zcio/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zcio_http_header {
    const char *key;
    const char *value;
} zcio_http_header;

typedef struct zcio_http_response {
    const char *protocol;     /* "HTTP" */
    const char *version;      /* "1.1"  */
    const char *status_code;  /* "200"  */
    const char *status_text;  /* "OK"   */
    const char *headers_json; /* {"k":"v",...} */
    const char *body;
    size_t      body_size;
    int32_t     status;       /* parsed integer status, 0 if unknown */
} zcio_http_response;

/* Per-request knobs. Zero-initialize for defaults ({0} == old behavior).
 *   connect_timeout_ms  TCP connect wait. <=0 -> default (15000 ms).
 *   timeout_ms          TOTAL deadline for the whole call -- connect, TLS
 *                       handshake, send, receive, across every redirect hop.
 *                       <=0 -> no overall deadline (per-op transport timeouts
 *                       still apply). On expiry the call fails with
 *                       ZCIO_ERR_TIMEOUT in zcio_last_error(). */
typedef struct zcio_http_opts {
    int connect_timeout_ms;
    int timeout_ms;
} zcio_http_opts;

ZCIO_API zcio_http_response zcio_http_get   (const char *url);
ZCIO_API zcio_http_response zcio_http_delete (const char *url);
ZCIO_API zcio_http_response zcio_http_post  (const char *url, const void *body, size_t n);
ZCIO_API zcio_http_response zcio_http_put   (const char *url, const void *body, size_t n);
ZCIO_API zcio_http_response zcio_http_request(const char *method, const char *url,
                                              const zcio_http_header *headers, size_t header_count,
                                              const void *body, size_t n);
/* zcio_http_request with per-request options. `opts` may be NULL (defaults). */
ZCIO_API zcio_http_response zcio_http_request_opts(const char *method, const char *url,
                                                   const zcio_http_header *headers, size_t header_count,
                                                   const void *body, size_t n,
                                                   const zcio_http_opts *opts);
ZCIO_API void zcio_http_response_free(zcio_http_response *r);

/* ---------------------------- keep-alive session -------------------------- *
 * zcio_http_request[_opts] is one-shot: every call pays a fresh TCP (+TLS)
 * connect. For a caller that repeatedly hits the SAME origin (an exchange's
 * REST API, a metrics endpoint) a session holds ONE persistent HTTP/1.1
 * connection open across calls, only reconnecting when the peer actually
 * closed it (idle timeout, restart) or a call fails outrightly -- one
 * transparent reconnect-and-retry, then the error surfaces normally.
 *
 * NOT internally synchronized: a session is a single logical connection, so
 * concurrent callers must serialize their own access to one zcio_http_session
 * (a mutex around the call site, or one session per thread) exactly as they
 * would around a bare socket. Does not follow redirects (a REST API origin
 * has no business issuing 3xx to begin with; use zcio_http_request_opts for
 * anything that might).
 */
typedef struct zcio_http_session zcio_http_session;

/* Parses `base_url`'s scheme/host/port as the session's fixed origin; every
 * later zcio_http_session_request call's `path` is resolved against it.
 * Returns NULL on a malformed URL or allocation failure. */
ZCIO_API ZCIO_NODISCARD zcio_http_session *zcio_http_session_create(const char *base_url);
ZCIO_API zcio_http_response zcio_http_session_request(zcio_http_session *sess,
                                                       const char *method, const char *path,
                                                       const zcio_http_header *headers, size_t header_count,
                                                       const void *body, size_t n,
                                                       const zcio_http_opts *opts);
ZCIO_API void zcio_http_session_free(zcio_http_session *sess);

#ifdef __cplusplus
}
#endif

#endif /* ZCIO_HTTP_H */
