/* zcio_addon.c - N-API native addon for the zcio C library.
 *
 * Pure C (node_api.h is C-friendly). Binds a practical subset of the zcio ABI:
 *   - version()           -> string
 *   - isIpv4(str)         -> bool
 *   - ring{New,Write,Read,Free,Available}
 *   - bufferSerial + scalar/string ops over a buffer-mode serializer
 *   - httpGet(url)        -> { status, body, headersJson, ... }
 *
 * Opaque pointers are held in napi_external values with finalizers that call the
 * matching zcio_*_free, so JS GC reclaims native resources automatically.
 */
#include <node_api.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "zcio/zcio.h"

/* -------------------------------------------------------------------------- */
/* helpers                                                                    */
/* -------------------------------------------------------------------------- */

#define ZNAPI_CALL(env, call)                                          \
    do {                                                               \
        napi_status _s = (call);                                       \
        if (_s != napi_ok) {                                           \
            const napi_extended_error_info *_e = NULL;                 \
            napi_get_last_error_info((env), &_e);                      \
            const char *_m = (_e && _e->error_message)                 \
                                 ? _e->error_message                   \
                                 : "N-API call failed";                \
            napi_throw_error((env), NULL, _m);                         \
            return NULL;                                               \
        }                                                              \
    } while (0)

static napi_value zthrow(napi_env env, const char *msg) {
    napi_throw_error(env, NULL, msg);
    return NULL;
}

/* read a JS string argument into a freshly malloc'd, NUL-terminated buffer */
static char *get_string_arg(napi_env env, napi_value v) {
    size_t len = 0;
    if (napi_get_value_string_utf8(env, v, NULL, 0, &len) != napi_ok) return NULL;
    char *buf = (char *)malloc(len + 1);
    if (!buf) return NULL;
    if (napi_get_value_string_utf8(env, v, buf, len + 1, &len) != napi_ok) {
        free(buf);
        return NULL;
    }
    return buf;
}

/* -------------------------------------------------------------------------- */
/* version() -> string                                                        */
/* -------------------------------------------------------------------------- */
static napi_value fn_version(napi_env env, napi_callback_info info) {
    (void)info;
    const char *v = zcio_version_string();
    napi_value out;
    ZNAPI_CALL(env, napi_create_string_utf8(env, v ? v : "", NAPI_AUTO_LENGTH, &out));
    return out;
}

/* -------------------------------------------------------------------------- */
/* isIpv4(str) -> bool                                                        */
/* -------------------------------------------------------------------------- */
static napi_value fn_is_ipv4(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "isIpv4(str) requires 1 argument");

    char *s = get_string_arg(env, argv[0]);
    if (!s) return zthrow(env, "isIpv4: expected a string argument");
    bool r = zcio_is_ipv4(s);
    free(s);

    napi_value out;
    ZNAPI_CALL(env, napi_get_boolean(env, r, &out));
    return out;
}

/* -------------------------------------------------------------------------- */
/* ring                                                                       */
/* -------------------------------------------------------------------------- */
static void ring_finalize(napi_env env, void *data, void *hint) {
    (void)env;
    (void)hint;
    if (data) zcio_ring_free((zcio_ring *)data);
}

/* ringNew(capacity[, nonBlocking]) -> external handle */
static napi_value fn_ring_new(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "ringNew(capacity) requires a capacity");

    int64_t cap = 0;
    ZNAPI_CALL(env, napi_get_value_int64(env, argv[0], &cap));
    if (cap <= 0) return zthrow(env, "ringNew: capacity must be > 0");

    bool non_blocking = true;
    if (argc >= 2) {
        napi_valuetype t;
        ZNAPI_CALL(env, napi_typeof(env, argv[1], &t));
        if (t == napi_boolean) ZNAPI_CALL(env, napi_get_value_bool(env, argv[1], &non_blocking));
    }

    zcio_ring *r = zcio_ring_new((size_t)cap, non_blocking);
    if (!r) return zthrow(env, "ringNew: zcio_ring_new failed");

    napi_value ext;
    ZNAPI_CALL(env, napi_create_external(env, r, ring_finalize, NULL, &ext));
    return ext;
}

static zcio_ring *unwrap_ring(napi_env env, napi_value v) {
    void *p = NULL;
    if (napi_get_value_external(env, v, &p) != napi_ok) return NULL;
    return (zcio_ring *)p;
}

/* ringWrite(handle, Buffer) -> int (bytes written, or negative error) */
static napi_value fn_ring_write(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "ringWrite(handle, buffer) requires 2 arguments");

    zcio_ring *r = unwrap_ring(env, argv[0]);
    if (!r) return zthrow(env, "ringWrite: invalid ring handle");

    bool is_buf = false;
    ZNAPI_CALL(env, napi_is_buffer(env, argv[1], &is_buf));
    if (!is_buf) return zthrow(env, "ringWrite: second argument must be a Buffer");

    void *data = NULL;
    size_t len = 0;
    ZNAPI_CALL(env, napi_get_buffer_info(env, argv[1], &data, &len));

    int64_t n = zcio_ring_write(r, data, len);

    napi_value out;
    ZNAPI_CALL(env, napi_create_int64(env, n, &out));
    return out;
}

/* ringRead(handle, length) -> Buffer (may be shorter than requested) */
static napi_value fn_ring_read(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "ringRead(handle, length) requires 2 arguments");

    zcio_ring *r = unwrap_ring(env, argv[0]);
    if (!r) return zthrow(env, "ringRead: invalid ring handle");

    int64_t want = 0;
    ZNAPI_CALL(env, napi_get_value_int64(env, argv[1], &want));
    if (want < 0) return zthrow(env, "ringRead: length must be >= 0");

    char *tmp = (char *)malloc((size_t)want ? (size_t)want : 1);
    if (!tmp) return zthrow(env, "ringRead: out of memory");

    int64_t n = zcio_ring_read(r, tmp, (size_t)want);
    if (n < 0) n = 0;

    napi_value out;
    napi_status s = napi_create_buffer_copy(env, (size_t)n, tmp, NULL, &out);
    free(tmp);
    if (s != napi_ok) return zthrow(env, "ringRead: failed to allocate result buffer");
    return out;
}

/* ringAvailableRead(handle) -> int */
static napi_value fn_ring_available_read(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "ringAvailableRead(handle) requires a handle");
    zcio_ring *r = unwrap_ring(env, argv[0]);
    if (!r) return zthrow(env, "ringAvailableRead: invalid ring handle");
    napi_value out;
    ZNAPI_CALL(env, napi_create_int64(env, (int64_t)zcio_ring_available_read(r), &out));
    return out;
}

/* ringFree(handle) -> undefined.
 *
 * Note: napi externals cannot have their wrapped pointer rebound, so we cannot
 * both free eagerly here AND keep the GC finalizer safe. To avoid a double free,
 * we let the finalizer own the lifetime and treat ringFree as advisory: it just
 * checks the handle is valid. Resources are reclaimed when the handle is GC'd.
 * For deterministic release, drop all references to the handle and let GC run. */
static napi_value fn_ring_free(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "ringFree(handle) requires a handle");

    void *p = NULL;
    if (napi_get_value_external(env, argv[0], &p) != napi_ok || !p)
        return zthrow(env, "ringFree: invalid ring handle");

    napi_value undef;
    ZNAPI_CALL(env, napi_get_undefined(env, &undef));
    return undef;
}

/* -------------------------------------------------------------------------- */
/* buffer-mode serializer                                                     */
/*                                                                            */
/* We bundle the zcio_serial together with its backing buffer so the          */
/* finalizer can free both.                                                   */
/* -------------------------------------------------------------------------- */
typedef struct {
    zcio_serial *z;
    void        *buf;
} serial_box;

static void serial_finalize(napi_env env, void *data, void *hint) {
    (void)env;
    (void)hint;
    serial_box *b = (serial_box *)data;
    if (!b) return;
    if (b->z) zcio_serial_free(b->z);
    if (b->buf) free(b->buf);
    free(b);
}

static serial_box *unwrap_serial(napi_env env, napi_value v) {
    void *p = NULL;
    if (napi_get_value_external(env, v, &p) != napi_ok) return NULL;
    return (serial_box *)p;
}

/* bufferSerial(size[, bitStream]) -> external handle */
static napi_value fn_buffer_serial(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "bufferSerial(size) requires a size");

    int64_t size = 0;
    ZNAPI_CALL(env, napi_get_value_int64(env, argv[0], &size));
    if (size <= 0) return zthrow(env, "bufferSerial: size must be > 0");

    bool bit_stream = false;
    if (argc >= 2) {
        napi_valuetype t;
        ZNAPI_CALL(env, napi_typeof(env, argv[1], &t));
        if (t == napi_boolean) ZNAPI_CALL(env, napi_get_value_bool(env, argv[1], &bit_stream));
    }

    serial_box *box = (serial_box *)calloc(1, sizeof(*box));
    if (!box) return zthrow(env, "bufferSerial: out of memory");
    box->buf = calloc(1, (size_t)size);
    if (!box->buf) {
        free(box);
        return zthrow(env, "bufferSerial: out of memory");
    }
    box->z = zcio_serial_new_buffer(box->buf, size, bit_stream);
    if (!box->z) {
        free(box->buf);
        free(box);
        return zthrow(env, "bufferSerial: zcio_serial_new_buffer failed");
    }

    napi_value ext;
    ZNAPI_CALL(env, napi_create_external(env, box, serial_finalize, NULL, &ext));
    return ext;
}

/* serialWriteI32(handle, value) */
static napi_value fn_serial_write_i32(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "serialWriteI32(handle, value) requires 2 arguments");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialWriteI32: invalid serial handle");
    int32_t v = 0;
    ZNAPI_CALL(env, napi_get_value_int32(env, argv[1], &v));
    zcio_serial_write_i32(b->z, v);
    napi_value undef;
    ZNAPI_CALL(env, napi_get_undefined(env, &undef));
    return undef;
}

/* serialReadI32(handle) -> int */
static napi_value fn_serial_read_i32(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "serialReadI32(handle) requires a handle");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialReadI32: invalid serial handle");
    int32_t v = zcio_serial_read_i32(b->z);
    napi_value out;
    ZNAPI_CALL(env, napi_create_int32(env, v, &out));
    return out;
}

/* serialWriteStr(handle, str) */
static napi_value fn_serial_write_str(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "serialWriteStr(handle, str) requires 2 arguments");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialWriteStr: invalid serial handle");

    size_t len = 0;
    if (napi_get_value_string_utf8(env, argv[1], NULL, 0, &len) != napi_ok)
        return zthrow(env, "serialWriteStr: expected a string");
    char *s = (char *)malloc(len + 1);
    if (!s) return zthrow(env, "serialWriteStr: out of memory");
    napi_status st = napi_get_value_string_utf8(env, argv[1], s, len + 1, &len);
    if (st != napi_ok) {
        free(s);
        return zthrow(env, "serialWriteStr: failed to read string");
    }
    zcio_serial_write_str(b->z, s, len);
    free(s);

    napi_value undef;
    ZNAPI_CALL(env, napi_get_undefined(env, &undef));
    return undef;
}

/* serialReadStr(handle) -> string */
static napi_value fn_serial_read_str(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "serialReadStr(handle) requires a handle");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialReadStr: invalid serial handle");

    size_t out_len = 0;
    char *s = zcio_serial_read_str(b->z, &out_len);
    napi_value out;
    napi_status st = napi_create_string_utf8(env, s ? s : "", s ? out_len : 0, &out);
    if (s) zcio_free(s);
    if (st != napi_ok) return zthrow(env, "serialReadStr: failed to create string");
    return out;
}

/* serialSetReadPos / serialSetWritePos helpers for roundtrip tests */
static napi_value fn_serial_set_read_pos(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "serialSetReadPos(handle, index) requires 2 arguments");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialSetReadPos: invalid serial handle");
    int64_t idx = 0;
    ZNAPI_CALL(env, napi_get_value_int64(env, argv[1], &idx));
    zcio_serial_set_read_pos(b->z, (size_t)idx);
    napi_value undef;
    ZNAPI_CALL(env, napi_get_undefined(env, &undef));
    return undef;
}

/* -------------------------------------------------------------------------- */
/* httpGet(url) -> { status, body, headersJson, statusText, version }         */
/* -------------------------------------------------------------------------- */
static napi_value fn_http_get(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "httpGet(url) requires a url");

    char *url = get_string_arg(env, argv[0]);
    if (!url) return zthrow(env, "httpGet: expected a string url");

    zcio_http_response r = zcio_http_get(url);
    free(url);

    napi_value obj;
    ZNAPI_CALL(env, napi_create_object(env, &obj));

    napi_value v_status, v_body, v_headers, v_statustext, v_version, v_proto;
    ZNAPI_CALL(env, napi_create_int32(env, r.status, &v_status));
    ZNAPI_CALL(env, napi_create_string_utf8(env, r.body ? r.body : "",
                                            r.body ? r.body_size : 0, &v_body));
    ZNAPI_CALL(env, napi_create_string_utf8(env, r.headers_json ? r.headers_json : "{}",
                                            NAPI_AUTO_LENGTH, &v_headers));
    ZNAPI_CALL(env, napi_create_string_utf8(env, r.status_text ? r.status_text : "",
                                            NAPI_AUTO_LENGTH, &v_statustext));
    ZNAPI_CALL(env, napi_create_string_utf8(env, r.version ? r.version : "",
                                            NAPI_AUTO_LENGTH, &v_version));
    ZNAPI_CALL(env, napi_create_string_utf8(env, r.protocol ? r.protocol : "",
                                            NAPI_AUTO_LENGTH, &v_proto));

    ZNAPI_CALL(env, napi_set_named_property(env, obj, "status", v_status));
    ZNAPI_CALL(env, napi_set_named_property(env, obj, "body", v_body));
    ZNAPI_CALL(env, napi_set_named_property(env, obj, "headersJson", v_headers));
    ZNAPI_CALL(env, napi_set_named_property(env, obj, "statusText", v_statustext));
    ZNAPI_CALL(env, napi_set_named_property(env, obj, "version", v_version));
    ZNAPI_CALL(env, napi_set_named_property(env, obj, "protocol", v_proto));

    zcio_http_response_free(&r);
    return obj;
}

/* ========================================================================== */
/* Generic zcio_stream wrapper                                                */
/*                                                                            */
/* A stream may be OWNED (created by us: memory_stream, ring_as_stream with   */
/* take_ownership) or BORROWED (returned by *_stream(handle): the owning      */
/* endpoint frees it). The finalizer frees only owned streams. An optional    */
/* backing buffer (memory streams) is freed with the box.                     */
/* ========================================================================== */
typedef struct {
    zcio_stream *s;
    bool         owns;   /* call zcio_stream_free on finalize */
    void        *buf;    /* optional backing memory to free   */
} stream_box;

static void stream_finalize(napi_env env, void *data, void *hint) {
    (void)env;
    (void)hint;
    stream_box *b = (stream_box *)data;
    if (!b) return;
    if (b->owns && b->s) zcio_stream_free(b->s);
    if (b->buf) free(b->buf);
    free(b);
}

static stream_box *unwrap_stream(napi_env env, napi_value v) {
    void *p = NULL;
    if (napi_get_value_external(env, v, &p) != napi_ok) return NULL;
    return (stream_box *)p;
}

/* Wrap an existing zcio_stream into a fresh external. owns=false for borrowed. */
static napi_value make_stream_ext(napi_env env, zcio_stream *s, bool owns, void *buf) {
    stream_box *box = (stream_box *)calloc(1, sizeof(*box));
    if (!box) return zthrow(env, "out of memory");
    box->s = s;
    box->owns = owns;
    box->buf = buf;
    napi_value ext;
    if (napi_create_external(env, box, stream_finalize, NULL, &ext) != napi_ok) {
        free(box);
        return zthrow(env, "failed to create stream handle");
    }
    return ext;
}

/* streamWrite(handle, Buffer) -> int64 bytes written (negative = error) */
static napi_value fn_stream_write(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "streamWrite(handle, buffer) requires 2 arguments");
    stream_box *b = unwrap_stream(env, argv[0]);
    if (!b || !b->s) return zthrow(env, "streamWrite: invalid stream handle");
    bool is_buf = false;
    ZNAPI_CALL(env, napi_is_buffer(env, argv[1], &is_buf));
    if (!is_buf) return zthrow(env, "streamWrite: second argument must be a Buffer");
    void *data = NULL;
    size_t len = 0;
    ZNAPI_CALL(env, napi_get_buffer_info(env, argv[1], &data, &len));
    int64_t n = zcio_write_full(b->s, data, len);
    napi_value out;
    ZNAPI_CALL(env, napi_create_int64(env, n, &out));
    return out;
}

/* streamRead(handle, n) -> Buffer (may be shorter; one read) */
static napi_value fn_stream_read(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "streamRead(handle, n) requires 2 arguments");
    stream_box *b = unwrap_stream(env, argv[0]);
    if (!b || !b->s) return zthrow(env, "streamRead: invalid stream handle");
    int64_t want = 0;
    ZNAPI_CALL(env, napi_get_value_int64(env, argv[1], &want));
    if (want < 0) return zthrow(env, "streamRead: n must be >= 0");
    char *tmp = (char *)malloc((size_t)want ? (size_t)want : 1);
    if (!tmp) return zthrow(env, "streamRead: out of memory");
    int64_t n = zcio_read(b->s, tmp, (size_t)want);
    if (n < 0) n = 0;
    napi_value out;
    napi_status s = napi_create_buffer_copy(env, (size_t)n, tmp, NULL, &out);
    free(tmp);
    if (s != napi_ok) return zthrow(env, "streamRead: failed to allocate buffer");
    return out;
}

/* streamReadFull(handle, n) -> Buffer (loops over short reads up to EOF) */
static napi_value fn_stream_read_full(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "streamReadFull(handle, n) requires 2 arguments");
    stream_box *b = unwrap_stream(env, argv[0]);
    if (!b || !b->s) return zthrow(env, "streamReadFull: invalid stream handle");
    int64_t want = 0;
    ZNAPI_CALL(env, napi_get_value_int64(env, argv[1], &want));
    if (want < 0) return zthrow(env, "streamReadFull: n must be >= 0");
    char *tmp = (char *)malloc((size_t)want ? (size_t)want : 1);
    if (!tmp) return zthrow(env, "streamReadFull: out of memory");
    int64_t n = zcio_read_full(b->s, tmp, (size_t)want);
    if (n < 0) n = 0;
    napi_value out;
    napi_status s = napi_create_buffer_copy(env, (size_t)n, tmp, NULL, &out);
    free(tmp);
    if (s != napi_ok) return zthrow(env, "streamReadFull: failed to allocate buffer");
    return out;
}

/* streamCopy(dst, src[, limit]) -> int64 bytes copied */
static napi_value fn_stream_copy(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value argv[3];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "streamCopy(dst, src[, limit]) requires 2 arguments");
    stream_box *dst = unwrap_stream(env, argv[0]);
    stream_box *src = unwrap_stream(env, argv[1]);
    if (!dst || !dst->s) return zthrow(env, "streamCopy: invalid dst handle");
    if (!src || !src->s) return zthrow(env, "streamCopy: invalid src handle");
    size_t limit = SIZE_MAX;
    if (argc >= 3) {
        napi_valuetype t;
        ZNAPI_CALL(env, napi_typeof(env, argv[2], &t));
        if (t == napi_number) {
            int64_t lim = 0;
            ZNAPI_CALL(env, napi_get_value_int64(env, argv[2], &lim));
            if (lim >= 0) limit = (size_t)lim;
        }
    }
    int64_t n = zcio_copy(dst->s, src->s, limit);
    napi_value out;
    ZNAPI_CALL(env, napi_create_int64(env, n, &out));
    return out;
}

/* ringAsStream(ringHandle) -> stream handle (borrows the ring) */
static napi_value fn_ring_as_stream(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "ringAsStream(ring) requires a handle");
    zcio_ring *r = unwrap_ring(env, argv[0]);
    if (!r) return zthrow(env, "ringAsStream: invalid ring handle");
    /* take_ownership=false: the ring's own external finalizer frees the ring.
     * This stream is OWNED (we created it) so its finalizer frees the stream
     * wrapper, but not the borrowed ring. */
    zcio_stream *s = zcio_ring_as_stream(r, false);
    if (!s) return zthrow(env, "ringAsStream: zcio_ring_as_stream failed");
    return make_stream_ext(env, s, true, NULL);
}

/* memoryStream(size) -> { handle, buffer } over a fresh backing buffer */
static napi_value fn_memory_stream(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "memoryStream(size) requires a size");
    int64_t size = 0;
    ZNAPI_CALL(env, napi_get_value_int64(env, argv[0], &size));
    if (size <= 0) return zthrow(env, "memoryStream: size must be > 0");
    void *mem = calloc(1, (size_t)size);
    if (!mem) return zthrow(env, "memoryStream: out of memory");
    zcio_stream *s = zcio_memory_stream(mem, (size_t)size);
    if (!s) { free(mem); return zthrow(env, "memoryStream: zcio_memory_stream failed"); }
    napi_value handle = make_stream_ext(env, s, true, mem);
    if (!handle) { return NULL; } /* box took ownership only on success; on error mem leaked once */
    /* Expose the backing memory as an external ArrayBuffer view so JS can read it. */
    napi_value buffer;
    ZNAPI_CALL(env, napi_create_external_buffer(env, (size_t)size, mem, NULL, NULL, &buffer));
    napi_value obj;
    ZNAPI_CALL(env, napi_create_object(env, &obj));
    ZNAPI_CALL(env, napi_set_named_property(env, obj, "handle", handle));
    ZNAPI_CALL(env, napi_set_named_property(env, obj, "buffer", buffer));
    return obj;
}

/* ========================================================================== */
/* TCP client                                                                 */
/* ========================================================================== */
static void tcp_client_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    if (data) zcio_tcp_client_free((zcio_tcp_client *)data);
}

/* tcpClientConnect(host, port) -> handle | null */
static napi_value fn_tcp_client_connect(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "tcpClientConnect(host, port) requires 2 arguments");
    char *host = get_string_arg(env, argv[0]);
    if (!host) return zthrow(env, "tcpClientConnect: host must be a string");
    int32_t port = 0;
    if (napi_get_value_int32(env, argv[1], &port) != napi_ok) { free(host); return zthrow(env, "tcpClientConnect: port must be a number"); }
    zcio_tcp_client *c = zcio_tcp_client_connect(host, port);
    free(host);
    if (!c) { napi_value n; ZNAPI_CALL(env, napi_get_null(env, &n)); return n; }
    napi_value ext;
    ZNAPI_CALL(env, napi_create_external(env, c, tcp_client_finalize, NULL, &ext));
    return ext;
}

/* tcpClientStream(handle) -> borrowed stream handle */
static napi_value fn_tcp_client_stream(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "tcpClientStream(handle) requires a handle");
    void *p = NULL;
    if (napi_get_value_external(env, argv[0], &p) != napi_ok || !p)
        return zthrow(env, "tcpClientStream: invalid handle");
    zcio_stream *s = zcio_tcp_client_stream((zcio_tcp_client *)p);
    if (!s) return zthrow(env, "tcpClientStream: no stream");
    return make_stream_ext(env, s, false, NULL); /* borrowed */
}

/* tcpClientFree(handle) -> undefined (advisory; finalizer owns lifetime) */
static napi_value fn_advisory_free(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    napi_value undef;
    ZNAPI_CALL(env, napi_get_undefined(env, &undef));
    return undef;
}

/* ========================================================================== */
/* TCP server                                                                 */
/* ========================================================================== */
static void tcp_server_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    if (data) zcio_tcp_server_free((zcio_tcp_server *)data);
}

/* tcpServerListen(port) -> handle | null */
static napi_value fn_tcp_server_listen(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "tcpServerListen(port) requires a port");
    int32_t port = 0;
    ZNAPI_CALL(env, napi_get_value_int32(env, argv[0], &port));
    zcio_tcp_server *s = zcio_tcp_server_listen(port);
    if (!s) { napi_value n; ZNAPI_CALL(env, napi_get_null(env, &n)); return n; }
    napi_value ext;
    ZNAPI_CALL(env, napi_create_external(env, s, tcp_server_finalize, NULL, &ext));
    return ext;
}

/* tcpServerAccept(server, timeoutMs) -> { id, connHandle } | null
 * The accepted conn is BORROWED (owned by the server map). We wrap it as a
 * non-owning external (no finalizer) so the conn pointer can be re-streamed. */
static napi_value fn_tcp_server_accept(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "tcpServerAccept(server, timeoutMs) requires a server");
    void *p = NULL;
    if (napi_get_value_external(env, argv[0], &p) != napi_ok || !p)
        return zthrow(env, "tcpServerAccept: invalid server handle");
    int32_t timeout_ms = 0;
    if (argc >= 2) ZNAPI_CALL(env, napi_get_value_int32(env, argv[1], &timeout_ms));
    size_t id = 0;
    zcio_tcp_conn *conn = zcio_tcp_server_accept((zcio_tcp_server *)p, &id, timeout_ms);
    if (!conn) { napi_value n; ZNAPI_CALL(env, napi_get_null(env, &n)); return n; }
    napi_value ext;
    ZNAPI_CALL(env, napi_create_external(env, conn, NULL, NULL, &ext)); /* borrowed: no finalizer */
    napi_value v_id, obj;
    ZNAPI_CALL(env, napi_create_int64(env, (int64_t)id, &v_id));
    ZNAPI_CALL(env, napi_create_object(env, &obj));
    ZNAPI_CALL(env, napi_set_named_property(env, obj, "id", v_id));
    ZNAPI_CALL(env, napi_set_named_property(env, obj, "connHandle", ext));
    return obj;
}

/* tcpConnStream(connHandle) -> borrowed stream handle */
static napi_value fn_tcp_conn_stream(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "tcpConnStream(connHandle) requires a handle");
    void *p = NULL;
    if (napi_get_value_external(env, argv[0], &p) != napi_ok || !p)
        return zthrow(env, "tcpConnStream: invalid conn handle");
    zcio_stream *s = zcio_tcp_conn_stream((zcio_tcp_conn *)p);
    if (!s) return zthrow(env, "tcpConnStream: no stream");
    return make_stream_ext(env, s, false, NULL); /* borrowed */
}

/* tcpServerCloseClient(server, id) -> int */
static napi_value fn_tcp_server_close_client(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "tcpServerCloseClient(server, id) requires 2 arguments");
    void *p = NULL;
    if (napi_get_value_external(env, argv[0], &p) != napi_ok || !p)
        return zthrow(env, "tcpServerCloseClient: invalid server handle");
    int64_t id = 0;
    ZNAPI_CALL(env, napi_get_value_int64(env, argv[1], &id));
    int rc = zcio_tcp_server_close_client((zcio_tcp_server *)p, (size_t)id);
    napi_value out;
    ZNAPI_CALL(env, napi_create_int32(env, rc, &out));
    return out;
}

/* ========================================================================== */
/* UDP client / server                                                        */
/* ========================================================================== */
static void udp_client_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    if (data) zcio_udp_client_free((zcio_udp_client *)data);
}
static void udp_server_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    if (data) zcio_udp_server_free((zcio_udp_server *)data);
}

/* udpClientOpen(host, port) -> handle | null */
static napi_value fn_udp_client_open(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "udpClientOpen(host, port) requires 2 arguments");
    char *host = get_string_arg(env, argv[0]);
    if (!host) return zthrow(env, "udpClientOpen: host must be a string");
    int32_t port = 0;
    if (napi_get_value_int32(env, argv[1], &port) != napi_ok) { free(host); return zthrow(env, "udpClientOpen: port must be a number"); }
    zcio_udp_client *c = zcio_udp_client_open(host, port);
    free(host);
    if (!c) { napi_value n; ZNAPI_CALL(env, napi_get_null(env, &n)); return n; }
    napi_value ext;
    ZNAPI_CALL(env, napi_create_external(env, c, udp_client_finalize, NULL, &ext));
    return ext;
}

/* udpClientStream(handle) -> borrowed stream */
static napi_value fn_udp_client_stream(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "udpClientStream(handle) requires a handle");
    void *p = NULL;
    if (napi_get_value_external(env, argv[0], &p) != napi_ok || !p)
        return zthrow(env, "udpClientStream: invalid handle");
    zcio_stream *s = zcio_udp_client_stream((zcio_udp_client *)p);
    if (!s) return zthrow(env, "udpClientStream: no stream");
    return make_stream_ext(env, s, false, NULL);
}

/* udpServerBind(port) -> handle | null */
static napi_value fn_udp_server_bind(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "udpServerBind(port) requires a port");
    int32_t port = 0;
    ZNAPI_CALL(env, napi_get_value_int32(env, argv[0], &port));
    zcio_udp_server *s = zcio_udp_server_bind(port);
    if (!s) { napi_value n; ZNAPI_CALL(env, napi_get_null(env, &n)); return n; }
    napi_value ext;
    ZNAPI_CALL(env, napi_create_external(env, s, udp_server_finalize, NULL, &ext));
    return ext;
}

/* udpServerReceive(server, nonBlock, timeoutUs) -> packetHandle | null
 * The packet is BORROWED (owned by the server). */
static napi_value fn_udp_server_receive(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value argv[3];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "udpServerReceive(server, nonBlock, timeoutUs) requires a server");
    void *p = NULL;
    if (napi_get_value_external(env, argv[0], &p) != napi_ok || !p)
        return zthrow(env, "udpServerReceive: invalid server handle");
    bool non_block = false;
    if (argc >= 2) { napi_valuetype t; ZNAPI_CALL(env, napi_typeof(env, argv[1], &t));
        if (t == napi_boolean) ZNAPI_CALL(env, napi_get_value_bool(env, argv[1], &non_block)); }
    uint32_t timeout_us = 0;
    if (argc >= 3) { napi_valuetype t; ZNAPI_CALL(env, napi_typeof(env, argv[2], &t));
        if (t == napi_number) ZNAPI_CALL(env, napi_get_value_uint32(env, argv[2], &timeout_us)); }
    zcio_udp_packet *pkt = zcio_udp_server_receive((zcio_udp_server *)p, non_block, timeout_us);
    if (!pkt) { napi_value n; ZNAPI_CALL(env, napi_get_null(env, &n)); return n; }
    napi_value ext;
    ZNAPI_CALL(env, napi_create_external(env, pkt, NULL, NULL, &ext)); /* borrowed */
    return ext;
}

/* udpPacketStream(packetHandle) -> borrowed stream */
static napi_value fn_udp_packet_stream(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "udpPacketStream(handle) requires a handle");
    void *p = NULL;
    if (napi_get_value_external(env, argv[0], &p) != napi_ok || !p)
        return zthrow(env, "udpPacketStream: invalid packet handle");
    zcio_stream *s = zcio_udp_packet_stream((zcio_udp_packet *)p);
    if (!s) return zthrow(env, "udpPacketStream: no stream");
    return make_stream_ext(env, s, false, NULL);
}

/* ========================================================================== */
/* Multicast                                                                  */
/* ========================================================================== */
static void mcast_sender_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    if (data) zcio_mcast_sender_free((zcio_mcast_sender *)data);
}
static void mcast_receiver_finalize(napi_env env, void *data, void *hint) {
    (void)env; (void)hint;
    if (data) zcio_mcast_receiver_free((zcio_mcast_receiver *)data);
}

/* mcastSenderOpen(group, port) -> handle | null */
static napi_value fn_mcast_sender_open(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "mcastSenderOpen(group, port) requires 2 arguments");
    char *group = get_string_arg(env, argv[0]);
    if (!group) return zthrow(env, "mcastSenderOpen: group must be a string");
    int32_t port = 0;
    if (napi_get_value_int32(env, argv[1], &port) != napi_ok) { free(group); return zthrow(env, "mcastSenderOpen: port must be a number"); }
    zcio_mcast_sender *s = zcio_mcast_sender_open(group, port);
    free(group);
    if (!s) { napi_value n; ZNAPI_CALL(env, napi_get_null(env, &n)); return n; }
    napi_value ext;
    ZNAPI_CALL(env, napi_create_external(env, s, mcast_sender_finalize, NULL, &ext));
    return ext;
}

static napi_value fn_mcast_sender_stream(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "mcastSenderStream(handle) requires a handle");
    void *p = NULL;
    if (napi_get_value_external(env, argv[0], &p) != napi_ok || !p)
        return zthrow(env, "mcastSenderStream: invalid handle");
    zcio_stream *s = zcio_mcast_sender_stream((zcio_mcast_sender *)p);
    if (!s) return zthrow(env, "mcastSenderStream: no stream");
    return make_stream_ext(env, s, false, NULL);
}

/* mcastReceiverOpen(group, port) -> handle | null */
static napi_value fn_mcast_receiver_open(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "mcastReceiverOpen(group, port) requires 2 arguments");
    char *group = get_string_arg(env, argv[0]);
    if (!group) return zthrow(env, "mcastReceiverOpen: group must be a string");
    int32_t port = 0;
    if (napi_get_value_int32(env, argv[1], &port) != napi_ok) { free(group); return zthrow(env, "mcastReceiverOpen: port must be a number"); }
    zcio_mcast_receiver *r = zcio_mcast_receiver_open(group, port);
    free(group);
    if (!r) { napi_value n; ZNAPI_CALL(env, napi_get_null(env, &n)); return n; }
    napi_value ext;
    ZNAPI_CALL(env, napi_create_external(env, r, mcast_receiver_finalize, NULL, &ext));
    return ext;
}

static napi_value fn_mcast_receiver_stream(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "mcastReceiverStream(handle) requires a handle");
    void *p = NULL;
    if (napi_get_value_external(env, argv[0], &p) != napi_ok || !p)
        return zthrow(env, "mcastReceiverStream: invalid handle");
    zcio_stream *s = zcio_mcast_receiver_stream((zcio_mcast_receiver *)p);
    if (!s) return zthrow(env, "mcastReceiverStream: no stream");
    return make_stream_ext(env, s, false, NULL);
}

/* ========================================================================== */
/* DNS                                                                        */
/* ========================================================================== */
/* resolveIpv4(host) -> string | null */
static napi_value fn_resolve_ipv4(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "resolveIpv4(host) requires a host");
    char *host = get_string_arg(env, argv[0]);
    if (!host) return zthrow(env, "resolveIpv4: host must be a string");
    char *ip = zcio_resolve_ipv4(host);
    free(host);
    if (!ip) { napi_value n; ZNAPI_CALL(env, napi_get_null(env, &n)); return n; }
    napi_value out;
    napi_status st = napi_create_string_utf8(env, ip, NAPI_AUTO_LENGTH, &out);
    zcio_free(ip);
    if (st != napi_ok) return zthrow(env, "resolveIpv4: failed to create string");
    return out;
}

/* dnsQueryA(host) -> string[] */
static napi_value fn_dns_query_a(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "dnsQueryA(host) requires a host");
    char *host = get_string_arg(env, argv[0]);
    if (!host) return zthrow(env, "dnsQueryA: host must be a string");
    size_t count = 0;
    char **v = zcio_dns_query_a(host, &count);
    free(host);
    napi_value arr;
    ZNAPI_CALL(env, napi_create_array_with_length(env, count, &arr));
    for (size_t i = 0; i < count; i++) {
        napi_value s;
        if (napi_create_string_utf8(env, v[i] ? v[i] : "", NAPI_AUTO_LENGTH, &s) != napi_ok) {
            if (v) zcio_strv_free(v, count);
            return zthrow(env, "dnsQueryA: failed to create string");
        }
        ZNAPI_CALL(env, napi_set_element(env, arr, (uint32_t)i, s));
    }
    if (v) zcio_strv_free(v, count);
    return arr;
}

/* localIpv4() -> string | null */
static napi_value fn_local_ipv4(napi_env env, napi_callback_info info) {
    (void)info;
    char *ip = zcio_local_ipv4();
    if (!ip) { napi_value n; ZNAPI_CALL(env, napi_get_null(env, &n)); return n; }
    napi_value out;
    napi_status st = napi_create_string_utf8(env, ip, NAPI_AUTO_LENGTH, &out);
    zcio_free(ip);
    if (st != napi_ok) return zthrow(env, "localIpv4: failed to create string");
    return out;
}

/* ========================================================================== */
/* Serial - count mode + full scalar/bit/bytes coverage                       */
/* ========================================================================== */
/* serialCount() -> external handle (count-mode serializer, no buffer) */
static napi_value fn_serial_count(napi_env env, napi_callback_info info) {
    (void)info;
    serial_box *box = (serial_box *)calloc(1, sizeof(*box));
    if (!box) return zthrow(env, "serialCount: out of memory");
    box->buf = NULL;
    box->z = zcio_serial_new_count();
    if (!box->z) { free(box); return zthrow(env, "serialCount: zcio_serial_new_count failed"); }
    napi_value ext;
    ZNAPI_CALL(env, napi_create_external(env, box, serial_finalize, NULL, &ext));
    return ext;
}

/* serialSetWritePos(handle, index) */
static napi_value fn_serial_set_write_pos(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "serialSetWritePos(handle, index) requires 2 arguments");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialSetWritePos: invalid serial handle");
    int64_t idx = 0;
    ZNAPI_CALL(env, napi_get_value_int64(env, argv[1], &idx));
    zcio_serial_set_write_pos(b->z, (size_t)idx);
    napi_value undef; ZNAPI_CALL(env, napi_get_undefined(env, &undef));
    return undef;
}

/* serialWritePos / serialReadPos / serialWriteLen / serialReadLen -> int64 */
#define SERIAL_POS_FN(NAME, CFN)                                            \
static napi_value NAME(napi_env env, napi_callback_info info) {             \
    size_t argc = 1; napi_value argv[1];                                    \
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));  \
    if (argc < 1) return zthrow(env, #NAME " requires a handle");           \
    serial_box *b = unwrap_serial(env, argv[0]);                            \
    if (!b || !b->z) return zthrow(env, #NAME ": invalid serial handle");   \
    napi_value out;                                                         \
    ZNAPI_CALL(env, napi_create_int64(env, CFN(b->z), &out));               \
    return out;                                                             \
}
SERIAL_POS_FN(fn_serial_write_pos, zcio_serial_write_pos)
SERIAL_POS_FN(fn_serial_read_pos,  zcio_serial_read_pos)
SERIAL_POS_FN(fn_serial_write_len, zcio_serial_write_len)
SERIAL_POS_FN(fn_serial_read_len,  zcio_serial_read_len)
#undef SERIAL_POS_FN

/* Integer scalar write/read (i8,u8,i16,u16,i32,u32). Values fit in JS number. */
#define SERIAL_INT_WR(WNAME, RNAME, WCFN, RCFN, CTYPE, GETFN, CREATEFN)     \
static napi_value WNAME(napi_env env, napi_callback_info info) {            \
    size_t argc = 2; napi_value argv[2];                                    \
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));  \
    if (argc < 2) return zthrow(env, #WNAME " requires 2 arguments");       \
    serial_box *b = unwrap_serial(env, argv[0]);                            \
    if (!b || !b->z) return zthrow(env, #WNAME ": invalid serial handle");  \
    int64_t tmp = 0;                                                        \
    ZNAPI_CALL(env, napi_get_value_int64(env, argv[1], &tmp));              \
    WCFN(b->z, (CTYPE)tmp);                                                 \
    napi_value undef; ZNAPI_CALL(env, napi_get_undefined(env, &undef));     \
    return undef;                                                           \
}                                                                          \
static napi_value RNAME(napi_env env, napi_callback_info info) {            \
    size_t argc = 1; napi_value argv[1];                                    \
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));  \
    if (argc < 1) return zthrow(env, #RNAME " requires a handle");          \
    serial_box *b = unwrap_serial(env, argv[0]);                            \
    if (!b || !b->z) return zthrow(env, #RNAME ": invalid serial handle");  \
    CTYPE v = RCFN(b->z);                                                   \
    napi_value out;                                                         \
    ZNAPI_CALL(env, CREATEFN(env, (GETFN)v, &out));                         \
    return out;                                                             \
}
SERIAL_INT_WR(fn_serial_write_i8,  fn_serial_read_i8,  zcio_serial_write_i8,  zcio_serial_read_i8,  int8_t,   int32_t, napi_create_int32)
SERIAL_INT_WR(fn_serial_write_u8,  fn_serial_read_u8,  zcio_serial_write_u8,  zcio_serial_read_u8,  uint8_t,  uint32_t, napi_create_uint32)
SERIAL_INT_WR(fn_serial_write_i16, fn_serial_read_i16, zcio_serial_write_i16, zcio_serial_read_i16, int16_t,  int32_t, napi_create_int32)
SERIAL_INT_WR(fn_serial_write_u16, fn_serial_read_u16, zcio_serial_write_u16, zcio_serial_read_u16, uint16_t, uint32_t, napi_create_uint32)
SERIAL_INT_WR(fn_serial_write_u32, fn_serial_read_u32, zcio_serial_write_u32, zcio_serial_read_u32, uint32_t, uint32_t, napi_create_uint32)
#undef SERIAL_INT_WR

/* i64/u64 via BigInt to preserve full width. */
static napi_value fn_serial_write_i64(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "serialWriteI64 requires 2 arguments");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialWriteI64: invalid serial handle");
    int64_t v = 0; bool lossless = false;
    ZNAPI_CALL(env, napi_get_value_bigint_int64(env, argv[1], &v, &lossless));
    zcio_serial_write_i64(b->z, v);
    napi_value undef; ZNAPI_CALL(env, napi_get_undefined(env, &undef));
    return undef;
}
static napi_value fn_serial_read_i64(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "serialReadI64 requires a handle");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialReadI64: invalid serial handle");
    int64_t v = zcio_serial_read_i64(b->z);
    napi_value out; ZNAPI_CALL(env, napi_create_bigint_int64(env, v, &out));
    return out;
}
static napi_value fn_serial_write_u64(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "serialWriteU64 requires 2 arguments");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialWriteU64: invalid serial handle");
    uint64_t v = 0; bool lossless = false;
    ZNAPI_CALL(env, napi_get_value_bigint_uint64(env, argv[1], &v, &lossless));
    zcio_serial_write_u64(b->z, v);
    napi_value undef; ZNAPI_CALL(env, napi_get_undefined(env, &undef));
    return undef;
}
static napi_value fn_serial_read_u64(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "serialReadU64 requires a handle");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialReadU64: invalid serial handle");
    uint64_t v = zcio_serial_read_u64(b->z);
    napi_value out; ZNAPI_CALL(env, napi_create_bigint_uint64(env, v, &out));
    return out;
}

/* f32/f64 via JS double. */
static napi_value fn_serial_write_f32(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "serialWriteF32 requires 2 arguments");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialWriteF32: invalid serial handle");
    double d = 0;
    ZNAPI_CALL(env, napi_get_value_double(env, argv[1], &d));
    zcio_serial_write_f32(b->z, (float)d);
    napi_value undef; ZNAPI_CALL(env, napi_get_undefined(env, &undef));
    return undef;
}
static napi_value fn_serial_read_f32(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "serialReadF32 requires a handle");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialReadF32: invalid serial handle");
    float v = zcio_serial_read_f32(b->z);
    napi_value out; ZNAPI_CALL(env, napi_create_double(env, (double)v, &out));
    return out;
}
static napi_value fn_serial_write_f64(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "serialWriteF64 requires 2 arguments");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialWriteF64: invalid serial handle");
    double d = 0;
    ZNAPI_CALL(env, napi_get_value_double(env, argv[1], &d));
    zcio_serial_write_f64(b->z, d);
    napi_value undef; ZNAPI_CALL(env, napi_get_undefined(env, &undef));
    return undef;
}
static napi_value fn_serial_read_f64(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "serialReadF64 requires a handle");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialReadF64: invalid serial handle");
    double v = zcio_serial_read_f64(b->z);
    napi_value out; ZNAPI_CALL(env, napi_create_double(env, v, &out));
    return out;
}

/* serialWriteBit(handle, bool) / serialReadBit(handle) -> bool */
static napi_value fn_serial_write_bit(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "serialWriteBit requires 2 arguments");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialWriteBit: invalid serial handle");
    bool bit = false;
    ZNAPI_CALL(env, napi_get_value_bool(env, argv[1], &bit));
    zcio_serial_write_bit(b->z, bit);
    napi_value undef; ZNAPI_CALL(env, napi_get_undefined(env, &undef));
    return undef;
}
static napi_value fn_serial_read_bit(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value argv[1];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "serialReadBit requires a handle");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialReadBit: invalid serial handle");
    bool v = zcio_serial_read_bit(b->z);
    napi_value out; ZNAPI_CALL(env, napi_get_boolean(env, v, &out));
    return out;
}

/* serialWriteBytes(handle, Buffer) -> int64 */
static napi_value fn_serial_write_bytes(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "serialWriteBytes(handle, buffer) requires 2 arguments");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialWriteBytes: invalid serial handle");
    bool is_buf = false;
    ZNAPI_CALL(env, napi_is_buffer(env, argv[1], &is_buf));
    if (!is_buf) return zthrow(env, "serialWriteBytes: second argument must be a Buffer");
    void *data = NULL; size_t len = 0;
    ZNAPI_CALL(env, napi_get_buffer_info(env, argv[1], &data, &len));
    int64_t n = zcio_serial_write_bytes(b->z, data, len);
    napi_value out; ZNAPI_CALL(env, napi_create_int64(env, n, &out));
    return out;
}

/* serialReadBytes(handle, n) -> Buffer (length = bytes actually read) */
static napi_value fn_serial_read_bytes(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 2) return zthrow(env, "serialReadBytes(handle, n) requires 2 arguments");
    serial_box *b = unwrap_serial(env, argv[0]);
    if (!b || !b->z) return zthrow(env, "serialReadBytes: invalid serial handle");
    int64_t want = 0;
    ZNAPI_CALL(env, napi_get_value_int64(env, argv[1], &want));
    if (want < 0) return zthrow(env, "serialReadBytes: n must be >= 0");
    char *tmp = (char *)malloc((size_t)want ? (size_t)want : 1);
    if (!tmp) return zthrow(env, "serialReadBytes: out of memory");
    int64_t n = zcio_serial_read_bytes(b->z, tmp, (size_t)want);
    if (n < 0) n = 0;
    napi_value out;
    napi_status s = napi_create_buffer_copy(env, (size_t)n, tmp, NULL, &out);
    free(tmp);
    if (s != napi_ok) return zthrow(env, "serialReadBytes: failed to allocate buffer");
    return out;
}

/* ========================================================================== */
/* HTTP POST                                                                  */
/* ========================================================================== */
static napi_value http_response_to_obj(napi_env env, zcio_http_response *r);

static napi_value fn_http_post(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    ZNAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    if (argc < 1) return zthrow(env, "httpPost(url, body) requires a url");
    char *url = get_string_arg(env, argv[0]);
    if (!url) return zthrow(env, "httpPost: expected a string url");
    void *data = NULL; size_t len = 0;
    if (argc >= 2) {
        bool is_buf = false;
        if (napi_is_buffer(env, argv[1], &is_buf) == napi_ok && is_buf)
            napi_get_buffer_info(env, argv[1], &data, &len);
    }
    zcio_http_response r = zcio_http_post(url, data, len);
    free(url);
    napi_value obj = http_response_to_obj(env, &r);
    zcio_http_response_free(&r);
    return obj;
}

/* shared response -> JS object builder (also used by httpGet) */
static napi_value http_response_to_obj(napi_env env, zcio_http_response *r) {
    napi_value obj;
    if (napi_create_object(env, &obj) != napi_ok) return NULL;
    napi_value v_status, v_body, v_headers, v_statustext, v_version, v_proto;
    if (napi_create_int32(env, r->status, &v_status) != napi_ok) return NULL;
    if (napi_create_string_utf8(env, r->body ? r->body : "", r->body ? r->body_size : 0, &v_body) != napi_ok) return NULL;
    if (napi_create_string_utf8(env, r->headers_json ? r->headers_json : "{}", NAPI_AUTO_LENGTH, &v_headers) != napi_ok) return NULL;
    if (napi_create_string_utf8(env, r->status_text ? r->status_text : "", NAPI_AUTO_LENGTH, &v_statustext) != napi_ok) return NULL;
    if (napi_create_string_utf8(env, r->version ? r->version : "", NAPI_AUTO_LENGTH, &v_version) != napi_ok) return NULL;
    if (napi_create_string_utf8(env, r->protocol ? r->protocol : "", NAPI_AUTO_LENGTH, &v_proto) != napi_ok) return NULL;
    napi_set_named_property(env, obj, "status", v_status);
    napi_set_named_property(env, obj, "body", v_body);
    napi_set_named_property(env, obj, "headersJson", v_headers);
    napi_set_named_property(env, obj, "statusText", v_statustext);
    napi_set_named_property(env, obj, "version", v_version);
    napi_set_named_property(env, obj, "protocol", v_proto);
    return obj;
}

/* -------------------------------------------------------------------------- */
/* module init                                                                */
/* -------------------------------------------------------------------------- */
static napi_value declare(napi_env env, napi_value exports,
                          const char *name, napi_callback fn) {
    napi_value f;
    if (napi_create_function(env, name, NAPI_AUTO_LENGTH, fn, NULL, &f) != napi_ok)
        return NULL;
    if (napi_set_named_property(env, exports, name, f) != napi_ok) return NULL;
    return exports;
}

static napi_value Init(napi_env env, napi_value exports) {
    zcio_init();

#define DECL(NAME, FN)                                                  \
    if (!declare(env, exports, NAME, FN)) return NULL;

    DECL("version", fn_version);
    DECL("isIpv4", fn_is_ipv4);

    DECL("ringNew", fn_ring_new);
    DECL("ringWrite", fn_ring_write);
    DECL("ringRead", fn_ring_read);
    DECL("ringAvailableRead", fn_ring_available_read);
    DECL("ringFree", fn_ring_free);

    DECL("bufferSerial", fn_buffer_serial);
    DECL("serialCount", fn_serial_count);
    DECL("serialWriteI32", fn_serial_write_i32);
    DECL("serialReadI32", fn_serial_read_i32);
    DECL("serialWriteStr", fn_serial_write_str);
    DECL("serialReadStr", fn_serial_read_str);
    DECL("serialSetReadPos", fn_serial_set_read_pos);
    DECL("serialSetWritePos", fn_serial_set_write_pos);
    DECL("serialWritePos", fn_serial_write_pos);
    DECL("serialReadPos", fn_serial_read_pos);
    DECL("serialWriteLen", fn_serial_write_len);
    DECL("serialReadLen", fn_serial_read_len);
    DECL("serialWriteI8", fn_serial_write_i8);
    DECL("serialReadI8", fn_serial_read_i8);
    DECL("serialWriteU8", fn_serial_write_u8);
    DECL("serialReadU8", fn_serial_read_u8);
    DECL("serialWriteI16", fn_serial_write_i16);
    DECL("serialReadI16", fn_serial_read_i16);
    DECL("serialWriteU16", fn_serial_write_u16);
    DECL("serialReadU16", fn_serial_read_u16);
    DECL("serialWriteU32", fn_serial_write_u32);
    DECL("serialReadU32", fn_serial_read_u32);
    DECL("serialWriteI64", fn_serial_write_i64);
    DECL("serialReadI64", fn_serial_read_i64);
    DECL("serialWriteU64", fn_serial_write_u64);
    DECL("serialReadU64", fn_serial_read_u64);
    DECL("serialWriteF32", fn_serial_write_f32);
    DECL("serialReadF32", fn_serial_read_f32);
    DECL("serialWriteF64", fn_serial_write_f64);
    DECL("serialReadF64", fn_serial_read_f64);
    DECL("serialWriteBit", fn_serial_write_bit);
    DECL("serialReadBit", fn_serial_read_bit);
    DECL("serialWriteBytes", fn_serial_write_bytes);
    DECL("serialReadBytes", fn_serial_read_bytes);

    /* generic stream verbs */
    DECL("streamWrite", fn_stream_write);
    DECL("streamRead", fn_stream_read);
    DECL("streamReadFull", fn_stream_read_full);
    DECL("streamCopy", fn_stream_copy);
    DECL("ringAsStream", fn_ring_as_stream);
    DECL("memoryStream", fn_memory_stream);

    /* TCP */
    DECL("tcpClientConnect", fn_tcp_client_connect);
    DECL("tcpClientStream", fn_tcp_client_stream);
    DECL("tcpClientFree", fn_advisory_free);
    DECL("tcpServerListen", fn_tcp_server_listen);
    DECL("tcpServerAccept", fn_tcp_server_accept);
    DECL("tcpConnStream", fn_tcp_conn_stream);
    DECL("tcpServerCloseClient", fn_tcp_server_close_client);
    DECL("tcpServerFree", fn_advisory_free);

    /* UDP */
    DECL("udpClientOpen", fn_udp_client_open);
    DECL("udpClientStream", fn_udp_client_stream);
    DECL("udpClientFree", fn_advisory_free);
    DECL("udpServerBind", fn_udp_server_bind);
    DECL("udpServerReceive", fn_udp_server_receive);
    DECL("udpPacketStream", fn_udp_packet_stream);
    DECL("udpServerFree", fn_advisory_free);

    /* Multicast */
    DECL("mcastSenderOpen", fn_mcast_sender_open);
    DECL("mcastSenderStream", fn_mcast_sender_stream);
    DECL("mcastSenderFree", fn_advisory_free);
    DECL("mcastReceiverOpen", fn_mcast_receiver_open);
    DECL("mcastReceiverStream", fn_mcast_receiver_stream);
    DECL("mcastReceiverFree", fn_advisory_free);

    /* DNS */
    DECL("resolveIpv4", fn_resolve_ipv4);
    DECL("dnsQueryA", fn_dns_query_a);
    DECL("localIpv4", fn_local_ipv4);

    DECL("httpGet", fn_http_get);
    DECL("httpPost", fn_http_post);

#undef DECL
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
