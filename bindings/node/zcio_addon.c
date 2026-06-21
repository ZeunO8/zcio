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
    DECL("serialWriteI32", fn_serial_write_i32);
    DECL("serialReadI32", fn_serial_read_i32);
    DECL("serialWriteStr", fn_serial_write_str);
    DECL("serialReadStr", fn_serial_read_str);
    DECL("serialSetReadPos", fn_serial_set_read_pos);

    DECL("httpGet", fn_http_get);

#undef DECL
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
