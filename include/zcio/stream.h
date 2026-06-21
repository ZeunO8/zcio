/* zcio/stream.h - the unified stream abstraction.
 *
 * This is the architectural heart of zcio and the direct replacement for C++'s
 * std::streambuf virtual dispatch. A `zcio_stream` is a fat pointer: a const
 * vtable of operations plus an opaque context. Every concrete backend (ring
 * buffer, memory buffer, TCP/UDP socket, archive entry, TLS overlay) supplies a
 * vtable; everything above the stream layer (Serial, HTTP, copy helpers) is
 * written once against this interface.
 *
 * Why a hand-rolled vtable instead of C++ virtuals:
 *   - Stable ABI: no name mangling, no fragile-base-class problem across the FFI.
 *   - O(1) dispatch with a single indirect call, branch-predictor friendly.
 *   - Backends can be added by any language that can fill a struct of fn ptrs.
 *
 * All byte-count returns are int64_t: >= 0 is the number of bytes transferred,
 * < 0 is a negated zcio_result. A short read/write (return < requested) is not
 * an error -- check zcio_stream_eof() to distinguish "done" from "try again".
 */
#ifndef ZCIO_STREAM_H
#define ZCIO_STREAM_H

#include "zcio/types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zcio_stream zcio_stream;

/* Operation table. Any op may be NULL when a backend does not support it; the
 * dispatcher returns ZCIO_ERR_UNSUPPORTED in that case. `ctx` is the backend's
 * private state (the value of zcio_stream::ctx). */
typedef struct zcio_stream_vtable {
    const char *name;  /* static identifier, e.g. "ring", "tcp" -- for diagnostics */

    int64_t (*read)  (void *ctx, void *dst, size_t n);
    int64_t (*write) (void *ctx, const void *src, size_t n);
    /* Reposition. `which` selects read/write cursor(s). Returns the new absolute
     * offset of the affected cursor, or a negated zcio_result. */
    int64_t (*seek)  (void *ctx, int64_t off, zcio_seek_origin origin, zcio_seek_which which);
    int     (*flush) (void *ctx);                 /* push buffered writes out     */
    int     (*close) (void *ctx);                 /* half/full close the endpoint */
    void    (*destroy)(void *ctx);                /* free ctx; called by stream_free */

    /* Optional fast-path / introspection hooks (may be NULL). */
    int64_t (*available)(void *ctx);              /* bytes readable without blocking */
    bool    (*eof)      (void *ctx);              /* true once no more data will come */
} zcio_stream_vtable;

/* A stream value. Owned by whoever created it; release with zcio_stream_free. */
struct zcio_stream {
    const zcio_stream_vtable *vt;
    void                     *ctx;
    uint32_t                  flags;   /* ZCIO_STREAM_* bits below */
};

enum {
    ZCIO_STREAM_OWNS_CTX = 1u << 0,    /* stream_free will call vt->destroy(ctx) */
    ZCIO_STREAM_READABLE = 1u << 1,
    ZCIO_STREAM_WRITABLE = 1u << 2,
};

/* --- lifecycle ---------------------------------------------------------- */

/* Allocate a stream wrapping (vt, ctx). flags should set OWNS_CTX if the stream
 * is responsible for destroying ctx. Returns NULL on OOM. */
ZCIO_API ZCIO_NODISCARD zcio_stream *
zcio_stream_new(const zcio_stream_vtable *vt, void *ctx, uint32_t flags);

/* Destroy a stream. If ZCIO_STREAM_OWNS_CTX is set and vt->destroy is non-NULL,
 * the backing context is destroyed too. NULL-safe. */
ZCIO_API void zcio_stream_free(zcio_stream *s);

/* --- dispatch wrappers (the public verbs) ------------------------------- */

ZCIO_API int64_t zcio_read   (zcio_stream *s, void *dst, size_t n);
ZCIO_API int64_t zcio_write  (zcio_stream *s, const void *src, size_t n);
ZCIO_API int64_t zcio_seek   (zcio_stream *s, int64_t off, zcio_seek_origin origin, zcio_seek_which which);
ZCIO_API int     zcio_flush  (zcio_stream *s);
ZCIO_API int     zcio_close  (zcio_stream *s);
ZCIO_API int64_t zcio_available(zcio_stream *s);
ZCIO_API bool    zcio_stream_eof(zcio_stream *s);
ZCIO_API const char *zcio_stream_name(const zcio_stream *s);

/* Read exactly n bytes (looping over short reads) unless EOF/error intervenes.
 * Returns total bytes read; < n means EOF or error was hit. */
ZCIO_API int64_t zcio_read_full (zcio_stream *s, void *dst, size_t n);
ZCIO_API int64_t zcio_write_full(zcio_stream *s, const void *src, size_t n);

/* Pump up to `limit` bytes (SIZE_MAX = until EOF) from src into dst using an
 * internal bounce buffer. Returns total bytes copied or a negated zcio_result. */
ZCIO_API int64_t zcio_copy(zcio_stream *dst, zcio_stream *src, size_t limit);

#ifdef __cplusplus
}
#endif

#endif /* ZCIO_STREAM_H */
