/* src/stream.c - generic stream dispatch + helpers. */
#include "zcio/stream.h"
#include "internal.h"

zcio_stream *zcio_stream_new(const zcio_stream_vtable *vt, void *ctx, uint32_t flags) {
    if (!vt) return NULL;
    zcio_stream *s = (zcio_stream *)zcio_xmalloc(sizeof *s);
    if (!s) return NULL;
    s->vt = vt;
    s->ctx = ctx;
    s->flags = flags;
    return s;
}

void zcio_stream_free(zcio_stream *s) {
    if (!s) return;
    if ((s->flags & ZCIO_STREAM_OWNS_CTX) && s->vt && s->vt->destroy)
        s->vt->destroy(s->ctx);
    free(s);
}

int64_t zcio_read(zcio_stream *s, void *dst, size_t n) {
    if (!s || !dst) return ZCIO_ERR_INVALID_ARG;
    if (!s->vt->read) return ZCIO_ERR_UNSUPPORTED;
    if (n == 0) return 0;
    return s->vt->read(s->ctx, dst, n);
}

int64_t zcio_write(zcio_stream *s, const void *src, size_t n) {
    if (!s || !src) return ZCIO_ERR_INVALID_ARG;
    if (!s->vt->write) return ZCIO_ERR_UNSUPPORTED;
    if (n == 0) return 0;
    return s->vt->write(s->ctx, src, n);
}

int64_t zcio_seek(zcio_stream *s, int64_t off, zcio_seek_origin origin, zcio_seek_which which) {
    if (!s) return ZCIO_ERR_INVALID_ARG;
    if (!s->vt->seek) return ZCIO_ERR_UNSUPPORTED;
    return s->vt->seek(s->ctx, off, origin, which);
}

int zcio_flush(zcio_stream *s) {
    if (!s) return ZCIO_ERR_INVALID_ARG;
    return s->vt->flush ? s->vt->flush(s->ctx) : ZCIO_OK;
}

int zcio_close(zcio_stream *s) {
    if (!s) return ZCIO_ERR_INVALID_ARG;
    return s->vt->close ? s->vt->close(s->ctx) : ZCIO_OK;
}

int64_t zcio_available(zcio_stream *s) {
    if (!s) return ZCIO_ERR_INVALID_ARG;
    return s->vt->available ? s->vt->available(s->ctx) : 0;
}

bool zcio_stream_eof(zcio_stream *s) {
    if (!s) return true;
    return s->vt->eof ? s->vt->eof(s->ctx) : false;
}

const char *zcio_stream_name(const zcio_stream *s) {
    return (s && s->vt) ? s->vt->name : "(null)";
}

int64_t zcio_read_full(zcio_stream *s, void *dst, size_t n) {
    char *p = (char *)dst;
    size_t got = 0;
    while (got < n) {
        int64_t r = zcio_read(s, p + got, n - got);
        if (r < 0) return got ? (int64_t)got : r;
        if (r == 0) break; /* EOF */
        got += (size_t)r;
    }
    return (int64_t)got;
}

int64_t zcio_write_full(zcio_stream *s, const void *src, size_t n) {
    const char *p = (const char *)src;
    size_t put = 0;
    while (put < n) {
        int64_t r = zcio_write(s, p + put, n - put);
        if (r < 0) return put ? (int64_t)put : r;
        if (r == 0) break;
        put += (size_t)r;
    }
    return (int64_t)put;
}

int64_t zcio_copy(zcio_stream *dst, zcio_stream *src, size_t limit) {
    if (!dst || !src) return ZCIO_ERR_INVALID_ARG;
    char buf[16384];
    int64_t total = 0;
    /* SIZE_MAX means "until EOF" (see stream.h). Casting it to int64_t yields
     * -1, which would skip the loop, so handle the unbounded case explicitly. */
    bool unbounded = (limit == SIZE_MAX);
    while (unbounded || total < (int64_t)limit) {
        size_t want = sizeof buf;
        if (!unbounded && limit - (size_t)total < want) want = limit - (size_t)total;
        int64_t r = zcio_read(src, buf, want);
        if (r < 0) return total ? total : r;
        if (r == 0) break;
        int64_t w = zcio_write_full(dst, buf, (size_t)r);
        if (w < 0) return total ? total : w;
        total += w;
        if (w < r) break; /* sink full */
    }
    return total;
}
