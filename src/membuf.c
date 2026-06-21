/* src/membuf.c - memory view + counting streams (port of memory/counting_streambuf). */
#include "zcio/membuf.h"
#include "internal.h"

/* --- shared context ----------------------------------------------------- */
typedef struct membuf {
    char   *data;        /* may be NULL for pure counting */
    size_t  size;
    size_t  rpos, wpos;
    int64_t total_read, total_written;
    bool    counting;
} membuf;

static int64_t mb_read(void *c, void *dst, size_t n) {
    membuf *m = (membuf *)c;
    if (m->data) {
        size_t avail = m->size - m->rpos;
        size_t k = n < avail ? n : avail;
        memcpy(dst, m->data + m->rpos, k);
        m->rpos += k;
        m->total_read += (int64_t)k;
        return (int64_t)k;
    }
    /* pure counting: nothing to give */
    return 0;
}

static int64_t mb_write(void *c, const void *src, size_t n) {
    membuf *m = (membuf *)c;
    if (m->data) {
        size_t avail = m->size - m->wpos;
        size_t k = n < avail ? n : avail;
        memcpy(m->data + m->wpos, src, k);
        m->wpos += k;
        m->total_written += (int64_t)k;
        return (int64_t)k;
    }
    m->total_written += (int64_t)n; /* counting sink swallows everything */
    return (int64_t)n;
}

static int64_t mb_seek(void *c, int64_t off, zcio_seek_origin origin, zcio_seek_which which) {
    membuf *m = (membuf *)c;
    int64_t base_r = (origin == ZCIO_SEEK_CUR) ? (int64_t)m->rpos : (origin == ZCIO_SEEK_END) ? (int64_t)m->size : 0;
    int64_t base_w = (origin == ZCIO_SEEK_CUR) ? (int64_t)m->wpos : (origin == ZCIO_SEEK_END) ? (int64_t)m->size : 0;
    int64_t ret = -1;
    if (which & ZCIO_SEEK_READ) {
        int64_t p = base_r + off;
        if (p < 0) p = 0; if (p > (int64_t)m->size) p = (int64_t)m->size;
        m->rpos = (size_t)p; ret = p;
    }
    if (which & ZCIO_SEEK_WRITE) {
        int64_t p = base_w + off;
        if (p < 0) p = 0; if (p > (int64_t)m->size) p = (int64_t)m->size;
        m->wpos = (size_t)p; ret = p;
    }
    return ret;
}

static int64_t mb_avail(void *c) {
    membuf *m = (membuf *)c;
    return m->data ? (int64_t)(m->size - m->rpos) : 0;
}

static void mb_destroy(void *c) { free(c); }

static const zcio_stream_vtable MEM_VT = {
    .name = "memory",
    .read = mb_read, .write = mb_write, .seek = mb_seek,
    .available = mb_avail, .destroy = mb_destroy,
};
static const zcio_stream_vtable COUNT_VT = {
    .name = "counting",
    .read = mb_read, .write = mb_write, .seek = mb_seek,
    .available = mb_avail, .destroy = mb_destroy,
};

static membuf *mb_new(void *data, size_t size, bool counting) {
    membuf *m = (membuf *)zcio_xcalloc(1, sizeof *m);
    if (!m) return NULL;
    m->data = (char *)data;
    m->size = size;
    m->counting = counting;
    return m;
}

zcio_stream *zcio_memory_stream(void *data, size_t size) {
    if (!data) return NULL;
    membuf *m = mb_new(data, size, false);
    if (!m) return NULL;
    return zcio_stream_new(&MEM_VT, m, ZCIO_STREAM_OWNS_CTX | ZCIO_STREAM_READABLE | ZCIO_STREAM_WRITABLE);
}

zcio_stream *zcio_counting_stream(void *data, size_t size) {
    membuf *m = mb_new(data, data ? size : 0, true);
    if (!m) return NULL;
    return zcio_stream_new(&COUNT_VT, m, ZCIO_STREAM_OWNS_CTX | ZCIO_STREAM_READABLE | ZCIO_STREAM_WRITABLE);
}

int64_t zcio_counting_bytes_written(zcio_stream *s) {
    if (!s || s->vt != &COUNT_VT) return ZCIO_ERR_INVALID_ARG;
    return ((membuf *)s->ctx)->total_written;
}
int64_t zcio_counting_bytes_read(zcio_stream *s) {
    if (!s || s->vt != &COUNT_VT) return ZCIO_ERR_INVALID_ARG;
    return ((membuf *)s->ctx)->total_read;
}
