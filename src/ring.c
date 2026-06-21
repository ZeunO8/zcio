/* src/ring.c - lock-free SPSC ring buffer (port of ring_streambuf).
 *
 * Layout when attached to external memory: [_Atomic size_t head]
 * [_Atomic size_t tail][data ...]. head is the producer cursor, tail the
 * consumer cursor; one slot is kept empty to distinguish full from empty.
 * All hot-path ops are O(1): index arithmetic + at most two memcpys.
 *
 * SPSC memory-order contract (explicit, do not change the algorithm):
 *   - The producer owns `head`: it reads its own head relaxed, publishes head
 *     with memory_order_release, and reads the consumer's `tail` with acquire.
 *   - The consumer owns `tail`: it reads its own tail relaxed, publishes tail
 *     with memory_order_release, and reads the producer's `head` with acquire.
 * The release/acquire pairing ensures data written into the buffer happens-
 * before the matching cursor advance is observed by the other thread. */
#include "zcio/ring.h"
#include "internal.h"
#include <stdatomic.h>

#if !defined(_WIN32)
#  include <sched.h>
#  define ZCIO_YIELD() sched_yield()
#else
#  define ZCIO_YIELD() Sleep(0)
#endif

typedef struct ring_header {
    _Atomic size_t head;
    _Atomic size_t tail;
} ring_header;

struct zcio_ring {
    void          *block;       /* owned allocation, NULL if attached */
    ring_header   *hdr;
    char          *data;
    size_t         capacity;    /* usable bytes (one slot reserved)   */
    bool           non_blocking;
};

size_t zcio_ring_header_size(void) { return sizeof(ring_header); }

static zcio_ring *ring_init(void *mem, size_t total, bool own, bool nb) {
    if (total <= sizeof(ring_header)) return NULL;
    zcio_ring *r = (zcio_ring *)zcio_xcalloc(1, sizeof *r);
    if (!r) return NULL;
    r->block = own ? mem : NULL;
    r->hdr = (ring_header *)mem;
    r->data = (char *)mem + sizeof(ring_header);
    r->capacity = total - sizeof(ring_header);
    r->non_blocking = nb;
    /* Single-threaded setup before either side runs; release is sufficient. */
    atomic_store_explicit(&r->hdr->head, 0, memory_order_release);
    atomic_store_explicit(&r->hdr->tail, 0, memory_order_release);
    return r;
}

zcio_ring *zcio_ring_new(size_t capacity, bool non_blocking) {
    /* guard the `capacity + sizeof(ring_header) + 1` sum against wraparound */
    if (capacity > SIZE_MAX - sizeof(ring_header) - 1) return NULL;
    size_t total = capacity + sizeof(ring_header) + 1; /* +1 reserved slot */
    void *mem = zcio_xmalloc(total);
    if (!mem) return NULL;
    zcio_ring *r = ring_init(mem, total, true, non_blocking);
    if (!r) { free(mem); return NULL; }
    return r;
}

zcio_ring *zcio_ring_attach(void *mem, size_t total_size, bool non_blocking) {
    if (!mem) return NULL;
    return ring_init(mem, total_size, false, non_blocking);
}

void zcio_ring_free(zcio_ring *r) {
    if (!r) return;
    free(r->block);
    free(r);
}

/* Consumer-side query: head is the other thread's cursor (acquire), tail is
 * our own (acquire is safe; relaxed would also do for a pure SPSC consumer). */
size_t zcio_ring_available_read(const zcio_ring *r) {
    size_t h = atomic_load_explicit(&r->hdr->head, memory_order_acquire);
    size_t t = atomic_load_explicit(&r->hdr->tail, memory_order_acquire);
    return (h + r->capacity - t) % r->capacity;
}

/* Producer-side query: tail is the other thread's cursor (acquire), head is
 * our own (acquire is safe; relaxed would also do for a pure SPSC producer). */
size_t zcio_ring_available_write(const zcio_ring *r) {
    size_t h = atomic_load_explicit(&r->hdr->head, memory_order_acquire);
    size_t t = atomic_load_explicit(&r->hdr->tail, memory_order_acquire);
    return (r->capacity - 1 + t - h) % r->capacity;
}

int64_t zcio_ring_write(zcio_ring *r, const void *src, size_t n) {
    if (!r || !src) return ZCIO_ERR_INVALID_ARG;
    const char *s = (const char *)src;
    size_t written = 0;
    int full_spins = 0;
    while (written < n) {
        size_t avail = zcio_ring_available_write(r);
        if (avail == 0) {
            if (r->non_blocking) {
                if (written > 0 || full_spins > 100) break;
                full_spins++;
            }
            ZCIO_YIELD();
            continue;
        }
        size_t chunk = avail < (n - written) ? avail : (n - written);
        /* producer owns head: read it relaxed */
        size_t h = atomic_load_explicit(&r->hdr->head, memory_order_relaxed);
        size_t end = (chunk < r->capacity - h) ? chunk : (r->capacity - h);
        memcpy(r->data + h, s + written, end);
        if (chunk > end) memcpy(r->data, s + written + end, chunk - end);
        /* publish head with release so the bytes above are visible first */
        atomic_store_explicit(&r->hdr->head, (h + chunk) % r->capacity, memory_order_release);
        written += chunk;
    }
    return (int64_t)written;
}

int64_t zcio_ring_read(zcio_ring *r, void *dst, size_t n) {
    if (!r || !dst) return ZCIO_ERR_INVALID_ARG;
    char *d = (char *)dst;
    size_t got = 0;
    long empty_spins = 0;
    while (got < n) {
        size_t avail = zcio_ring_available_read(r);
        if (avail == 0) {
            if (r->non_blocking) {
                if (got > 0 || empty_spins > 1000000) break;
                empty_spins++;
            }
            ZCIO_YIELD();
            continue;
        }
        size_t chunk = avail < (n - got) ? avail : (n - got);
        /* consumer owns tail: read it relaxed */
        size_t t = atomic_load_explicit(&r->hdr->tail, memory_order_relaxed);
        size_t end = (chunk < r->capacity - t) ? chunk : (r->capacity - t);
        memcpy(d + got, r->data + t, end);
        if (chunk > end) memcpy(d + got + end, r->data, chunk - end);
        /* publish tail with release so the freed slots are visible to producer */
        atomic_store_explicit(&r->hdr->tail, (t + chunk) % r->capacity, memory_order_release);
        got += chunk;
    }
    return (int64_t)got;
}

/* --- stream adapter ----------------------------------------------------- */
static int64_t ring_s_read(void *c, void *d, size_t n)        { return zcio_ring_read((zcio_ring *)c, d, n); }
static int64_t ring_s_write(void *c, const void *s, size_t n) { return zcio_ring_write((zcio_ring *)c, s, n); }
static int64_t ring_s_avail(void *c)                          { return (int64_t)zcio_ring_available_read((zcio_ring *)c); }
static void    ring_s_destroy(void *c)                        { zcio_ring_free((zcio_ring *)c); }

static const zcio_stream_vtable RING_VT = {
    .name = "ring",
    .read = ring_s_read,
    .write = ring_s_write,
    .available = ring_s_avail,
    .destroy = ring_s_destroy,
};

zcio_stream *zcio_ring_as_stream(zcio_ring *r, bool take_ownership) {
    if (!r) return NULL;
    uint32_t flags = ZCIO_STREAM_READABLE | ZCIO_STREAM_WRITABLE;
    if (take_ownership) flags |= ZCIO_STREAM_OWNS_CTX;
    return zcio_stream_new(&RING_VT, r, flags);
}
