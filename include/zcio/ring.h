/* zcio/ring.h - lock-free single-producer/single-consumer ring buffer.
 *
 * Port of ring_streambuf. All operations are O(1) and zero-copy at the buffer
 * boundary (a write of N bytes is at most two memcpys around the wrap point).
 * Head/tail are C11 atomics so one thread may produce while another consumes.
 *
 * The ring can own its memory (zcio_ring_new) or wrap caller memory laid out as
 * [atomic head][atomic tail][data...] (zcio_ring_attach), enabling shared-memory
 * IPC exactly like the original ring_header scheme.
 */
#ifndef ZCIO_RING_H
#define ZCIO_RING_H

#include "zcio/types.h"
#include "zcio/stream.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zcio_ring zcio_ring;

/* Number of header bytes zcio_ring_attach expects at the front of its block. */
ZCIO_API size_t zcio_ring_header_size(void);

/* Allocate a ring with `capacity` bytes of usable data space. `non_blocking`
 * selects the original's spin-or-yield behavior on full/empty. */
ZCIO_API ZCIO_NODISCARD zcio_ring *zcio_ring_new(size_t capacity, bool non_blocking);

/* Wrap an externally provided block of `total_size` bytes (header + data). */
ZCIO_API ZCIO_NODISCARD zcio_ring *
zcio_ring_attach(void *mem, size_t total_size, bool non_blocking);

ZCIO_API void zcio_ring_free(zcio_ring *r);

ZCIO_API int64_t zcio_ring_write(zcio_ring *r, const void *src, size_t n);
ZCIO_API int64_t zcio_ring_read (zcio_ring *r, void *dst, size_t n);
ZCIO_API size_t  zcio_ring_available_read (const zcio_ring *r);
ZCIO_API size_t  zcio_ring_available_write(const zcio_ring *r);

/* Adapt a ring as a generic zcio_stream (borrows the ring; free the stream
 * before the ring, or pass take_ownership to transfer it). */
ZCIO_API ZCIO_NODISCARD zcio_stream *zcio_ring_as_stream(zcio_ring *r, bool take_ownership);

#ifdef __cplusplus
}
#endif

#endif /* ZCIO_RING_H */
