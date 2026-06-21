/* zcio/membuf.h - fixed memory view + byte-counting streams.
 *
 * memory: a non-owning view over a caller buffer (port of memory_streambuf).
 * counting: tallies bytes read/written, optionally over a buffer
 *           (port of counting_streambuf). Both are O(1) per operation.
 */
#ifndef ZCIO_MEMBUF_H
#define ZCIO_MEMBUF_H

#include "zcio/types.h"
#include "zcio/stream.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Stream over a fixed, caller-owned memory region. Read and write cursors are
 * independent. The returned stream borrows `data`; it never frees it. */
ZCIO_API ZCIO_NODISCARD zcio_stream *zcio_memory_stream(void *data, size_t size);

/* Counting stream. If `data`/`size` are non-NULL, bytes pass through the buffer;
 * otherwise it is a pure sink/sizer. Query totals with the accessors below. */
ZCIO_API ZCIO_NODISCARD zcio_stream *zcio_counting_stream(void *data, size_t size);
ZCIO_API int64_t zcio_counting_bytes_written(zcio_stream *s);
ZCIO_API int64_t zcio_counting_bytes_read   (zcio_stream *s);

#ifdef __cplusplus
}
#endif

#endif /* ZCIO_MEMBUF_H */
