/* zcio/serial.h - bit/byte serializer over a zcio_stream.
 *
 * Direct port of the C++ `Serial` class. A serializer reads/writes either whole
 * bytes or individual bits (MSB-of-a-byte packing identical to the original),
 * on top of any zcio_stream. Three specialized modes mirror the original:
 *   - count mode  : tallies how many bytes *would* be written (sizing pass)
 *   - buffer mode : reads/writes a caller-owned fixed memory block, O(1)/op
 *   - stream mode : delegates to a backing zcio_stream
 *
 * Typed read/write helpers replace C++'s templated operator<< / operator>>.
 * Endianness is host-native (matching the original's trivially-copyable path).
 */
#ifndef ZCIO_SERIAL_H
#define ZCIO_SERIAL_H

#include "zcio/types.h"
#include "zcio/stream.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zcio_serial zcio_serial;

/* --- construction ------------------------------------------------------- */

/* Stream-backed serializer. If `bit_stream` is true, byte ops are bit-packed.
 * The serial does NOT take ownership of `s` unless `take_ownership` is true. */
ZCIO_API ZCIO_NODISCARD zcio_serial *
zcio_serial_new(zcio_stream *s, bool bit_stream, bool take_ownership);

/* Count-mode serializer: writes are tallied, not stored. */
ZCIO_API ZCIO_NODISCARD zcio_serial *zcio_serial_new_count(void);

/* Buffer-mode serializer over caller-owned memory of `size` bytes. */
ZCIO_API ZCIO_NODISCARD zcio_serial *
zcio_serial_new_buffer(void *buffer, int64_t size, bool bit_stream);

ZCIO_API void zcio_serial_free(zcio_serial *z);

/* --- bulk byte I/O ------------------------------------------------------ */
ZCIO_API int64_t zcio_serial_write_bytes(zcio_serial *z, const void *src, size_t size);
ZCIO_API int64_t zcio_serial_read_bytes (zcio_serial *z, void *dst, size_t size);

/* --- single byte / bit -------------------------------------------------- */
ZCIO_API void    zcio_serial_write_byte(zcio_serial *z, uint8_t byte);
ZCIO_API uint8_t zcio_serial_read_byte (zcio_serial *z);
ZCIO_API void    zcio_serial_write_bit (zcio_serial *z, bool bit);
ZCIO_API bool    zcio_serial_read_bit  (zcio_serial *z);

/* Pack/unpack `count` bits from/into a byte array `bits` starting at bit
 * index `index`. Each element of `bits` holds one bit in its LSB (as in the
 * original BitContainer contract). Requires a bit-stream serial. */
ZCIO_API void zcio_serial_write_bits(zcio_serial *z, const uint8_t *bits, size_t index, size_t count);
ZCIO_API void zcio_serial_read_bits (zcio_serial *z, uint8_t *bits, size_t index, size_t count);

/* --- fixed-width typed helpers (host-endian, replace operator<< / >>) ---- */
#define ZCIO_SERIAL_SCALAR(SUF, T)                                       \
    ZCIO_API void zcio_serial_write_##SUF(zcio_serial *z, T v);          \
    ZCIO_API T    zcio_serial_read_##SUF (zcio_serial *z);
ZCIO_SERIAL_SCALAR(i8,  int8_t)
ZCIO_SERIAL_SCALAR(u8,  uint8_t)
ZCIO_SERIAL_SCALAR(i16, int16_t)
ZCIO_SERIAL_SCALAR(u16, uint16_t)
ZCIO_SERIAL_SCALAR(i32, int32_t)
ZCIO_SERIAL_SCALAR(u32, uint32_t)
ZCIO_SERIAL_SCALAR(i64, int64_t)
ZCIO_SERIAL_SCALAR(u64, uint64_t)
ZCIO_SERIAL_SCALAR(f32, float)
ZCIO_SERIAL_SCALAR(f64, double)
#undef ZCIO_SERIAL_SCALAR

/* Length-prefixed string (u64 length + bytes), mirroring the std::string path. */
ZCIO_API void  zcio_serial_write_str(zcio_serial *z, const char *s, size_t len);
/* Reads a length-prefixed string into a freshly malloc'd, NUL-terminated buffer.
 * Caller frees with zcio_free. *out_len receives the byte length (may be NULL). */
ZCIO_API char *zcio_serial_read_str(zcio_serial *z, size_t *out_len);

/* --- positioning & status ---------------------------------------------- */
ZCIO_API int64_t zcio_serial_write_pos(zcio_serial *z);
ZCIO_API int64_t zcio_serial_read_pos (zcio_serial *z);
ZCIO_API void    zcio_serial_set_write_pos(zcio_serial *z, size_t index);
ZCIO_API void    zcio_serial_set_read_pos (zcio_serial *z, size_t index);
ZCIO_API int64_t zcio_serial_write_len(zcio_serial *z);
ZCIO_API int64_t zcio_serial_read_len (zcio_serial *z);

/* Flush any partial write-bit byte and sync the underlying stream. */
ZCIO_API void zcio_serial_synchronize(zcio_serial *z);

ZCIO_API bool   zcio_serial_read_eof  (zcio_serial *z);
ZCIO_API bool   zcio_serial_read_empty(zcio_serial *z);
ZCIO_API bool   zcio_serial_short_read(zcio_serial *z); /* last read < requested */
ZCIO_API size_t zcio_serial_last_read (zcio_serial *z);
ZCIO_API void   zcio_serial_clear_read(zcio_serial *z);

/* Free memory returned by zcio_serial_read_str (and other zcio_*_str helpers). */
ZCIO_API void zcio_free(void *p);

#ifdef __cplusplus
}
#endif

#endif /* ZCIO_SERIAL_H */
