/* src/serial.c - bit/byte serializer (port of the C++ Serial class).
 *
 * Modes (mutually exclusive):
 *   - stream : delegates byte I/O to a backing zcio_stream
 *   - count  : tallies bytes that would be written (sizing pass)
 *   - buffer : reads/writes a caller-owned fixed memory block, O(1)/op
 * Bit packing matches the original: bits fill a byte LSB-first; writeByte while
 * mid-bit flushes through writeBit so byte/bit writes interleave correctly. */
#include "zcio/serial.h"
#include "internal.h"

typedef enum { MODE_STREAM, MODE_COUNT, MODE_BUFFER } serial_mode;

struct zcio_serial {
    serial_mode mode;
    zcio_stream *stream;
    bool         owns_stream;
    bool         bit_stream;

    /* bit cursors */
    uint8_t cur_read_byte;
    uint8_t bits_read;     /* 0..8, 8 means "need a fresh byte" */
    uint8_t cur_write_byte;
    uint8_t bits_written;  /* 0..8 */

    /* count mode */
    uint64_t count_total;
    uint64_t count_wpos;
    uint64_t count_rpos;

    /* buffer mode */
    char   *buf;
    int64_t buf_size;
    int64_t buf_rpos;
    int64_t buf_wpos;

    /* status flags */
    bool   read_eof;
    bool   read_empty;
    bool   short_read;
    size_t last_read;
};

/* --- construction ------------------------------------------------------- */
zcio_serial *zcio_serial_new(zcio_stream *s, bool bit_stream, bool take_ownership) {
    if (!s) return NULL;
    zcio_serial *z = (zcio_serial *)zcio_xcalloc(1, sizeof *z);
    if (!z) return NULL;
    z->mode = MODE_STREAM;
    z->stream = s;
    z->owns_stream = take_ownership;
    z->bit_stream = bit_stream;
    z->bits_read = 8;
    return z;
}

zcio_serial *zcio_serial_new_count(void) {
    zcio_serial *z = (zcio_serial *)zcio_xcalloc(1, sizeof *z);
    if (!z) return NULL;
    z->mode = MODE_COUNT;
    z->bits_read = 8;
    return z;
}

zcio_serial *zcio_serial_new_buffer(void *buffer, int64_t size, bool bit_stream) {
    if (!buffer || size < 0) return NULL;
    zcio_serial *z = (zcio_serial *)zcio_xcalloc(1, sizeof *z);
    if (!z) return NULL;
    z->mode = MODE_BUFFER;
    z->buf = (char *)buffer;
    z->buf_size = size;
    z->bit_stream = bit_stream;
    z->bits_read = 8;
    return z;
}

void zcio_serial_free(zcio_serial *z) {
    if (!z) return;
    if (z->owns_stream) zcio_stream_free(z->stream);
    free(z);
}

/* --- raw byte path (non bit-packed) ------------------------------------- */
static int64_t raw_write(zcio_serial *z, const char *src, size_t size) {
    switch (z->mode) {
        case MODE_COUNT:
            z->count_total += size;
            z->count_wpos += size;
            return (int64_t)size;
        case MODE_BUFFER:
            if (z->buf_wpos <= z->buf_size - (int64_t)size) {
                memcpy(z->buf + z->buf_wpos, src, size);
                z->buf_wpos += (int64_t)size;
            }
            return (int64_t)size;
        case MODE_STREAM:
        default:
            return zcio_write_full(z->stream, src, size);
    }
}

static int64_t raw_read(zcio_serial *z, char *dst, size_t size) {
    switch (z->mode) {
        case MODE_COUNT:
            z->count_rpos += size;
            z->last_read = size;
            return (int64_t)size;
        case MODE_BUFFER:
            if (z->buf_rpos <= z->buf_size - (int64_t)size) {
                memcpy(dst, z->buf + z->buf_rpos, size);
                z->buf_rpos += (int64_t)size;
                z->last_read = size;
                return (int64_t)size;
            }
            z->last_read = 0;
            z->read_eof = true;
            return 0;
        case MODE_STREAM:
        default: {
            int64_t r = zcio_read_full(z->stream, dst, size);
            if (r < 0) { z->last_read = 0; return 0; }
            z->last_read = (size_t)r;
            if ((size_t)r != size) {
                z->short_read = true;
                if (zcio_stream_eof(z->stream)) z->read_eof = true;
                else z->read_empty = true;
            } else {
                z->read_empty = z->read_eof = false;
            }
            return r;
        }
    }
}

/* --- single byte / bit -------------------------------------------------- */
void zcio_serial_write_byte(zcio_serial *z, uint8_t byte) {
    if (z->bit_stream && z->bits_written > 0 && z->bits_written < 8) {
        for (int e = 0; e < 8; e++) zcio_serial_write_bit(z, (byte >> e) & 1);
        return;
    }
    raw_write(z, (const char *)&byte, 1);
    z->cur_write_byte = 0;
    z->bits_written = 0;
}

uint8_t zcio_serial_read_byte(zcio_serial *z) {
    if (z->bit_stream && z->bits_read > 0 && z->bits_read < 8) {
        uint8_t byte = 0;
        for (int e = 0; e < 8; e++) byte |= (uint8_t)(zcio_serial_read_bit(z) << e);
        return byte;
    }
    char b = 0;
    raw_read(z, &b, 1);
    z->cur_read_byte = (uint8_t)b;
    z->bits_read = 0;
    return z->cur_read_byte;
}

void zcio_serial_write_bit(zcio_serial *z, bool bit) {
    z->cur_write_byte |= (uint8_t)(bit << z->bits_written);
    z->bits_written++;
    if (z->bits_written == 8) zcio_serial_write_byte(z, z->cur_write_byte);
}

bool zcio_serial_read_bit(zcio_serial *z) {
    if (z->bits_read == 0 || z->bits_read == 8) {
        char b = 0;
        raw_read(z, &b, 1);
        z->cur_read_byte = (uint8_t)b;
        z->bits_read = 0;
    }
    return (z->cur_read_byte >> (z->bits_read++)) & 1;
}

/* --- bulk byte I/O ------------------------------------------------------ */
int64_t zcio_serial_write_bytes(zcio_serial *z, const void *src, size_t size) {
    if (!z || !src) return ZCIO_ERR_INVALID_ARG;
    if (z->bit_stream && z->mode == MODE_STREAM) {
        const uint8_t *p = (const uint8_t *)src;
        for (size_t i = 0; i < size; i++) zcio_serial_write_byte(z, p[i]);
        return (int64_t)size;
    }
    return raw_write(z, (const char *)src, size);
}

int64_t zcio_serial_read_bytes(zcio_serial *z, void *dst, size_t size) {
    if (!z || !dst) return ZCIO_ERR_INVALID_ARG;
    if (z->bit_stream && z->mode == MODE_STREAM) {
        uint8_t *p = (uint8_t *)dst;
        for (size_t i = 0; i < size; i++) p[i] = zcio_serial_read_byte(z);
        z->last_read = size;
        return (int64_t)size;
    }
    return raw_read(z, (char *)dst, size);
}

/* --- bit arrays --------------------------------------------------------- */
void zcio_serial_write_bits(zcio_serial *z, const uint8_t *bits, size_t index, size_t count) {
    if (!z->bit_stream) { zcio_set_error_("write_bits requires a bit stream"); return; }
    for (size_t i = 0; i < count; i++) zcio_serial_write_bit(z, bits[index + i] & 1);
}

void zcio_serial_read_bits(zcio_serial *z, uint8_t *bits, size_t index, size_t count) {
    if (!z->bit_stream) { zcio_set_error_("read_bits requires a bit stream"); return; }
    for (size_t i = 0; i < count; i++) bits[index + i] = (uint8_t)zcio_serial_read_bit(z);
}

/* --- typed scalars (host-endian) ---------------------------------------- */
#define ZCIO_SERIAL_SCALAR(SUF, T)                                            \
    void zcio_serial_write_##SUF(zcio_serial *z, T v) {                       \
        zcio_serial_write_bytes(z, &v, sizeof v);                             \
    }                                                                          \
    T zcio_serial_read_##SUF(zcio_serial *z) {                                \
        T v = 0; zcio_serial_read_bytes(z, &v, sizeof v); return v;           \
    }
ZCIO_SERIAL_SCALAR(i8,  int8_t)
ZCIO_SERIAL_SCALAR(u8,  uint8_t)
ZCIO_SERIAL_SCALAR(i16, int16_t)
ZCIO_SERIAL_SCALAR(u16, uint16_t)
ZCIO_SERIAL_SCALAR(i32, int32_t)
ZCIO_SERIAL_SCALAR(u32, uint32_t)
ZCIO_SERIAL_SCALAR(i64, int64_t)
ZCIO_SERIAL_SCALAR(u64, uint64_t)
#undef ZCIO_SERIAL_SCALAR
/* float/double can't be zero-initialized via "= 0" portably as bit pattern but
 * 0.0 is fine; keep them explicit to avoid the macro's integer init. */
void zcio_serial_write_f32(zcio_serial *z, float v)  { zcio_serial_write_bytes(z, &v, sizeof v); }
float zcio_serial_read_f32(zcio_serial *z) { float v = 0; zcio_serial_read_bytes(z, &v, sizeof v); return v; }
void zcio_serial_write_f64(zcio_serial *z, double v) { zcio_serial_write_bytes(z, &v, sizeof v); }
double zcio_serial_read_f64(zcio_serial *z) { double v = 0; zcio_serial_read_bytes(z, &v, sizeof v); return v; }

/* --- length-prefixed string --------------------------------------------- */
void zcio_serial_write_str(zcio_serial *z, const char *s, size_t len) {
    uint64_t n = (uint64_t)len;
    zcio_serial_write_bytes(z, &n, sizeof n);
    if (len) zcio_serial_write_bytes(z, s, len);
}

char *zcio_serial_read_str(zcio_serial *z, size_t *out_len) {
    uint64_t n = 0;
    if (zcio_serial_read_bytes(z, &n, sizeof n) != (int64_t)sizeof n) return NULL;
    char *out = (char *)malloc((size_t)n + 1);
    if (!out) return NULL;
    if (n) {
        int64_t r = zcio_serial_read_bytes(z, out, (size_t)n);
        if (r < (int64_t)n) { /* short read: still NUL-terminate what we got */ }
    }
    out[n] = '\0';
    if (out_len) *out_len = (size_t)n;
    return out;
}

/* --- positioning & status ---------------------------------------------- */
int64_t zcio_serial_write_pos(zcio_serial *z) {
    switch (z->mode) {
        case MODE_COUNT:  return (int64_t)z->count_wpos;
        case MODE_BUFFER: return z->buf_wpos;
        default:          return zcio_seek(z->stream, 0, ZCIO_SEEK_CUR, ZCIO_SEEK_WRITE);
    }
}
int64_t zcio_serial_read_pos(zcio_serial *z) {
    switch (z->mode) {
        case MODE_COUNT:  return (int64_t)z->count_rpos;
        case MODE_BUFFER: return z->buf_rpos;
        default:          return zcio_seek(z->stream, 0, ZCIO_SEEK_CUR, ZCIO_SEEK_READ);
    }
}
void zcio_serial_set_write_pos(zcio_serial *z, size_t i) {
    switch (z->mode) {
        case MODE_COUNT:  z->count_wpos = i; break;
        case MODE_BUFFER: z->buf_wpos = (int64_t)i; break;
        default:          zcio_seek(z->stream, (int64_t)i, ZCIO_SEEK_SET, ZCIO_SEEK_WRITE); break;
    }
}
void zcio_serial_set_read_pos(zcio_serial *z, size_t i) {
    switch (z->mode) {
        case MODE_COUNT:  z->count_rpos = i; break;
        case MODE_BUFFER: z->buf_rpos = (int64_t)i; break;
        default:          zcio_seek(z->stream, (int64_t)i, ZCIO_SEEK_SET, ZCIO_SEEK_READ); break;
    }
}
int64_t zcio_serial_write_len(zcio_serial *z) {
    if (z->mode == MODE_COUNT)  return (int64_t)z->count_total;
    if (z->mode == MODE_BUFFER) return z->buf_size;
    return zcio_seek(z->stream, 0, ZCIO_SEEK_END, ZCIO_SEEK_WRITE);
}
int64_t zcio_serial_read_len(zcio_serial *z) {
    if (z->mode == MODE_COUNT)  return (int64_t)z->count_total;
    if (z->mode == MODE_BUFFER) return z->buf_size;
    return zcio_available(z->stream);
}

void zcio_serial_synchronize(zcio_serial *z) {
    if (z->bits_written > 0 && z->bits_written < 8) {
        z->bits_written = 8;
        zcio_serial_write_byte(z, z->cur_write_byte);
    }
    if (z->mode == MODE_STREAM) zcio_flush(z->stream);
}

bool   zcio_serial_read_eof(zcio_serial *z)   { return z->read_eof; }
bool   zcio_serial_read_empty(zcio_serial *z) { return z->read_empty; }
bool   zcio_serial_short_read(zcio_serial *z) { bool v = z->short_read; z->short_read = false; return v; }
size_t zcio_serial_last_read(zcio_serial *z)  { return z->last_read; }
void   zcio_serial_clear_read(zcio_serial *z) { z->read_eof = z->read_empty = z->short_read = false; }
