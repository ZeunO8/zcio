/* src/hpack.c - HPACK (RFC 7541) header compression.
 *
 * Decode side keeps a bounded FIFO dynamic table; encode side is deliberately
 * STATELESS (literal-without-indexing, static name refs, no Huffman) so a
 * server encoder can never be driven out of sync with a peer decoder. The
 * prefixed-integer and Huffman primitives here are shared verbatim with QPACK.
 *
 * Every length that comes off the wire is bounds-checked against the block and
 * the caller's caps BEFORE it drives a copy or an allocation, and all integer
 * arithmetic on wire values is overflow-checked (see zhp_int_decode_). Parsing
 * is single-pass and linear in the input; no recursion on attacker bytes.
 */
#include "http_internal.h"

#include <string.h>

/* ========================================================================= *
 *  Prefixed integers (RFC 7541 sec. 5.1) - shared with QPACK
 * ========================================================================= */

int zhp_int_decode_(const uint8_t *p, size_t n, unsigned prefix_bits, uint64_t *out) {
    if (n == 0)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: truncated integer");

    uint64_t prefix_max = ((uint64_t)1 << prefix_bits) - 1;
    uint64_t v = (uint64_t)(p[0] & prefix_max);
    if (v < prefix_max) {          /* fits entirely in the prefix */
        *out = v;
        return 1;
    }

    /* Continuation octets carry 7 value bits each, MSB = "more follows". A
     * value capped at ZHP_INT_MAX (2^24) needs at most 4 of them; a 5th octet
     * (shift 28) cannot fit under the cap, so rejecting it there also bounds
     * `shift` well under 64 and defeats an all-continuation-padding DoS. */
    size_t i = 1;
    unsigned shift = 0;
    for (;;) {
        if (i >= n)
            return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: truncated integer");
        uint8_t b = p[i++];
        v += (uint64_t)(b & 0x7f) << shift;    /* shift <= 21 here, no UB */
        if (v > ZHP_INT_MAX)
            return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: integer exceeds cap");
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift >= 28)
            return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: integer too long");
    }
    *out = v;
    return (int)i;
}

int zhp_int_encode_(zhs_buf *out, unsigned prefix_bits, uint8_t flags, uint64_t v) {
    uint8_t prefix_max = (uint8_t)(((unsigned)1 << prefix_bits) - 1u);
    if (v < prefix_max)
        return zhs_buf_append_u8_(out, (uint8_t)(flags | (uint8_t)v));

    int r = zhs_buf_append_u8_(out, (uint8_t)(flags | prefix_max));
    if (r != ZCIO_OK) return r;
    v -= prefix_max;
    while (v >= 128) {
        r = zhs_buf_append_u8_(out, (uint8_t)(0x80 | (v & 0x7f)));
        if (r != ZCIO_OK) return r;
        v >>= 7;
    }
    return zhs_buf_append_u8_(out, (uint8_t)v);
}

/* ========================================================================= *
 *  Huffman (RFC 7541 Appendix B) - shared with QPACK
 * ========================================================================= *
 * Canonical decode via zlib-style count[]/symbol[] tables (see puff.c). These
 * are pure const data generated from the RFC's per-symbol {code,length} table
 * and verified against the RFC examples: HUFF_COUNT[len] is the number of
 * symbols of code length `len`, HUFF_SYMBOL is every symbol in canonical
 * (length, then code) order. Symbol 256 is EOS and must never decode to output.
 */
#define ZHP_HUFF_MAXBITS 30

static const uint16_t HUFF_COUNT[ZHP_HUFF_MAXBITS + 1] = {
    0, 0, 0, 0, 0, 10, 26, 32, 6, 0, 5, 3, 2, 6, 2, 3, 0, 0, 0, 3, 8, 13, 26,
    29, 12, 4, 15, 19, 29, 0, 4,
};

static const uint16_t HUFF_SYMBOL[257] = {
    48, 49, 50, 97, 99, 101, 105, 111, 115, 116, 32, 37, 45, 46, 47, 51, 52,
    53, 54, 55, 56, 57, 61, 65, 95, 98, 100, 102, 103, 104, 108, 109, 110,
    112, 114, 117, 58, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78,
    79, 80, 81, 82, 83, 84, 85, 86, 87, 89, 106, 107, 113, 118, 119, 120,
    121, 122, 38, 42, 44, 59, 88, 90, 33, 34, 40, 41, 63, 39, 43, 124, 35,
    62, 0, 36, 64, 91, 93, 126, 94, 125, 60, 96, 123, 92, 195, 208, 128, 130,
    131, 162, 184, 194, 224, 226, 153, 161, 167, 172, 176, 177, 179, 209,
    216, 217, 227, 229, 230, 129, 132, 133, 134, 136, 146, 154, 156, 160,
    163, 164, 169, 170, 173, 178, 181, 185, 186, 187, 189, 190, 196, 198,
    228, 232, 233, 1, 135, 137, 138, 139, 140, 141, 143, 147, 149, 150, 151,
    152, 155, 157, 158, 165, 166, 168, 174, 175, 180, 182, 183, 188, 191,
    197, 231, 239, 9, 142, 144, 145, 148, 159, 171, 206, 215, 225, 236, 237,
    199, 207, 234, 235, 192, 193, 200, 201, 202, 205, 210, 213, 218, 219,
    238, 240, 242, 243, 255, 203, 204, 211, 212, 214, 221, 222, 223, 241,
    244, 245, 246, 247, 248, 250, 251, 252, 253, 254, 2, 3, 4, 5, 6, 7, 8,
    11, 12, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 127, 220, 249, 10, 13, 22, 256,
};

static inline unsigned huff_bit(const uint8_t *in, size_t pos) {
    return (in[pos >> 3] >> (7u - (pos & 7u))) & 1u;
}

/* Decode one canonical symbol starting at *bitpos. Returns 0 and writes
 * *sym (>=0) on success, 1 if the input ran out mid-code (trailing padding),
 * -1 if no code matched within MAXBITS (impossible for this complete table). */
static int huff_symbol(const uint8_t *in, size_t total_bits, size_t *bitpos, int *sym) {
    uint32_t code = 0, first = 0;
    size_t index = 0;
    for (unsigned len = 1; len <= ZHP_HUFF_MAXBITS; len++) {
        if (*bitpos >= total_bits) return 1;   /* out of bits -> padding */
        code = (code << 1) | huff_bit(in, (*bitpos)++);
        uint32_t cnt = HUFF_COUNT[len];
        if (code < first + cnt) {
            *sym = HUFF_SYMBOL[index + (code - first)];
            return 0;
        }
        index += cnt;
        first = (first + cnt) << 1;
    }
    return -1;
}

int zhp_huff_decode_(const uint8_t *in, size_t n, zhs_buf *out, size_t max_out) {
    if (n > SIZE_MAX / 8)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: huffman input too large");
    size_t total_bits = n * 8;
    size_t bitpos = 0, produced = 0;

    while (bitpos < total_bits) {
        size_t start = bitpos;
        int sym = -1;
        int r = huff_symbol(in, total_bits, &bitpos, &sym);
        if (r == 1) {
            /* Remaining bits are EOS padding: at most 7 bits, all ones. */
            size_t pad = total_bits - start;
            if (pad > 7)
                return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: huffman padding too long");
            for (size_t bp = start; bp < total_bits; bp++)
                if (!huff_bit(in, bp))
                    return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: huffman padding not all ones");
            break;
        }
        if (r < 0)
            return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: invalid huffman code");
        if (sym == 256)   /* EOS must never appear as a decoded value */
            return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: huffman EOS symbol");
        if (produced >= max_out)
            return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: huffman output exceeds limit");
        int a = zhs_buf_append_u8_(out, (uint8_t)sym);
        if (a != ZCIO_OK) return a;   /* NOMEM */
        produced++;
    }
    return ZCIO_OK;
}

/* ========================================================================= *
 *  Static table (RFC 7541 Appendix A) - 61 entries, 1-indexed on the wire
 * ========================================================================= */

static const struct { const char *name; const char *value; } HPACK_STATIC[] = {
    { ":authority", "" }, { ":method", "GET" }, { ":method", "POST" },
    { ":path", "/" }, { ":path", "/index.html" }, { ":scheme", "http" },
    { ":scheme", "https" }, { ":status", "200" }, { ":status", "204" },
    { ":status", "206" }, { ":status", "304" }, { ":status", "400" },
    { ":status", "404" }, { ":status", "500" }, { "accept-charset", "" },
    { "accept-encoding", "gzip, deflate" }, { "accept-language", "" },
    { "accept-ranges", "" }, { "accept", "" },
    { "access-control-allow-origin", "" }, { "age", "" }, { "allow", "" },
    { "authorization", "" }, { "cache-control", "" },
    { "content-disposition", "" }, { "content-encoding", "" },
    { "content-language", "" }, { "content-length", "" },
    { "content-location", "" }, { "content-range", "" }, { "content-type", "" },
    { "cookie", "" }, { "date", "" }, { "etag", "" }, { "expect", "" },
    { "expires", "" }, { "from", "" }, { "host", "" }, { "if-match", "" },
    { "if-modified-since", "" }, { "if-none-match", "" }, { "if-range", "" },
    { "if-unmodified-since", "" }, { "last-modified", "" }, { "link", "" },
    { "location", "" }, { "max-forwards", "" }, { "proxy-authenticate", "" },
    { "proxy-authorization", "" }, { "range", "" }, { "referer", "" },
    { "refresh", "" }, { "retry-after", "" }, { "server", "" },
    { "set-cookie", "" }, { "strict-transport-security", "" },
    { "transfer-encoding", "" }, { "user-agent", "" }, { "vary", "" },
    { "via", "" }, { "www-authenticate", "" },
};
#define HPACK_STATIC_N ((size_t)(sizeof HPACK_STATIC / sizeof HPACK_STATIC[0]))

/* ASCII case-insensitive equality (header names in the tables are lowercase). */
static bool ci_eq(const char *a, const char *b) {
    for (;; a++, b++) {
        unsigned char ca = (unsigned char)*a, cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 32);
        if (ca != cb) return false;
        if (!ca) return true;
    }
}

/* First static index (1-based) whose name matches, or 0. */
static int hpack_static_name_index(const char *name) {
    for (size_t i = 0; i < HPACK_STATIC_N; i++)
        if (ci_eq(HPACK_STATIC[i].name, name)) return (int)(i + 1);
    return 0;
}

/* ========================================================================= *
 *  Dynamic table (decoder only): FIFO deque, newest at tail-1
 * ========================================================================= *
 * `e[head, tail)` are the live entries oldest-first; the newest (lowest wire
 * index) sits at e[tail-1]. Each entry owns its two heap strings. Cost per
 * RFC 7541 sec. 4.1 is name+value+32. The array grows/compacts like zhs_buf so
 * a long-lived connection cannot accrete a dead prefix.
 */
typedef struct zhp_ent { char *name; size_t nlen; char *val; size_t vlen; } zhp_ent;

struct zhp_dec {
    size_t   max;    /* current max table size (bytes)                        */
    size_t   used;   /* current accounted size (sum of costs)                 */
    zhp_ent *e;
    size_t   head, tail, cap;
};

zhp_dec *zhp_dec_new_(size_t max_table_bytes) {
    zhp_dec *d = (zhp_dec *)zcio_xcalloc(1, sizeof *d);
    if (!d) return NULL;
    /* Clamp the initial max as well (not just later size-updates), so a caller
     * passing an over-large capacity can never grow the table past our cap. */
    d->max = max_table_bytes > ZHP_DEC_TABLE_MAX ? ZHP_DEC_TABLE_MAX : max_table_bytes;
    return d;
}

void zhp_dec_free_(zhp_dec *d) {
    if (!d) return;
    for (size_t i = d->head; i < d->tail; i++) {
        free(d->e[i].name);
        free(d->e[i].val);
    }
    free(d->e);
    free(d);
}

static void dec_evict(zhp_dec *d) {           /* drop the oldest entry */
    zhp_ent *o = &d->e[d->head++];
    d->used -= o->nlen + o->vlen + 32;
    free(o->name);
    free(o->val);
    if (d->head == d->tail) d->head = d->tail = 0;
}

static void dec_set_max(zhp_dec *d, size_t newmax) {
    d->max = newmax;
    while (d->used > d->max && d->head < d->tail) dec_evict(d);
}

/* Ensure e[tail] is writable (compact, else grow). */
static int dec_reserve(zhp_dec *d) {
    if (d->tail < d->cap) return ZCIO_OK;
    if (d->head > 0) {
        size_t n = d->tail - d->head;
        if (n) memmove(d->e, d->e + d->head, n * sizeof *d->e);
        d->head = 0;
        d->tail = n;
        if (d->tail < d->cap) return ZCIO_OK;
    }
    size_t ncap = d->cap ? d->cap * 2 : 16;
    zhp_ent *ne = (zhp_ent *)realloc(d->e, ncap * sizeof *ne);
    if (!ne) return ZCIO_ERR_NOMEM;
    d->e = ne;
    d->cap = ncap;
    return ZCIO_OK;
}

/* Insert (name,value) as the newest entry, evicting oldest to fit. name/value
 * are COPIED before any eviction because they may alias the very entry being
 * evicted (RFC 7541 permits a self-referential add). An entry larger than the
 * whole table empties it and is not stored - not an error (sec. 4.4). */
static int dec_add(zhp_dec *d, const char *name, size_t nlen,
                   const char *val, size_t vlen) {
    size_t cost = nlen + vlen + 32;   /* nlen,vlen <= ZHP_INT_MAX: no overflow */
    char *nm = (char *)zcio_xmalloc(nlen);
    char *vv = (char *)zcio_xmalloc(vlen);
    if (!nm || !vv) { free(nm); free(vv); return ZCIO_ERR_NOMEM; }
    if (nlen) memcpy(nm, name, nlen);
    if (vlen) memcpy(vv, val, vlen);

    while (d->used + cost > d->max && d->head < d->tail) dec_evict(d);
    if (cost > d->max) { free(nm); free(vv); return ZCIO_OK; } /* never fits */
    if (dec_reserve(d) != ZCIO_OK) { free(nm); free(vv); return ZCIO_ERR_NOMEM; }

    d->e[d->tail].name = nm; d->e[d->tail].nlen = nlen;
    d->e[d->tail].val  = vv; d->e[d->tail].vlen = vlen;
    d->tail++;
    d->used += cost;
    return ZCIO_OK;
}

/* Resolve a wire index to a table entry. Static: 1..N. Dynamic: N+1.. maps to
 * newest.. . vl may be NULL (name-only reference). Borrowed pointers, valid
 * until the next table mutation. */
static int hpack_resolve(zhp_dec *d, uint64_t idx,
                         const char **nm, size_t *nl,
                         const char **vl, size_t *vln) {
    if (idx == 0)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: index 0");
    if (idx <= HPACK_STATIC_N) {
        *nm = HPACK_STATIC[idx - 1].name;
        *nl = strlen(*nm);
        if (vl) { *vl = HPACK_STATIC[idx - 1].value; *vln = strlen(*vl); }
        return ZCIO_OK;
    }
    uint64_t di = idx - HPACK_STATIC_N - 1;   /* 0 = newest */
    size_t   cnt = d->tail - d->head;
    if (di >= cnt)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: index out of range");
    zhp_ent *e = &d->e[d->tail - 1 - (size_t)di];
    *nm = e->name;
    *nl = e->nlen;
    if (vl) { *vl = e->val; *vln = e->vlen; }
    return ZCIO_OK;
}

/* ========================================================================= *
 *  Field-representation decode (RFC 7541 sec. 6)
 * ========================================================================= */

/* Read a length-prefixed string literal (7-bit prefix, top bit = Huffman).
 * On Huffman input decodes into `scratch` (reset first) and points *out at it;
 * otherwise *out borrows the block directly. Length is bounds-checked against
 * both the remaining block and max_out before any copy/decode. */
static int hpack_string(const uint8_t *block, size_t len, size_t *pos,
                        size_t max_out, zhs_buf *scratch,
                        const char **out, size_t *outlen) {
    if (*pos >= len)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: truncated string");
    bool huff = (block[*pos] & 0x80) != 0;

    uint64_t slen;
    int c = zhp_int_decode_(block + *pos, len - *pos, 7, &slen);
    if (c < 0) return c;
    *pos += (size_t)c;
    if (slen > (uint64_t)(len - *pos))
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: string exceeds block");

    const uint8_t *s = block + *pos;
    *pos += (size_t)slen;
    if (huff) {
        zhs_buf_reset_(scratch);
        int r = zhp_huff_decode_(s, (size_t)slen, scratch, max_out);
        if (r != ZCIO_OK) return r;
        *out = scratch->data ? (const char *)scratch->data : "";
        *outlen = scratch->len;
    } else {
        if ((size_t)slen > max_out)
            return zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: string exceeds limit");
        *out = (const char *)s;
        *outlen = (size_t)slen;
    }
    return ZCIO_OK;
}

/* Literal representation body: an (index | 0) name reference followed by a
 * string-literal value. prefix_bits selects the name-index prefix width
 * (6 = incremental indexing, 4 = without / never indexed). */
static int hpack_literal(zhp_dec *d, const uint8_t *block, size_t len, size_t *pos,
                         unsigned prefix_bits, size_t max_out,
                         zhs_buf *nbuf, zhs_buf *vbuf,
                         const char **nm, size_t *nl,
                         const char **vl, size_t *vln) {
    uint64_t nidx;
    int c = zhp_int_decode_(block + *pos, len - *pos, prefix_bits, &nidx);
    if (c < 0) return c;
    *pos += (size_t)c;
    if (nidx == 0) {
        int r = hpack_string(block, len, pos, max_out, nbuf, nm, nl);
        if (r != ZCIO_OK) return r;
    } else {
        int r = hpack_resolve(d, nidx, nm, nl, NULL, NULL);
        if (r != ZCIO_OK) return r;
    }
    return hpack_string(block, len, pos, max_out, vbuf, vl, vln);
}

int zhp_decode_(zhp_dec *d, const uint8_t *block, size_t len,
                size_t max_decoded_bytes, zhp_emit_fn emit, void *u) {
    size_t   pos = 0;
    size_t   decoded = 0;        /* running sum of emitted name+value lengths */
    bool     seen_field = false; /* a size update after this point is illegal */
    zhs_buf  nbuf = {0}, vbuf = {0};  /* Huffman scratch (name / value)       */
    int      rc = ZCIO_OK;

    while (pos < len) {
        uint8_t     b   = block[pos];
        const char *nm  = NULL, *vl = NULL;
        size_t      nl  = 0, vln = 0;
        bool        add = false;

        if (b & 0x80) {                     /* 6.1 Indexed Header Field */
            uint64_t idx;
            int c = zhp_int_decode_(block + pos, len - pos, 7, &idx);
            if (c < 0) { rc = c; goto done; }
            pos += (size_t)c;
            if ((rc = hpack_resolve(d, idx, &nm, &nl, &vl, &vln)) != ZCIO_OK) goto done;
        } else if (b & 0x40) {              /* 6.2.1 Literal, incremental idx */
            rc = hpack_literal(d, block, len, &pos, 6, max_decoded_bytes,
                               &nbuf, &vbuf, &nm, &nl, &vl, &vln);
            if (rc != ZCIO_OK) goto done;
            add = true;
        } else if (b & 0x20) {              /* 6.3 Dynamic Table Size Update */
            if (seen_field) {
                rc = zcio_fail_(ZCIO_ERR_PROTOCOL,
                                "hpack: size update after field line");
                goto done;
            }
            uint64_t newmax;
            int c = zhp_int_decode_(block + pos, len - pos, 5, &newmax);
            if (c < 0) { rc = c; goto done; }
            pos += (size_t)c;
            if (newmax > ZHP_DEC_TABLE_MAX) {
                rc = zcio_fail_(ZCIO_ERR_PROTOCOL,
                                "hpack: size update exceeds cap");
                goto done;
            }
            dec_set_max(d, (size_t)newmax);
            continue;                       /* not a field line: no emit */
        } else {                            /* 6.2.2/6.2.3 Literal, prefix 4 */
            rc = hpack_literal(d, block, len, &pos, 4, max_decoded_bytes,
                               &nbuf, &vbuf, &nm, &nl, &vl, &vln);
            if (rc != ZCIO_OK) goto done;
        }

        seen_field = true;

        /* RFC 9113 header-list-size guard on the sum of name+value octets,
         * checked without overflow (invariant: decoded <= max_decoded_bytes). */
        if (nl > max_decoded_bytes - decoded ||
            vln > max_decoded_bytes - decoded - nl) {
            rc = zcio_fail_(ZCIO_ERR_PROTOCOL, "hpack: header list too large");
            goto done;
        }
        decoded += nl + vln;

        /* Emit BEFORE any table mutation: nm/vl may borrow the dynamic entry
         * that a subsequent add would evict. */
        int er = emit(u, nm ? nm : "", nl, vl ? vl : "", vln);
        if (er != 0) { rc = er; goto done; }
        if (add && (rc = dec_add(d, nm ? nm : "", nl, vl ? vl : "", vln)) != ZCIO_OK)
            goto done;
    }

done:
    zhs_buf_free_(&nbuf);
    zhs_buf_free_(&vbuf);
    return rc;
}

/* ========================================================================= *
 *  Stateless encode (literal without indexing; static name refs; no Huffman)
 * ========================================================================= */

static int hpack_raw_string(zhs_buf *out, const char *s, size_t n) {
    int r = zhp_int_encode_(out, 7, 0x00, (uint64_t)n);   /* H = 0 */
    if (r != ZCIO_OK) return r;
    return zhs_buf_append_(out, s, n);
}

int zhp_encode_(zhs_buf *out, const char *name, const char *value) {
    if (!name || !value)
        return zcio_fail_(ZCIO_ERR_INVALID_ARG, "hpack: null header");
    int sidx = hpack_static_name_index(name);
    int r;
    if (sidx > 0) {
        /* literal without indexing (0b0000), name index = sidx (prefix 4) */
        r = zhp_int_encode_(out, 4, 0x00, (uint64_t)sidx);
    } else {
        r = zhp_int_encode_(out, 4, 0x00, 0);          /* index 0: literal name */
        if (r != ZCIO_OK) return r;
        r = hpack_raw_string(out, name, strlen(name));
    }
    if (r != ZCIO_OK) return r;
    return hpack_raw_string(out, value, strlen(value));
}

int zhp_encode_status_(zhs_buf *out, int status) {
    char v[16];
    int n = snprintf(v, sizeof v, "%d", status);
    if (n < 0 || (size_t)n >= sizeof v)
        return zcio_fail_(ZCIO_ERR, "hpack: bad status %d", status);
    /* ":status" is static index 8; emit its name ref + the numeric value. */
    int r = zhp_int_encode_(out, 4, 0x00, 8);
    if (r != ZCIO_OK) return r;
    return hpack_raw_string(out, v, (size_t)n);
}
