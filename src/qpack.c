/* src/qpack.c - QPACK (RFC 9204) field-section codec, static table only.
 *
 * We advertise SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0: there is no dynamic
 * table and no encoder stream, so the decoder rejects every dynamic or
 * post-base reference and any nonzero Required Insert Count. Encoding is
 * stateless (static name refs, else a literal name; never Huffman), matching
 * the HPACK encoder's "cannot desync" posture.
 *
 * The prefixed-integer and Huffman primitives are reused from hpack.c
 * (zhp_int_decode_ / zhp_huff_decode_) - QPACK shares HPACK's Huffman code.
 * Every wire length is bounds-checked against the block and the caller's caps
 * before any copy/decode; parsing is single-pass and linear in the input.
 */
#include "http_internal.h"

#include <string.h>

/* ========================================================================= *
 *  Static table (RFC 9204 Appendix A) - 99 entries, 0-indexed on the wire
 * ========================================================================= */

static const struct { const char *name; const char *value; } QPACK_STATIC[] = {
    { ":authority", "" }, { ":path", "/" }, { "age", "0" },
    { "content-disposition", "" }, { "content-length", "0" }, { "cookie", "" },
    { "date", "" }, { "etag", "" }, { "if-modified-since", "" },
    { "if-none-match", "" }, { "last-modified", "" }, { "link", "" },
    { "location", "" }, { "referer", "" }, { "set-cookie", "" },
    { ":method", "CONNECT" }, { ":method", "DELETE" }, { ":method", "GET" },
    { ":method", "HEAD" }, { ":method", "OPTIONS" }, { ":method", "POST" },
    { ":method", "PUT" }, { ":scheme", "http" }, { ":scheme", "https" },
    { ":status", "103" }, { ":status", "200" }, { ":status", "304" },
    { ":status", "404" }, { ":status", "503" }, { "accept", "*/*" },
    { "accept", "application/dns-message" },
    { "accept-encoding", "gzip, deflate, br" }, { "accept-ranges", "bytes" },
    { "access-control-allow-headers", "cache-control" },
    { "access-control-allow-headers", "content-type" },
    { "access-control-allow-origin", "*" }, { "cache-control", "max-age=0" },
    { "cache-control", "max-age=2592000" }, { "cache-control", "max-age=604800" },
    { "cache-control", "no-cache" }, { "cache-control", "no-store" },
    { "cache-control", "public, max-age=31536000" }, { "content-encoding", "br" },
    { "content-encoding", "gzip" }, { "content-type", "application/dns-message" },
    { "content-type", "application/javascript" },
    { "content-type", "application/json" },
    { "content-type", "application/x-www-form-urlencoded" },
    { "content-type", "image/gif" }, { "content-type", "image/jpeg" },
    { "content-type", "image/png" }, { "content-type", "text/css" },
    { "content-type", "text/html;charset=utf-8" }, { "content-type", "text/plain" },
    { "content-type", "text/plain;charset=utf-8" }, { "range", "bytes=0-" },
    { "strict-transport-security", "max-age=31536000" },
    { "strict-transport-security", "max-age=31536000;includesubdomains" },
    { "strict-transport-security", "max-age=31536000;includesubdomains;preload" },
    { "vary", "accept-encoding" }, { "vary", "origin" },
    { "x-content-type-options", "nosniff" }, { "x-xss-protection", "1; mode=block" },
    { ":status", "100" }, { ":status", "204" }, { ":status", "206" },
    { ":status", "302" }, { ":status", "400" }, { ":status", "403" },
    { ":status", "421" }, { ":status", "425" }, { ":status", "500" },
    { "accept-language", "" }, { "access-control-allow-credentials", "FALSE" },
    { "access-control-allow-credentials", "TRUE" },
    { "access-control-allow-headers", "*" },
    { "access-control-allow-methods", "get" },
    { "access-control-allow-methods", "get, post, options" },
    { "access-control-allow-methods", "options" },
    { "access-control-expose-headers", "content-length" },
    { "access-control-request-headers", "content-type" },
    { "access-control-request-method", "get" },
    { "access-control-request-method", "post" }, { "alt-svc", "clear" },
    { "authorization", "" },
    { "content-security-policy",
      "script-src 'none';object-src 'none';base-uri 'none'" },
    { "early-data", "1" }, { "expect-ct", "" }, { "forwarded", "" },
    { "if-range", "" }, { "origin", "" }, { "purpose", "prefetch" },
    { "server", "" }, { "timing-allow-origin", "*" },
    { "upgrade-insecure-requests", "1" }, { "user-agent", "" },
    { "x-forwarded-for", "" }, { "x-frame-options", "deny" },
    { "x-frame-options", "sameorigin" },
};
#define QPACK_STATIC_N ((size_t)(sizeof QPACK_STATIC / sizeof QPACK_STATIC[0]))

/* ":status" first appears here; the name-only reference used for any status
 * that lacks a full (name+value) static entry. */
#define QPACK_STATUS_NAME_IDX 24

/* ASCII case-insensitive equality (table names are lowercase). */
static bool ci_eq(const char *a, const char *b) {
    for (;; a++, b++) {
        unsigned char ca = (unsigned char)*a, cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca = (unsigned char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (unsigned char)(cb + 32);
        if (ca != cb) return false;
        if (!ca) return true;
    }
}

/* First static index (0-based) whose name matches, or -1. */
static int qpack_static_name_index(const char *name) {
    for (size_t i = 0; i < QPACK_STATIC_N; i++)
        if (ci_eq(QPACK_STATIC[i].name, name)) return (int)i;
    return -1;
}

/* ========================================================================= *
 *  Decode (RFC 9204 sec. 4.5)
 * ========================================================================= */

/* Read a string literal whose Huffman bit was already extracted by the caller
 * (its position differs between representations) and whose length is a
 * `prefix_bits`-wide prefixed integer at block[*pos]. On Huffman input decodes
 * into `scratch` (reset first) and points *out at it; otherwise *out borrows
 * the block. Length is bounds-checked against the block and max_out first. */
static int qpack_read_string(const uint8_t *block, size_t len, size_t *pos,
                             bool huff, unsigned prefix_bits, size_t max_out,
                             zhs_buf *scratch, const char **out, size_t *outlen) {
    uint64_t slen;
    int c = zhp_int_decode_(block + *pos, len - *pos, prefix_bits, &slen);
    if (c < 0) return c;
    *pos += (size_t)c;
    if (slen > (uint64_t)(len - *pos))
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "qpack: string exceeds block");

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
            return zcio_fail_(ZCIO_ERR_PROTOCOL, "qpack: string exceeds limit");
        *out = (const char *)s;
        *outlen = (size_t)slen;
    }
    return ZCIO_OK;
}

int zqp_decode_(const uint8_t *block, size_t len, size_t max_decoded_bytes,
                zhp_emit_fn emit, void *u) {
    /* --- Encoded Field Section Prefix (sec. 4.5.1) --- */
    size_t   pos = 0;
    uint64_t ric;
    int c = zhp_int_decode_(block, len, 8, &ric);   /* Required Insert Count */
    if (c < 0) return c;
    pos += (size_t)c;
    if (ric != 0)   /* dynamic table capacity is 0: RIC must be 0 */
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "qpack: nonzero required insert count");
    if (pos >= len)
        return zcio_fail_(ZCIO_ERR_PROTOCOL, "qpack: truncated field section prefix");
    uint64_t base;
    c = zhp_int_decode_(block + pos, len - pos, 7, &base);  /* Delta Base; S ignored */
    if (c < 0) return c;
    pos += (size_t)c;

    /* --- Field lines --- */
    size_t  decoded = 0;
    zhs_buf nbuf = {0}, vbuf = {0};
    int     rc = ZCIO_OK;

    while (pos < len) {
        uint8_t     b  = block[pos];
        const char *nm = NULL, *vl = NULL;
        size_t      nl = 0, vln = 0;

        if (b & 0x80) {                     /* 4.5.2 Indexed Field Line */
            if (!(b & 0x40)) {              /* T=0: dynamic table (we have none) */
                rc = zcio_fail_(ZCIO_ERR_PROTOCOL, "qpack: dynamic indexed line");
                goto done;
            }
            uint64_t idx;
            int r = zhp_int_decode_(block + pos, len - pos, 6, &idx);
            if (r < 0) { rc = r; goto done; }
            pos += (size_t)r;
            if (idx >= QPACK_STATIC_N) {
                rc = zcio_fail_(ZCIO_ERR_PROTOCOL, "qpack: static index out of range");
                goto done;
            }
            nm = QPACK_STATIC[idx].name;  nl  = strlen(nm);
            vl = QPACK_STATIC[idx].value; vln = strlen(vl);
        } else if (b & 0x40) {              /* 4.5.4 Literal w/ Name Reference */
            if (!(b & 0x10)) {              /* T=0: dynamic name ref */
                rc = zcio_fail_(ZCIO_ERR_PROTOCOL, "qpack: dynamic name ref");
                goto done;
            }
            uint64_t idx;
            int r = zhp_int_decode_(block + pos, len - pos, 4, &idx);
            if (r < 0) { rc = r; goto done; }
            pos += (size_t)r;
            if (idx >= QPACK_STATIC_N) {
                rc = zcio_fail_(ZCIO_ERR_PROTOCOL, "qpack: static name index out of range");
                goto done;
            }
            nm = QPACK_STATIC[idx].name; nl = strlen(nm);
            if (pos >= len) {
                rc = zcio_fail_(ZCIO_ERR_PROTOCOL, "qpack: truncated literal value");
                goto done;
            }
            rc = qpack_read_string(block, len, &pos, (block[pos] & 0x80) != 0,
                                   7, max_decoded_bytes, &vbuf, &vl, &vln);
            if (rc != ZCIO_OK) goto done;
        } else if (b & 0x20) {              /* 4.5.6 Literal w/ Literal Name */
            rc = qpack_read_string(block, len, &pos, (b & 0x08) != 0,
                                   3, max_decoded_bytes, &nbuf, &nm, &nl);
            if (rc != ZCIO_OK) goto done;
            if (pos >= len) {
                rc = zcio_fail_(ZCIO_ERR_PROTOCOL, "qpack: truncated literal value");
                goto done;
            }
            rc = qpack_read_string(block, len, &pos, (block[pos] & 0x80) != 0,
                                   7, max_decoded_bytes, &vbuf, &vl, &vln);
            if (rc != ZCIO_OK) goto done;
        } else if (b & 0x10) {              /* 4.5.3 Indexed, post-base */
            rc = zcio_fail_(ZCIO_ERR_PROTOCOL, "qpack: post-base indexed line");
            goto done;
        } else {                            /* 4.5.5 Literal, post-base name ref */
            rc = zcio_fail_(ZCIO_ERR_PROTOCOL, "qpack: post-base name ref");
            goto done;
        }

        /* Header-list-size guard on the sum of name+value octets, overflow-safe
         * (invariant: decoded <= max_decoded_bytes). */
        if (nl > max_decoded_bytes - decoded ||
            vln > max_decoded_bytes - decoded - nl) {
            rc = zcio_fail_(ZCIO_ERR_PROTOCOL, "qpack: header list too large");
            goto done;
        }
        decoded += nl + vln;

        int er = emit(u, nm ? nm : "", nl, vl ? vl : "", vln);
        if (er != 0) { rc = er; goto done; }
    }

done:
    zhs_buf_free_(&nbuf);
    zhs_buf_free_(&vbuf);
    return rc;
}

/* ========================================================================= *
 *  Stateless encode
 * ========================================================================= */

/* Value/name string literal: 7-bit length prefix, Huffman bit clear. */
static int qpack_raw_string(zhs_buf *out, const char *s, size_t n) {
    int r = zhp_int_encode_(out, 7, 0x00, (uint64_t)n);
    if (r != ZCIO_OK) return r;
    return zhs_buf_append_(out, s, n);
}

int zqp_prefix_encode_(zhs_buf *out) {
    int r = zhs_buf_append_u8_(out, 0x00);   /* Required Insert Count = 0 */
    if (r != ZCIO_OK) return r;
    return zhs_buf_append_u8_(out, 0x00);    /* S = 0, Delta Base = 0 */
}

int zqp_encode_(zhs_buf *out, const char *name, const char *value) {
    if (!name || !value)
        return zcio_fail_(ZCIO_ERR_INVALID_ARG, "qpack: null header");
    size_t vlen = strlen(value);
    int idx = qpack_static_name_index(name);
    int r;
    if (idx >= 0) {
        /* 4.5.4 Literal w/ Name Reference: 01 N=0 T=1(static) + 4-bit index. */
        r = zhp_int_encode_(out, 4, 0x50, (uint64_t)idx);
        if (r != ZCIO_OK) return r;
    } else {
        /* 4.5.6 Literal w/ Literal Name: 001 N=0 H=0 + 3-bit name length. */
        size_t nlen = strlen(name);
        r = zhp_int_encode_(out, 3, 0x20, (uint64_t)nlen);
        if (r != ZCIO_OK) return r;
        r = zhs_buf_append_(out, name, nlen);
        if (r != ZCIO_OK) return r;
    }
    return qpack_raw_string(out, value, vlen);
}

int zqp_encode_status_(zhs_buf *out, int status) {
    int idx = -1;
    switch (status) {   /* full (name+value) static entries */
        case 100: idx = 63; break; case 103: idx = 24; break;
        case 200: idx = 25; break; case 204: idx = 64; break;
        case 206: idx = 65; break; case 302: idx = 66; break;
        case 304: idx = 26; break; case 400: idx = 67; break;
        case 403: idx = 68; break; case 404: idx = 27; break;
        case 421: idx = 69; break; case 425: idx = 70; break;
        case 500: idx = 71; break; case 503: idx = 28; break;
        default: break;
    }
    if (idx >= 0)   /* 4.5.2 Indexed Field Line: 1 T=1(static) + 6-bit index. */
        return zhp_int_encode_(out, 6, 0xC0, (uint64_t)idx);

    /* Fall back to a name reference on ":status" + the numeric value. */
    char v[16];
    int n = snprintf(v, sizeof v, "%d", status);
    if (n < 0 || (size_t)n >= sizeof v)
        return zcio_fail_(ZCIO_ERR, "qpack: bad status %d", status);
    int r = zhp_int_encode_(out, 4, 0x50, QPACK_STATUS_NAME_IDX);
    if (r != ZCIO_OK) return r;
    return qpack_raw_string(out, v, (size_t)n);
}
