/* src/ws.c - RFC 6455 WebSocket, client and server roles.
 *
 * A websocket session is used OUTSIDE the server event loop: on the server the
 * connection is detached from the loop (zhs_detach_for_upgrade_) and the stream
 * is driven synchronously with a blocking timeout; the client dials its own
 * transport. Consequently every I/O here is blocking (timeout-bounded), unlike
 * the sans-I/O h1/h2 parsers.
 *
 * This TU is self-contained for crypto: it carries its own SHA-1 and Base64 so
 * the handshake works with ZCIO_TLS=none (no OpenSSL). Entropy for the client
 * key and per-frame masking keys comes from zcio_rand_bytes_ (the OS CSPRNG).
 *
 * Ownership:
 *   - server role: the zcio_ws owns the detached zcio_stream* outright.
 *   - client role: the zcio_ws owns the zcio_tcp_client (which owns the stream)
 *     and, for wss, the zcio_tls_ctx it created; ws->stream is borrowed from the
 *     client. zcio_ws_free releases whichever it owns.
 *   - zcio_ws_msg.data is malloc'd and returned to the caller (zcio_ws_msg_free).
 *
 * Security: single frame parser, single-pass and linear over the input buffer;
 * every wire-derived length is overflow-checked before it drives a copy, and the
 * reassembled message is capped by max_msg_bytes (close 1009). RSV bits, bad
 * masking direction, oversized/fragmented control frames, reserved opcodes and
 * invalid UTF-8 all trip the mandated close code and abort the session.
 */
#include "zcio/ws.h"
#include "zcio/net.h"
#include "zcio/tls.h"
#include "http_internal.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* RFC 6455 §4.2.2 magic GUID appended to the key before hashing. */
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define WS_DEFAULT_MAX_MSG ((size_t)16 * 1024 * 1024)
#define WS_DEFAULT_TIMEOUT 30000
#define WS_HANDSHAKE_HEAD_CAP ((size_t)64 * 1024)

/* Frame opcodes (low nibble of byte 0). */
enum {
    WS_OP_CONT  = 0x0,
    WS_OP_TEXT  = 0x1,
    WS_OP_BIN   = 0x2,
    WS_OP_CLOSE = 0x8,
    WS_OP_PING  = 0x9,
    WS_OP_PONG  = 0xA,
};

/* ws_pump outcomes (>=0); negative is a negated zcio_result. */
enum { WS_MSG = 0, WS_MORE = 1, WS_CLOSED = 2 };

struct zcio_ws {
    zcio_stream     *stream;    /* borrowed when client!=NULL, owned otherwise  */
    zcio_tcp_client *client;    /* client role: owns transport; NULL for server */
    zcio_tls_ctx    *tls_ctx;   /* client wss: owned, freed after client        */

    zhs_buf  in;                /* buffered, not-yet-parsed inbound bytes       */
    zhs_buf  frag;              /* reassembly buffer for a fragmented message   */
    int      cur_opcode;        /* opcode of the in-progress fragmented message */
    bool     frag_active;       /* a fragmented data message is being assembled */

    size_t   max_msg_bytes;
    int      timeout_ms;        /* per-op read/write timeout                    */
    bool     is_server;         /* masks nothing, requires masked input         */
    bool     close_sent;
    bool     close_recv;
    bool     failed;            /* protocol error or dead transport             */
    uint16_t close_code;        /* code received from the peer (0 if none)      */
};

/* ========================================================================= *
 *  SHA-1 (RFC 3174) - self-contained, only used on the tiny handshake string
 * ========================================================================= */

static void sha1_block(uint32_t st[5], const uint8_t p[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i*4] << 24 | (uint32_t)p[i*4+1] << 16 |
               (uint32_t)p[i*4+2] << 8 | (uint32_t)p[i*4+3];
    for (int i = 16; i < 80; i++) {
        uint32_t v = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        w[i] = (v << 1) | (v >> 31);
    }
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | ((~b) & d);          k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                     k = 0xCA62C1D6; }
        uint32_t t = ((a << 5) | (a >> 27)) + f + e + k + w[i];
        e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = t;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e;
}

static void sha1(const uint8_t *msg, size_t len, uint8_t out[20]) {
    uint32_t st[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    uint64_t bits = (uint64_t)len * 8;
    size_t full = len / 64;
    for (size_t i = 0; i < full; i++) sha1_block(st, msg + i * 64);

    uint8_t block[64];
    size_t rem = len - full * 64;
    memcpy(block, msg + full * 64, rem);
    block[rem++] = 0x80;                     /* mandatory trailing 1 bit */
    if (rem > 56) {                          /* length won't fit: flush, then a fresh block */
        memset(block + rem, 0, 64 - rem);
        sha1_block(st, block);
        memset(block, 0, 56);
    } else {
        memset(block + rem, 0, 56 - rem);
    }
    for (int i = 0; i < 8; i++) block[56 + i] = (uint8_t)(bits >> (56 - i * 8));
    sha1_block(st, block);

    for (int i = 0; i < 5; i++) {
        out[i*4]   = (uint8_t)(st[i] >> 24);
        out[i*4+1] = (uint8_t)(st[i] >> 16);
        out[i*4+2] = (uint8_t)(st[i] >> 8);
        out[i*4+3] = (uint8_t)st[i];
    }
}

/* ========================================================================= *
 *  Base64 encode (no line wrapping)
 * ========================================================================= */

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* out must hold ((n+2)/3)*4 + 1 bytes. */
static void base64(const uint8_t *in, size_t n, char *out) {
    size_t o = 0, i = 0;
    for (; i + 3 <= n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i+1] << 8 | in[i+2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = B64[(v >> 6) & 63];
        out[o++] = B64[v & 63];
    }
    size_t r = n - i;
    if (r == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = '=';
        out[o++] = '=';
    } else if (r == 2) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i+1] << 8;
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = B64[(v >> 6) & 63];
        out[o++] = '=';
    }
    out[o] = '\0';
}

/* Sec-WebSocket-Accept = base64(sha1(key + GUID)). out holds 29 bytes. */
static int ws_compute_accept(const char *key, char out[29]) {
    size_t klen = strlen(key);
    size_t total = klen + (sizeof WS_GUID - 1);
    uint8_t *cat = (uint8_t *)zcio_xmalloc(total);
    if (!cat) return ZCIO_ERR_NOMEM;
    memcpy(cat, key, klen);
    memcpy(cat + klen, WS_GUID, sizeof WS_GUID - 1);
    uint8_t dig[20];
    sha1(cat, total, dig);
    free(cat);
    base64(dig, 20, out);
    return ZCIO_OK;
}

/* ========================================================================= *
 *  small helpers
 * ========================================================================= */

/* Reject CR/LF/other control bytes (header/handshake injection guard). */
static bool ws_hdr_token_ok(const char *s) {
    if (!s) return false;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if (*p < 0x20 || *p == 0x7f) return false;
    return true;
}

/* Blocking timeout for the underlying transport. Reaches through a wss TLS
 * overlay to the socket stream, so recv/send deadlines are honored over TLS. */
static void ws_apply_timeout(zcio_ws *ws, int timeout_ms) {
    (void)zcio_stream_set_timeout_(ws->stream, timeout_ms);
}

/* ========================================================================= *
 *  frame output
 * ========================================================================= */

/* Serialize one frame. Client role masks with a fresh random key; server role
 * never masks. Returns ZCIO_OK or a negated zcio_result (transport error). */
static int ws_send_frame(zcio_ws *ws, uint8_t opcode, bool fin,
                         const void *data, size_t len) {
    uint8_t hdr[14];
    size_t h = 0;
    hdr[h++] = (uint8_t)((fin ? 0x80 : 0) | (opcode & 0x0f));
    uint8_t mbit = ws->is_server ? 0 : 0x80;
    if (len < 126) {
        hdr[h++] = (uint8_t)(mbit | len);
    } else if (len <= 0xffff) {
        hdr[h++] = (uint8_t)(mbit | 126);
        hdr[h++] = (uint8_t)((len >> 8) & 0xff);
        hdr[h++] = (uint8_t)(len & 0xff);
    } else {
        hdr[h++] = (uint8_t)(mbit | 127);
        for (int i = 0; i < 8; i++)
            hdr[h++] = (uint8_t)((uint64_t)len >> (56 - i * 8));
    }
    uint8_t key[4] = { 0, 0, 0, 0 };
    if (!ws->is_server) {
        if (zcio_rand_bytes_(key, 4) != ZCIO_OK)
            return zcio_fail_(ZCIO_ERR, "ws: entropy for mask key failed");
        memcpy(hdr + h, key, 4);
        h += 4;
    }

    ws_apply_timeout(ws, ws->timeout_ms);
    if (zcio_write_full(ws->stream, hdr, h) != (int64_t)h)
        return zcio_fail_(ZCIO_ERR, "ws: frame header write failed");
    if (len == 0) return ZCIO_OK;

    if (ws->is_server) {
        if (zcio_write_full(ws->stream, data, len) != (int64_t)len)
            return zcio_fail_(ZCIO_ERR, "ws: frame payload write failed");
    } else {
        /* Mask in bounded chunks so a large payload needs no scratch of its
         * own size. Chunk is a multiple of 4 so key alignment is preserved. */
        const uint8_t *src = (const uint8_t *)data;
        uint8_t chunk[1024];
        for (size_t off = 0; off < len; ) {
            size_t c = len - off;
            if (c > sizeof chunk) c = sizeof chunk;
            for (size_t i = 0; i < c; i++)
                chunk[i] = (uint8_t)(src[off + i] ^ key[(off + i) & 3]);
            if (zcio_write_full(ws->stream, chunk, c) != (int64_t)c)
                return zcio_fail_(ZCIO_ERR, "ws: frame payload write failed");
            off += c;
        }
    }
    return ZCIO_OK;
}

/* Emit the mandated Close and mark the session failed; returns ZCIO_ERR_PROTOCOL. */
static int ws_protocol_fail(zcio_ws *ws, uint16_t code, const char *msg) {
    if (!ws->close_sent) {
        uint8_t p[2] = { (uint8_t)(code >> 8), (uint8_t)code };
        (void)ws_send_frame(ws, WS_OP_CLOSE, true, p, 2); /* best-effort */
        ws->close_sent = true;
    }
    ws->failed = true;
    return zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: %s", msg);
}

/* ========================================================================= *
 *  frame input
 * ========================================================================= */

/* Read one chunk into ws->in with the given per-read timeout (-1 blocks).
 * ZCIO_OK on progress, ZCIO_ERR_TIMEOUT, ZCIO_ERR_EOF, or a negated result. */
static int ws_fill(zcio_ws *ws, int timeout_ms) {
    uint8_t tmp[4096];
    ws_apply_timeout(ws, timeout_ms);
    int64_t n = zcio_read(ws->stream, tmp, sizeof tmp);
    if (n > 0)
        return zhs_buf_append_(&ws->in, tmp, (size_t)n) == ZCIO_OK ? ZCIO_OK : ZCIO_ERR_NOMEM;
    if (n == 0) return ZCIO_ERR_EOF;
    if (n == ZCIO_ERR_TIMEOUT || n == ZCIO_ERR_WOULDBLOCK) return ZCIO_ERR_TIMEOUT;
    return (int)n; /* EOF / hard error */
}

/* Emit a completed message from [data,data+len) into *out (malloc'd, NUL-term). */
static int ws_emit(zcio_ws_msg *out, int opcode, const uint8_t *data, size_t len) {
    void *d = zcio_xmalloc(len + 1);
    if (!d) return zcio_fail_(ZCIO_ERR_NOMEM, "ws: out of memory");
    memcpy(d, data, len);
    ((uint8_t *)d)[len] = 0;
    out->type = (opcode == WS_OP_TEXT) ? ZCIO_WS_TEXT : ZCIO_WS_BINARY;
    out->data = d;
    out->len = len;
    return WS_MSG;
}

/* Parse as many buffered frames as are complete, transparently answering ping
 * and finishing a peer close. Returns WS_MSG (message in *out), WS_MORE (need
 * bytes), WS_CLOSED (peer closed -> EOF), or a negated zcio_result. */
static int ws_pump(zcio_ws *ws, zcio_ws_msg *out) {
    for (;;) {
        size_t avail = ZHS_AVAIL(&ws->in);
        if (avail < 2) return WS_MORE;
        uint8_t *p = ZHS_PTR(&ws->in);

        if (p[0] & 0x70) return ws_protocol_fail(ws, 1002, "reserved bit set");
        uint8_t opcode = p[0] & 0x0f;
        bool fin = (p[0] & 0x80) != 0;
        bool masked = (p[1] & 0x80) != 0;
        uint64_t len = p[1] & 0x7f;

        size_t base = 2;
        if (len == 126) base = 4;
        else if (len == 127) base = 10;
        if (avail < base) return WS_MORE;
        if (len == 126) {
            len = ((uint64_t)p[2] << 8) | p[3];
        } else if (len == 127) {
            len = 0;
            for (int i = 0; i < 8; i++) len = (len << 8) | p[2 + i];
            if (len >> 63) return ws_protocol_fail(ws, 1002, "64-bit length high bit set");
        }

        /* Masking direction is mandatory and role-specific. */
        if (ws->is_server && !masked)  return ws_protocol_fail(ws, 1002, "unmasked client frame");
        if (!ws->is_server && masked)  return ws_protocol_fail(ws, 1002, "masked server frame");

        bool control = (opcode & 0x08) != 0;
        if (opcode != WS_OP_CONT && opcode != WS_OP_TEXT && opcode != WS_OP_BIN &&
            opcode != WS_OP_CLOSE && opcode != WS_OP_PING && opcode != WS_OP_PONG)
            return ws_protocol_fail(ws, 1002, "reserved opcode");
        if (control && (!fin || len > 125))
            return ws_protocol_fail(ws, 1002, "fragmented or oversized control frame");

        /* Cap the reassembled message before committing to the copy. Written
         * overflow-safe so a max_msg_bytes lowered mid-fragment (making the
         * already-buffered frag exceed the cap) cannot underflow the subtraction
         * and defeat the limit. */
        if (!control && (ZHS_AVAIL(&ws->frag) > ws->max_msg_bytes ||
                         len > ws->max_msg_bytes - ZHS_AVAIL(&ws->frag)))
            return ws_protocol_fail(ws, 1009, "message exceeds max_msg_bytes");

        size_t data_off = masked ? base + 4 : base;
        if (avail < data_off) return WS_MORE;            /* still need the mask key */
        if (len > (uint64_t)(SIZE_MAX - data_off))
            return ws_protocol_fail(ws, 1009, "frame length overflow");
        size_t frame_total = data_off + (size_t)len;
        if (avail < frame_total) return WS_MORE;

        uint8_t *payload = p + data_off;
        if (masked) {
            const uint8_t *k = p + base;
            for (size_t i = 0; i < (size_t)len; i++) payload[i] ^= k[i & 3];
        }

        switch (opcode) {
        case WS_OP_PING: {
            int s = ws_send_frame(ws, WS_OP_PONG, true, payload, (size_t)len);
            zhs_buf_consume_(&ws->in, frame_total);
            if (s != ZCIO_OK) return s;
            continue;
        }
        case WS_OP_PONG:
            zhs_buf_consume_(&ws->in, frame_total);
            continue;
        case WS_OP_CLOSE: {
            uint16_t code = 1005; /* "no status present" per RFC 6455 §7.1.5 */
            if (len == 1) {
                zhs_buf_consume_(&ws->in, frame_total);
                return ws_protocol_fail(ws, 1002, "malformed close payload");
            }
            if (len >= 2) {
                code = (uint16_t)((uint16_t)payload[0] << 8 | payload[1]);
                /* RFC 6455 §7.4.1: reject codes that are invalid on the wire
                 * (0-999, the local-only 1004/1005/1006/1015, and the reserved
                 * 1016-2999); permit 1000-1003, 1007-1014, and 3000-4999. */
                bool code_ok = (code >= 1000 && code <= 1003)
                            || (code >= 1007 && code <= 1014)
                            || (code >= 3000 && code <= 4999);
                if (!code_ok) {
                    zhs_buf_consume_(&ws->in, frame_total);
                    return ws_protocol_fail(ws, 1002, "invalid close code");
                }
                if (len > 2 && !zhs_utf8_valid_(payload + 2, (size_t)len - 2)) {
                    zhs_buf_consume_(&ws->in, frame_total);
                    return ws_protocol_fail(ws, 1007, "close reason not UTF-8");
                }
            }
            ws->close_code = code;
            ws->close_recv = true;
            if (!ws->close_sent) { /* echo the peer's code (RFC 6455 §5.5.1) */
                uint8_t cp[2] = { (uint8_t)(code >> 8), (uint8_t)code };
                (void)ws_send_frame(ws, WS_OP_CLOSE, true, len >= 2 ? cp : NULL,
                                    len >= 2 ? 2 : 0);
                ws->close_sent = true;
            }
            zhs_buf_consume_(&ws->in, frame_total);
            return WS_CLOSED;
        }
        case WS_OP_TEXT:
        case WS_OP_BIN: {
            if (ws->frag_active)
                return ws_protocol_fail(ws, 1002, "new data frame during fragmented message");
            if (fin) {
                if (opcode == WS_OP_TEXT && !zhs_utf8_valid_(payload, (size_t)len)) {
                    zhs_buf_consume_(&ws->in, frame_total);
                    return ws_protocol_fail(ws, 1007, "invalid UTF-8 text message");
                }
                int r = ws_emit(out, opcode, payload, (size_t)len);
                zhs_buf_consume_(&ws->in, frame_total);
                return r;
            }
            ws->frag_active = true;
            ws->cur_opcode = opcode;
            int a = zhs_buf_append_(&ws->frag, payload, (size_t)len);
            zhs_buf_consume_(&ws->in, frame_total);
            if (a != ZCIO_OK) return zcio_fail_(ZCIO_ERR_NOMEM, "ws: out of memory");
            continue;
        }
        case WS_OP_CONT: {
            if (!ws->frag_active)
                return ws_protocol_fail(ws, 1002, "continuation with no message in progress");
            int a = zhs_buf_append_(&ws->frag, payload, (size_t)len);
            zhs_buf_consume_(&ws->in, frame_total);
            if (a != ZCIO_OK) return zcio_fail_(ZCIO_ERR_NOMEM, "ws: out of memory");
            if (fin) {
                size_t mlen = ZHS_AVAIL(&ws->frag);
                const uint8_t *mdat = ZHS_PTR(&ws->frag);
                if (ws->cur_opcode == WS_OP_TEXT && !zhs_utf8_valid_(mdat, mlen)) {
                    ws->frag_active = false;
                    zhs_buf_reset_(&ws->frag);
                    return ws_protocol_fail(ws, 1007, "invalid UTF-8 text message");
                }
                int r = ws_emit(out, ws->cur_opcode, mdat, mlen);
                ws->frag_active = false;
                zhs_buf_reset_(&ws->frag);
                return r;
            }
            continue;
        }
        default:
            /* unreachable: opcode already validated above */
            return ws_protocol_fail(ws, 1002, "reserved opcode");
        }
    }
}

/* ========================================================================= *
 *  lifecycle
 * ========================================================================= */

static zcio_ws *ws_new(zcio_stream *st, bool is_server,
                       zcio_tcp_client *client, zcio_tls_ctx *tls) {
    zcio_ws *ws = (zcio_ws *)zcio_xcalloc(1, sizeof *ws);
    if (!ws) return NULL;
    ws->stream = st;
    ws->is_server = is_server;
    ws->client = client;
    ws->tls_ctx = tls;
    ws->max_msg_bytes = WS_DEFAULT_MAX_MSG;
    ws->timeout_ms = WS_DEFAULT_TIMEOUT;
    ws_apply_timeout(ws, ws->timeout_ms);
    return ws;
}

void zcio_ws_msg_free(zcio_ws_msg *m) {
    if (!m) return;
    free(m->data);
    m->data = NULL;
    m->len = 0;
}

/* ========================================================================= *
 *  server handshake
 * ========================================================================= */

bool zcio_http_req_is_ws_upgrade(const zcio_http_req *r) {
    return r && r->ws_upgrade;
}

zcio_ws *zcio_ws_accept(zcio_http_req *r) {
    if (!r || !r->ws_upgrade) {
        zcio_fail_(ZCIO_ERR_INVALID_ARG, "ws_accept: not a websocket upgrade");
        return NULL;
    }
    const char *key = zhs_hdrs_get_(&r->headers, "sec-websocket-key");
    if (!key) {
        zcio_fail_(ZCIO_ERR_PROTOCOL, "ws_accept: missing Sec-WebSocket-Key");
        return NULL;
    }
    char accept[29];
    if (ws_compute_accept(key, accept) != ZCIO_OK) {
        zcio_fail_(ZCIO_ERR_NOMEM, "ws_accept: out of memory");
        return NULL;
    }

    /* Build the 101; every append is checked so a truncated resp never ships. */
    zhs_buf resp = {0};
    int ok = zhs_buf_append_str_(&resp,
                 "HTTP/1.1 101 Switching Protocols\r\n"
                 "Upgrade: websocket\r\n"
                 "Connection: Upgrade\r\n"
                 "Sec-WebSocket-Accept: ") == ZCIO_OK
          && zhs_buf_append_str_(&resp, accept) == ZCIO_OK
          && zhs_buf_append_str_(&resp, "\r\n\r\n") == ZCIO_OK;
    if (!ok) {
        zhs_buf_free_(&resp);
        zcio_fail_(ZCIO_ERR_NOMEM, "ws_accept: out of memory");
        return NULL;
    }

    /* Sends the 101 (+ any queued output) and hands over the stream, plus any
     * bytes the client pipelined after the handshake (they alias connection
     * memory freed after we return, so seed them into ws->in immediately). */
    const uint8_t *leftover = NULL;
    size_t leftover_len = 0;
    zcio_stream *st = zhs_detach_for_upgrade_(r, resp.data, resp.len,
                                              &leftover, &leftover_len);
    zhs_buf_free_(&resp);
    if (!st) {
        zcio_fail_(ZCIO_ERR, "ws_accept: connection detach failed");
        return NULL;
    }

    zcio_ws *ws = ws_new(st, true, NULL, NULL);
    if (!ws) {
        zcio_stream_free(st); /* the connection is now ours to close */
        zcio_fail_(ZCIO_ERR_NOMEM, "ws_accept: out of memory");
        return NULL;
    }
    if (leftover_len && zhs_buf_append_(&ws->in, leftover, leftover_len) != ZCIO_OK) {
        zcio_ws_free(ws);
        zcio_fail_(ZCIO_ERR_NOMEM, "ws_accept: out of memory");
        return NULL;
    }
    return ws;
}

/* ========================================================================= *
 *  client handshake
 * ========================================================================= */

/* Parse ws://, wss://, http:// or https:// (the last two arrive via redirects).
 * *host_out / *path_out are malloc'd. Returns ZCIO_OK or a negated result. */
static int ws_url_parse(const char *url, bool *secure,
                        char **host_out, int *port_out, char **path_out) {
    *host_out = NULL;
    *path_out = NULL;
    if (!url) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "ws: NULL url");

    const char *sep = strstr(url, "://");
    if (!sep) return zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: no scheme in '%s'", url);
    size_t slen = (size_t)(sep - url);

    /* case-insensitive scheme match */
    char sc[8];
    if (slen >= sizeof sc) return zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: bad scheme");
    for (size_t i = 0; i < slen; i++) sc[i] = (char)tolower((unsigned char)url[i]);
    sc[slen] = '\0';
    bool sec;
    if (strcmp(sc, "ws") == 0 || strcmp(sc, "http") == 0) sec = false;
    else if (strcmp(sc, "wss") == 0 || strcmp(sc, "https") == 0) sec = true;
    else return zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: unsupported scheme '%s'", sc);

    const char *auth = sep + 3;
    const char *slash = strchr(auth, '/');
    const char *path_src = slash ? slash : "/";
    size_t auth_len = slash ? (size_t)(slash - auth) : strlen(auth);

    /* Strip userinfo up to the last '@'. */
    for (size_t i = 0; i < auth_len; i++)
        if (auth[i] == '@') { size_t used = i + 1; auth += used; auth_len -= used; i = (size_t)-1; }

    /* host[:port], with IPv6 literals in brackets. */
    const char *hb;
    size_t hlen;
    const char *ps = NULL;
    size_t pslen = 0;
    if (auth_len > 0 && auth[0] == '[') {
        const char *rb = memchr(auth, ']', auth_len);
        if (!rb) return zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: unterminated IPv6 literal");
        hb = auth + 1;
        hlen = (size_t)(rb - hb);
        const char *after = rb + 1;
        size_t after_len = auth_len - (size_t)(after - auth);
        if (after_len > 0) {
            if (after[0] != ':') return zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: malformed authority");
            ps = after + 1;
            pslen = after_len - 1;
        }
    } else {
        const char *colon = memchr(auth, ':', auth_len);
        hb = auth;
        hlen = colon ? (size_t)(colon - auth) : auth_len;
        if (colon) { ps = colon + 1; pslen = auth_len - (hlen + 1); }
    }
    if (hlen == 0) return zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: empty host in '%s'", url);

    int port = sec ? 443 : 80;
    if (ps && pslen > 0) {
        char pb[16];
        if (pslen >= sizeof pb) return zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: invalid port");
        memcpy(pb, ps, pslen);
        pb[pslen] = '\0';
        char *end = NULL;
        long v = strtol(pb, &end, 10);
        if (end == pb || *end != '\0' || v < 1 || v > 65535)
            return zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: invalid port '%s'", pb);
        port = (int)v;
    }

    char *host = (char *)zcio_xmalloc(hlen + 1);
    char *path = zcio_strdup_(path_src);
    if (!host || !path) { free(host); free(path); return zcio_fail_(ZCIO_ERR_NOMEM, "ws: out of memory"); }
    memcpy(host, hb, hlen);
    host[hlen] = '\0';
    *secure = sec;
    *port_out = port;
    *host_out = host;
    *path_out = path;
    return ZCIO_OK;
}

/* Write the opening GET Upgrade request. Extra headers are CR/LF-validated. */
static int ws_send_handshake(zcio_stream *s, const char *host, int port, bool secure,
                             const char *path, const char *key,
                             const zcio_http_header *headers, size_t nheaders) {
    zhs_buf req = {0};
    bool v6 = strchr(host, ':') != NULL;
    int defp = secure ? 443 : 80;
    int ok = zhs_buf_append_str_(&req, "GET ") == ZCIO_OK
          && zhs_buf_append_str_(&req, path) == ZCIO_OK
          && zhs_buf_append_str_(&req, " HTTP/1.1\r\nHost: ") == ZCIO_OK
          && (v6 ? zhs_buf_append_str_(&req, "[") == ZCIO_OK : true)
          && zhs_buf_append_str_(&req, host) == ZCIO_OK
          && (v6 ? zhs_buf_append_str_(&req, "]") == ZCIO_OK : true);
    if (ok && port != defp) {
        char pb[16];
        snprintf(pb, sizeof pb, ":%d", port);
        ok = zhs_buf_append_str_(&req, pb) == ZCIO_OK;
    }
    if (ok)
        ok = zhs_buf_append_str_(&req,
                 "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 "Sec-WebSocket-Key: ") == ZCIO_OK
          && zhs_buf_append_str_(&req, key) == ZCIO_OK
          && zhs_buf_append_str_(&req, "\r\nSec-WebSocket-Version: 13\r\n") == ZCIO_OK;

    for (size_t i = 0; ok && i < nheaders; i++) {
        if (!headers[i].key) continue;
        ok = zhs_buf_append_str_(&req, headers[i].key) == ZCIO_OK
          && zhs_buf_append_str_(&req, ": ") == ZCIO_OK
          && zhs_buf_append_str_(&req, headers[i].value ? headers[i].value : "") == ZCIO_OK
          && zhs_buf_append_str_(&req, "\r\n") == ZCIO_OK;
    }
    if (ok) ok = zhs_buf_append_str_(&req, "\r\n") == ZCIO_OK;
    if (!ok) { zhs_buf_free_(&req); return zcio_fail_(ZCIO_ERR_NOMEM, "ws: out of memory"); }

    int64_t w = zcio_write_full(s, req.data, req.len);
    int rc = ((size_t)w == req.len) ? ZCIO_OK
                                    : zcio_fail_(ZCIO_ERR, "ws: handshake write failed");
    zhs_buf_free_(&req);
    return rc;
}

/* Read the response head into *acc until "\r\n\r\n"; *body_start is the index
 * (from acc's readable start) of the first byte after the terminator. */
static int ws_read_head(zcio_stream *s, zhs_buf *acc, size_t *body_start) {
    for (;;) {
        size_t n = ZHS_AVAIL(acc);
        if (n >= 4) {
            const uint8_t *d = ZHS_PTR(acc);
            for (size_t i = 0; i + 3 < n; i++)
                if (d[i] == '\r' && d[i+1] == '\n' && d[i+2] == '\r' && d[i+3] == '\n') {
                    *body_start = i + 4;
                    return ZCIO_OK;
                }
        }
        if (n > WS_HANDSHAKE_HEAD_CAP)
            return zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: handshake response too large");
        uint8_t tmp[2048];
        int64_t r = zcio_read(s, tmp, sizeof tmp);
        if (r <= 0)
            return zcio_fail_(r == 0 ? ZCIO_ERR_EOF : (zcio_result)r, "ws: handshake read failed");
        if (zhs_buf_append_(acc, tmp, (size_t)r) != ZCIO_OK)
            return ZCIO_ERR_NOMEM;
    }
}

/* Parse "HTTP/1.1 NNN ..." -> *status. */
static int ws_parse_status(const uint8_t *h, size_t len, int *status) {
    const uint8_t *nl = memchr(h, '\n', len);
    size_t ll = nl ? (size_t)(nl - h) : len;
    const uint8_t *sp = memchr(h, ' ', ll);
    if (!sp) return zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: malformed status line");
    const uint8_t *c = sp + 1;
    int code = 0, digits = 0;
    while (c < h + ll && *c >= '0' && *c <= '9' && digits < 3) { code = code * 10 + (*c - '0'); c++; digits++; }
    if (digits != 3) return zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: malformed status code");
    *status = code;
    return ZCIO_OK;
}

/* True if comma-separated field `list` contains `token` (case-insensitive),
 * ignoring OWS around each element. */
static bool ws_ci_has_token(const char *list, const char *token) {
    size_t tl = strlen(token);
    for (const char *p = list; *p;) {
        while (*p == ' ' || *p == '\t' || *p == ',') p++;
        const char *e = p;
        while (*e && *e != ',') e++;
        const char *te = e;
        while (te > p && (te[-1] == ' ' || te[-1] == '\t')) te--;
        if ((size_t)(te - p) == tl) {
            size_t i = 0;
            for (; i < tl; i++)
                if (tolower((unsigned char)p[i]) != tolower((unsigned char)token[i])) break;
            if (i == tl) return true;
        }
        p = e;
    }
    return false;
}

/* Case-insensitive header lookup in a raw head block; malloc'd value or NULL. */
static char *ws_find_header(const uint8_t *h, size_t len, const char *name) {
    size_t nl = strlen(name);
    const uint8_t *line = h, *end = h + len;
    while (line < end) {
        const uint8_t *eol = memchr(line, '\n', (size_t)(end - line));
        const uint8_t *le = eol ? eol : end;
        const uint8_t *colon = memchr(line, ':', (size_t)(le - line));
        if (colon && (size_t)(colon - line) == nl) {
            bool m = true;
            for (size_t i = 0; i < nl; i++)
                if ((char)tolower((unsigned char)line[i]) != (char)tolower((unsigned char)name[i])) { m = false; break; }
            if (m) {
                const uint8_t *v = colon + 1;
                while (v < le && (*v == ' ' || *v == '\t')) v++;
                const uint8_t *ve = le;
                while (ve > v && (ve[-1] == '\r' || ve[-1] == ' ' || ve[-1] == '\t')) ve--;
                size_t vl = (size_t)(ve - v);
                char *out = (char *)zcio_xmalloc(vl + 1);
                if (!out) return NULL;
                memcpy(out, v, vl);
                out[vl] = '\0';
                return out;
            }
        }
        if (!eol) break;
        line = eol + 1;
    }
    return NULL;
}

/* Turn a redirect Location into an absolute url (scheme-preserving when the
 * target is relative). Downgrade refusal happens on the next parse iteration. */
static char *ws_resolve(const char *loc, const char *host, int port, bool secure) {
    if (!loc || !*loc) { zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: empty Location"); return NULL; }
    if (strstr(loc, "://")) return zcio_strdup_(loc);
    if (loc[0] != '/') { zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: unsupported relative redirect"); return NULL; }

    const char *scheme = secure ? "wss" : "ws";
    int defp = secure ? 443 : 80;
    bool v6 = strchr(host, ':') != NULL;
    char pb[16];
    pb[0] = '\0';
    if (port != defp) snprintf(pb, sizeof pb, ":%d", port);
    size_t need = strlen(scheme) + 3 + (v6 ? 2 : 0) + strlen(host) + strlen(pb) + strlen(loc) + 1;
    char *out = (char *)zcio_xmalloc(need);
    if (!out) { zcio_fail_(ZCIO_ERR_NOMEM, "ws: out of memory"); return NULL; }
    snprintf(out, need, "%s://%s%s%s%s%s", scheme, v6 ? "[" : "", host, v6 ? "]" : "", pb, loc);
    return out;
}

zcio_ws *
zcio_ws_connect(const char *url, const zcio_http_header *headers, size_t nheaders) {
    /* Guard extra headers up-front so a hostile value cannot inject request
     * lines (mirrors the http client's CRLF check). */
    for (size_t i = 0; i < nheaders; i++) {
        if (!headers[i].key) continue;
        if (!ws_hdr_token_ok(headers[i].key) ||
            (headers[i].value && !ws_hdr_token_ok(headers[i].value))) {
            zcio_fail_(ZCIO_ERR_INVALID_ARG, "ws: illegal characters in extra header");
            return NULL;
        }
    }

    char *cur = zcio_strdup_(url);
    if (url && !cur) { zcio_fail_(ZCIO_ERR_NOMEM, "ws: out of memory"); return NULL; }

    bool prev_secure = false, have_prev = false;

    for (int redir = 0; redir <= 3; redir++) {
        bool secure;
        char *host = NULL, *path = NULL;
        int port = 0;
        if (ws_url_parse(cur, &secure, &host, &port, &path) != ZCIO_OK) {
            free(cur);
            return NULL;
        }
        /* Refuse a wss/https -> ws/http downgrade across a redirect. */
        if (have_prev && prev_secure && !secure) {
            free(host); free(path); free(cur);
            zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: refusing secure->insecure redirect downgrade");
            return NULL;
        }

        zcio_tls_ctx *tls = NULL;
        zcio_tcp_client *client = NULL;
        if (secure) {
            tls = zcio_tls_client_ctx(host);
            if (!tls) {
                free(host); free(path); free(cur);
                zcio_fail_(ZCIO_ERR_TLS, "ws: TLS context creation failed");
                return NULL;
            }
            client = zcio_tcp_client_connect_tls(host, port, tls, true);
        } else {
            client = zcio_tcp_client_connect(host, port);
        }
        if (!client) {
            /* zcio_tcp_client_connect[_tls] already called zcio_fail_ with a
             * specific reason (DNS failure, timed out, connect refused, ...)
             * -- preserve it instead of clobbering with a bare "connect
             * failed" that hides which of those it actually was. */
            char underlying[192];
            snprintf(underlying, sizeof underlying, "%s", zcio_last_error());
            if (tls) zcio_tls_ctx_free(tls);
            free(host); free(path); free(cur);
            zcio_fail_(ZCIO_ERR_CONNECT, "ws: connect failed: %s", underlying);
            return NULL;
        }
        zcio_stream *s = zcio_tcp_client_stream(client);

        uint8_t rnd[16];
        char key[25];
        if (zcio_rand_bytes_(rnd, 16) != ZCIO_OK) {
            zcio_tcp_client_free(client); if (tls) zcio_tls_ctx_free(tls);
            free(host); free(path); free(cur);
            zcio_fail_(ZCIO_ERR, "ws: entropy for key failed");
            return NULL;
        }
        base64(rnd, 16, key);

        if (ws_send_handshake(s, host, port, secure, path, key, headers, nheaders) != ZCIO_OK) {
            zcio_tcp_client_free(client); if (tls) zcio_tls_ctx_free(tls);
            free(host); free(path); free(cur);
            return NULL;
        }

        zhs_buf acc = {0};
        size_t body_start = 0;
        if (ws_read_head(s, &acc, &body_start) != ZCIO_OK) {
            zhs_buf_free_(&acc);
            zcio_tcp_client_free(client); if (tls) zcio_tls_ctx_free(tls);
            free(host); free(path); free(cur);
            return NULL;
        }
        int status = 0;
        if (ws_parse_status(ZHS_PTR(&acc), body_start, &status) != ZCIO_OK) {
            zhs_buf_free_(&acc);
            zcio_tcp_client_free(client); if (tls) zcio_tls_ctx_free(tls);
            free(host); free(path); free(cur);
            return NULL;
        }

        if (status == 101) {
            /* RFC 6455 §4.1: the 101 must also carry Upgrade: websocket and
             * Connection: Upgrade (token, case-insensitive). */
            char *up = ws_find_header(ZHS_PTR(&acc), body_start, "upgrade");
            char *cn = ws_find_header(ZHS_PTR(&acc), body_start, "connection");
            bool hdr_ok = up && cn
                       && ws_ci_has_token(up, "websocket")
                       && ws_ci_has_token(cn, "upgrade");
            free(up); free(cn);
            char *got = ws_find_header(ZHS_PTR(&acc), body_start, "sec-websocket-accept");
            char expected[29];
            (void)ws_compute_accept(key, expected);
            bool match = hdr_ok && got && strcmp(got, expected) == 0;
            free(got);
            if (!match) {
                zhs_buf_free_(&acc);
                zcio_tcp_client_free(client); if (tls) zcio_tls_ctx_free(tls);
                free(host); free(path); free(cur);
                zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: Sec-WebSocket-Accept mismatch");
                return NULL;
            }
            zcio_ws *ws = ws_new(s, false, client, tls);
            if (!ws) {
                zhs_buf_free_(&acc);
                zcio_tcp_client_free(client); if (tls) zcio_tls_ctx_free(tls);
                free(host); free(path); free(cur);
                zcio_fail_(ZCIO_ERR_NOMEM, "ws: out of memory");
                return NULL;
            }
            /* Any bytes past the head are the start of the frame stream. */
            size_t left = ZHS_AVAIL(&acc) - body_start;
            if (left && zhs_buf_append_(&ws->in, ZHS_PTR(&acc) + body_start, left) != ZCIO_OK) {
                zhs_buf_free_(&acc);
                zcio_ws_free(ws);
                free(host); free(path); free(cur);
                zcio_fail_(ZCIO_ERR_NOMEM, "ws: out of memory");
                return NULL;
            }
            zhs_buf_free_(&acc);
            free(host); free(path); free(cur);
            return ws;
        }

        if ((status == 301 || status == 302 || status == 307 || status == 308) && redir < 3) {
            char *loc = ws_find_header(ZHS_PTR(&acc), body_start, "location");
            zhs_buf_free_(&acc);
            if (!loc) {
                zcio_tcp_client_free(client); if (tls) zcio_tls_ctx_free(tls);
                free(host); free(path); free(cur);
                zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: redirect without Location");
                return NULL;
            }
            char *next = ws_resolve(loc, host, port, secure);
            free(loc);
            zcio_tcp_client_free(client); if (tls) zcio_tls_ctx_free(tls);
            free(host); free(path); free(cur);
            prev_secure = secure;
            have_prev = true;
            if (!next) return NULL; /* ws_resolve set the error */
            cur = next;
            continue;
        }

        /* Anything else is a failed handshake. */
        zhs_buf_free_(&acc);
        zcio_tcp_client_free(client); if (tls) zcio_tls_ctx_free(tls);
        free(host); free(path); free(cur);
        zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: handshake rejected (status %d)", status);
        return NULL;
    }

    free(cur);
    zcio_fail_(ZCIO_ERR_PROTOCOL, "ws: too many redirects");
    return NULL;
}

/* ========================================================================= *
 *  I/O
 * ========================================================================= */

int zcio_ws_send(zcio_ws *ws, zcio_ws_type type, const void *data, size_t len) {
    if (!ws) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "ws_send: NULL session");
    if (ws->failed || ws->close_sent)
        return zcio_fail_(ZCIO_ERR, "ws_send: session is closing/closed");
    uint8_t op;
    if (type == ZCIO_WS_TEXT) {
        if (len && !zhs_utf8_valid_(data, len))
            return zcio_fail_(ZCIO_ERR_INVALID_ARG, "ws_send: text payload not UTF-8");
        op = WS_OP_TEXT;
    } else if (type == ZCIO_WS_BINARY) {
        op = WS_OP_BIN;
    } else {
        return zcio_fail_(ZCIO_ERR_INVALID_ARG, "ws_send: invalid message type");
    }
    return ws_send_frame(ws, op, true, data, len);
}

int zcio_ws_send_text(zcio_ws *ws, const char *text) {
    if (!text) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "ws_send_text: NULL text");
    return zcio_ws_send(ws, ZCIO_WS_TEXT, text, strlen(text));
}

int zcio_ws_recv(zcio_ws *ws, zcio_ws_msg *out, int timeout_ms) {
    if (!ws || !out) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "ws_recv: NULL argument");
    memset(out, 0, sizeof *out);
    if (ws->close_recv || ws->failed) return ZCIO_ERR_EOF;

    bool bounded = timeout_ms >= 0;
    uint64_t deadline = bounded ? zcio_now_ms_() + (uint64_t)timeout_ms : 0;

    for (;;) {
        int r = ws_pump(ws, out);
        if (r == WS_MSG)    return ZCIO_OK;
        if (r == WS_CLOSED) return ZCIO_ERR_EOF;
        if (r < 0)          return r;
        /* WS_MORE: pull more bytes, honoring the deadline. */
        int to = -1;
        if (bounded) {
            uint64_t now = zcio_now_ms_();
            if (now >= deadline) return zcio_fail_(ZCIO_ERR_TIMEOUT, "ws_recv: timeout");
            uint64_t rem = deadline - now;
            to = rem > (uint64_t)INT_MAX ? INT_MAX : (int)rem;
        }
        int fr = ws_fill(ws, to);
        if (fr == ZCIO_ERR_TIMEOUT) {
            if (!bounded) continue; /* per-op timeout, not the overall deadline */
            return zcio_fail_(ZCIO_ERR_TIMEOUT, "ws_recv: timeout");
        }
        if (fr == ZCIO_ERR_EOF) { ws->failed = true; return ZCIO_ERR_EOF; }
        if (fr < 0) return fr;
    }
}

int zcio_ws_ping(zcio_ws *ws, const void *data, size_t len) {
    if (!ws) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "ws_ping: NULL session");
    if (ws->failed || ws->close_sent)
        return zcio_fail_(ZCIO_ERR, "ws_ping: session is closing/closed");
    if (len > 125) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "ws_ping: payload exceeds 125 bytes");
    return ws_send_frame(ws, WS_OP_PING, true, data, len);
}

int zcio_ws_close(zcio_ws *ws, uint16_t code, const char *reason) {
    if (!ws) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "ws_close: NULL session");

    if (!ws->close_sent && !ws->failed) {
        uint8_t pl[125];
        pl[0] = (uint8_t)(code >> 8);
        pl[1] = (uint8_t)code;
        size_t n = 2;
        if (reason) {
            size_t rl = strlen(reason);
            if (rl > 123) return zcio_fail_(ZCIO_ERR_INVALID_ARG, "ws_close: reason too long");
            if (rl && !zhs_utf8_valid_(reason, rl))
                return zcio_fail_(ZCIO_ERR_INVALID_ARG, "ws_close: reason not UTF-8");
            memcpy(pl + 2, reason, rl);
            n += rl;
        }
        int s = ws_send_frame(ws, WS_OP_CLOSE, true, pl, n);
        ws->close_sent = true;
        if (s != ZCIO_OK) { ws->failed = true; return ZCIO_OK; } /* transport gone */
    }

    /* Wait (bounded) for the peer's echo, discarding any straggling frames. */
    if (!ws->close_recv && !ws->failed) {
        uint64_t deadline = zcio_now_ms_() +
                            (ws->timeout_ms > 0 ? (uint64_t)ws->timeout_ms : WS_DEFAULT_TIMEOUT);
        zcio_ws_msg m;
        while (!ws->close_recv) {
            uint64_t now = zcio_now_ms_();
            if (now >= deadline) break;
            int r = ws_pump(ws, &m);
            if (r == WS_MSG) { zcio_ws_msg_free(&m); continue; }
            if (r == WS_CLOSED) break;
            if (r < 0) { ws->failed = true; break; }
            int rem = (int)(deadline - now);
            int fr = ws_fill(ws, rem);
            if (fr == ZCIO_ERR_TIMEOUT) { if (zcio_now_ms_() >= deadline) break; continue; }
            if (fr != ZCIO_OK) { ws->failed = true; break; } /* EOF or error */
        }
    }
    return ZCIO_OK;
}

uint16_t zcio_ws_close_code(const zcio_ws *ws) {
    return ws ? ws->close_code : 0;
}

void zcio_ws_set_max_msg_bytes(zcio_ws *ws, size_t cap) {
    if (ws && cap) ws->max_msg_bytes = cap;
}

void zcio_ws_set_timeout(zcio_ws *ws, int timeout_ms) {
    if (ws) ws->timeout_ms = timeout_ms;
}

void zcio_ws_free(zcio_ws *ws) {
    if (!ws) return;
    if (!ws->close_sent && !ws->failed)
        (void)zcio_ws_close(ws, 1000, NULL); /* best-effort graceful close */

    if (ws->client) {
        /* client owns the stream; ws->stream is borrowed from it. */
        zcio_tcp_client_free(ws->client);
        if (ws->tls_ctx) zcio_tls_ctx_free(ws->tls_ctx);
    } else if (ws->stream) {
        zcio_stream_free(ws->stream);
    }
    zhs_buf_free_(&ws->in);
    zhs_buf_free_(&ws->frag);
    free(ws);
}
