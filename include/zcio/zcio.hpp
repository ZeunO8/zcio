// zcio.hpp - header-only C++ RAII wrapper over the zcio C ABI.
//
// Re-exposes the ergonomics the original C++ iostreams library had (stream
// objects, operator<< / operator>>) but built entirely on the pure-C zcio core.
// No zcio C++ source exists; this is a thin, zero-overhead wrapper that owns C
// handles via unique_ptr-style RAII and never leaks them.
//
//     #include <zcio/zcio.hpp>
//     zcio::Ring ring(4096);
//     zcio::Serial s = zcio::Serial::buffer(buf, sizeof buf);
//     s << 42 << 3.14 << std::string("hi");
//
#ifndef ZCIO_HPP
#define ZCIO_HPP

#include <zcio/zcio.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace zcio {

inline std::string version() { return zcio_version_string(); }
inline void init() { zcio_init(); }

class Error : public std::runtime_error {
public:
    explicit Error(const std::string& what) : std::runtime_error(what) {}
};

inline std::string last_error() { return zcio_last_error(); }

// --- a non-owning view of a zcio_stream* ------------------------------------
class StreamRef {
public:
    explicit StreamRef(zcio_stream* s) noexcept : s_(s) {}
    zcio_stream* get() const noexcept { return s_; }
    explicit operator bool() const noexcept { return s_ != nullptr; }

    int64_t write(const void* p, size_t n) { return zcio_write_full(s_, p, n); }
    int64_t read(void* p, size_t n)        { return zcio_read(s_, p, n); }
    int64_t read_full(void* p, size_t n)   { return zcio_read_full(s_, p, n); }
    int64_t write(std::string_view sv)     { return zcio_write_full(s_, sv.data(), sv.size()); }

    std::string read_string(size_t n) {
        std::string out(n, '\0');
        int64_t got = zcio_read(s_, out.data(), n);
        out.resize(got > 0 ? static_cast<size_t>(got) : 0);
        return out;
    }
    int flush() { return zcio_flush(s_); }

    int64_t available() const { return zcio_available(s_); }
    bool eof() const { return zcio_stream_eof(s_); }
    int64_t seek(int64_t off,
                 zcio_seek_origin origin = ZCIO_SEEK_SET,
                 zcio_seek_which which = ZCIO_SEEK_BOTH) {
        return zcio_seek(s_, off, origin, which);
    }
    const char* name() const { return zcio_stream_name(s_); }

protected:
    zcio_stream* s_;
};

// Pump up to `limit` bytes from src into dst (SIZE_MAX = until EOF).
inline int64_t copy(StreamRef dst, StreamRef src, size_t limit = SIZE_MAX) {
    return zcio_copy(dst.get(), src.get(), limit);
}

// --- owning stream ----------------------------------------------------------
class Stream : public StreamRef {
public:
    explicit Stream(zcio_stream* s) noexcept : StreamRef(s) {}
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;
    Stream(Stream&& o) noexcept : StreamRef(o.s_) { o.s_ = nullptr; }
    Stream& operator=(Stream&& o) noexcept {
        if (this != &o) { reset(); s_ = o.s_; o.s_ = nullptr; }
        return *this;
    }
    ~Stream() { reset(); }
    void reset() { if (s_) { zcio_stream_free(s_); s_ = nullptr; } }
};

// --- ring buffer ------------------------------------------------------------
class Ring {
public:
    explicit Ring(size_t capacity, bool non_blocking = false)
        : r_(zcio_ring_new(capacity, non_blocking)) {
        if (!r_) throw Error("zcio_ring_new failed");
    }
    Ring(const Ring&) = delete;
    Ring& operator=(const Ring&) = delete;
    Ring(Ring&& o) noexcept : r_(o.r_) { o.r_ = nullptr; }
    ~Ring() { if (r_) zcio_ring_free(r_); }

    int64_t write(const void* p, size_t n) { return zcio_ring_write(r_, p, n); }
    int64_t read(void* p, size_t n)        { return zcio_ring_read(r_, p, n); }
    int64_t write(std::string_view sv)     { return zcio_ring_write(r_, sv.data(), sv.size()); }
    size_t available() const { return zcio_ring_available_read(r_); }

    // Borrowed stream view over this ring (ring must outlive it).
    StreamRef as_stream() { return StreamRef(zcio_ring_as_stream(r_, false)); }
    zcio_ring* get() const noexcept { return r_; }

private:
    zcio_ring* r_;
};

// --- serializer -------------------------------------------------------------
class Serial {
public:
    static Serial buffer(void* mem, int64_t size, bool bit_stream = false) {
        return Serial(zcio_serial_new_buffer(mem, size, bit_stream));
    }
    static Serial counting() { return Serial(zcio_serial_new_count()); }
    // Build over a borrowed stream; the Serial does not own it.
    static Serial over(StreamRef s, bool bit_stream = false) {
        return Serial(zcio_serial_new(s.get(), bit_stream, false));
    }

    Serial(const Serial&) = delete;
    Serial& operator=(const Serial&) = delete;
    Serial(Serial&& o) noexcept : z_(o.z_) { o.z_ = nullptr; }
    ~Serial() { if (z_) zcio_serial_free(z_); }

    Serial& operator<<(int8_t v)   { zcio_serial_write_i8(z_, v);  return *this; }
    Serial& operator<<(uint8_t v)  { zcio_serial_write_u8(z_, v);  return *this; }
    Serial& operator<<(int16_t v)  { zcio_serial_write_i16(z_, v); return *this; }
    Serial& operator<<(uint16_t v) { zcio_serial_write_u16(z_, v); return *this; }
    Serial& operator<<(int32_t v)  { zcio_serial_write_i32(z_, v); return *this; }
    Serial& operator<<(uint32_t v) { zcio_serial_write_u32(z_, v); return *this; }
    Serial& operator<<(int64_t v)  { zcio_serial_write_i64(z_, v); return *this; }
    Serial& operator<<(uint64_t v) { zcio_serial_write_u64(z_, v); return *this; }
    Serial& operator<<(double v)   { zcio_serial_write_f64(z_, v); return *this; }
    Serial& operator<<(float v)    { zcio_serial_write_f32(z_, v); return *this; }
    Serial& operator<<(const std::string& s) {
        zcio_serial_write_str(z_, s.data(), s.size()); return *this;
    }

    Serial& operator>>(int8_t& v)   { v = zcio_serial_read_i8(z_);  return *this; }
    Serial& operator>>(uint8_t& v)  { v = zcio_serial_read_u8(z_);  return *this; }
    Serial& operator>>(int16_t& v)  { v = zcio_serial_read_i16(z_); return *this; }
    Serial& operator>>(uint16_t& v) { v = zcio_serial_read_u16(z_); return *this; }
    Serial& operator>>(int32_t& v)  { v = zcio_serial_read_i32(z_); return *this; }
    Serial& operator>>(uint32_t& v) { v = zcio_serial_read_u32(z_); return *this; }
    Serial& operator>>(int64_t& v)  { v = zcio_serial_read_i64(z_); return *this; }
    Serial& operator>>(uint64_t& v) { v = zcio_serial_read_u64(z_); return *this; }
    Serial& operator>>(double& v)   { v = zcio_serial_read_f64(z_); return *this; }
    Serial& operator>>(float& v)    { v = zcio_serial_read_f32(z_); return *this; }
    Serial& operator>>(std::string& s) {
        size_t n = 0;
        char* p = zcio_serial_read_str(z_, &n);
        s.assign(p ? p : "", p ? n : 0);
        zcio_free(p);
        return *this;
    }

    // bulk byte I/O
    int64_t write_bytes(const void* p, size_t n) { return zcio_serial_write_bytes(z_, p, n); }
    int64_t read_bytes(void* p, size_t n)        { return zcio_serial_read_bytes(z_, p, n); }
    void    write_byte(uint8_t b) { zcio_serial_write_byte(z_, b); }
    uint8_t read_byte()           { return zcio_serial_read_byte(z_); }

    // bit I/O
    void write_bit(bool b) { zcio_serial_write_bit(z_, b); }
    bool read_bit()        { return zcio_serial_read_bit(z_); }
    // Each vector element holds one bit in its LSB. Writes `count` bits
    // starting at element `index`.
    void write_bits(const std::vector<uint8_t>& bits, size_t index, size_t count) {
        zcio_serial_write_bits(z_, bits.data(), index, count);
    }
    void read_bits(std::vector<uint8_t>& bits, size_t index, size_t count) {
        if (bits.size() < index + count) bits.resize(index + count);
        zcio_serial_read_bits(z_, bits.data(), index, count);
    }

    void synchronize()     { zcio_serial_synchronize(z_); }

    // positioning
    int64_t write_pos()    { return zcio_serial_write_pos(z_); }
    int64_t read_pos()     { return zcio_serial_read_pos(z_); }
    void set_write_pos(size_t i) { zcio_serial_set_write_pos(z_, i); }
    void set_read_pos(size_t i)  { zcio_serial_set_read_pos(z_, i); }
    int64_t write_len()    { return zcio_serial_write_len(z_); }
    int64_t read_len()     { return zcio_serial_read_len(z_); }

    // status
    bool   read_eof()    { return zcio_serial_read_eof(z_); }
    bool   read_empty()  { return zcio_serial_read_empty(z_); }
    bool   short_read()  { return zcio_serial_short_read(z_); }
    size_t last_read()   { return zcio_serial_last_read(z_); }
    void   clear_read()  { zcio_serial_clear_read(z_); }

    zcio_serial* get() const noexcept { return z_; }

private:
    explicit Serial(zcio_serial* z) : z_(z) {
        if (!z_) throw Error("zcio_serial creation failed");
    }
    zcio_serial* z_;
};

// --- memory stream ----------------------------------------------------------
inline Stream memory_stream(void* data, size_t size) {
    return Stream(zcio_memory_stream(data, size));
}

// --- TLS context (RAII, borrowed by endpoints) ------------------------------
inline bool tls_available() { return zcio_tls_available(); }
inline std::string tls_backend_name() { return zcio_tls_backend_name(); }

class TlsCtx {
public:
    // Client context that verifies `host` (SNI + cert hostname).
    static TlsCtx client(const std::string& host) {
        return TlsCtx(zcio_tls_client_ctx(host.c_str()));
    }
    // Server context with a generated self-signed cert.
    static TlsCtx server() { return TlsCtx(zcio_tls_server_ctx()); }
    // Server context from PEM cert/key file paths.
    static TlsCtx server_files(const std::string& cert, const std::string& key) {
        return TlsCtx(zcio_tls_server_ctx_files(cert.c_str(), key.c_str()));
    }

    TlsCtx(const TlsCtx&) = delete;
    TlsCtx& operator=(const TlsCtx&) = delete;
    TlsCtx(TlsCtx&& o) noexcept : c_(o.c_) { o.c_ = nullptr; }
    TlsCtx& operator=(TlsCtx&& o) noexcept {
        if (this != &o) { if (c_) zcio_tls_ctx_free(c_); c_ = o.c_; o.c_ = nullptr; }
        return *this;
    }
    ~TlsCtx() { if (c_) zcio_tls_ctx_free(c_); }

    zcio_tls_ctx* get() const noexcept { return c_; }

private:
    explicit TlsCtx(zcio_tls_ctx* c) : c_(c) {
        if (!c_) throw Error("zcio_tls ctx creation failed: " + last_error());
    }
    zcio_tls_ctx* c_;
};

// --- TCP --------------------------------------------------------------------
class TcpClient {
public:
    TcpClient(const std::string& host, int port)
        : c_(zcio_tcp_client_connect(host.c_str(), port)) {
        if (!c_) throw Error("tcp connect failed: " + last_error());
    }
    // Secure variant: borrows ctx (caller keeps owning it).
    TcpClient(const std::string& host, int port, TlsCtx& ctx, bool verify = true)
        : c_(zcio_tcp_client_connect_tls(host.c_str(), port, ctx.get(), verify)) {
        if (!c_) throw Error("tls tcp connect failed: " + last_error());
    }
    TcpClient(const TcpClient&) = delete;
    TcpClient& operator=(const TcpClient&) = delete;
    TcpClient(TcpClient&& o) noexcept : c_(o.c_) { o.c_ = nullptr; }
    ~TcpClient() { if (c_) zcio_tcp_client_free(c_); }
    StreamRef stream() { return StreamRef(zcio_tcp_client_stream(c_)); }

    int tls_upgrade(TlsCtx& ctx) { return zcio_tcp_client_tls_upgrade(c_, ctx.get()); }
    int wait_readable(int timeout_ms) { return zcio_tcp_client_wait_readable(c_, timeout_ms); }
    int wait_writable(int timeout_ms) { return zcio_tcp_client_wait_writable(c_, timeout_ms); }
    int bytes_available() { return zcio_tcp_client_bytes_available(c_); }

private:
    zcio_tcp_client* c_;
};

// A borrowed accepted connection: id + non-owning stream + wait helpers.
struct TcpConn {
    size_t id = 0;
    StreamRef stream{nullptr};
    zcio_tcp_conn* conn = nullptr;

    explicit operator bool() const noexcept { return conn != nullptr; }
    int wait_readable(int timeout_ms) { return zcio_tcp_conn_wait_readable(conn, timeout_ms); }
    int wait_writable(int timeout_ms) { return zcio_tcp_conn_wait_writable(conn, timeout_ms); }
};

class TcpServer {
public:
    explicit TcpServer(int port) : s_(zcio_tcp_server_listen(port)) {
        if (!s_) throw Error("tcp listen failed: " + last_error());
    }
    // Secure listener: borrows ctx.
    TcpServer(int port, TlsCtx& ctx, bool non_blocking = false)
        : s_(zcio_tcp_server_listen_tls(port, ctx.get(), non_blocking)) {
        if (!s_) throw Error("tls tcp listen failed: " + last_error());
    }
    TcpServer(const TcpServer&) = delete;
    TcpServer& operator=(const TcpServer&) = delete;
    ~TcpServer() { if (s_) zcio_tcp_server_free(s_); }

    // Accept one client; returns a borrowed conn (id + stream) or empty on timeout.
    TcpConn accept_conn(int timeout_ms = 1000) {
        TcpConn out;
        zcio_tcp_conn* c = zcio_tcp_server_accept(s_, &out.id, timeout_ms);
        out.conn = c;
        out.stream = StreamRef(c ? zcio_tcp_conn_stream(c) : nullptr);
        return out;
    }
    // Back-compat: returns just the borrowed stream.
    StreamRef accept(int timeout_ms = 1000) {
        return accept_conn(timeout_ms).stream;
    }
    int close_client(size_t id) { return zcio_tcp_server_close_client(s_, id); }

private:
    zcio_tcp_server* s_;
};

// --- UDP --------------------------------------------------------------------
class UdpClient {
public:
    UdpClient(const std::string& host, int port)
        : c_(zcio_udp_client_open(host.c_str(), port)) {
        if (!c_) throw Error("udp client open failed: " + last_error());
    }
    UdpClient(const UdpClient&) = delete;
    UdpClient& operator=(const UdpClient&) = delete;
    UdpClient(UdpClient&& o) noexcept : c_(o.c_) { o.c_ = nullptr; }
    ~UdpClient() { if (c_) zcio_udp_client_free(c_); }
    StreamRef stream() { return StreamRef(zcio_udp_client_stream(c_)); }

private:
    zcio_udp_client* c_;
};

class UdpServer {
public:
    explicit UdpServer(int port) : s_(zcio_udp_server_bind(port)) {
        if (!s_) throw Error("udp server bind failed: " + last_error());
    }
    UdpServer(const UdpServer&) = delete;
    UdpServer& operator=(const UdpServer&) = delete;
    UdpServer(UdpServer&& o) noexcept : s_(o.s_) { o.s_ = nullptr; }
    ~UdpServer() { if (s_) zcio_udp_server_free(s_); }

    // Receive one datagram; returns a borrowed per-peer packet stream or empty.
    StreamRef receive(bool non_block = false, unsigned timeout_us = 1000000) {
        zcio_udp_packet* p = zcio_udp_server_receive(s_, non_block, timeout_us);
        return StreamRef(p ? zcio_udp_packet_stream(p) : nullptr);
    }

private:
    zcio_udp_server* s_;
};

// --- UDP multicast ----------------------------------------------------------
class McastSender {
public:
    McastSender(const std::string& group, int port)
        : s_(zcio_mcast_sender_open(group.c_str(), port)) {
        if (!s_) throw Error("mcast sender open failed: " + last_error());
    }
    McastSender(const McastSender&) = delete;
    McastSender& operator=(const McastSender&) = delete;
    McastSender(McastSender&& o) noexcept : s_(o.s_) { o.s_ = nullptr; }
    ~McastSender() { if (s_) zcio_mcast_sender_free(s_); }
    StreamRef stream() { return StreamRef(zcio_mcast_sender_stream(s_)); }

private:
    zcio_mcast_sender* s_;
};

class McastReceiver {
public:
    McastReceiver(const std::string& group, int port)
        : r_(zcio_mcast_receiver_open(group.c_str(), port)) {
        if (!r_) throw Error("mcast receiver open failed: " + last_error());
    }
    McastReceiver(const McastReceiver&) = delete;
    McastReceiver& operator=(const McastReceiver&) = delete;
    McastReceiver(McastReceiver&& o) noexcept : r_(o.r_) { o.r_ = nullptr; }
    ~McastReceiver() { if (r_) zcio_mcast_receiver_free(r_); }
    StreamRef stream() { return StreamRef(zcio_mcast_receiver_stream(r_)); }

private:
    zcio_mcast_receiver* r_;
};

// --- DNS --------------------------------------------------------------------
inline bool is_ipv4(const std::string& s) { return zcio_is_ipv4(s.c_str()); }

inline std::string resolve_ipv4(const std::string& host) {
    char* p = zcio_resolve_ipv4(host.c_str());
    std::string out(p ? p : "");
    zcio_free(p);
    return out;
}

inline std::string local_ipv4() {
    char* p = zcio_local_ipv4();
    std::string out(p ? p : "");
    zcio_free(p);
    return out;
}

inline std::vector<std::string> dns_query_a(const std::string& host) {
    size_t n = 0;
    char** v = zcio_dns_query_a(host.c_str(), &n);
    std::vector<std::string> out;
    if (v) {
        out.reserve(n);
        for (size_t i = 0; i < n; ++i) out.emplace_back(v[i] ? v[i] : "");
        zcio_strv_free(v, n);
    }
    return out;
}

inline std::vector<std::string> dns_query_aaaa(const std::string& host) {
    size_t n = 0;
    char** v = zcio_dns_query_aaaa(host.c_str(), &n);
    std::vector<std::string> out;
    if (v) {
        out.reserve(n);
        for (size_t i = 0; i < n; ++i) out.emplace_back(v[i] ? v[i] : "");
        zcio_strv_free(v, n);
    }
    return out;
}

// --- HTTP -------------------------------------------------------------------
struct HttpResponse {
    int status = 0;
    std::string status_text, version, headers_json, body;
};

struct HttpHeader { std::string key, value; };

namespace detail {
inline HttpResponse from_c(zcio_http_response r) {
    HttpResponse out;
    out.status = r.status;
    if (r.status_text)  out.status_text = r.status_text;
    if (r.version)      out.version = r.version;
    if (r.headers_json) out.headers_json = r.headers_json;
    if (r.body && r.body_size) out.body.assign(r.body, r.body_size);
    zcio_http_response_free(&r);
    return out;
}
}  // namespace detail

inline HttpResponse http_get(const std::string& url) {
    return detail::from_c(zcio_http_get(url.c_str()));
}
inline HttpResponse http_delete(const std::string& url) {
    return detail::from_c(zcio_http_delete(url.c_str()));
}
inline HttpResponse http_post(const std::string& url, std::string_view body = {}) {
    return detail::from_c(zcio_http_post(url.c_str(), body.data(), body.size()));
}
inline HttpResponse http_put(const std::string& url, std::string_view body = {}) {
    return detail::from_c(zcio_http_put(url.c_str(), body.data(), body.size()));
}
inline HttpResponse http_request(const std::string& method, const std::string& url,
                                 const std::vector<HttpHeader>& headers = {},
                                 std::string_view body = {}) {
    std::vector<zcio_http_header> ch;
    ch.reserve(headers.size());
    for (const auto& h : headers) ch.push_back({h.key.c_str(), h.value.c_str()});
    return detail::from_c(zcio_http_request(method.c_str(), url.c_str(),
                                            ch.empty() ? nullptr : ch.data(),
                                            ch.size(), body.data(), body.size()));
}

}  // namespace zcio

#endif  // ZCIO_HPP
