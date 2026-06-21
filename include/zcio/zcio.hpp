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

protected:
    zcio_stream* s_;
};

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

    Serial& operator<<(int32_t v)  { zcio_serial_write_i32(z_, v); return *this; }
    Serial& operator<<(uint32_t v) { zcio_serial_write_u32(z_, v); return *this; }
    Serial& operator<<(int64_t v)  { zcio_serial_write_i64(z_, v); return *this; }
    Serial& operator<<(uint64_t v) { zcio_serial_write_u64(z_, v); return *this; }
    Serial& operator<<(double v)   { zcio_serial_write_f64(z_, v); return *this; }
    Serial& operator<<(float v)    { zcio_serial_write_f32(z_, v); return *this; }
    Serial& operator<<(const std::string& s) {
        zcio_serial_write_str(z_, s.data(), s.size()); return *this;
    }

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

    void write_bit(bool b) { zcio_serial_write_bit(z_, b); }
    bool read_bit()        { return zcio_serial_read_bit(z_); }
    void synchronize()     { zcio_serial_synchronize(z_); }
    int64_t write_pos()    { return zcio_serial_write_pos(z_); }

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

// --- TCP --------------------------------------------------------------------
class TcpClient {
public:
    TcpClient(const std::string& host, int port)
        : c_(zcio_tcp_client_connect(host.c_str(), port)) {
        if (!c_) throw Error("tcp connect failed: " + last_error());
    }
    TcpClient(const TcpClient&) = delete;
    TcpClient& operator=(const TcpClient&) = delete;
    TcpClient(TcpClient&& o) noexcept : c_(o.c_) { o.c_ = nullptr; }
    ~TcpClient() { if (c_) zcio_tcp_client_free(c_); }
    StreamRef stream() { return StreamRef(zcio_tcp_client_stream(c_)); }

private:
    zcio_tcp_client* c_;
};

class TcpServer {
public:
    explicit TcpServer(int port) : s_(zcio_tcp_server_listen(port)) {
        if (!s_) throw Error("tcp listen failed: " + last_error());
    }
    TcpServer(const TcpServer&) = delete;
    TcpServer& operator=(const TcpServer&) = delete;
    ~TcpServer() { if (s_) zcio_tcp_server_free(s_); }

    // Returns a borrowed stream for the accepted connection, or empty on timeout.
    StreamRef accept(int timeout_ms = 1000) {
        size_t id = 0;
        zcio_tcp_conn* c = zcio_tcp_server_accept(s_, &id, timeout_ms);
        return StreamRef(c ? zcio_tcp_conn_stream(c) : nullptr);
    }

private:
    zcio_tcp_server* s_;
};

// --- HTTP -------------------------------------------------------------------
struct HttpResponse {
    int status = 0;
    std::string status_text, version, headers_json, body;
};

inline HttpResponse http_get(const std::string& url) {
    zcio_http_response r = zcio_http_get(url.c_str());
    HttpResponse out;
    out.status = r.status;
    if (r.status_text)  out.status_text = r.status_text;
    if (r.version)      out.version = r.version;
    if (r.headers_json) out.headers_json = r.headers_json;
    if (r.body && r.body_size) out.body.assign(r.body, r.body_size);
    zcio_http_response_free(&r);
    return out;
}

}  // namespace zcio

#endif  // ZCIO_HPP
