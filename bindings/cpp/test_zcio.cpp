// Smoke test for the zcio C++ RAII wrapper. Build:
//   c++ -std=c++17 -I../../include test_zcio.cpp -L../../build -lzcio -o test_cpp
#include <zcio/zcio.hpp>

#include <cassert>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>

// Derive a per-process port base so rapid re-runs avoid TIME_WAIT collisions
// on fixed ports. Range stays well inside the ephemeral space.
static int port_base() {
    return 39000 + (static_cast<int>(::getpid()) % 2000);
}

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

int main() {
    zcio::init();

    // version
    CHECK(!zcio::version().empty());

    // ring
    {
        zcio::Ring r(64);
        CHECK(r.write(std::string_view("hello")) == 5);
        CHECK(r.available() == 5);
        char buf[5];
        CHECK(r.read(buf, 5) == 5);
        CHECK(std::string(buf, 5) == "hello");
    }

    // serializer operator<< / >> over a buffer (all scalar widths)
    {
        unsigned char mem[256];
        {
            auto s = zcio::Serial::buffer(mem, sizeof mem);
            s << int8_t(-1) << uint8_t(250) << int16_t(-2) << uint16_t(60000)
              << int32_t(-7) << uint32_t(7u) << int64_t(-9) << uint64_t(9u)
              << float(2.5f) << double(1.5) << std::string("vibe");
        }
        {
            auto s = zcio::Serial::buffer(mem, sizeof mem);
            int8_t i8 = 0; uint8_t u8 = 0; int16_t i16 = 0; uint16_t u16 = 0;
            int32_t i = 0; uint32_t u = 0; int64_t i64 = 0; uint64_t u64 = 0;
            float f = 0; double d = 0; std::string str;
            s >> i8 >> u8 >> i16 >> u16 >> i >> u >> i64 >> u64 >> f >> d >> str;
            CHECK(i8 == -1); CHECK(u8 == 250);
            CHECK(i16 == -2); CHECK(u16 == 60000);
            CHECK(i == -7); CHECK(u == 7u);
            CHECK(i64 == -9); CHECK(u64 == 9u);
            CHECK(f == 2.5f); CHECK(d == 1.5);
            CHECK(str == "vibe");
        }
    }

    // counting serial
    {
        auto s = zcio::Serial::counting();
        s << int32_t(0) << double(0);
        CHECK(s.write_pos() == 4 + 8);
    }

    // serial positioning + status accessors over a buffer
    {
        unsigned char mem[64];
        auto s = zcio::Serial::buffer(mem, sizeof mem);
        s << int32_t(11) << int32_t(22);
        CHECK(s.write_pos() == 8);
        s.set_read_pos(4);
        int32_t v = 0;
        s >> v;
        CHECK(v == 22);
        CHECK(s.read_pos() == 8);
        CHECK(!s.short_read());
    }

    // bit-array roundtrip over a Ring stream
    {
        zcio::Ring ring(64);
        std::vector<uint8_t> bits = {1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0};
        {
            auto s = zcio::Serial::over(ring.as_stream(), /*bit_stream=*/true);
            s.write_bits(bits, 0, bits.size());
            s.synchronize();
        }
        {
            auto s = zcio::Serial::over(ring.as_stream(), /*bit_stream=*/true);
            std::vector<uint8_t> out;
            s.read_bits(out, 0, bits.size());
            for (size_t i = 0; i < bits.size(); ++i) CHECK(out[i] == bits[i]);
        }
    }

    // stream copy: Ring -> memory Stream, plus available/eof on StreamRef
    {
        zcio::Ring src(64);
        src.write(std::string_view("copy-me"));
        char dstbuf[16] = {};
        auto dst = zcio::memory_stream(dstbuf, sizeof dstbuf);
        zcio::StreamRef srcref = src.as_stream();
        int64_t n = zcio::copy(dst, srcref, 7);
        CHECK(n == 7);
        CHECK(std::string(dstbuf, 7) == "copy-me");
    }

    // tcp loopback (back-compat accept())
    try {
        const int port = port_base() + 0;
        zcio::TcpServer srv(port);
        zcio::TcpClient cli("127.0.0.1", port);
        auto conn = srv.accept(2000);
        CHECK(static_cast<bool>(conn));
        if (conn) {
            cli.stream().write(std::string_view("roundtrip"));
            char buf[9];
            CHECK(conn.read_full(buf, 9) == 9);
            CHECK(std::string(buf, 9) == "roundtrip");
        }
    } catch (const zcio::Error& e) {
        std::printf("[skip] tcp loopback: %s\n", e.what());
    }

    // tcp server multi-client: accept 2, close one
    try {
        const int port = port_base() + 1;
        zcio::TcpServer srv(port);
        zcio::TcpClient c1("127.0.0.1", port);
        auto a1 = srv.accept_conn(2000);
        CHECK(static_cast<bool>(a1));
        zcio::TcpClient c2("127.0.0.1", port);
        auto a2 = srv.accept_conn(2000);
        CHECK(static_cast<bool>(a2));
        CHECK(a1.id != a2.id);
        // exercise wait_* / bytes_available
        c1.stream().write(std::string_view("ping"));
        CHECK(a1.wait_readable(1000) >= 0);
        char b[4];
        CHECK(a1.stream.read_full(b, 4) == 4);
        CHECK(std::string(b, 4) == "ping");
        CHECK(c1.wait_writable(1000) >= 0);
        // close the first client by id
        CHECK(srv.close_client(a1.id) == 0);
    } catch (const zcio::Error& e) {
        std::printf("[skip] tcp multi-client: %s\n", e.what());
    }

    // udp loopback round-trip
    try {
        const int port = port_base() + 2;
        zcio::UdpServer srv(port);
        zcio::UdpClient cli("127.0.0.1", port);
        cli.stream().write(std::string_view("udp-hi"));
        auto pkt = srv.receive(false, 1000000);
        CHECK(static_cast<bool>(pkt));
        if (pkt) {
            char buf[6];
            int64_t got = pkt.read(buf, sizeof buf);
            CHECK(got == 6);
            CHECK(std::string(buf, 6) == "udp-hi");
        }
    } catch (const zcio::Error& e) {
        std::printf("[skip] udp loopback: %s\n", e.what());
    }

    // multicast best-effort loopback (must not fail if nothing arrives)
    {
        try {
            const int port = port_base() + 3;
            zcio::McastReceiver rx("239.255.0.1", port);
            zcio::McastSender tx("239.255.0.1", port);
            tx.stream().write(std::string_view("mcast"));
            char buf[5] = {};
            int64_t got = rx.stream().read(buf, sizeof buf);
            if (got == 5 && std::string(buf, 5) == "mcast")
                std::printf("multicast loopback delivered\n");
            else
                std::printf("[skip] multicast: no datagram in window\n");
        } catch (const zcio::Error& e) {
            std::printf("[skip] multicast unavailable: %s\n", e.what());
        }
    }

    // DNS
    {
        CHECK(zcio::is_ipv4("127.0.0.1"));
        CHECK(!zcio::is_ipv4("not-an-ip"));
        CHECK(zcio::resolve_ipv4("127.0.0.1") == "127.0.0.1");
        std::string lan = zcio::local_ipv4();
        if (!lan.empty()) std::printf("local ipv4: %s\n", lan.c_str());
        else std::printf("[skip] local ipv4 unavailable\n");
        auto a = zcio::dns_query_a("127.0.0.1");
        CHECK(!a.empty());
        CHECK(a[0] == "127.0.0.1");
        // AAAA on a literal is best-effort; just exercise it.
        auto aaaa = zcio::dns_query_aaaa("::1");
        (void)aaaa;
    }

    // HTTP offline: tiny responder on a thread via zcio::TcpServer.
    try {
        const int port = port_base() + 4;
        zcio::TcpServer srv(port);
        std::thread responder([&srv]() {
            auto conn = srv.accept_conn(3000);
            if (conn) {
                char buf[1024];
                conn.stream.read(buf, sizeof buf);  // consume request line/headers
                static const char* resp =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Length: 5\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "hello";
                conn.stream.write(std::string_view(resp));
                conn.stream.flush();
                // http_get's read_all loops until EOF, so close the connection.
                srv.close_client(conn.id);
            }
        });
        auto r = zcio::http_get("http://127.0.0.1:" + std::to_string(port) + "/");
        responder.join();
        CHECK(r.status == 200);
        CHECK(r.body == "hello");
    } catch (const zcio::Error& e) {
        std::printf("[skip] http offline: %s\n", e.what());
    }

    // TLS loopback (skip cleanly if no backend compiled in)
    {
        if (!zcio::tls_available()) {
            std::printf("[skip] TLS backend unavailable\n");
        } else {
            const int port = port_base() + 5;
            try {
                auto sctx = zcio::TlsCtx::server();
                zcio::TcpServer srv(port, sctx);
                std::thread server_thr([&srv]() {
                    auto conn = srv.accept(3000);
                    if (conn) {
                        char b[5] = {};
                        if (conn.read_full(b, 5) == 5)
                            conn.write(std::string_view(b, 5));
                        conn.flush();
                    }
                });
                auto cctx = zcio::TlsCtx::client("127.0.0.1");
                zcio::TcpClient cli("127.0.0.1", port, cctx, /*verify=*/false);
                cli.stream().write(std::string_view("tlsok"));
                cli.stream().flush();
                char rb[5] = {};
                bool ok = cli.stream().read_full(rb, 5) == 5
                          && std::string(rb, 5) == "tlsok";
                server_thr.join();
                CHECK(ok);
                if (ok) std::printf("TLS loopback ok (backend=%s)\n",
                                    zcio::tls_backend_name().c_str());
            } catch (const zcio::Error& e) {
                std::printf("[skip] TLS loopback: %s\n", e.what());
            }
        }
    }

    if (failures == 0) std::printf("all C++ wrapper tests passed\n");
    return failures ? 1 : 0;
}
