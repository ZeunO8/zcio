// Smoke test for the zcio C++ RAII wrapper. Build:
//   c++ -std=c++17 -I../../include test_zcio.cpp -L../../build -lzcio -o test_cpp
#include <zcio/zcio.hpp>

#include <cassert>
#include <cstdio>
#include <string>

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

    // serializer operator<< / >> over a buffer
    {
        unsigned char mem[256];
        {
            auto s = zcio::Serial::buffer(mem, sizeof mem);
            s << int32_t(-7) << double(1.5) << std::string("vibe");
        }
        {
            auto s = zcio::Serial::buffer(mem, sizeof mem);
            int32_t i = 0; double d = 0; std::string str;
            s >> i >> d >> str;
            CHECK(i == -7);
            CHECK(d == 1.5);
            CHECK(str == "vibe");
        }
    }

    // counting serial
    {
        auto s = zcio::Serial::counting();
        s << int32_t(0) << double(0);
        CHECK(s.write_pos() == 4 + 8);
    }

    // tcp loopback
    {
        zcio::TcpServer srv(39911);
        zcio::TcpClient cli("127.0.0.1", 39911);
        auto conn = srv.accept(2000);
        CHECK(static_cast<bool>(conn));
        if (conn) {
            cli.stream().write(std::string_view("roundtrip"));
            char buf[9];
            CHECK(conn.read_full(buf, 9) == 9);
            CHECK(std::string(buf, 9) == "roundtrip");
        }
    }

    if (failures == 0) std::printf("all C++ wrapper tests passed\n");
    return failures ? 1 : 0;
}
