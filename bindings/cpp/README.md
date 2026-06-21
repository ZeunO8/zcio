# zcio — C++ RAII wrapper

Header-only. The wrapper itself lives at `include/zcio/zcio.hpp` so it installs
alongside the C headers and is included as `<zcio/zcio.hpp>`. It re-exposes the
ergonomics of the original C++ `iostreams` library (stream objects, `<<` / `>>`)
over the pure-C zcio core, with RAII ownership of every C handle.

```cpp
#include <zcio/zcio.hpp>

zcio::Ring ring(4096);
ring.write(std::string_view("hello"));

unsigned char mem[256];
auto s = zcio::Serial::buffer(mem, sizeof mem);
s << int32_t(42) << 3.14 << std::string("vibe");

zcio::TcpClient cli("example.com", 80);
cli.stream().write("GET / HTTP/1.0\r\n\r\n");
```

## Build & test

Requires the zcio library built first (static is fine):

```sh
cmake -S ../.. -B ../../build && cmake --build ../../build
c++ -std=c++17 -I../../include test_zcio.cpp -L../../build -lzcio \
    -Wl,-rpath,../../build -o test_cpp
./test_cpp
```
