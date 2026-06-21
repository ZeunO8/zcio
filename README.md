# zcio

**A pure C23 streaming I/O library** — a ground-up C rewrite of the C++
`iostreams` library. zcio exposes a feature-rich, stable C ABI designed to be
consumed directly or wrapped by other languages. There is **no C++ in the
core**: every abstraction `std::streambuf` provided via virtual dispatch is
re-implemented here with an explicit, branch-predictable vtable.

## Why a C rewrite

The original `iostreams` already shipped a flat C API on top of a C++ core. zcio
makes that C surface *native*: no name mangling, no exceptions, no RTTI, no STL
across the FFI boundary. That is what lets Python, Node, C++, and anything else
with a C FFI bind it cleanly.

## Design principles

- **One stream abstraction.** Everything — ring buffers, memory views, TCP/UDP
  sockets, TLS overlays, archive entries — is a `zcio_stream`: a const vtable of
  operations plus an opaque context (`include/zcio/stream.h`). This is the
  direct, ABI-stable replacement for C++ virtual `streambuf` dispatch.
- **O(1) constant-time hot paths.** Per-operation cost is independent of total
  bytes streamed. The ring buffer is lock-free SPSC with atomic head/tail and
  at most two memcpys per op; the TCP server indexes connections by id in a
  growable array, not a tree. (Network/DNS/TLS handshakes are syscall-bound and
  inherently not O(1) — those are called out, not hidden.)
  > Note: the original brief floated "O(0) / infinite time" as a goal. There is
  > no such complexity class, and "infinite time" is the *worst* outcome. The
  > achievable and intended target is O(1) per operation, which is what the core
  > delivers.
- **Zero mandatory dependencies.** The core compiles with no TLS or archive
  libraries. Both are optional, pluggable backends selected at build time.

## Modules

| Header | What it gives you |
|---|---|
| `zcio/stream.h` | the `zcio_stream` vtable + `read/write/seek/flush/copy` verbs |
| `zcio/serial.h` | bit/byte serializer (count, buffer, and stream modes) |
| `zcio/ring.h`   | lock-free SPSC ring buffer (own or shared-memory) |
| `zcio/membuf.h` | fixed memory view + byte-counting streams |
| `zcio/net.h`    | TCP client/server, UDP client/server, UDP multicast |
| `zcio/tls.h`    | pluggable TLS backend (OpenSSL default, or compiled out) |
| `zcio/http.h`   | minimal synchronous HTTP/1.1 client |
| `zcio/dns.h`    | resolution + address utilities |
| `zcio/archive.h`| tar/gz entries via libarchive (opt-in) |
| `zcio/zcio.hpp` | header-only C++ RAII wrapper (ergonomic `<<` / `>>`) |

## Build

```sh
cmake -S . -B build -DZCIO_BUILD_SHARED=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

A single `ctest` run drives the whole suite: the C tests **and** the language
bindings (C++, Python, Node). The C++ binding test only needs a C++ compiler;
the Python (ctypes) and Node (N-API) binding tests load the shared library, so
they are registered only when `-DZCIO_BUILD_SHARED=ON` and `python3` / `node`
are found (otherwise they are skipped with a message, never failed). The Node
test compiles its native addon on demand via `node-gyp`.

### Build options

| Option | Default | Meaning |
|---|---|---|
| `ZCIO_TLS` | `openssl` | TLS backend: `openssl` or `none` |
| `ZCIO_WITH_ARCHIVE` | `OFF` | libarchive support (FetchContent-clones a fork; opt in) |
| `ZCIO_BUILD_TESTS` | `ON` | build the C test suite |
| `ZCIO_BUILD_SHARED` | `OFF` | also build `libzcio` shared (needed for the Python/Node bindings) |
| `ZCIO_BUILD_BINDING_TESTS` | `ON` | register the C++/Python/Node binding tests in CTest |

To build with no TLS dependency at all: `-DZCIO_TLS=none`.

## Example (C)

```c
#include <zcio/zcio.h>

zcio_ring *r = zcio_ring_new(4096, false);
zcio_stream *s = zcio_ring_as_stream(r, true);   /* take ownership */
zcio_serial *w = zcio_serial_new(s, /*bit_stream=*/false, /*own=*/false);
zcio_serial_write_i32(w, 42);
zcio_serial_write_str(w, "hi", 2);
zcio_serial_free(w);
zcio_stream_free(s);                              /* frees the ring too */
```

## Language bindings

All bindings sit on the same C ABI and ship with their own tests:

- **Python** (`bindings/python/`) — pure ctypes, no compiled extension.
  `ZCIO_LIBRARY=build/libzcio.dylib python bindings/python/test_zcio.py`
- **Node** (`bindings/node/`) — N-API native addon.
  `cd bindings/node && npm run build && node test/test.js`
- **C++** (`include/zcio/zcio.hpp`) — header-only RAII wrapper re-exposing the
  original iostream-style `<<` / `>>` ergonomics.
  `c++ -std=c++17 -Iinclude bindings/cpp/test_zcio.cpp -Lbuild -lzcio -o t && ./t`

## Status

Core, networking, TLS (OpenSSL), HTTP, and DNS are implemented and tested. The
archive backend is implemented but opt-in (it pulls a non-canonical libarchive
fork via FetchContent).

**Test coverage: every one of the ~104 public C functions is exercised** by the
C suite (14 executables run under CTest): serializer (bytes/bits/arrays/all
scalar widths/positioning/status/count mode), ring + shared-memory attach,
memory/counting streams, generic stream verbs (copy/seek/available/eof/flush),
TCP (loopback, multi-client, `close_client`, wait/bytes-available), UDP
(loopback + multi-peer demux), UDP multicast, DNS/IPv4 utilities, an in-process
HTTP loopback covering GET/POST/PUT/DELETE/custom-request, archive round-trip
(when compiled in), and a threaded TLS loopback exercising the
custom-BIO-over-stream handshake plus the backend registry and cert/key loading.

All three language bindings ship their own test suites at parity with the C API
surface (Python 26 cases, Node, C++), each validated end-to-end through the C
ABI including TCP/UDP/multicast/HTTP/TLS.
