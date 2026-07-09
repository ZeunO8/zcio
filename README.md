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
| `zcio/tls.h`    | pluggable TLS backend (OpenSSL default, or compiled out) + ALPN |
| `zcio/http.h`   | minimal synchronous HTTP/1.1 client |
| `zcio/http_server.h` | hardened HTTP/1.1 · HTTP/2 · HTTP/3 server (version by config) + auto-HTTPS |
| `zcio/ws.h`     | RFC 6455 WebSocket client + server (auto ws→wss upgrade) |
| `zcio/dns.h`    | resolution + address utilities |
| `zcio/archive.h`| tar/gz entries via libarchive (opt-in) |
| `zcio/zcio.hpp` | header-only C++ RAII wrapper (ergonomic `<<` / `>>`) |

## HTTP server (1.1 / 2 / 3) + WebSocket

`zcio/http_server.h` is a single-threaded, non-blocking, **hardened** origin
server. Which protocol versions it offers is a config setting — the wire
negotiation (ALPN for h2, prior-knowledge preface, QUIC/ALPN for h3) is handled
internally. HTTP/3 requires OpenSSL ≥ 3.5 (QUIC); without it the server simply
declines to offer h3.

```c
#include "zcio/http_server.h"
#include "zcio/ws.h"

/* A detached WebSocket session owns its connection and is used synchronously,
 * so run it OFF the event loop (the handler must never block — see note). */
static void *ws_echo(void *arg) {
    zcio_ws *ws = (zcio_ws *)arg;
    zcio_ws_msg m;
    while (zcio_ws_recv(ws, &m, 30000) == ZCIO_OK) {
        zcio_ws_send(ws, m.type, m.data, m.len);      /* echo               */
        zcio_ws_msg_free(&m);
    }
    zcio_ws_free(ws);
    return NULL;
}

static void on_request(zcio_http_req *req, void *user) {
    if (zcio_http_req_is_ws_upgrade(req)) {           /* WebSocket handshake  */
        zcio_ws *ws = zcio_ws_accept(req);            /* detaches the conn    */
        pthread_t t;                                  /* hand off to a thread */
        pthread_create(&t, NULL, ws_echo, ws);
        pthread_detach(t);
        return;
    }
    const char *body = "hello";
    zcio_http_respond(req, 200, NULL, 0, body, 5);    /* respond in-line      */
}

int main(void) {
    zcio_http_server_config cfg = {0};
    cfg.port     = 8443;
    cfg.versions = ZCIO_HTTP1_1 | ZCIO_HTTP2 | ZCIO_HTTP3;  /* by config     */
    cfg.require_tls   = true;     /* self-signed if no cert/key given         */
    cfg.redirect_port = 8080;     /* plaintext :8080 → 301 https://…          */
    cfg.hsts          = true;     /* Strict-Transport-Security on TLS resps   */

    zcio_http_server *s = zcio_http_server_start(&cfg, on_request, NULL);
    zcio_http_server_run(s);      /* until zcio_http_server_stop() (e.g. from */
    zcio_http_server_free(s);     /* a SIGINT handler — it is async-safe)     */
}
```

> The handler runs **synchronously on the event-loop thread**, so it must not
> block: respond quickly, and hand any long-lived work (a WebSocket session, a
> slow backend call) to a thread of your own — as `on_request` does above.

**Algorithmic security** is a first-class goal: every parser is single-pass and
linear-time over bounded input, and all limits are enforced *before* memory is
committed — header/URL/body caps, per-connection output caps, slowloris and idle
deadlines, and explicit flood guards for HTTP/2 (rapid-reset, CONTINUATION,
SETTINGS/PING) and HPACK/QPACK integer + Huffman bounds. Request smuggling is
refused structurally (no TE+CL, no obs-fold, no bare-LF, single Host, strict
chunked framing). WebSocket framing enforces the RFC 6455 mask/RSV/UTF-8/control
-frame rules. See `include/zcio/http_server.h` and `include/zcio/ws.h` for the
full contract and every tunable limit.

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
| `ZCIO_TLS` | `openssl` (`none` on iOS/Android) | TLS backend: `openssl` or `none` |
| `ZCIO_WITH_ARCHIVE` | `OFF` | libarchive support (FetchContent-clones a fork; opt in) |
| `ZCIO_BUILD_TESTS` | `ON` (`OFF` when cross-compiling) | build the C test suite |
| `ZCIO_BUILD_SHARED` | `OFF` | also build `libzcio` shared (needed for the Python/Node bindings) |
| `ZCIO_BUILD_BINDING_TESTS` | `ON` | register the C++/Python/Node binding tests in CTest |

To build with no TLS dependency at all: `-DZCIO_TLS=none`.

### iOS & Android (zero dependencies)

zcio builds for iOS and Android out of the box using only core OS system
libraries (libc + BSD sockets) — no OpenSSL, no libarchive, nothing to vendor.
On mobile targets the TLS backend defaults to `none` and the test suite
defaults off (opt back in to run it on-target — see below).
`CMakePresets.json` covers the common targets:

```sh
# iOS (run on macOS with Xcode installed)
cmake --preset ios           && cmake --build --preset ios
cmake --preset ios-simulator && cmake --build --preset ios-simulator

# Android (point ANDROID_NDK_ROOT at an installed NDK)
export ANDROID_NDK_ROOT="$HOME/Library/Android/sdk/ndk/<version>"
cmake --preset android-arm64  && cmake --build --preset android-arm64
# also: android-armv7, android-x86_64
```

### On-target mobile testing

Cross-compiled binaries can't execute on the build host, so passing
`-DZCIO_BUILD_TESTS=ON` on a cross build wires `CMAKE_CROSSCOMPILING_EMULATOR`
to a launcher (`cmake/ZcioMobileTest.cmake`): `adb` push-and-run for Android
(emulator or USB device), `xcrun simctl spawn` into the booted simulator for
iOS. A plain `ctest` then behaves exactly like a host run — TLS/archive tests
self-skip on the dependency-free mobile builds.

```sh
# Android: boot an emulator (or attach a device), then
cmake --preset android-arm64 -DZCIO_BUILD_TESTS=ON
cmake --build --preset android-arm64
ctest --test-dir build/android-arm64 --output-on-failure

# iOS simulator: boot one, then
xcrun simctl boot "iPhone 17 Pro"
cmake --preset ios-simulator -DZCIO_BUILD_TESTS=ON
cmake --build --preset ios-simulator
ctest --test-dir build/ios-simulator --output-on-failure
```

Projects embedding zcio can reuse the launcher for their own cross-compiled
suites: `include(${zcio_SOURCE_DIR}/cmake/ZcioMobileTest.cmake)`, call
`zcio_enable_mobile_testing()` before registering test targets, and stage any
extra on-device runtime files by setting the test's `ZCIO_PUSH_FILES`
environment variable to a colon-separated list of host paths (Android; the
iOS simulator shares the host filesystem, so host paths just work).

Each preset produces a static `libzcio.a` under `build/<preset>/`; on Android,
`-DZCIO_BUILD_SHARED=ON` additionally yields a `libzcio.so` that links against
nothing beyond the system libc. The device presets target iOS 13+ and Android
API 24+ (override `ANDROID_PLATFORM` / `CMAKE_OSX_DEPLOYMENT_TARGET` to taste),
and CI cross-builds all five mobile targets on every push. One runtime note:
UDP multicast on iOS requires the `com.apple.developer.networking.multicast`
entitlement, and on Android a `WifiManager.MulticastLock`.

### Install & consume

```sh
cmake --install build --prefix /usr/local
```

This installs the library, headers, a `pkg-config` file, and a CMake package
config so downstream projects can consume zcio either way:

```cmake
find_package(zcio CONFIG REQUIRED)
target_link_libraries(myapp PRIVATE zcio::zcio)
```
```sh
cc myapp.c $(pkg-config --cflags --libs zcio) -o myapp
```

### Sanitizers

```sh
cmake -S . -B build-asan -DZCIO_SANITIZE=address,undefined -DZCIO_BUILD_BINDING_TESTS=OFF
cmake --build build-asan && ctest --test-dir build-asan --output-on-failure
```

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
fork via FetchContent). Desktop (Linux/macOS/Windows) is tested end-to-end in
CI; iOS and Android are cross-compiled in CI as dependency-free static
libraries (the whole core is plain POSIX, so the same code paths run there).

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

## License

MIT — see [LICENSE](LICENSE).
