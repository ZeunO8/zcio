# Changelog

All notable changes to **zcio** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses a
four-component version (`MAJOR.MINOR.PATCH.TWEAK`); the shared-library SONAME
tracks `MAJOR`.

## [1.0.0.0]

First stable release. The C ABI is now considered frozen for the 1.x series.

### Added
- **Install + packaging**: `install()` rules for the library and headers, a
  CMake package config (`find_package(zcio)`), an installed `zcio.pc`
  (pkg-config), and a versioned shared library with `SOVERSION`.
- **Sanitizers**: `ZCIO_SANITIZE=address|undefined|thread` build option.
- **CI**: GitHub Actions matrix building and running the full CTest suite
  (including the C++/Python/Node binding tests) on Linux and macOS, plus a
  core+networking run on Windows.
- **Portable test threading** (`tests/c/zthread.h`) so the loopback tests run on
  Windows as well as POSIX.
- **TLS bindings** for Python and Node; assorted parity additions across the
  three bindings.
- `LICENSE` (MIT), `CHANGELOG.md`, `CONTRIBUTING.md`, `.clang-tidy`.

### Fixed (security & correctness hardening)
- **SIGPIPE**: sends to a closed peer no longer terminate the host process.
- **EINTR**: `select`/`recv`/`send`/`accept`/`connect` are retried on signals.
- `serial_read_str` no longer trusts an attacker-controlled length (overflow /
  unbounded-allocation fix); short reads never expose an uninitialized tail.
- Buffer-mode serial writes report the honest byte count on overflow.
- Stream-mode reads surface real errors instead of masking them as EOF.
- `zcio_copy(limit = SIZE_MAX)` copies until EOF (previously a no-op).
- Thread-safe one-time `zcio_init`.
- Lock-free ring buffer: explicit acquire/release ordering + capacity overflow
  guard.
- TCP write error taxonomy (`WOULDBLOCK` / `EPIPE`-as-EOF); consistent `0`-as-EOF
  semantics; non-blocking connect so the connect timeout applies; bounded
  per-server client-id allocation.
- Multicast group parsed with `inet_pton`; `SO_RCVTIMEO` normalized; larger UDP
  receive buffer.
- **HTTP**: blocked HTTPS→HTTP redirect downgrade; relative `Location`
  resolution; response-size cap; CRLF/header-injection rejection; URL hardening
  (port range, IPv6 literals, userinfo stripping).
- **Archive**: capped untrusted entry sizes; checked libarchive write returns.
- **TLS**: post-handshake `SSL_get_verify_result` check; one-time BIO method
  init; single shutdown.

### Header portability
- Public headers fall back to a plain `enum` on pre-C23 C compilers; removed the
  removed-in-C++20 `<cstdbool>`.

## [0.9.1.0]
- Run the C++/Python/Node binding tests under CTest; Node test prints `[ ok ]`
  per case; multicast Node test no longer skips.

## [0.9.0.0]
- Full C API test coverage; cross-language binding parity (Python, Node, C++).

## [0.8.1.0]
- Initial public release: pure C23 streaming I/O core (stream/serial/ring/
  membuf), TCP/UDP/multicast networking, pluggable TLS (OpenSSL), HTTP client,
  optional libarchive support, and Python/Node/C++ bindings.
