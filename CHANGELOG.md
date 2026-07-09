# Changelog

All notable changes to **zcio** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses a
four-component version (`MAJOR.MINOR.PATCH.TWEAK`); the shared-library SONAME
tracks `MAJOR`.

## [1.3.2.0] - 2026-07-09

### Fixed
- **TLS per-op read timeout was fatal**: a timed-out `zcio_read` on a TLS
  stream (e.g. `zcio_ws_recv` with a short timeout on a `wss://` session, the
  idiomatic service-loop pattern) surfaced as a hard `ZCIO_ERR_TLS`
  ("SSL_read: transport error") and killed the session, because the custom
  BIO only marked `ZCIO_ERR_WOULDBLOCK` — not `ZCIO_ERR_TIMEOUT` — as
  retryable, so OpenSSL saw a syscall failure. Timeouts (and would-blocks)
  now propagate out of `SSL_read`/`SSL_write` as `ZCIO_ERR_TIMEOUT` /
  `ZCIO_ERR_WOULDBLOCK`, leaving the session usable; regression covered by
  `tls_read_timeout_transient` (test_tls).

## [1.3.1.0] - 2026-07-09

### Added
- **Host-scoped TCP listeners**: `zcio_tcp_server_listen_host` /
  `zcio_tcp_server_listen_host_tls` bind a specific interface instead of
  INADDR_ANY (NULL/`""`/`"*"` keep the bind-all behavior; names resolve to
  IPv4, so `"localhost"` gives a loopback-only control plane).
- **Listener fd adoption**: `zcio_tcp_server_adopt` wraps an already-bound,
  already-listening socket (supervisor-inherited fds, custom socket options)
  in a `zcio_tcp_server`; on failure the fd stays owned by the caller.

### Fixed
- **HTTP client vs keep-alive servers**: the client framed every response by
  EOF, so any server that honored HTTP/1.1 keep-alive (i.e. nearly every
  production origin) stalled the request until the peer's idle timeout
  (~30 s) and then surfaced `http: read failed`. Requests now send
  `Connection: close` (unless the caller supplies a `Connection` header), and
  the reader stops as soon as a `Content-Length` body is complete or a
  chunked body is terminated, falling back to EOF only when the response
  carries no framing.
- **`Transfer-Encoding: chunked` responses** are now de-chunked; previously
  the raw chunk framing was returned in `body`.
- **Implicit init in TLS context creators**: `zcio_tls_client_ctx` /
  `zcio_tls_server_ctx*` now call `zcio_init()` themselves, so the first
  `zcio_http_get("https://...")` or `zcio_ws_connect("wss://...")` of a
  process no longer fails with `TLS context creation failed` when the
  embedder never called `zcio_init()` (the documented contract — constructors
  self-init — now holds on the TLS path too).

## [1.3.0.0] - 2026-07-09

### Added
- **Device auto-provisioning in the mobile test launchers**: `ctest` no longer
  requires a running emulator/simulator. If no device is online, the Android
  launcher boots the best available AVD (`ZCIO_ANDROID_AVD` to pick one) and,
  when none exists, creates `zcio-test` via `avdmanager` — installing a
  system image with `sdkmanager` on first use (Java auto-detected, including
  Android Studio's bundled JBR). The iOS launcher boots the best available
  device (iPhones first, newest runtime first) via `simctl bootstatus -b`
  and, when none exists, creates one from the newest supported iPhone type
  with `simctl create`, downloading the platform runtime as a last resort.
  Concurrent launchers (`ctest -j`) serialize the boot behind a lock. Opt out
  with `ZCIO_NO_AUTOBOOT=1`; `ZCIO_BOOT_TIMEOUT` bounds the Android wait
  [600 s]; `ZCIO_ANDROID_DEFAULT_IMAGE_API` (cache) selects the image API for
  created AVDs [android-36].

## [1.2.0.0] - 2026-07-09

### Added
- **On-target mobile testing** (`cmake/ZcioMobileTest.cmake`): cross-compiled
  test suites now run through CTest via `CMAKE_CROSSCOMPILING_EMULATOR` — an
  `adb` push-and-run launcher for Android (emulator or device, exit codes
  propagated) and an `xcrun simctl spawn` launcher for the iOS simulator.
  Opt in with `-DZCIO_BUILD_TESTS=ON` on a cross build; a plain `ctest` then
  behaves like a host run. Dependents embedding zcio can reuse the launcher
  for their own suites (`zcio_enable_mobile_testing()`), staging extra
  on-device runtime files per test via a `ZCIO_PUSH_FILES` environment list.
  Verified: full suite green on an Android 16 arm64 emulator and an iOS 26.5
  simulator.

### Fixed
- `test_tls_more` failed to *compile* against the iOS SDK, where `system()`
  is marked unavailable; cert generation now degrades to the documented
  "openssl CLI unavailable" skip there.

## [1.1.0.0] - 2026-07-09

### Added
- **HTTP server** (`zcio/http_server.h`): a single-threaded, non-blocking,
  hardened origin server speaking **HTTP/1.1, HTTP/2, and HTTP/3** — the offered
  version(s) are a config bitmask; ALPN, HTTP/2 prior-knowledge preface
  detection, and QUIC negotiation are handled internally. HTTP/3 runs over the
  OpenSSL ≥ 3.5 QUIC stack and self-disables (never offered) otherwise.
- **WebSocket** (`zcio/ws.h`): RFC 6455 client and server. Server upgrades detach
  the connection from the event loop; the client dials `ws://`/`wss://`,
  auto-upgrades `ws→wss` across redirects, and refuses `wss→ws` downgrades.
- **Auto-HTTPS**: optional plaintext redirect listener (301 → `https://`),
  `Strict-Transport-Security` (HSTS) on TLS responses, and `Alt-Svc: h3` advertising
  when HTTP/3 is enabled.
- **TLS ALPN + non-blocking handshake** (`zcio/tls.h`): `zcio_tls_ctx_set_alpn`,
  `zcio_tls_wrap_nb` / `zcio_tls_handshake` (incremental handshake for the event
  loop), and `zcio_tls_stream_alpn`.
- **HPACK** (RFC 7541) and **QPACK** (RFC 9204, static-table) codecs, and OS-entropy
  helper used for WebSocket masking/nonces.

### Security
- Algorithmically hardened parsers: single-pass, linear-time, every length
  bounds-checked and overflow-guarded before allocation; bounded (non-hashed)
  header storage.
- HTTP/1.1 request-smuggling defenses: reject Transfer-Encoding + Content-Length
  together, obs-fold, bare-LF line endings, whitespace before `:`, and multiple
  `Host`; strict chunked framing with a running body cap.
- HTTP/2 flood guards: rapid-reset (CVE-2023-44487), CONTINUATION flood
  (CVE-2024-27316), SETTINGS/PING floods, and flow-control window overflow.
- Response-header injection refused (CR/LF/NUL and hop-by-hop/server-owned headers
  filtered); slowloris / idle / write deadlines and per-connection output caps.
- Full suite passes under `-fsanitize=address,undefined`, including a real
  end-to-end HTTP/3 exchange (OpenSSL QUIC client vs the server).

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
