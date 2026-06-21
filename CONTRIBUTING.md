# Contributing to zcio

Thanks for your interest in zcio.

## Ground rules

- **The core is pure C23.** No C++ in `src/` or the C public headers. The only
  C++ in the tree is the header-only wrapper (`include/zcio/zcio.hpp`) and the
  binding tests.
- **The C ABI is frozen for the 1.x series.** Additions are fine; do not change
  the signature, size, or semantics of an existing public symbol or struct
  without a major version bump. The frozen surfaces include the `zcio_stream`
  struct + vtable and the `zcio_http_response` struct.
- Error convention: count-returning functions return `int64_t` (`>= 0` bytes,
  `< 0` a negated `zcio_result`); status-only functions return `zcio_result`.
- Returned heap memory is released with `zcio_free` / `zcio_strv_free`.
  Borrowed `*_stream` handles are owned by their parent and must not be freed.

## Building and testing

```sh
cmake -S . -B build -DZCIO_BUILD_SHARED=ON
cmake --build build
ctest --test-dir build --output-on-failure   # C tests + C++/Python/Node bindings
```

Run a sanitized build before sending changes that touch parsing, the ring
buffer, or the networking layer:

```sh
cmake -S . -B build-asan -DZCIO_SANITIZE=address,undefined -DZCIO_BUILD_BINDING_TESTS=OFF
cmake --build build-asan && ctest --test-dir build-asan --output-on-failure
```

## Pull requests

- Add or update tests for any behavior change (`tests/c/`, and the matching
  binding test where relevant).
- Keep CI green (Linux + macOS full suite, Windows core, sanitized leg).
- Update `CHANGELOG.md` under the unreleased/next-version heading.
