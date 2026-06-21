/* zcio - a pure C23 streaming I/O library.
 *
 * zcio is a ground-up C rewrite of the C++ `iostreams` library. It exposes a
 * feature-rich, stable C ABI designed to be consumed directly or wrapped by
 * other languages (Python, Node, C++, ...). There is no C++ in the core: every
 * abstraction that std::streambuf provided via virtual dispatch is implemented
 * here with an explicit, branch-predictable vtable (see zcio/stream.h).
 *
 * Design goals:
 *   - O(1) constant-time hot paths: per-operation cost is independent of the
 *     total number of bytes streamed. Ring/memory buffers are zero-copy; handle
 *     lookups are slab-indexed rather than tree-based.
 *   - Zero mandatory dependencies in the core. TLS and archive support are
 *     optional, pluggable backends selected at build time.
 *   - A flat, opaque-handle ABI that any FFI can bind without C++ name mangling,
 *     exceptions, or RTTI.
 *
 * This umbrella header pulls in the whole public surface. Include individual
 * headers (zcio/serial.h, zcio/net.h, ...) for finer-grained dependencies.
 */
#ifndef ZCIO_H
#define ZCIO_H

#include "zcio/types.h"
#include "zcio/stream.h"
#include "zcio/serial.h"
#include "zcio/ring.h"
#include "zcio/membuf.h"
#include "zcio/net.h"
#include "zcio/tls.h"
#include "zcio/http.h"
#include "zcio/archive.h"
#include "zcio/dns.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Library-wide one-time initialization (socket subsystem, TLS backend). Safe to
 * call multiple times and from multiple threads; only the first call does work.
 * Most constructors call this implicitly, but binding layers may call it eagerly. */
void zcio_init(void);
void zcio_shutdown(void);

/* Semantic version string, e.g. "0.1.0". */
const char *zcio_version_string(void);
void        zcio_version(int *major, int *minor, int *patch);

#ifdef __cplusplus
}
#endif

#endif /* ZCIO_H */
