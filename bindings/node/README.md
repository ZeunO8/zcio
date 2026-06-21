# zcio — Node.js native bindings

N-API (`node_api.h`, pure C) bindings for the [`zcio`](../../) streaming I/O C
library. Exposes a practical subset of the C ABI: version info, IPv4 detection,
a lock-free ring buffer, a buffer-mode serializer, and a synchronous HTTP GET.

## Prerequisites

1. Build the zcio **shared** library first. From the repo root:

   ```sh
   cmake -B build -DZCIO_BUILD_SHARED=ON
   cmake --build build
   ```

   This produces `build/libzcio.dylib` (macOS) / `.so` (Linux) which the addon
   links against. The `binding.gyp` references headers at `../../include` and the
   library at `../../build` (with an rpath so it loads at runtime).

2. Node.js with `node-gyp` available (`npm i -g node-gyp`, plus a C toolchain).

## Build

```sh
cd bindings/node
npm run build        # == node-gyp rebuild
```

The compiled addon lands at `build/Release/zcio_native.node`.

## Test

```sh
node test/test.js
```

Exercises `version()`, `isIpv4('127.0.0.1') === true`, and a `Ring` write/read
roundtrip (plus a `BufferSerial` scalar/string roundtrip).

## API

```js
const zcio = require('zcio'); // i.e. ./index.js

zcio.version();                       // -> "x.y.z"
zcio.isIpv4('127.0.0.1');             // -> true
const res = zcio.httpGet('http://example.com/');
// res = { status, body, headersJson, statusText, version, protocol }

const r = new zcio.Ring(1024);        // capacity in bytes
r.write(Buffer.from('hi'));           // -> bytes written
r.availableRead();                    // -> bytes available
r.read(2);                            // -> Buffer
r.free();                             // advisory; GC frees the native ring

const s = new zcio.BufferSerial(256);
s.writeI32(42); s.writeStr('hello');
s.setReadPos(0);
s.readI32();  // 42
s.readStr();  // 'hello'
```

Opaque native pointers are held in N-API externals with finalizers that call the
matching `zcio_*_free`, so resources are reclaimed by JS garbage collection.
