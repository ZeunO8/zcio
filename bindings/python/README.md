# zcio — Python binding

Pure `ctypes` over the zcio C ABI. No compiled extension; it just loads the
shared library.

## Setup

Build the shared library first:

```sh
cmake -S ../.. -B ../../build -DZCIO_BUILD_SHARED=ON
cmake --build ../../build
```

The binding locates `libzcio` automatically in a sibling `build/` directory, or
you can point it explicitly:

```sh
export ZCIO_LIBRARY=$PWD/../../build/libzcio.dylib   # .so on Linux, .dll on Windows
python test_zcio.py
```

## Usage

```python
import zcio

print(zcio.version())

r = zcio.Ring(64)
r.write(b"hello")
assert r.read(5) == b"hello"

s = zcio.Serial(256)
s.write_i32(42); s.write_str("hi")
rd = zcio.Serial(256, buffer=s.buffer)
assert rd.read_i32() == 42 and rd.read_str() == "hi"

srv = zcio.TcpServer(8080)
cli = zcio.TcpClient("127.0.0.1", 8080)
conn = srv.accept(1000)
cli.stream.write(b"ping")
assert conn.read_full(4) == b"ping"
```
