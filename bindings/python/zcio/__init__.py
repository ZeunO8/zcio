"""zcio - Python ctypes binding for the zcio C library.

Loads the zcio shared library and exposes Pythonic wrappers over the C ABI:
ring buffers, the bit/byte serializer, in-memory streams, TCP/UDP endpoints,
HTTP, and DNS helpers. No compiled extension required -- pure ctypes over the
stable C ABI.

Build the shared lib first:
    cmake -S . -B build -DZCIO_BUILD_SHARED=ON && cmake --build build
Then either install this package or set ZCIO_LIBRARY to the .so/.dylib/.dll.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from typing import Optional

__all__ = [
    "lib", "version", "is_ipv4", "resolve_ipv4", "local_ipv4",
    "Ring", "Serial", "MemoryStream", "TcpClient", "TcpServer",
    "UdpClient", "UdpServer", "http_get", "http_post", "ZcioError",
]


class ZcioError(RuntimeError):
    pass


def _find_library() -> str:
    env = os.environ.get("ZCIO_LIBRARY")
    if env:
        return env
    names = {
        "darwin": ["libzcio.dylib"],
        "win32": ["zcio.dll", "libzcio.dll"],
    }.get(sys.platform, ["libzcio.so"])
    # Search common build locations relative to this file and CWD.
    here = os.path.dirname(os.path.abspath(__file__))
    roots = [
        os.path.join(here, "..", "..", "..", "build"),
        os.path.join(here, "..", "..", "build"),
        os.getcwd(),
        os.path.join(os.getcwd(), "build"),
    ]
    for root in roots:
        for n in names:
            cand = os.path.normpath(os.path.join(root, n))
            if os.path.exists(cand):
                return cand
    found = ctypes.util.find_library("zcio")
    if found:
        return found
    raise ZcioError(
        "could not locate the zcio shared library; build with "
        "-DZCIO_BUILD_SHARED=ON or set ZCIO_LIBRARY"
    )


lib = ctypes.CDLL(_find_library())

# --- prototype declarations --------------------------------------------------
c = ctypes
_void_p = c.c_void_p


def _decl(name, restype, *argtypes):
    fn = getattr(lib, name)
    fn.restype = restype
    fn.argtypes = list(argtypes)
    return fn


_decl("zcio_init", None)
_decl("zcio_version_string", c.c_char_p)
_decl("zcio_last_error", c.c_char_p)
_decl("zcio_free", None, _void_p)

# ring
_decl("zcio_ring_new", _void_p, c.c_size_t, c.c_bool)
_decl("zcio_ring_free", None, _void_p)
_decl("zcio_ring_write", c.c_int64, _void_p, _void_p, c.c_size_t)
_decl("zcio_ring_read", c.c_int64, _void_p, _void_p, c.c_size_t)
_decl("zcio_ring_available_read", c.c_size_t, _void_p)

# serial (buffer mode + a representative set of ops)
_decl("zcio_serial_new_buffer", _void_p, _void_p, c.c_int64, c.c_bool)
_decl("zcio_serial_free", None, _void_p)
_decl("zcio_serial_write_i32", None, _void_p, c.c_int32)
_decl("zcio_serial_read_i32", c.c_int32, _void_p)
_decl("zcio_serial_write_u64", None, _void_p, c.c_uint64)
_decl("zcio_serial_read_u64", c.c_uint64, _void_p)
_decl("zcio_serial_write_f64", None, _void_p, c.c_double)
_decl("zcio_serial_read_f64", c.c_double, _void_p)
_decl("zcio_serial_write_str", None, _void_p, c.c_char_p, c.c_size_t)
_decl("zcio_serial_read_str", c.c_void_p, _void_p, c.POINTER(c.c_size_t))
_decl("zcio_serial_write_pos", c.c_int64, _void_p)

# memory stream
_decl("zcio_memory_stream", _void_p, _void_p, c.c_size_t)
_decl("zcio_stream_free", None, _void_p)
_decl("zcio_read", c.c_int64, _void_p, _void_p, c.c_size_t)
_decl("zcio_write", c.c_int64, _void_p, _void_p, c.c_size_t)
_decl("zcio_write_full", c.c_int64, _void_p, _void_p, c.c_size_t)
_decl("zcio_read_full", c.c_int64, _void_p, _void_p, c.c_size_t)
_decl("zcio_seek", c.c_int64, _void_p, c.c_int64, c.c_int, c.c_uint)

# net
_decl("zcio_tcp_client_connect", _void_p, c.c_char_p, c.c_int)
_decl("zcio_tcp_client_free", None, _void_p)
_decl("zcio_tcp_client_stream", _void_p, _void_p)
_decl("zcio_tcp_server_listen", _void_p, c.c_int)
_decl("zcio_tcp_server_free", None, _void_p)
_decl("zcio_tcp_server_accept", _void_p, _void_p, c.POINTER(c.c_size_t), c.c_int)
_decl("zcio_tcp_conn_stream", _void_p, _void_p)
_decl("zcio_udp_client_open", _void_p, c.c_char_p, c.c_int)
_decl("zcio_udp_client_free", None, _void_p)
_decl("zcio_udp_client_stream", _void_p, _void_p)
_decl("zcio_udp_server_bind", _void_p, c.c_int)
_decl("zcio_udp_server_free", None, _void_p)
_decl("zcio_udp_server_receive", _void_p, _void_p, c.c_bool, c.c_uint)
_decl("zcio_udp_packet_stream", _void_p, _void_p)

# dns
_decl("zcio_is_ipv4", c.c_bool, c.c_char_p)
_decl("zcio_resolve_ipv4", c.c_void_p, c.c_char_p)
_decl("zcio_local_ipv4", c.c_void_p)

# http
class _HttpResponse(c.Structure):
    _fields_ = [
        ("protocol", c.c_char_p),
        ("version", c.c_char_p),
        ("status_code", c.c_char_p),
        ("status_text", c.c_char_p),
        ("headers_json", c.c_char_p),
        ("body", c.c_void_p),
        ("body_size", c.c_size_t),
        ("status", c.c_int32),
    ]


_decl("zcio_http_get", _HttpResponse, c.c_char_p)
_decl("zcio_http_post", _HttpResponse, c.c_char_p, _void_p, c.c_size_t)
_decl("zcio_http_response_free", None, c.POINTER(_HttpResponse))

lib.zcio_init()


# --- helpers -----------------------------------------------------------------
SEEK_SET, SEEK_CUR, SEEK_END = 0, 1, 2
SEEK_READ, SEEK_WRITE, SEEK_BOTH = 1, 2, 3


def _take_cstr(ptr) -> Optional[str]:
    """Copy a malloc'd C string into Python and free it."""
    if not ptr:
        return None
    s = c.cast(ptr, c.c_char_p).value
    lib.zcio_free(ptr)
    return s.decode() if s is not None else None


def version() -> str:
    return lib.zcio_version_string().decode()


def is_ipv4(s: str) -> bool:
    return bool(lib.zcio_is_ipv4(s.encode()))


def resolve_ipv4(host: str) -> Optional[str]:
    return _take_cstr(lib.zcio_resolve_ipv4(host.encode()))


def local_ipv4() -> Optional[str]:
    return _take_cstr(lib.zcio_local_ipv4())


# --- Ring --------------------------------------------------------------------
class Ring:
    def __init__(self, capacity: int, non_blocking: bool = False):
        self._h = lib.zcio_ring_new(capacity, non_blocking)
        if not self._h:
            raise ZcioError("ring allocation failed")

    def write(self, data: bytes) -> int:
        buf = (c.c_char * len(data)).from_buffer_copy(data)
        return lib.zcio_ring_write(self._h, buf, len(data))

    def read(self, n: int) -> bytes:
        buf = (c.c_char * n)()
        got = lib.zcio_ring_read(self._h, buf, n)
        return bytes(buf[:got]) if got > 0 else b""

    @property
    def available(self) -> int:
        return lib.zcio_ring_available_read(self._h)

    def close(self):
        if self._h:
            lib.zcio_ring_free(self._h)
            self._h = None

    __del__ = close


# --- Serial (buffer-backed) --------------------------------------------------
class Serial:
    """Buffer-mode serializer. Pass an existing bytearray to share its storage."""

    def __init__(self, size: int = 4096, bit_stream: bool = False, buffer=None):
        self._buf = buffer if buffer is not None else bytearray(size)
        self._carr = (c.c_char * len(self._buf)).from_buffer(self._buf)
        self._h = lib.zcio_serial_new_buffer(self._carr, len(self._buf), bit_stream)
        if not self._h:
            raise ZcioError("serial allocation failed")

    def write_i32(self, v): lib.zcio_serial_write_i32(self._h, v)
    def read_i32(self): return lib.zcio_serial_read_i32(self._h)
    def write_u64(self, v): lib.zcio_serial_write_u64(self._h, v)
    def read_u64(self): return lib.zcio_serial_read_u64(self._h)
    def write_f64(self, v): lib.zcio_serial_write_f64(self._h, v)
    def read_f64(self): return lib.zcio_serial_read_f64(self._h)

    def write_str(self, s: str):
        b = s.encode()
        lib.zcio_serial_write_str(self._h, b, len(b))

    def read_str(self) -> Optional[str]:
        n = c.c_size_t(0)
        ptr = lib.zcio_serial_read_str(self._h, c.byref(n))
        if not ptr:
            return None
        raw = c.string_at(ptr, n.value)
        lib.zcio_free(ptr)
        return raw.decode()

    @property
    def write_pos(self) -> int:
        return lib.zcio_serial_write_pos(self._h)

    @property
    def buffer(self) -> bytearray:
        return self._buf

    def close(self):
        if self._h:
            lib.zcio_serial_free(self._h)
            self._h = None

    __del__ = close


# --- thin stream/net wrappers ------------------------------------------------
class _Stream:
    """Borrowed stream handle (owned by its parent endpoint)."""

    def __init__(self, handle):
        self._h = handle

    def write(self, data: bytes) -> int:
        buf = (c.c_char * len(data)).from_buffer_copy(data)
        return lib.zcio_write_full(self._h, buf, len(data))

    def read(self, n: int) -> bytes:
        buf = (c.c_char * n)()
        got = lib.zcio_read(self._h, buf, n)
        return bytes(buf[:got]) if got > 0 else b""

    def read_full(self, n: int) -> bytes:
        buf = (c.c_char * n)()
        got = lib.zcio_read_full(self._h, buf, n)
        return bytes(buf[:got]) if got > 0 else b""


class MemoryStream(_Stream):
    def __init__(self, size: int = 4096, buffer=None):
        self._buf = buffer if buffer is not None else bytearray(size)
        self._carr = (c.c_char * len(self._buf)).from_buffer(self._buf)
        super().__init__(lib.zcio_memory_stream(self._carr, len(self._buf)))

    def seek_read(self, off: int, origin: int = SEEK_SET):
        lib.zcio_seek(self._h, off, origin, SEEK_READ)

    def close(self):
        if self._h:
            lib.zcio_stream_free(self._h)
            self._h = None

    __del__ = close


class TcpClient:
    def __init__(self, host: str, port: int):
        self._h = lib.zcio_tcp_client_connect(host.encode(), port)
        if not self._h:
            raise ZcioError(f"tcp connect failed: {lib.zcio_last_error().decode()}")
        self.stream = _Stream(lib.zcio_tcp_client_stream(self._h))

    def close(self):
        if self._h:
            lib.zcio_tcp_client_free(self._h)
            self._h = None

    __del__ = close


class TcpServer:
    def __init__(self, port: int):
        self._h = lib.zcio_tcp_server_listen(port)
        if not self._h:
            raise ZcioError(f"tcp listen failed: {lib.zcio_last_error().decode()}")

    def accept(self, timeout_ms: int = 1000):
        cid = c.c_size_t(0)
        conn = lib.zcio_tcp_server_accept(self._h, c.byref(cid), timeout_ms)
        if not conn:
            return None
        return _Stream(lib.zcio_tcp_conn_stream(conn))

    def close(self):
        if self._h:
            lib.zcio_tcp_server_free(self._h)
            self._h = None

    __del__ = close


class UdpClient:
    def __init__(self, host: str, port: int):
        self._h = lib.zcio_udp_client_open(host.encode(), port)
        if not self._h:
            raise ZcioError("udp open failed")
        self.stream = _Stream(lib.zcio_udp_client_stream(self._h))

    def close(self):
        if self._h:
            lib.zcio_udp_client_free(self._h)
            self._h = None

    __del__ = close


class UdpServer:
    def __init__(self, port: int):
        self._h = lib.zcio_udp_server_bind(port)
        if not self._h:
            raise ZcioError("udp bind failed")

    def receive(self, non_block: bool = False, timeout_us: int = 1000000):
        pkt = lib.zcio_udp_server_receive(self._h, non_block, timeout_us)
        if not pkt:
            return None
        return _Stream(lib.zcio_udp_packet_stream(pkt))

    def close(self):
        if self._h:
            lib.zcio_udp_server_free(self._h)
            self._h = None

    __del__ = close


# --- HTTP --------------------------------------------------------------------
def _http_result(resp: "_HttpResponse") -> dict:
    body = b""
    if resp.body and resp.body_size:
        body = c.string_at(resp.body, resp.body_size)
    out = {
        "status": resp.status,
        "status_text": resp.status_text.decode() if resp.status_text else "",
        "version": resp.version.decode() if resp.version else "",
        "headers_json": resp.headers_json.decode() if resp.headers_json else "{}",
        "body": body,
    }
    lib.zcio_http_response_free(c.byref(resp))
    return out


def http_get(url: str) -> dict:
    return _http_result(lib.zcio_http_get(url.encode()))


def http_post(url: str, body: bytes) -> dict:
    buf = (c.c_char * len(body)).from_buffer_copy(body) if body else None
    return _http_result(lib.zcio_http_post(url.encode(), buf, len(body)))
