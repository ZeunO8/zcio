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
    "dns_query_a", "dns_query_aaaa",
    "tls_available", "tls_backend_name", "TlsCtx",
    "Ring", "Serial", "MemoryStream", "CountingStream", "Stream",
    "TcpClient", "TcpServer",
    "UdpClient", "UdpServer", "McastSender", "McastReceiver",
    "http_get", "http_post", "http_put", "http_delete", "http_request",
    "copy", "ZcioError",
    "SEEK_SET", "SEEK_CUR", "SEEK_END",
    "SEEK_READ", "SEEK_WRITE", "SEEK_BOTH",
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
_decl("zcio_ring_available_write", c.c_size_t, _void_p)
_decl("zcio_ring_as_stream", _void_p, _void_p, c.c_bool)

# serial
_decl("zcio_serial_new", _void_p, _void_p, c.c_bool, c.c_bool)
_decl("zcio_serial_new_count", _void_p)
_decl("zcio_serial_new_buffer", _void_p, _void_p, c.c_int64, c.c_bool)
_decl("zcio_serial_free", None, _void_p)
_decl("zcio_serial_write_bytes", c.c_int64, _void_p, _void_p, c.c_size_t)
_decl("zcio_serial_read_bytes", c.c_int64, _void_p, _void_p, c.c_size_t)
_decl("zcio_serial_write_byte", None, _void_p, c.c_uint8)
_decl("zcio_serial_read_byte", c.c_uint8, _void_p)
_decl("zcio_serial_write_bit", None, _void_p, c.c_bool)
_decl("zcio_serial_read_bit", c.c_bool, _void_p)
_decl("zcio_serial_write_bits", None, _void_p, c.POINTER(c.c_uint8), c.c_size_t, c.c_size_t)
_decl("zcio_serial_read_bits", None, _void_p, c.POINTER(c.c_uint8), c.c_size_t, c.c_size_t)

# scalar serial helpers (i8/u8/i16/u16/i32/u32/i64/u64/f32/f64)
_SERIAL_SCALARS = {
    "i8": c.c_int8, "u8": c.c_uint8, "i16": c.c_int16, "u16": c.c_uint16,
    "i32": c.c_int32, "u32": c.c_uint32, "i64": c.c_int64, "u64": c.c_uint64,
    "f32": c.c_float, "f64": c.c_double,
}
for _suf, _ct in _SERIAL_SCALARS.items():
    _decl(f"zcio_serial_write_{_suf}", None, _void_p, _ct)
    _decl(f"zcio_serial_read_{_suf}", _ct, _void_p)

_decl("zcio_serial_write_str", None, _void_p, c.c_char_p, c.c_size_t)
_decl("zcio_serial_read_str", c.c_void_p, _void_p, c.POINTER(c.c_size_t))
_decl("zcio_serial_write_pos", c.c_int64, _void_p)
_decl("zcio_serial_read_pos", c.c_int64, _void_p)
_decl("zcio_serial_set_write_pos", None, _void_p, c.c_size_t)
_decl("zcio_serial_set_read_pos", None, _void_p, c.c_size_t)
_decl("zcio_serial_write_len", c.c_int64, _void_p)
_decl("zcio_serial_read_len", c.c_int64, _void_p)
_decl("zcio_serial_synchronize", None, _void_p)
_decl("zcio_serial_read_eof", c.c_bool, _void_p)
_decl("zcio_serial_read_empty", c.c_bool, _void_p)
_decl("zcio_serial_short_read", c.c_bool, _void_p)
_decl("zcio_serial_last_read", c.c_size_t, _void_p)
_decl("zcio_serial_clear_read", None, _void_p)

# stream
_decl("zcio_memory_stream", _void_p, _void_p, c.c_size_t)
_decl("zcio_counting_stream", _void_p, _void_p, c.c_size_t)
_decl("zcio_counting_bytes_written", c.c_int64, _void_p)
_decl("zcio_counting_bytes_read", c.c_int64, _void_p)
_decl("zcio_stream_free", None, _void_p)
_decl("zcio_read", c.c_int64, _void_p, _void_p, c.c_size_t)
_decl("zcio_write", c.c_int64, _void_p, _void_p, c.c_size_t)
_decl("zcio_write_full", c.c_int64, _void_p, _void_p, c.c_size_t)
_decl("zcio_read_full", c.c_int64, _void_p, _void_p, c.c_size_t)
_decl("zcio_seek", c.c_int64, _void_p, c.c_int64, c.c_int, c.c_uint)
_decl("zcio_flush", c.c_int, _void_p)
_decl("zcio_close", c.c_int, _void_p)
_decl("zcio_available", c.c_int64, _void_p)
_decl("zcio_stream_eof", c.c_bool, _void_p)
_decl("zcio_stream_name", c.c_char_p, _void_p)
_decl("zcio_copy", c.c_int64, _void_p, _void_p, c.c_size_t)

# net -- tcp
_decl("zcio_tcp_client_connect", _void_p, c.c_char_p, c.c_int)
_decl("zcio_tcp_client_free", None, _void_p)
_decl("zcio_tcp_client_stream", _void_p, _void_p)
_decl("zcio_tcp_client_wait_readable", c.c_int, _void_p, c.c_int)
_decl("zcio_tcp_client_wait_writable", c.c_int, _void_p, c.c_int)
_decl("zcio_tcp_client_bytes_available", c.c_int, _void_p)
_decl("zcio_tcp_server_listen", _void_p, c.c_int)
_decl("zcio_tcp_server_free", None, _void_p)
_decl("zcio_tcp_server_accept", _void_p, _void_p, c.POINTER(c.c_size_t), c.c_int)
_decl("zcio_tcp_server_close_client", c.c_int, _void_p, c.c_size_t)
_decl("zcio_tcp_conn_stream", _void_p, _void_p)
_decl("zcio_tcp_conn_wait_readable", c.c_int, _void_p, c.c_int)
_decl("zcio_tcp_conn_wait_writable", c.c_int, _void_p, c.c_int)

# net -- udp
_decl("zcio_udp_client_open", _void_p, c.c_char_p, c.c_int)
_decl("zcio_udp_client_free", None, _void_p)
_decl("zcio_udp_client_stream", _void_p, _void_p)
_decl("zcio_udp_server_bind", _void_p, c.c_int)
_decl("zcio_udp_server_free", None, _void_p)
_decl("zcio_udp_server_receive", _void_p, _void_p, c.c_bool, c.c_uint)
_decl("zcio_udp_packet_stream", _void_p, _void_p)

# net -- multicast
_decl("zcio_mcast_sender_open", _void_p, c.c_char_p, c.c_int)
_decl("zcio_mcast_sender_free", None, _void_p)
_decl("zcio_mcast_sender_stream", _void_p, _void_p)
_decl("zcio_mcast_receiver_open", _void_p, c.c_char_p, c.c_int)
_decl("zcio_mcast_receiver_free", None, _void_p)
_decl("zcio_mcast_receiver_stream", _void_p, _void_p)

# tls
_decl("zcio_tls_available", c.c_bool)
_decl("zcio_tls_backend_name", c.c_char_p)
_decl("zcio_tls_client_ctx", _void_p, c.c_char_p)
_decl("zcio_tls_server_ctx", _void_p)
_decl("zcio_tls_server_ctx_files", _void_p, c.c_char_p, c.c_char_p)
_decl("zcio_tls_ctx_free", None, _void_p)
_decl("zcio_tcp_client_connect_tls", _void_p, c.c_char_p, c.c_int, _void_p, c.c_bool)
_decl("zcio_tcp_server_listen_tls", _void_p, c.c_int, _void_p, c.c_bool)

# dns
_decl("zcio_is_ipv4", c.c_bool, c.c_char_p)
_decl("zcio_resolve_ipv4", c.c_void_p, c.c_char_p)
_decl("zcio_local_ipv4", c.c_void_p)
_decl("zcio_dns_query_a", c.POINTER(c.c_void_p), c.c_char_p, c.POINTER(c.c_size_t))
_decl("zcio_dns_query_aaaa", c.POINTER(c.c_void_p), c.c_char_p, c.POINTER(c.c_size_t))
_decl("zcio_strv_free", None, c.POINTER(c.c_void_p), c.c_size_t)

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


class _HttpHeader(c.Structure):
    _fields_ = [("key", c.c_char_p), ("value", c.c_char_p)]


_decl("zcio_http_get", _HttpResponse, c.c_char_p)
_decl("zcio_http_delete", _HttpResponse, c.c_char_p)
_decl("zcio_http_post", _HttpResponse, c.c_char_p, _void_p, c.c_size_t)
_decl("zcio_http_put", _HttpResponse, c.c_char_p, _void_p, c.c_size_t)
_decl("zcio_http_request", _HttpResponse, c.c_char_p, c.c_char_p,
      c.POINTER(_HttpHeader), c.c_size_t, _void_p, c.c_size_t)
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


def tls_available() -> bool:
    """True if a real TLS backend (not the 'none' stub) is compiled in."""
    return bool(lib.zcio_tls_available())


def tls_backend_name() -> str:
    n = lib.zcio_tls_backend_name()
    return n.decode() if n else ""


def resolve_ipv4(host: str) -> Optional[str]:
    return _take_cstr(lib.zcio_resolve_ipv4(host.encode()))


def local_ipv4() -> Optional[str]:
    return _take_cstr(lib.zcio_local_ipv4())


def _take_strv(fn, host: str) -> list:
    """Call a zcio_dns_query_* fn, copy results, free with zcio_strv_free."""
    n = c.c_size_t(0)
    ptr = fn(host.encode(), c.byref(n))
    if not ptr:
        return []
    out = []
    for i in range(n.value):
        s = c.cast(ptr[i], c.c_char_p).value
        out.append(s.decode() if s is not None else "")
    lib.zcio_strv_free(ptr, n.value)
    return out


def dns_query_a(host: str) -> list:
    """Resolve all A (IPv4) records for `host`."""
    return _take_strv(lib.zcio_dns_query_a, host)


def dns_query_aaaa(host: str) -> list:
    """Resolve all AAAA (IPv6) records for `host`."""
    return _take_strv(lib.zcio_dns_query_aaaa, host)


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

    @property
    def available_write(self) -> int:
        return lib.zcio_ring_available_write(self._h)

    def as_stream(self, take_ownership: bool = False) -> "Stream":
        """Adapt this ring as a generic Stream. If take_ownership, the returned
        Stream's close() frees the ring too (do not close the Ring yourself)."""
        h = lib.zcio_ring_as_stream(self._h, take_ownership)
        if not h:
            raise ZcioError("ring_as_stream failed")
        if take_ownership:
            self._h = None  # ring is now owned by the stream
            return Stream(h, owns=True)
        # Non-owning: the stream wrapper is still ours to free (zcio_ring_as_stream
        # allocates a fresh zcio_stream), but the underlying ring is borrowed. Keep
        # a Python reference to this Ring so it cannot be GC'd (and freed) while the
        # borrowing stream is still alive -- otherwise the stream would dangle.
        return Stream(h, owns=True, parent=self)

    def close(self):
        if self._h:
            lib.zcio_ring_free(self._h)
            self._h = None

    __del__ = close


# --- Serial (buffer-backed) --------------------------------------------------
def _make_scalar_methods(cls):
    """Attach write_<suf>/read_<suf> methods for every scalar type."""
    for suf in _SERIAL_SCALARS:
        wfn = getattr(lib, f"zcio_serial_write_{suf}")
        rfn = getattr(lib, f"zcio_serial_read_{suf}")
        setattr(cls, f"write_{suf}",
                (lambda wfn: lambda self, v: wfn(self._h, v))(wfn))
        setattr(cls, f"read_{suf}",
                (lambda rfn: lambda self: rfn(self._h))(rfn))
    return cls


@_make_scalar_methods
class Serial:
    """Bit/byte serializer.

    Buffer mode (default): pass an existing bytearray to share its storage.
    Count mode (count=True): tallies bytes a write *would* take, stores nothing.
    Stream mode: pass a Stream/MemoryStream via `stream=`.
    """

    def __init__(self, size: int = 4096, bit_stream: bool = False, buffer=None,
                 count: bool = False, stream=None, take_ownership: bool = False):
        self._buf = None
        self._carr = None
        if count:
            self._h = lib.zcio_serial_new_count()
        elif stream is not None:
            self._h = lib.zcio_serial_new(stream._h, bit_stream, take_ownership)
        else:
            self._buf = buffer if buffer is not None else bytearray(size)
            self._carr = (c.c_char * len(self._buf)).from_buffer(self._buf)
            self._h = lib.zcio_serial_new_buffer(self._carr, len(self._buf), bit_stream)
        if not self._h:
            raise ZcioError("serial allocation failed")

    # --- bulk bytes ---
    def write_bytes(self, data: bytes) -> int:
        buf = (c.c_char * len(data)).from_buffer_copy(data) if data else None
        return lib.zcio_serial_write_bytes(self._h, buf, len(data))

    def read_bytes(self, n: int) -> bytes:
        buf = (c.c_char * n)()
        got = lib.zcio_serial_read_bytes(self._h, buf, n)
        return bytes(buf[:got]) if got > 0 else b""

    # --- single byte / bit ---
    def write_byte(self, v: int): lib.zcio_serial_write_byte(self._h, v)
    def read_byte(self) -> int: return lib.zcio_serial_read_byte(self._h)
    def write_bit(self, v: bool): lib.zcio_serial_write_bit(self._h, bool(v))
    def read_bit(self) -> bool: return bool(lib.zcio_serial_read_bit(self._h))

    def write_bits(self, bits, index: int = 0, count: Optional[int] = None):
        """Pack `count` bits (each LSB of a byte in `bits`) starting at `index`."""
        arr = (c.c_uint8 * len(bits))(*[1 if b else 0 for b in bits])
        n = len(bits) if count is None else count
        lib.zcio_serial_write_bits(self._h, arr, index, n)

    def read_bits(self, count: int, index: int = 0) -> list:
        arr = (c.c_uint8 * (index + count))()
        lib.zcio_serial_read_bits(self._h, arr, index, count)
        return [bool(arr[index + i]) for i in range(count)]

    # --- string ---
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

    # --- positioning ---
    @property
    def write_pos(self) -> int:
        return lib.zcio_serial_write_pos(self._h)

    @property
    def read_pos(self) -> int:
        return lib.zcio_serial_read_pos(self._h)

    def set_write_pos(self, index: int): lib.zcio_serial_set_write_pos(self._h, index)
    def set_read_pos(self, index: int): lib.zcio_serial_set_read_pos(self._h, index)

    @property
    def write_len(self) -> int:
        return lib.zcio_serial_write_len(self._h)

    @property
    def read_len(self) -> int:
        return lib.zcio_serial_read_len(self._h)

    def synchronize(self): lib.zcio_serial_synchronize(self._h)

    # --- read status ---
    def read_eof(self) -> bool: return bool(lib.zcio_serial_read_eof(self._h))
    def read_empty(self) -> bool: return bool(lib.zcio_serial_read_empty(self._h))
    def short_read(self) -> bool: return bool(lib.zcio_serial_short_read(self._h))
    def last_read(self) -> int: return lib.zcio_serial_last_read(self._h)
    def clear_read(self): lib.zcio_serial_clear_read(self._h)

    @property
    def buffer(self) -> Optional[bytearray]:
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

    def write_raw(self, data: bytes) -> int:
        """Single (possibly short) write, not looped like write()."""
        buf = (c.c_char * len(data)).from_buffer_copy(data) if data else None
        return lib.zcio_write(self._h, buf, len(data))

    def read_full(self, n: int) -> bytes:
        buf = (c.c_char * n)()
        got = lib.zcio_read_full(self._h, buf, n)
        return bytes(buf[:got]) if got > 0 else b""

    def seek(self, off: int, origin: int = SEEK_SET, which: int = SEEK_BOTH) -> int:
        return lib.zcio_seek(self._h, off, origin, which)

    def seek_read(self, off: int, origin: int = SEEK_SET) -> int:
        return lib.zcio_seek(self._h, off, origin, SEEK_READ)

    def seek_write(self, off: int, origin: int = SEEK_SET) -> int:
        return lib.zcio_seek(self._h, off, origin, SEEK_WRITE)

    def flush(self) -> int:
        return lib.zcio_flush(self._h)

    @property
    def available(self) -> int:
        return lib.zcio_available(self._h)

    @property
    def eof(self) -> bool:
        return bool(lib.zcio_stream_eof(self._h))

    @property
    def name(self) -> str:
        n = lib.zcio_stream_name(self._h) if self._h else None
        return n.decode() if n else ""


class Stream(_Stream):
    """An owning wrapper over a zcio_stream handle (e.g. ring_as_stream)."""

    def __init__(self, handle, owns: bool = True, parent=None):
        super().__init__(handle)
        self._owns = owns
        # Optional strong reference to a parent object the stream borrows from
        # (e.g. a Ring), pinning its lifetime to ours so it cannot be freed first.
        self._parent = parent

    def close(self):
        if self._h:
            if self._owns:
                lib.zcio_stream_free(self._h)
            self._h = None
        self._parent = None

    __del__ = close


class MemoryStream(_Stream):
    def __init__(self, size: int = 4096, buffer=None):
        self._buf = buffer if buffer is not None else bytearray(size)
        self._carr = (c.c_char * len(self._buf)).from_buffer(self._buf)
        super().__init__(lib.zcio_memory_stream(self._carr, len(self._buf)))

    def close(self):
        if self._h:
            lib.zcio_stream_free(self._h)
            self._h = None

    __del__ = close


class CountingStream(_Stream):
    """Byte-counting stream. With a buffer, bytes pass through it; otherwise it
    is a pure sink/sizer. Query totals via bytes_written / bytes_read."""

    def __init__(self, size: int = 0, buffer=None):
        if buffer is not None:
            self._buf = buffer
        elif size > 0:
            self._buf = bytearray(size)
        else:
            self._buf = None
        if self._buf is not None:
            self._carr = (c.c_char * len(self._buf)).from_buffer(self._buf)
            super().__init__(lib.zcio_counting_stream(self._carr, len(self._buf)))
        else:
            self._carr = None
            super().__init__(lib.zcio_counting_stream(None, 0))
        if not self._h:
            raise ZcioError("counting_stream allocation failed")

    @property
    def bytes_written(self) -> int:
        return lib.zcio_counting_bytes_written(self._h)

    @property
    def bytes_read(self) -> int:
        return lib.zcio_counting_bytes_read(self._h)

    @property
    def buffer(self):
        return self._buf

    def close(self):
        if self._h:
            lib.zcio_stream_free(self._h)
            self._h = None

    __del__ = close


class TcpConn:
    """Borrowed accepted connection (owned by its TcpServer's connection map)."""

    def __init__(self, handle, conn_id: int):
        self._h = handle
        self.id = conn_id
        self.stream = _Stream(lib.zcio_tcp_conn_stream(handle))

    def wait_readable(self, timeout_ms: int = 1000) -> int:
        return lib.zcio_tcp_conn_wait_readable(self._h, timeout_ms)

    def wait_writable(self, timeout_ms: int = 1000) -> int:
        return lib.zcio_tcp_conn_wait_writable(self._h, timeout_ms)


class TlsCtx:
    """An opaque per-role TLS configuration (client or server). Borrowed by the
    endpoints it is passed to -- the caller owns it and may share one ctx across
    many connections, then release it (here, on GC / ctx_free())."""

    def __init__(self, handle):
        if not handle:
            raise ZcioError(f"tls ctx creation failed: {lib.zcio_last_error().decode()}")
        self._h = handle

    @classmethod
    def client(cls, host: str) -> "TlsCtx":
        """Client context that verifies `host` (SNI + cert hostname)."""
        return cls(lib.zcio_tls_client_ctx(host.encode()))

    @classmethod
    def server(cls) -> "TlsCtx":
        """Server context with a generated self-signed cert."""
        return cls(lib.zcio_tls_server_ctx())

    @classmethod
    def server_files(cls, cert_path: str, key_path: str) -> "TlsCtx":
        """Server context from PEM cert/key file paths."""
        return cls(lib.zcio_tls_server_ctx_files(cert_path.encode(), key_path.encode()))

    def ctx_free(self):
        if self._h:
            lib.zcio_tls_ctx_free(self._h)
            self._h = None

    __del__ = ctx_free


class TcpClient:
    def __init__(self, host: str, port: int, tls: Optional["TlsCtx"] = None,
                 verify: bool = True):
        if tls is not None:
            self._h = lib.zcio_tcp_client_connect_tls(
                host.encode(), port, tls._h, verify)
        else:
            self._h = lib.zcio_tcp_client_connect(host.encode(), port)
        if not self._h:
            raise ZcioError(f"tcp connect failed: {lib.zcio_last_error().decode()}")
        # Keep the TLS ctx alive for the connection's lifetime (it is borrowed).
        self._tls = tls
        self.stream = _Stream(lib.zcio_tcp_client_stream(self._h))

    def wait_readable(self, timeout_ms: int = 1000) -> int:
        return lib.zcio_tcp_client_wait_readable(self._h, timeout_ms)

    def wait_writable(self, timeout_ms: int = 1000) -> int:
        return lib.zcio_tcp_client_wait_writable(self._h, timeout_ms)

    @property
    def bytes_available(self) -> int:
        return lib.zcio_tcp_client_bytes_available(self._h)

    def close(self):
        if self._h:
            lib.zcio_tcp_client_free(self._h)
            self._h = None

    __del__ = close


class TcpServer:
    def __init__(self, port: int, tls: Optional["TlsCtx"] = None,
                 non_blocking: bool = False):
        if tls is not None:
            self._h = lib.zcio_tcp_server_listen_tls(port, tls._h, non_blocking)
        else:
            self._h = lib.zcio_tcp_server_listen(port)
        if not self._h:
            raise ZcioError(f"tcp listen failed: {lib.zcio_last_error().decode()}")
        # Keep the TLS ctx alive for the server's lifetime (it is borrowed).
        self._tls = tls

    def accept(self, timeout_ms: int = 1000):
        """Accept one client, returning a borrowed _Stream (or None on timeout)."""
        conn = self.accept_conn(timeout_ms)
        return conn.stream if conn is not None else None

    def accept_conn(self, timeout_ms: int = 1000):
        """Accept one client, returning a TcpConn (carrying .id and .stream)."""
        cid = c.c_size_t(0)
        conn = lib.zcio_tcp_server_accept(self._h, c.byref(cid), timeout_ms)
        if not conn:
            return None
        return TcpConn(conn, cid.value)

    def close_client(self, conn_id: int) -> int:
        return lib.zcio_tcp_server_close_client(self._h, conn_id)

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


class McastSender:
    """Multicast sender: write datagrams to (group, port)."""

    def __init__(self, group: str, port: int):
        self._h = lib.zcio_mcast_sender_open(group.encode(), port)
        if not self._h:
            raise ZcioError(f"mcast sender open failed: {lib.zcio_last_error().decode()}")
        self.stream = _Stream(lib.zcio_mcast_sender_stream(self._h))

    def close(self):
        if self._h:
            lib.zcio_mcast_sender_free(self._h)
            self._h = None

    __del__ = close


class McastReceiver:
    """Multicast receiver: joins (group, port) and reads datagrams."""

    def __init__(self, group: str, port: int):
        self._h = lib.zcio_mcast_receiver_open(group.encode(), port)
        if not self._h:
            raise ZcioError(f"mcast receiver open failed: {lib.zcio_last_error().decode()}")
        self.stream = _Stream(lib.zcio_mcast_receiver_stream(self._h))

    def close(self):
        if self._h:
            lib.zcio_mcast_receiver_free(self._h)
            self._h = None

    __del__ = close


# --- copy --------------------------------------------------------------------
def copy(dst: "_Stream", src: "_Stream", limit: Optional[int] = None) -> int:
    """Pump up to `limit` bytes (None = until EOF) from src into dst."""
    SIZE_MAX = (1 << (8 * c.sizeof(c.c_size_t))) - 1
    n = SIZE_MAX if limit is None else limit
    return lib.zcio_copy(dst._h, src._h, n)


# --- HTTP --------------------------------------------------------------------
def _http_result(resp: "_HttpResponse") -> dict:
    body = b""
    if resp.body and resp.body_size:
        body = c.string_at(resp.body, resp.body_size)
    out = {
        "status": resp.status,
        "status_text": resp.status_text.decode() if resp.status_text else "",
        "protocol": resp.protocol.decode() if resp.protocol else "",
        "version": resp.version.decode() if resp.version else "",
        "headers_json": resp.headers_json.decode() if resp.headers_json else "{}",
        "body": body,
    }
    lib.zcio_http_response_free(c.byref(resp))
    return out


def http_get(url: str) -> dict:
    return _http_result(lib.zcio_http_get(url.encode()))


def http_delete(url: str) -> dict:
    return _http_result(lib.zcio_http_delete(url.encode()))


def http_post(url: str, body: bytes = b"") -> dict:
    buf = (c.c_char * len(body)).from_buffer_copy(body) if body else None
    return _http_result(lib.zcio_http_post(url.encode(), buf, len(body)))


def http_put(url: str, body: bytes = b"") -> dict:
    buf = (c.c_char * len(body)).from_buffer_copy(body) if body else None
    return _http_result(lib.zcio_http_put(url.encode(), buf, len(body)))


def http_request(method: str, url: str, headers: Optional[dict] = None,
                 body: bytes = b"") -> dict:
    """Issue an arbitrary HTTP request with optional headers (a dict)."""
    headers = headers or {}
    items = list(headers.items())
    harr = (_HttpHeader * len(items))() if items else None
    _keep = []  # keep encoded bytes alive for the call
    for i, (k, v) in enumerate(items):
        kb, vb = str(k).encode(), str(v).encode()
        _keep.append((kb, vb))
        harr[i].key = kb
        harr[i].value = vb
    buf = (c.c_char * len(body)).from_buffer_copy(body) if body else None
    return _http_result(lib.zcio_http_request(
        method.encode(), url.encode(), harr, len(items), buf, len(body)))
