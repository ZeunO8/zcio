"""Smoke tests for the zcio Python binding. Run: python test_zcio.py
Requires the shared lib built at ../../build (cmake -DZCIO_BUILD_SHARED=ON)."""
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zcio


class SkipTest(Exception):
    """Raise to mark a test as skipped (environment-dependent)."""


def _free_port():
    """Ask the OS for a currently-free TCP port. Avoids TIME_WAIT collisions
    between back-to-back runs (zcio's C server sets no SO_REUSEADDR)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------------------
# basics
# ---------------------------------------------------------------------------
def test_version():
    v = zcio.version()
    assert v and v[0].isdigit(), v
    print("version:", v)


def test_ipv4():
    assert zcio.is_ipv4("127.0.0.1")
    assert not zcio.is_ipv4("999.0.0.1")
    assert zcio.resolve_ipv4("8.8.8.8") == "8.8.8.8"


def test_dns_query_a():
    addrs = zcio.dns_query_a("localhost")
    assert isinstance(addrs, list) and len(addrs) >= 1, addrs
    # at least one should be a v4 literal (commonly 127.0.0.1)
    assert any(zcio.is_ipv4(a) for a in addrs), addrs


def test_dns_query_aaaa():
    # may legitimately be empty on hosts without IPv6; just must not crash.
    addrs = zcio.dns_query_aaaa("localhost")
    assert isinstance(addrs, list)


def test_local_ipv4():
    ip = zcio.local_ipv4()
    # returns a string or None; if a string it should look like a v4 address
    assert ip is None or zcio.is_ipv4(ip), ip


# ---------------------------------------------------------------------------
# ring
# ---------------------------------------------------------------------------
def test_ring():
    r = zcio.Ring(64)
    assert r.write(b"hello zcio") == 10
    assert r.available == 10
    assert r.available_write == 54
    assert r.read(10) == b"hello zcio"
    assert r.available == 0
    r.close()


# ---------------------------------------------------------------------------
# serial
# ---------------------------------------------------------------------------
def test_serial():
    s = zcio.Serial(256)
    s.write_i32(-42)
    s.write_u64(0xCAFEBABE)
    s.write_f64(2.5)
    s.write_str("hi")
    rd = zcio.Serial(256, buffer=s.buffer)
    assert rd.read_i32() == -42
    assert rd.read_u64() == 0xCAFEBABE
    assert rd.read_f64() == 2.5
    assert rd.read_str() == "hi"


def test_serial_all_scalars():
    s = zcio.Serial(512)
    s.write_i8(-5)
    s.write_u8(250)
    s.write_i16(-1000)
    s.write_u16(60000)
    s.write_i32(-100000)
    s.write_u32(4000000000)
    s.write_i64(-9_000_000_000)
    s.write_u64(18_000_000_000)
    s.write_f32(1.5)
    s.write_f64(3.25)
    rd = zcio.Serial(512, buffer=s.buffer)
    assert rd.read_i8() == -5
    assert rd.read_u8() == 250
    assert rd.read_i16() == -1000
    assert rd.read_u16() == 60000
    assert rd.read_i32() == -100000
    assert rd.read_u32() == 4000000000
    assert rd.read_i64() == -9_000_000_000
    assert rd.read_u64() == 18_000_000_000
    assert abs(rd.read_f32() - 1.5) < 1e-6
    assert rd.read_f64() == 3.25


def test_serial_byte_and_bytes():
    s = zcio.Serial(64)
    s.write_byte(0xAB)
    s.write_bytes(b"raw-bytes")
    rd = zcio.Serial(64, buffer=s.buffer)
    assert rd.read_byte() == 0xAB
    assert rd.read_bytes(9) == b"raw-bytes"


def test_serial_bits_roundtrip():
    pattern = [True, False, True, True, False, False, True, False, True]
    s = zcio.Serial(64, bit_stream=True)
    s.write_bits(pattern)
    s.synchronize()
    rd = zcio.Serial(64, bit_stream=True, buffer=s.buffer)
    got = rd.read_bits(len(pattern))
    assert got == pattern, (got, pattern)


def test_serial_single_bits():
    s = zcio.Serial(16, bit_stream=True)
    for b in (True, True, False, True, False):
        s.write_bit(b)
    s.synchronize()
    rd = zcio.Serial(16, bit_stream=True, buffer=s.buffer)
    assert [rd.read_bit() for _ in range(5)] == [True, True, False, True, False]


def test_serial_positioning():
    s = zcio.Serial(64)
    s.write_i32(1)
    s.write_i32(2)
    assert s.write_pos == 8
    s.set_write_pos(0)
    s.write_i32(99)
    rd = zcio.Serial(64, buffer=s.buffer)
    assert rd.read_i32() == 99
    assert rd.read_pos == 4
    rd.set_read_pos(4)
    assert rd.read_i32() == 2


def test_serial_count_mode():
    s = zcio.Serial(count=True)
    s.write_i32(0)        # 4
    s.write_f64(0.0)      # 8
    s.write_str("abc")    # 8 (u64 len) + 3
    assert s.write_pos == 4 + 8 + 8 + 3, s.write_pos


def test_serial_read_status():
    s = zcio.Serial(8)
    s.write_i16(7)
    rd = zcio.Serial(8, buffer=s.buffer)
    assert rd.read_i16() == 7
    assert not rd.short_read()
    rd.read_bytes(100)  # overread the 8-byte buffer
    assert rd.short_read() or rd.read_empty() or rd.read_eof()
    assert isinstance(rd.last_read(), int)
    rd.clear_read()


# ---------------------------------------------------------------------------
# streams
# ---------------------------------------------------------------------------
def test_memory_stream():
    m = zcio.MemoryStream(32)
    assert m.write(b"0123456789") == 10
    m.seek_read(0)
    assert m.read_full(10) == b"0123456789"
    m.close()


def test_stream_verbs():
    m = zcio.MemoryStream(32)
    m.write(b"abcdef")
    assert m.flush() == 0
    m.seek_read(0)
    assert m.available >= 0
    assert m.read(3) == b"abc"
    assert m.name  # backend identifier, e.g. "membuf"/"memory"
    m.close()


def test_copy_ring_to_memory():
    r = zcio.Ring(64)
    r.write(b"payload-via-copy")
    src = r.as_stream(take_ownership=True)
    dst = zcio.MemoryStream(64)
    n = zcio.copy(dst, src, limit=len(b"payload-via-copy"))
    assert n == 16, n
    dst.seek_read(0)
    assert dst.read_full(16) == b"payload-via-copy"
    src.close()
    dst.close()


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------
def test_tcp_loopback():
    port = _free_port()
    srv = zcio.TcpServer(port)
    cli = zcio.TcpClient("127.0.0.1", port)
    conn = srv.accept(2000)
    assert conn is not None
    cli.stream.write(b"ping")
    assert conn.read_full(4) == b"ping"
    cli.close()
    srv.close()


def test_tcp_wait_and_avail():
    port = _free_port()
    srv = zcio.TcpServer(port)
    cli = zcio.TcpClient("127.0.0.1", port)
    conn = srv.accept_conn(2000)
    assert conn is not None
    cli.stream.write(b"hello!")
    # server side should become readable
    assert conn.wait_readable(2000) >= 0
    # client should be writable
    assert cli.wait_writable(2000) >= 0
    data = conn.stream.read_full(6)
    assert data == b"hello!"
    # now have server reply so the client has data to read
    conn.stream.write(b"yo")
    assert cli.wait_readable(2000) >= 0
    _ = cli.bytes_available  # just exercise it (>= 0 or -1 acceptable)
    assert cli.stream.read_full(2) == b"yo"
    cli.close()
    srv.close()


def test_tcp_two_clients_and_close():
    port = _free_port()
    srv = zcio.TcpServer(port)
    c1 = zcio.TcpClient("127.0.0.1", port)
    conn1 = srv.accept_conn(2000)
    c2 = zcio.TcpClient("127.0.0.1", port)
    conn2 = srv.accept_conn(2000)
    assert conn1 is not None and conn2 is not None
    assert conn1.id != conn2.id, (conn1.id, conn2.id)
    c1.stream.write(b"aaa")
    c2.stream.write(b"bbb")
    assert conn1.stream.read_full(3) == b"aaa"
    assert conn2.stream.read_full(3) == b"bbb"
    # close just one client connection on the server
    assert srv.close_client(conn1.id) == 0
    c1.close()
    c2.close()
    srv.close()


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------
def test_udp_loopback():
    port = _free_port()
    srv = zcio.UdpServer(port)
    cli = zcio.UdpClient("127.0.0.1", port)
    cli.stream.write(b"udp-ping")
    pkt = srv.receive(timeout_us=2_000_000)
    assert pkt is not None
    assert pkt.read(8) == b"udp-ping"
    cli.close()
    srv.close()


def test_udp_two_clients():
    port = _free_port()
    srv = zcio.UdpServer(port)
    c1 = zcio.UdpClient("127.0.0.1", port)
    c2 = zcio.UdpClient("127.0.0.1", port)
    c1.stream.write(b"one")
    c2.stream.write(b"two")
    got = set()
    for _ in range(2):
        pkt = srv.receive(timeout_us=2_000_000)
        assert pkt is not None
        got.add(pkt.read(3))
    assert got == {b"one", b"two"}, got
    c1.close()
    c2.close()
    srv.close()


# ---------------------------------------------------------------------------
# Multicast (best-effort; SKIP if no datagram arrives)
# ---------------------------------------------------------------------------
def test_multicast_loopback():
    group, port = "239.255.0.1", _free_port()
    try:
        recv = zcio.McastReceiver(group, port)
    except zcio.ZcioError as e:
        raise SkipTest(f"mcast receiver open failed: {e}")
    try:
        send = zcio.McastSender(group, port)
    except zcio.ZcioError as e:
        recv.close()
        raise SkipTest(f"mcast sender open failed: {e}")
    try:
        # exercise open/stream/write/free regardless of routing
        send.stream.write(b"mcast-hi")
        time.sleep(0.1)
        send.stream.write(b"mcast-hi")
        # best-effort receive; many headless envs have no mcast loopback route
        data = recv.stream.read(8)
        if not data:
            raise SkipTest("no multicast datagram (no loopback route, headless)")
        assert data == b"mcast-hi", data
    finally:
        send.close()
        recv.close()


# ---------------------------------------------------------------------------
# HTTP (offline: tiny server in a thread)
# ---------------------------------------------------------------------------
def _start_http_server():
    """Raw-socket HTTP/1.1 server returning 200 OK with a fixed body.
    Returns (port, stop_fn)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def serve():
        srv.settimeout(0.25)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(1.0)
                # drain request headers
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                body = b"hello from test server"
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n"
                    b"\r\n" + body
                )
                conn.sendall(resp)
            except OSError:
                pass
            finally:
                conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    def shutdown():
        stop.set()
        t.join(timeout=2)
        srv.close()

    return port, shutdown


def test_http_get_offline():
    port, shutdown = _start_http_server()
    try:
        time.sleep(0.05)
        resp = zcio.http_get(f"http://127.0.0.1:{port}/")
        assert resp["status"] == 200, resp
        assert b"hello from test server" in resp["body"], resp["body"]
    finally:
        shutdown()


def test_http_request_verb():
    port, shutdown = _start_http_server()
    try:
        time.sleep(0.05)
        resp = zcio.http_request("GET", f"http://127.0.0.1:{port}/",
                                 headers={"X-Test": "1"})
        assert resp["status"] == 200, resp
        assert b"hello from test server" in resp["body"]
    finally:
        shutdown()


def test_http_bad_host():
    # A clearly-unresolvable host: status 0, no crash.
    resp = zcio.http_get("http://no-such-host.invalid.zzz/")
    assert resp["status"] == 0, resp


# ---------------------------------------------------------------------------
# runner
# ---------------------------------------------------------------------------
def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = skipped = 0
    for t in tests:
        try:
            t()
            print(f"[ ok ] {t.__name__}")
        except SkipTest as e:
            skipped += 1
            print(f"[SKIP] {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"[FAIL] {t.__name__}: {e}")
    passed = len(tests) - failed - skipped
    print(f"{passed} passed, {skipped} skipped, {failed} failed "
          f"(of {len(tests)})")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
