"""Smoke tests for the zcio Python binding. Run: python test_zcio.py
Requires the shared lib built at ../../build (cmake -DZCIO_BUILD_SHARED=ON)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zcio


def test_version():
    v = zcio.version()
    assert v and v[0].isdigit(), v
    print("version:", v)


def test_ipv4():
    assert zcio.is_ipv4("127.0.0.1")
    assert not zcio.is_ipv4("999.0.0.1")
    assert zcio.resolve_ipv4("8.8.8.8") == "8.8.8.8"


def test_ring():
    r = zcio.Ring(64)
    assert r.write(b"hello zcio") == 10
    assert r.available == 10
    assert r.read(10) == b"hello zcio"
    assert r.available == 0
    r.close()


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


def test_memory_stream():
    m = zcio.MemoryStream(32)
    assert m.write(b"0123456789") == 10
    m.seek_read(0)
    assert m.read_full(10) == b"0123456789"
    m.close()


def test_tcp_loopback():
    srv = zcio.TcpServer(39901)
    cli = zcio.TcpClient("127.0.0.1", 39901)
    conn = srv.accept(2000)
    assert conn is not None
    cli.stream.write(b"ping")
    assert conn.read_full(4) == b"ping"
    cli.close()
    srv.close()


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"[ ok ] {t.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"[FAIL] {t.__name__}: {e}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
