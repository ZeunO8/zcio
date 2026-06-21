'use strict';

/* zcio Node binding test suite.
 *
 * Mirrors the C `ztest` harness output: each named test prints `[ ok ] <name>`,
 * `[skip] <name>: <why>`, or `[FAIL] <name>: <error>`, then a final tally. The
 * process exits non-zero if any test fails so CTest flags it. */

const assert = require('assert');
const { spawn } = require('child_process');
const path = require('path');
const zcio = require('..');

/* ---- tiny runner -------------------------------------------------------- */
const tests = [];
function test(name, fn) { tests.push({ name, fn }); }

class Skip extends Error {}
function skip(msg) { throw new Skip(msg); }

/* Synchronous sleep. The multicast receiver socket is non-blocking, so we must
 * block the (single) JS thread between a send and the next poll to give the
 * datagram time to loop back. Atomics.wait is the only synchronous sleep in
 * Node that doesn't busy-spin. */
const _sleepBuf = new Int32Array(new SharedArrayBuffer(4));
function sleepSync(ms) { Atomics.wait(_sleepBuf, 0, 0, ms); }

/* Randomize a port base per run so repeated runs don't collide with sockets
 * lingering in TIME_WAIT. */
const PORT_BASE = 20000 + Math.floor(Math.random() * 20000);
let nextPort = PORT_BASE;
function port() { return nextPort++; }

/* ---- tests -------------------------------------------------------------- */
test('version', () => {
  const v = zcio.version();
  assert.strictEqual(typeof v, 'string');
  assert.ok(v.length > 0, 'version string should be non-empty');
});

test('isIpv4', () => {
  assert.strictEqual(zcio.isIpv4('127.0.0.1'), true, '127.0.0.1 is IPv4');
  assert.strictEqual(zcio.isIpv4('not.an.ip'), false, 'garbage is not IPv4');
  assert.strictEqual(zcio.isIpv4('::1'), false, 'IPv6 is not IPv4');
});

test('ring_roundtrip', () => {
  const ring = new zcio.Ring(1024);
  const payload = Buffer.from('hello zcio ring');
  assert.strictEqual(ring.write(payload), payload.length, 'wrote all bytes');
  assert.strictEqual(ring.availableRead(), payload.length, 'available == written');
  const got = ring.read(payload.length);
  assert.ok(Buffer.isBuffer(got), 'read returns a Buffer');
  assert.strictEqual(got.toString(), payload.toString(), 'roundtrip matches');
  ring.free();
});

test('serial_scalars', () => {
  const s = new zcio.BufferSerial(512);
  s.writeI8(-5); s.writeU8(250);
  s.writeI16(-1234); s.writeU16(60000);
  s.writeI32(0x1234abcd | 0); s.writeU32(0xdeadbeef >>> 0);
  s.writeI64(-9007199254740993n); s.writeU64(18446744073709551610n);
  s.writeF32(1.5); s.writeF64(3.141592653589793);
  s.writeStr('serialized');
  s.writeBytes(Buffer.from([1, 2, 3, 4, 5]));

  s.setReadPos(0);
  assert.strictEqual(s.readI8(), -5, 'i8');
  assert.strictEqual(s.readU8(), 250, 'u8');
  assert.strictEqual(s.readI16(), -1234, 'i16');
  assert.strictEqual(s.readU16(), 60000, 'u16');
  assert.strictEqual(s.readI32(), 0x1234abcd | 0, 'i32');
  assert.strictEqual(s.readU32(), 0xdeadbeef >>> 0, 'u32');
  assert.strictEqual(s.readI64(), -9007199254740993n, 'i64');
  assert.strictEqual(s.readU64(), 18446744073709551610n, 'u64');
  assert.ok(Math.abs(s.readF32() - 1.5) < 1e-6, 'f32');
  assert.strictEqual(s.readF64(), 3.141592653589793, 'f64');
  assert.strictEqual(s.readStr(), 'serialized', 'string');
  assert.deepStrictEqual([...s.readBytes(5)], [1, 2, 3, 4, 5], 'bytes');
});

test('serial_bits', () => {
  const s = new zcio.BufferSerial(64, true /* bitStream */);
  const bits = [true, false, true, true, false, false, false, true];
  for (const b of bits) s.writeBit(b);
  s.setReadPos(0);
  for (let i = 0; i < bits.length; i++) {
    assert.strictEqual(s.readBit(), bits[i], `bit ${i}`);
  }
});

test('serial_count_sizing', () => {
  const c = new zcio.CountSerial();
  c.writeI32(0);                   // 4
  c.writeU16(0);                   // 2
  c.writeF64(0);                   // 8
  c.writeBytes(Buffer.alloc(10));  // 10
  c.writeStr('abc');               // 8 (u64 len) + 3
  assert.strictEqual(Number(c.writeLen()), 35, 'count-mode sizing total');
});

test('stream_copy_ring_to_memory', () => {
  const ring = new zcio.Ring(256);
  const payload = Buffer.from('copy me through a stream');
  ring.write(payload);
  const rstream = ring.asStream();
  const mem = new zcio.MemoryStream(256);
  const copied = mem.copyFrom(rstream, payload.length);
  assert.strictEqual(copied, payload.length, 'copied all bytes');
  assert.strictEqual(mem.buffer.slice(0, payload.length).toString(), payload.toString(),
    'memory stream holds the copied data');
  ring.free();
});

test('tcp_loopback', () => {
  const PORT = port();
  const server = zcio.TcpServer.listen(PORT);
  assert.ok(server, 'tcp server listening');
  const client = zcio.TcpClient.connect('127.0.0.1', PORT);
  assert.ok(client, 'tcp client connected');

  const accepted = server.accept(1000);
  assert.ok(accepted, 'server accepted a client');
  assert.strictEqual(typeof accepted.id, 'number', 'accept returns numeric id');

  const msg = Buffer.from('ping over tcp');
  assert.strictEqual(client.stream().write(msg), msg.length, 'client wrote full message');
  assert.strictEqual(accepted.stream.readFull(msg.length).toString(), msg.toString(),
    'tcp loopback roundtrip');

  const reply = Buffer.from('pong');
  accepted.stream.write(reply);
  assert.strictEqual(client.stream().readFull(reply.length).toString(), reply.toString(),
    'tcp reverse roundtrip');

  client.free(); server.free();
});

test('tcp_two_clients_close', () => {
  const PORT = port();
  const server = zcio.TcpServer.listen(PORT);
  assert.ok(server, 'tcp server listening (2-client)');
  const c1 = zcio.TcpClient.connect('127.0.0.1', PORT);
  const c2 = zcio.TcpClient.connect('127.0.0.1', PORT);
  assert.ok(c1 && c2, 'both clients connected');

  const a1 = server.accept(1000);
  const a2 = server.accept(1000);
  assert.ok(a1 && a2, 'accepted two clients');
  assert.notStrictEqual(a1.id, a2.id, 'distinct client ids');

  assert.ok(server.closeClient(a1.id) >= 0, 'closeClient succeeded');

  const m = Buffer.from('still here');
  c2.stream().write(m);
  assert.strictEqual(a2.stream.readFull(m.length).toString(), m.toString(),
    'second client still works after closing first');

  c1.free(); c2.free(); server.free();
});

test('udp_loopback', () => {
  const PORT = port();
  const server = zcio.UdpServer.bind(PORT);
  assert.ok(server, 'udp server bound');
  const client = zcio.UdpClient.open('127.0.0.1', PORT);
  assert.ok(client, 'udp client open');

  const msg = Buffer.from('datagram');
  assert.strictEqual(client.stream().write(msg), msg.length, 'udp client wrote datagram');

  const pkt = server.receive(false, 500000 /* 500ms */);
  try {
    if (!pkt) skip('no datagram received within timeout');
    assert.strictEqual(pkt.read(msg.length).toString(), msg.toString(), 'udp loopback roundtrip');
  } finally {
    client.free(); server.free();
  }
});

test('multicast_loopback', () => {
  const GROUP = '239.255.42.99';
  const PORT = port();
  const recv = zcio.McastReceiver.open(GROUP, PORT);
  const send = zcio.McastSender.open(GROUP, PORT);
  if (!recv || !send) {
    if (recv) recv.free();
    if (send) send.free();
    skip('could not open sender/receiver (no multicast route)');
  }
  try {
    const msg = Buffer.from('mcast hello');
    let got = null;
    // Resend + poll with short sleeps, mirroring the C test, so the looped-back
    // datagram has time to arrive on the non-blocking receiver socket.
    for (let attempt = 0; attempt < 10 && !got; attempt++) {
      send.stream().write(msg);
      for (let i = 0; i < 20 && !got; i++) {
        let r = null;
        try { r = recv.stream().read(msg.length); } catch (_) { r = null; }
        if (r && r.length >= msg.length) got = r;
        else sleepSync(5);
      }
    }
    if (!got) skip('no multicast loopback route on this host');
    assert.strictEqual(got.toString(), msg.toString(), 'multicast loopback roundtrip');
  } finally {
    send.free(); recv.free();
  }
});

test('dns', () => {
  const ip = zcio.resolveIpv4('localhost');
  if (ip !== null) {
    assert.strictEqual(typeof ip, 'string', 'resolveIpv4 returns a string');
    assert.ok(zcio.isIpv4(ip), 'resolved localhost is a valid IPv4 literal');
  }
  const a = zcio.dnsQueryA('localhost');
  assert.ok(Array.isArray(a), 'dnsQueryA returns an array');
  for (const rec of a) assert.strictEqual(typeof rec, 'string', 'A record is a string');
  const local = zcio.localIpv4();
  if (local !== null) assert.ok(zcio.isIpv4(local), 'localIpv4 is a valid IPv4 literal');
  assert.strictEqual(zcio.resolveIpv4('8.8.8.8'), '8.8.8.8', 'IPv4 literal resolves to itself');
});

/* zcio's HTTP client is synchronous and blocks the event loop, so the test
 * server runs in a separate process (http_server.js prints "PORT <n>"). */
function startHttpServer() {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(__dirname, 'http_server.js')], {
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    let buf = '';
    const onData = (d) => {
      buf += d.toString();
      const m = buf.match(/PORT (\d+)/);
      if (m) { child.stdout.off('data', onData); resolve({ child, port: parseInt(m[1], 10) }); }
    };
    child.stdout.on('data', onData);
    child.on('error', reject);
    setTimeout(() => reject(new Error('http server did not start')), 5000).unref();
  });
}

test('http_get_post_loopback', async () => {
  const { child, port: hport } = await startHttpServer();
  try {
    const url = `http://127.0.0.1:${hport}/`;
    const r = zcio.httpGet(url);
    assert.strictEqual(r.status, 200, 'httpGet status 200');
    // body is now a Buffer (binary-safe); compare as text via toString()
    assert.ok(Buffer.isBuffer(r.body), 'httpGet body is a Buffer');
    assert.strictEqual(r.body.toString(), 'hello from node http', 'httpGet body matches');

    const pr = zcio.httpPost(url, Buffer.from('payload123'));
    assert.strictEqual(pr.status, 200, 'httpPost status 200');
    assert.strictEqual(pr.body.toString(), 'posted:payload123', 'httpPost echoes body');
  } finally {
    child.kill();
  }
});

test('http_verbs', async () => {
  const { child, port: hport } = await startHttpServer();
  try {
    const url = `http://127.0.0.1:${hport}/`;
    const del = zcio.httpDelete(url);
    assert.strictEqual(del.status, 200, 'httpDelete status 200');
    assert.strictEqual(del.body.toString(), 'deleted', 'httpDelete body');

    const put = zcio.httpPut(url, Buffer.from('putbody'));
    assert.strictEqual(put.status, 200, 'httpPut status 200');
    assert.strictEqual(put.body.toString(), 'put:putbody', 'httpPut echoes body');

    // httpRequest with a custom header (object form) the server echoes back
    const req = zcio.httpRequest('GET', url, { 'X-Echo': 'hi-there' });
    assert.strictEqual(req.status, 200, 'httpRequest status 200');
    assert.strictEqual(req.body.toString(), 'echo:hi-there', 'httpRequest passes headers');
  } finally {
    child.kill();
  }
});

test('http_bad_host', () => {
  // .invalid is reserved to never resolve (RFC 6761); must not crash.
  const r = zcio.httpGet('http://nonexistent.host.invalid:1/');
  assert.strictEqual(r.status, 0, 'bad host returns status 0 without crashing');
});

/* ---- run ---------------------------------------------------------------- */
(async () => {
  console.log('zcio version:', zcio.version());
  let pass = 0, fail = 0, skipped = 0;
  for (const t of tests) {
    try {
      await t.fn();
      pass++;
      console.log(`[ ok ] ${t.name}`);
    } catch (e) {
      if (e instanceof Skip) {
        skipped++;
        console.log(`[skip] ${t.name}: ${e.message}`);
      } else {
        fail++;
        console.log(`[FAIL] ${t.name}: ${e && e.stack ? e.stack : e}`);
      }
    }
  }
  let line = `\n${pass}/${tests.length} tests passed`;
  if (skipped) line += `, ${skipped} skipped`;
  if (fail) line += `, ${fail} failed`;
  console.log(line);
  process.exit(fail ? 1 : 0);
})();
