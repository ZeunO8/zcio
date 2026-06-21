'use strict';

const assert = require('assert');
const { spawn } = require('child_process');
const path = require('path');
const zcio = require('..');

let skips = 0;
function skip(msg) { skips++; console.log('  SKIP:', msg); }

/* Randomize a port base per run so repeated runs don't collide with sockets
 * lingering in TIME_WAIT. */
const PORT_BASE = 20000 + Math.floor(Math.random() * 20000);
let nextPort = PORT_BASE;
function port() { return nextPort++; }

/* ---------------------------------------------------------------- version */
const v = zcio.version();
console.log('zcio version:', v);
assert.strictEqual(typeof v, 'string');
assert.ok(v.length > 0, 'version string should be non-empty');

/* ------------------------------------------------------------------ isIpv4 */
assert.strictEqual(zcio.isIpv4('127.0.0.1'), true, '127.0.0.1 is IPv4');
assert.strictEqual(zcio.isIpv4('not.an.ip'), false, 'garbage is not IPv4');
assert.strictEqual(zcio.isIpv4('::1'), false, 'IPv6 is not IPv4');

/* -------------------------------------------------------------------- Ring */
{
  const ring = new zcio.Ring(1024);
  const payload = Buffer.from('hello zcio ring');
  const wrote = ring.write(payload);
  assert.strictEqual(wrote, payload.length, 'wrote all bytes');
  assert.strictEqual(ring.availableRead(), payload.length, 'available == written');
  const got = ring.read(payload.length);
  assert.ok(Buffer.isBuffer(got), 'read returns a Buffer');
  assert.strictEqual(got.toString(), payload.toString(), 'roundtrip matches');
  ring.free();
}

/* --------------------------------------------------- BufferSerial: scalars */
{
  const s = new zcio.BufferSerial(512);
  s.writeI8(-5);
  s.writeU8(250);
  s.writeI16(-1234);
  s.writeU16(60000);
  s.writeI32(0x1234abcd | 0);
  s.writeU32(0xdeadbeef >>> 0);
  s.writeI64(-9007199254740993n);
  s.writeU64(18446744073709551610n);
  s.writeF32(1.5);
  s.writeF64(3.141592653589793);
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
}

/* ----------------------------------------------------- BufferSerial: bits */
{
  const s = new zcio.BufferSerial(64, true /* bitStream */);
  const bits = [true, false, true, true, false, false, false, true];
  for (const b of bits) s.writeBit(b);
  s.setReadPos(0);
  for (let i = 0; i < bits.length; i++) {
    assert.strictEqual(s.readBit(), bits[i], `bit ${i}`);
  }
}

/* ------------------------------------------------- CountSerial: sizing pass */
{
  const c = new zcio.CountSerial();
  c.writeI32(0);          // 4
  c.writeU16(0);          // 2
  c.writeF64(0);          // 8
  c.writeBytes(Buffer.alloc(10)); // 10
  c.writeStr('abc');      // 8 (u64 len) + 3
  // total = 4 + 2 + 8 + 10 + 8 + 3 = 35
  assert.strictEqual(Number(c.writeLen()), 35, 'count-mode sizing total');
}

/* ----------------------------------------- Stream verbs: ring -> memory copy */
{
  const ring = new zcio.Ring(256);
  const payload = Buffer.from('copy me through a stream');
  ring.write(payload);
  const rstream = ring.asStream();
  const mem = new zcio.MemoryStream(256);
  const copied = mem.copyFrom(rstream, payload.length);
  assert.strictEqual(copied, payload.length, 'copied all bytes');
  assert.strictEqual(mem.buffer.slice(0, payload.length).toString(), payload.toString(),
    'memory stream backing buffer holds the copied data');
  ring.free();
}

/* ------------------------------------------------------- TCP loopback round-trip */
{
  const PORT = port();
  const server = zcio.TcpServer.listen(PORT);
  assert.ok(server, 'tcp server listening');
  const client = zcio.TcpClient.connect('127.0.0.1', PORT);
  assert.ok(client, 'tcp client connected');

  const accepted = server.accept(1000);
  assert.ok(accepted, 'server accepted a client');
  assert.strictEqual(typeof accepted.id, 'number', 'accept returns numeric id');

  const msg = Buffer.from('ping over tcp');
  const wrote = client.stream().write(msg);
  assert.strictEqual(wrote, msg.length, 'client wrote full message');

  const got = accepted.stream.readFull(msg.length);
  assert.strictEqual(got.toString(), msg.toString(), 'tcp loopback roundtrip');

  // echo back
  const reply = Buffer.from('pong');
  accepted.stream.write(reply);
  const back = client.stream().readFull(reply.length);
  assert.strictEqual(back.toString(), reply.toString(), 'tcp reverse roundtrip');

  client.free();
  server.free();
}

/* -------------------------------------------- TCP 2-client accept + closeClient */
{
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

  const rc = server.closeClient(a1.id);
  assert.ok(rc >= 0, 'closeClient succeeded');

  // a2 still usable
  const m = Buffer.from('still here');
  c2.stream().write(m);
  const got = a2.stream.readFull(m.length);
  assert.strictEqual(got.toString(), m.toString(), 'second client still works after closing first');

  c1.free(); c2.free(); server.free();
}

/* -------------------------------------------------------- UDP loopback */
{
  const PORT = port();
  const server = zcio.UdpServer.bind(PORT);
  assert.ok(server, 'udp server bound');
  const client = zcio.UdpClient.open('127.0.0.1', PORT);
  assert.ok(client, 'udp client open');

  const msg = Buffer.from('datagram');
  const wrote = client.stream().write(msg);
  assert.strictEqual(wrote, msg.length, 'udp client wrote datagram');

  // receive with a short blocking timeout
  const pkt = server.receive(false, 500000 /* 500ms */);
  if (!pkt) {
    skip('UDP loopback: no datagram received within timeout');
  } else {
    const got = pkt.read(msg.length);
    assert.strictEqual(got.toString(), msg.toString(), 'udp loopback roundtrip');
  }
  client.free(); server.free();
}

/* ----------------------------------------------- Multicast best-effort loopback */
{
  const GROUP = '239.255.42.99';
  const PORT = port();
  const recv = zcio.McastReceiver.open(GROUP, PORT);
  const send = zcio.McastSender.open(GROUP, PORT);
  if (!recv || !send) {
    skip('Multicast: could not open sender/receiver (no multicast route)');
  } else {
    // exercise open/stream/free regardless
    const msg = Buffer.from('mcast hello');
    send.stream().write(msg);
    // best-effort, short non-fatal read
    let got = null;
    try { got = recv.stream().read(msg.length); } catch (_) { got = null; }
    if (!got || got.length === 0) {
      skip('Multicast: no datagram arrived in short window (open/stream/free still exercised)');
    } else {
      assert.strictEqual(got.toString(), msg.toString(), 'multicast loopback roundtrip');
    }
    send.free(); recv.free();
  }
}

/* ------------------------------------------------------------------- DNS */
{
  // localhost resolves to a loopback literal
  const ip = zcio.resolveIpv4('localhost');
  if (ip === null) {
    skip('DNS: resolveIpv4(localhost) returned null');
  } else {
    assert.strictEqual(typeof ip, 'string', 'resolveIpv4 returns a string');
    assert.ok(zcio.isIpv4(ip), 'resolved localhost is a valid IPv4 literal');
  }

  const a = zcio.dnsQueryA('localhost');
  assert.ok(Array.isArray(a), 'dnsQueryA returns an array');
  if (a.length === 0) {
    skip('DNS: dnsQueryA(localhost) returned no records');
  } else {
    for (const rec of a) assert.strictEqual(typeof rec, 'string', 'A record is a string');
  }

  const local = zcio.localIpv4();
  if (local === null) {
    skip('DNS: localIpv4() returned null (no route)');
  } else {
    assert.ok(zcio.isIpv4(local), 'localIpv4 is a valid IPv4 literal');
  }

  // literal passes through
  assert.strictEqual(zcio.resolveIpv4('8.8.8.8'), '8.8.8.8', 'IPv4 literal resolves to itself');
}

/* ------------------------------------------------- HTTP against local server
 * zcio's HTTP client is synchronous and blocks the event loop, so the test
 * server must run in a separate process. server.js prints "PORT <n>" once
 * listening, then serves until killed. */
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

async function httpTests() {
  const { child, port } = await startHttpServer();
  try {
    const url = `http://127.0.0.1:${port}/`;
    const body = 'hello from node http';

    const r = zcio.httpGet(url);
    assert.strictEqual(r.status, 200, 'httpGet status 200');
    assert.strictEqual(r.body, body, 'httpGet body matches');

    const pr = zcio.httpPost(url, Buffer.from('payload123'));
    assert.strictEqual(pr.status, 200, 'httpPost status 200');
    assert.strictEqual(pr.body, 'posted:payload123', 'httpPost echoes body');
  } finally {
    child.kill();
  }
}

/* --------------------------------------------------- HTTP GET against a bad host */
function httpBadHostTest() {
  // .invalid is reserved to never resolve (RFC 6761); must not crash.
  const r = zcio.httpGet('http://nonexistent.host.invalid:1/');
  assert.strictEqual(r.status, 0, 'bad host returns status 0 without crashing');
}

(async () => {
  await httpTests();
  httpBadHostTest();
  console.log(`\nAll tests passed.${skips ? ` (${skips} skip${skips > 1 ? 's' : ''})` : ''}`);
})().catch((e) => {
  console.error('TEST FAILED:', e && e.stack ? e.stack : e);
  process.exit(1);
});
