'use strict';

const assert = require('assert');
const zcio = require('..');

// version()
const v = zcio.version();
console.log('zcio version:', v);
assert.strictEqual(typeof v, 'string');
assert.ok(v.length > 0, 'version string should be non-empty');

// isIpv4()
assert.strictEqual(zcio.isIpv4('127.0.0.1'), true, '127.0.0.1 is IPv4');
assert.strictEqual(zcio.isIpv4('not.an.ip'), false, 'garbage is not IPv4');
assert.strictEqual(zcio.isIpv4('::1'), false, 'IPv6 is not IPv4');

// Ring write/read roundtrip
const ring = new zcio.Ring(1024);
const payload = Buffer.from('hello zcio ring');
const wrote = ring.write(payload);
assert.strictEqual(wrote, payload.length, 'wrote all bytes');
assert.strictEqual(ring.availableRead(), payload.length, 'available == written');

const got = ring.read(payload.length);
assert.ok(Buffer.isBuffer(got), 'read returns a Buffer');
assert.strictEqual(got.toString(), payload.toString(), 'roundtrip matches');
ring.free();

// BufferSerial roundtrip (scalar + string)
const s = new zcio.BufferSerial(256);
s.writeI32(0x1234abcd | 0);
s.writeStr('serialized');
s.setReadPos(0);
assert.strictEqual(s.readI32(), 0x1234abcd | 0, 'i32 roundtrip');
assert.strictEqual(s.readStr(), 'serialized', 'string roundtrip');

console.log('All tests passed.');
