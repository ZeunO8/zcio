'use strict';

const native = require('./build/Release/zcio_native.node');

/* -------------------------------------------------------------------------- */
/* Ring                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Thin OO wrapper around the ring handle functions. The underlying native ring
 * is reclaimed by GC via the external finalizer; `free()` is advisory.
 */
class Ring {
  /**
   * @param {number} capacity usable data capacity in bytes
   * @param {boolean} [nonBlocking=true]
   */
  constructor(capacity, nonBlocking = true) {
    this._handle = native.ringNew(capacity, nonBlocking);
  }

  /** @param {Buffer} buf @returns {number} bytes written (negative on error) */
  write(buf) {
    if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
    return native.ringWrite(this._handle, buf);
  }

  /** @param {number} length @returns {Buffer} up to `length` bytes */
  read(length) {
    return native.ringRead(this._handle, length);
  }

  /** @returns {number} bytes currently available to read */
  availableRead() {
    return native.ringAvailableRead(this._handle);
  }

  /**
   * Adapt this ring as a generic Stream (borrows the ring). The ring must
   * outlive the returned stream.
   * @returns {Stream}
   */
  asStream() {
    return new Stream(native.ringAsStream(this._handle));
  }

  /** Advisory release; the native ring is freed on GC. */
  free() {
    if (this._handle) {
      native.ringFree(this._handle);
      this._handle = null;
    }
  }
}

/* -------------------------------------------------------------------------- */
/* Stream                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Wrapper around a native zcio_stream handle (borrowed or owned). Used for
 * TCP/UDP/multicast endpoints, ring adapters and memory streams.
 */
class Stream {
  /** @param {*} handle native external stream handle */
  constructor(handle) {
    this._handle = handle;
  }

  /** @param {Buffer} buf @returns {number} bytes written (negative on error) */
  write(buf) {
    if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
    return native.streamWrite(this._handle, buf);
  }

  /** @param {number} n @returns {Buffer} up to `n` bytes (one read) */
  read(n) {
    return native.streamRead(this._handle, n);
  }

  /** @param {number} n @returns {Buffer} exactly `n` bytes unless EOF/error */
  readFull(n) {
    return native.streamReadFull(this._handle, n);
  }

  /**
   * Pump bytes from `src` into this stream.
   * @param {Stream} src
   * @param {number} [limit] max bytes (default: until EOF)
   * @returns {number} bytes copied (negative on error)
   */
  copyFrom(src, limit) {
    return native.streamCopy(this._handle, src._handle, limit);
  }
}

/**
 * A memory-backed stream over a fresh buffer. `buffer` is a Node Buffer view of
 * the same native memory the stream reads/writes.
 */
class MemoryStream extends Stream {
  /** @param {number} size backing buffer size in bytes */
  constructor(size) {
    const { handle, buffer } = native.memoryStream(size);
    super(handle);
    /** @type {Buffer} live view of the backing memory */
    this.buffer = buffer;
  }
}

/* -------------------------------------------------------------------------- */
/* Serial                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Mixin of scalar/bit/bytes accessors shared by buffer- and count-mode serials.
 */
class SerialBase {
  writeI8(v) { return native.serialWriteI8(this._handle, v); }
  readI8() { return native.serialReadI8(this._handle); }
  writeU8(v) { return native.serialWriteU8(this._handle, v); }
  readU8() { return native.serialReadU8(this._handle); }
  writeI16(v) { return native.serialWriteI16(this._handle, v); }
  readI16() { return native.serialReadI16(this._handle); }
  writeU16(v) { return native.serialWriteU16(this._handle, v); }
  readU16() { return native.serialReadU16(this._handle); }
  writeI32(v) { return native.serialWriteI32(this._handle, v); }
  readI32() { return native.serialReadI32(this._handle); }
  writeU32(v) { return native.serialWriteU32(this._handle, v); }
  readU32() { return native.serialReadU32(this._handle); }
  /** @param {bigint} v */
  writeI64(v) { return native.serialWriteI64(this._handle, BigInt(v)); }
  /** @returns {bigint} */
  readI64() { return native.serialReadI64(this._handle); }
  /** @param {bigint} v */
  writeU64(v) { return native.serialWriteU64(this._handle, BigInt(v)); }
  /** @returns {bigint} */
  readU64() { return native.serialReadU64(this._handle); }
  writeF32(v) { return native.serialWriteF32(this._handle, v); }
  readF32() { return native.serialReadF32(this._handle); }
  writeF64(v) { return native.serialWriteF64(this._handle, v); }
  readF64() { return native.serialReadF64(this._handle); }
  writeBit(b) { return native.serialWriteBit(this._handle, !!b); }
  readBit() { return native.serialReadBit(this._handle); }
  /** @param {Buffer} buf */
  writeBytes(buf) {
    if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
    return native.serialWriteBytes(this._handle, buf);
  }
  /** @param {number} n @returns {Buffer} */
  readBytes(n) { return native.serialReadBytes(this._handle, n); }
  writeStr(s) { return native.serialWriteStr(this._handle, s); }
  readStr() { return native.serialReadStr(this._handle); }
  setReadPos(index) { return native.serialSetReadPos(this._handle, index); }
  setWritePos(index) { return native.serialSetWritePos(this._handle, index); }
  writePos() { return native.serialWritePos(this._handle); }
  readPos() { return native.serialReadPos(this._handle); }
  writeLen() { return native.serialWriteLen(this._handle); }
  readLen() { return native.serialReadLen(this._handle); }
}

/** Buffer-mode serializer over a fresh fixed-size backing buffer. */
class BufferSerial extends SerialBase {
  /**
   * @param {number} size backing buffer size in bytes
   * @param {boolean} [bitStream=false]
   */
  constructor(size, bitStream = false) {
    super();
    this._handle = native.bufferSerial(size, bitStream);
  }
}

/**
 * Count-mode serializer: writes are tallied (not stored), so writeLen() reports
 * how many bytes a payload would occupy. Use for sizing passes.
 */
class CountSerial extends SerialBase {
  constructor() {
    super();
    this._handle = native.serialCount();
  }
}

/* -------------------------------------------------------------------------- */
/* TCP                                                                        */
/* -------------------------------------------------------------------------- */

/** TCP client connection. Returns null from connect() failure via factory. */
class TcpClient {
  /**
   * @param {string} host
   * @param {number} port
   * @returns {TcpClient|null}
   */
  static connect(host, port) {
    const h = native.tcpClientConnect(host, port);
    if (!h) return null;
    const c = Object.create(TcpClient.prototype);
    c._handle = h;
    return c;
  }

  /** @returns {Stream} borrowed I/O stream */
  stream() {
    if (!this._stream) this._stream = new Stream(native.tcpClientStream(this._handle));
    return this._stream;
  }

  /** Advisory; native client freed on GC. */
  free() {
    if (this._handle) { native.tcpClientFree(this._handle); this._handle = null; this._stream = null; }
  }
}

/** TCP server (accept loop). */
class TcpServer {
  /**
   * @param {number} port
   * @returns {TcpServer|null}
   */
  static listen(port) {
    const h = native.tcpServerListen(port);
    if (!h) return null;
    const s = Object.create(TcpServer.prototype);
    s._handle = h;
    return s;
  }

  /**
   * Accept one client.
   * @param {number} [timeoutMs=0]
   * @returns {{id:number, stream:Stream, connHandle:*}|null}
   */
  accept(timeoutMs = 0) {
    const r = native.tcpServerAccept(this._handle, timeoutMs);
    if (!r) return null;
    return { id: r.id, connHandle: r.connHandle, stream: new Stream(native.tcpConnStream(r.connHandle)) };
  }

  /** @param {number} id @returns {number} */
  closeClient(id) {
    return native.tcpServerCloseClient(this._handle, id);
  }

  /** Advisory; native server freed on GC. */
  free() {
    if (this._handle) { native.tcpServerFree(this._handle); this._handle = null; }
  }
}

/* -------------------------------------------------------------------------- */
/* UDP                                                                        */
/* -------------------------------------------------------------------------- */

/** UDP client (connected to a host:port). */
class UdpClient {
  /**
   * @param {string} host
   * @param {number} port
   * @returns {UdpClient|null}
   */
  static open(host, port) {
    const h = native.udpClientOpen(host, port);
    if (!h) return null;
    const c = Object.create(UdpClient.prototype);
    c._handle = h;
    return c;
  }

  /** @returns {Stream} borrowed datagram stream */
  stream() {
    if (!this._stream) this._stream = new Stream(native.udpClientStream(this._handle));
    return this._stream;
  }

  free() {
    if (this._handle) { native.udpClientFree(this._handle); this._handle = null; this._stream = null; }
  }
}

/** UDP server bound to a port. */
class UdpServer {
  /**
   * @param {number} port
   * @returns {UdpServer|null}
   */
  static bind(port) {
    const h = native.udpServerBind(port);
    if (!h) return null;
    const s = Object.create(UdpServer.prototype);
    s._handle = h;
    return s;
  }

  /**
   * Receive one datagram.
   * @param {boolean} [nonBlock=false]
   * @param {number} [timeoutUs=0]
   * @returns {Stream|null} borrowed per-peer packet stream
   */
  receive(nonBlock = false, timeoutUs = 0) {
    const pkt = native.udpServerReceive(this._handle, nonBlock, timeoutUs);
    if (!pkt) return null;
    return new Stream(native.udpPacketStream(pkt));
  }

  free() {
    if (this._handle) { native.udpServerFree(this._handle); this._handle = null; }
  }
}

/* -------------------------------------------------------------------------- */
/* Multicast                                                                  */
/* -------------------------------------------------------------------------- */

/** UDP multicast sender. */
class McastSender {
  /**
   * @param {string} group
   * @param {number} port
   * @returns {McastSender|null}
   */
  static open(group, port) {
    const h = native.mcastSenderOpen(group, port);
    if (!h) return null;
    const s = Object.create(McastSender.prototype);
    s._handle = h;
    return s;
  }

  /** @returns {Stream} */
  stream() {
    if (!this._stream) this._stream = new Stream(native.mcastSenderStream(this._handle));
    return this._stream;
  }

  free() {
    if (this._handle) { native.mcastSenderFree(this._handle); this._handle = null; this._stream = null; }
  }
}

/** UDP multicast receiver. */
class McastReceiver {
  /**
   * @param {string} group
   * @param {number} port
   * @returns {McastReceiver|null}
   */
  static open(group, port) {
    const h = native.mcastReceiverOpen(group, port);
    if (!h) return null;
    const r = Object.create(McastReceiver.prototype);
    r._handle = h;
    return r;
  }

  /** @returns {Stream} */
  stream() {
    if (!this._stream) this._stream = new Stream(native.mcastReceiverStream(this._handle));
    return this._stream;
  }

  free() {
    if (this._handle) { native.mcastReceiverFree(this._handle); this._handle = null; this._stream = null; }
  }
}

/* -------------------------------------------------------------------------- */
/* module exports                                                             */
/* -------------------------------------------------------------------------- */

module.exports = {
  /** @returns {string} zcio semantic version */
  version: () => native.version(),

  /** @param {string} s @returns {boolean} */
  isIpv4: (s) => native.isIpv4(s),

  /** @param {string} host @returns {string|null} resolved IPv4 literal */
  resolveIpv4: (host) => native.resolveIpv4(host),

  /** @param {string} host @returns {string[]} all A records */
  dnsQueryA: (host) => native.dnsQueryA(host),

  /** @returns {string|null} best-effort primary local IPv4 */
  localIpv4: () => native.localIpv4(),

  /**
   * Synchronous HTTP GET.
   * @param {string} url
   * @returns {{status:number, body:string, headersJson:string, statusText:string, version:string, protocol:string}}
   */
  httpGet: (url) => native.httpGet(url),

  /**
   * Synchronous HTTP POST.
   * @param {string} url
   * @param {Buffer} [body]
   */
  httpPost: (url, body) => native.httpPost(url, Buffer.isBuffer(body) ? body : Buffer.from(body || '')),

  Ring,
  Stream,
  MemoryStream,
  BufferSerial,
  CountSerial,
  TcpClient,
  TcpServer,
  UdpClient,
  UdpServer,
  McastSender,
  McastReceiver,

  /** Direct access to the raw native binding, for advanced use. */
  native,
};
