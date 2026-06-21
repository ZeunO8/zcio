'use strict';

const native = require('./build/Release/zcio_native.node');

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

  /** Advisory release; the native ring is freed on GC. */
  free() {
    if (this._handle) {
      native.ringFree(this._handle);
      this._handle = null;
    }
  }
}

/**
 * Thin wrapper around a buffer-mode serializer.
 */
class BufferSerial {
  /**
   * @param {number} size backing buffer size in bytes
   * @param {boolean} [bitStream=false]
   */
  constructor(size, bitStream = false) {
    this._handle = native.bufferSerial(size, bitStream);
  }

  writeI32(v) { return native.serialWriteI32(this._handle, v); }
  readI32() { return native.serialReadI32(this._handle); }
  writeStr(s) { return native.serialWriteStr(this._handle, s); }
  readStr() { return native.serialReadStr(this._handle); }
  setReadPos(index) { return native.serialSetReadPos(this._handle, index); }
}

module.exports = {
  /** @returns {string} zcio semantic version */
  version: () => native.version(),

  /** @param {string} s @returns {boolean} */
  isIpv4: (s) => native.isIpv4(s),

  /**
   * Synchronous HTTP GET.
   * @param {string} url
   * @returns {{status:number, body:string, headersJson:string, statusText:string, version:string, protocol:string}}
   */
  httpGet: (url) => native.httpGet(url),

  Ring,
  BufferSerial,

  /** Direct access to the raw native binding, for advanced use. */
  native,
};
