/**
 * CLN1 — the encrypted file envelope. Normative spec: PROTOCOL.md §4.
 *
 * Layout: a 32-byte header, then AES-256-GCM chunks in an OAE2 STREAM
 * construction:
 *   nonce = nonce_prefix(8) || u32BE(counter | lastFlag<<31)
 *   aad   = the full 32-byte header
 *
 * Two properties are worth naming because they are what the chunking buys:
 * using the header as AAD binds every chunk to the file it belongs to (so
 * chunks cannot be moved between files, and the key epoch cannot be edited),
 * and putting the last-chunk flag in the nonce means a truncated file fails to
 * authenticate rather than decrypting to a shorter, plausible-looking one.
 *
 * AES-GCM rather than XChaCha20-Poly1305 for one reason: it is the only AEAD
 * `crypto.subtle` offers, so a browser can decrypt these files with no
 * dependencies. Everything else about the format is cipher-agnostic.
 *
 * This module is pure `Uint8Array` in, `Uint8Array` out — no platform imports,
 * no ambient randomness. It is pinned byte-for-byte against the shared test
 * vectors in `test/vectors.json`, which a Go implementation generates and this
 * implementation must reproduce exactly.
 */

import { gcm } from '@noble/ciphers/aes.js';

export const CLN1_HEADER_SIZE = 32;
export const CLN1_DEFAULT_CHUNK_SIZE = 1 << 20; // 1 MiB
export const CLN1_VERSION = 1;
export const CLN1_ALG_AES_GCM_STREAM = 1;
export const CLN1_MEDIA_JPEG = 1;
export const CLN1_MEDIA_MP4 = 2;

const GCM_OVERHEAD = 16;
const LAST_CHUNK_FLAG = 0x80000000;
const MAGIC = new Uint8Array([0x43, 0x4c, 0x4e, 0x31]); // "CLN1"

export interface Cln1Header {
  version: number;
  alg: number;
  media: number;
  chunkSize: number;
  keyEpoch: number;
  noncePrefix: Uint8Array; // 8 bytes
  fileId: Uint8Array; // 8 bytes
}

export function encodeHeader(h: Cln1Header): Uint8Array {
  if (h.noncePrefix.length !== 8 || h.fileId.length !== 8) {
    throw new Error('cln1: noncePrefix and fileId must be 8 bytes');
  }
  const out = new Uint8Array(CLN1_HEADER_SIZE);
  const dv = new DataView(out.buffer);
  out.set(MAGIC, 0);
  out[4] = h.version;
  out[5] = h.alg;
  out[6] = h.media;
  out[7] = 0; // reserved
  dv.setUint32(8, h.chunkSize, false);
  dv.setUint32(12, h.keyEpoch, false);
  out.set(h.noncePrefix, 16);
  out.set(h.fileId, 24);
  return out;
}

export function parseHeader(b: Uint8Array): Cln1Header {
  if (b.length < CLN1_HEADER_SIZE) {
    throw new Error(`cln1: header needs ${CLN1_HEADER_SIZE} bytes, got ${b.length}`);
  }
  for (let i = 0; i < 4; i++) {
    if (b[i] !== MAGIC[i]) throw new Error('cln1: bad magic');
  }
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const h: Cln1Header = {
    version: b[4],
    alg: b[5],
    media: b[6],
    chunkSize: dv.getUint32(8, false),
    keyEpoch: dv.getUint32(12, false),
    noncePrefix: b.slice(16, 24),
    fileId: b.slice(24, 32),
  };
  if (h.version !== CLN1_VERSION) throw new Error(`cln1: unsupported version ${h.version}`);
  if (h.alg !== CLN1_ALG_AES_GCM_STREAM) throw new Error(`cln1: unsupported alg ${h.alg}`);
  if (h.media !== CLN1_MEDIA_JPEG && h.media !== CLN1_MEDIA_MP4) {
    throw new Error(`cln1: unsupported media ${h.media}`);
  }
  if (h.chunkSize === 0 || h.chunkSize > 64 * (1 << 20)) {
    throw new Error(`cln1: implausible chunk size ${h.chunkSize}`);
  }
  if (h.keyEpoch === 0) throw new Error('cln1: key epoch must be >= 1');
  return h;
}

function chunkNonce(prefix: Uint8Array, counter: number, last: boolean): Uint8Array {
  const nonce = new Uint8Array(12);
  nonce.set(prefix, 0);
  // >>> 0 keeps the value an unsigned 32-bit int after setting the flag bit.
  const c = last ? (counter | LAST_CHUNK_FLAG) >>> 0 : counter >>> 0;
  new DataView(nonce.buffer).setUint32(8, c, false);
  return nonce;
}

/** Bytes AES-GCM adds per chunk (the auth tag). Exported for streaming callers. */
export const CLN1_GCM_OVERHEAD = GCM_OVERHEAD;

/**
 * Seal one plaintext chunk. `index`/`last` drive the counter nonce;
 * `headerBytes` is the AAD binding every chunk to the file header. This is
 * the single per-chunk primitive shared by the whole-file and streaming
 * paths, so both produce byte-identical CLN1 output (vector-tested).
 */
export function sealChunk(
  dek: Uint8Array,
  headerBytes: Uint8Array,
  noncePrefix: Uint8Array,
  index: number,
  last: boolean,
  plain: Uint8Array,
): Uint8Array {
  return gcm(dek, chunkNonce(noncePrefix, index, last), headerBytes).encrypt(plain);
}

/** Open one sealed chunk. Throws on authentication failure. */
export function openChunk(
  dek: Uint8Array,
  headerBytes: Uint8Array,
  noncePrefix: Uint8Array,
  index: number,
  last: boolean,
  sealed: Uint8Array,
): Uint8Array {
  try {
    return gcm(dek, chunkNonce(noncePrefix, index, last), headerBytes).decrypt(sealed);
  } catch {
    throw new Error(`cln1: chunk ${index} failed authentication`);
  }
}

/**
 * Seal plaintext into a full CLN1 file under a caller-supplied header.
 * Callers must draw noncePrefix/fileId fresh from a CSPRNG per file (see
 * makeHeader in this module).
 */
export function encryptWithHeader(
  dek: Uint8Array,
  header: Cln1Header,
  plaintext: Uint8Array,
): Uint8Array {
  if (dek.length !== 32) throw new Error(`cln1: key must be 32 bytes, got ${dek.length}`);
  const headerBytes = encodeHeader(header);
  parseHeader(headerBytes); // validate field ranges

  const chunkSize = header.chunkSize;
  // At least one (possibly empty) chunk so the file always authenticates.
  const nChunks = Math.max(1, Math.ceil(plaintext.length / chunkSize));
  if (nChunks > LAST_CHUNK_FLAG) throw new Error('cln1: plaintext exceeds counter space');

  const out = new Uint8Array(CLN1_HEADER_SIZE + plaintext.length + nChunks * GCM_OVERHEAD);
  out.set(headerBytes, 0);
  let offset = CLN1_HEADER_SIZE;
  for (let i = 0; i < nChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, plaintext.length);
    const last = i === nChunks - 1;
    const sealed = sealChunk(dek, headerBytes, header.noncePrefix, i, last, plaintext.subarray(start, end));
    out.set(sealed, offset);
    offset += sealed.length;
  }
  return out;
}

/** Open a full CLN1 file and return the plaintext. */
export function decrypt(dek: Uint8Array, file: Uint8Array): Uint8Array {
  if (dek.length !== 32) throw new Error(`cln1: key must be 32 bytes, got ${dek.length}`);
  const header = parseHeader(file);
  const headerBytes = file.subarray(0, CLN1_HEADER_SIZE);
  const body = file.subarray(CLN1_HEADER_SIZE);
  const sealedChunk = header.chunkSize + GCM_OVERHEAD;

  if (body.length < GCM_OVERHEAD) throw new Error('cln1: body too short');
  const nChunks = Math.ceil(body.length / sealedChunk);

  const out = new Uint8Array(body.length - nChunks * GCM_OVERHEAD);
  let outOffset = 0;
  for (let i = 0; i < nChunks; i++) {
    const start = i * sealedChunk;
    const last = i === nChunks - 1;
    const end = last ? body.length : start + sealedChunk;
    if (!last && end > body.length) throw new Error('cln1: truncated interior chunk');
    if (end - start < GCM_OVERHEAD) throw new Error(`cln1: chunk ${i} shorter than auth tag`);
    const plain = openChunk(dek, headerBytes, header.noncePrefix, i, last, body.subarray(start, end));
    out.set(plain, outOffset);
    outOffset += plain.length;
  }
  return out;
}

/**
 * Incremental CLN1 decryptor for network-streamed ciphertext: feed bytes in
 * whatever sizes they arrive, get plaintext chunks out as soon as they can be
 * authenticated. Chunks carry no length prefix — every non-last sealed chunk
 * is exactly chunkSize+16 bytes — and last-ness is bound into the nonce, so a
 * buffered full-size block is only decryptable as non-last once at least one
 * byte exists beyond it (hence the strictly-greater drain condition). The
 * final chunk can therefore only be opened at EOF, via finish().
 */
export class Cln1StreamDecryptor {
  private readonly dek: Uint8Array;
  private segments: Uint8Array[] = [];
  private buffered = 0;
  private headerBytes: Uint8Array | null = null;
  private header: Cln1Header | null = null;
  private counter = 0;
  private finished = false;

  constructor(dek: Uint8Array) {
    if (dek.length !== 32) throw new Error(`cln1: key must be 32 bytes, got ${dek.length}`);
    this.dek = dek;
  }

  /** Consume exactly `n` buffered bytes (caller guarantees n <= buffered). */
  private take(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let offset = 0;
    while (offset < n) {
      const seg = this.segments[0];
      const want = n - offset;
      if (seg.length <= want) {
        out.set(seg, offset);
        offset += seg.length;
        this.segments.shift();
      } else {
        out.set(seg.subarray(0, want), offset);
        this.segments[0] = seg.subarray(want);
        offset += want;
      }
    }
    this.buffered -= n;
    return out;
  }

  /** Feed ciphertext bytes; returns plaintext for every chunk now provably non-last. */
  push(bytes: Uint8Array): Uint8Array[] {
    if (this.finished) throw new Error('cln1: push after finish');
    if (bytes.length > 0) {
      this.segments.push(bytes);
      this.buffered += bytes.length;
    }
    if (!this.header) {
      if (this.buffered < CLN1_HEADER_SIZE) return [];
      this.headerBytes = this.take(CLN1_HEADER_SIZE);
      this.header = parseHeader(this.headerBytes);
    }
    const sealedChunk = this.header.chunkSize + GCM_OVERHEAD;
    const out: Uint8Array[] = [];
    while (this.buffered > sealedChunk) {
      out.push(
        openChunk(
          this.dek,
          this.headerBytes!,
          this.header.noncePrefix,
          this.counter++,
          false,
          this.take(sealedChunk),
        ),
      );
    }
    return out;
  }

  /** Signal EOF; decrypts and returns the final chunk. Throws on truncation. */
  finish(): Uint8Array {
    if (this.finished) throw new Error('cln1: finish called twice');
    this.finished = true;
    if (!this.header) throw new Error('cln1: stream truncated before header');
    if (this.buffered < GCM_OVERHEAD) {
      throw new Error('cln1: stream truncated (final chunk shorter than auth tag)');
    }
    return openChunk(
      this.dek,
      this.headerBytes!,
      this.header.noncePrefix,
      this.counter,
      true,
      this.take(this.buffered),
    );
  }
}

/**
 * Build a fresh header for encryption. `random16` must be 16 CSPRNG bytes:
 * 8 become the nonce prefix and 8 the file id.
 *
 * The nonce prefix MUST be fresh per file. Every file starts its chunk counter
 * at zero, so two files sharing both a DEK and a nonce prefix would reuse
 * (key, nonce) pairs — the one failure mode that breaks AES-GCM outright. A
 * per-photo DEK already makes this hard to hit; drawing the prefix per file
 * makes it impossible.
 */
export function makeHeader(
  media: number,
  keyEpoch: number,
  random16: Uint8Array,
  chunkSize: number = CLN1_DEFAULT_CHUNK_SIZE,
): Cln1Header {
  if (random16.length !== 16) throw new Error('cln1: makeHeader needs 16 random bytes');
  return {
    version: CLN1_VERSION,
    alg: CLN1_ALG_AES_GCM_STREAM,
    media,
    chunkSize,
    keyEpoch,
    noncePrefix: random16.slice(0, 8),
    fileId: random16.slice(8, 16),
  };
}
