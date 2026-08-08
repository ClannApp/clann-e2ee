/**
 * Test fixtures. Everything here is deterministic on purpose: a crypto test
 * that passes only sometimes is worse than no test.
 */

import { x25519, ed25519 } from '@noble/curves/ed25519.js';

import { bytesToBase64 } from '../src/bytes';
import { signSelfBinding } from '../src/identity';
import type { RandomSource } from '../src/random';
import type { DeviceRecord } from '../src/types';

/**
 * A counter-based stand-in for a CSPRNG. Reproducible, and — because every
 * draw differs — it still catches code that reuses a nonce it should not.
 */
export function seededRandom(start = 1): RandomSource {
  let n = start;
  return (len: number) => {
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) out[i] = (n * 31 + i * 7 + (n >> 8)) & 0xff;
    n = (n + 1) & 0xffff;
    return out;
  };
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export interface TestDevice {
  record: DeviceRecord;
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  edSecretKey: Uint8Array;
  publicKeyBase64: string;
  edPublicKeyBase64: string;
}

/**
 * A device with real keys and a real self-signature.
 *
 * `seedByte` fills both 32-byte seeds, so devices are distinguishable at a
 * glance in failure output.
 */
export function makeDevice(id: string, userId: string, seedByte: number): TestDevice {
  const secretKey = new Uint8Array(32).fill(seedByte);
  const edSecretKey = new Uint8Array(32).fill(seedByte ^ 0xff);
  const publicKey = x25519.getPublicKey(secretKey);
  const edPublicKey = ed25519.getPublicKey(edSecretKey);
  const publicKeyBase64 = bytesToBase64(publicKey);
  const edPublicKeyBase64 = bytesToBase64(edPublicKey);
  return {
    secretKey,
    publicKey,
    edSecretKey,
    publicKeyBase64,
    edPublicKeyBase64,
    record: {
      id,
      user_id: userId,
      x25519_public_key: publicKeyBase64,
      ed25519_public_key: edPublicKeyBase64,
      self_signature: signSelfBinding(edSecretKey, userId, publicKeyBase64),
    },
  };
}

export const pubKeys = (d: TestDevice) => ({
  publicKeyBase64: d.publicKeyBase64,
  edPublicKeyBase64: d.edPublicKeyBase64,
});

export const keypair = (d: TestDevice) => ({
  publicKey: d.publicKey,
  secretKey: d.secretKey,
});
