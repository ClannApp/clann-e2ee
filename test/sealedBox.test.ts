import { test } from 'node:test';
import assert from 'node:assert/strict';

import { seal, sealOpen, SEALED_BOX_OVERHEAD } from '../src/sealedBox';
import { makeDevice } from './helpers';

const alice = makeDevice('D-alice', 'U-alice', 0x11);
const mallory = makeDevice('D-mallory', 'U-mallory', 0x22);
const groupKey = new Uint8Array(32).fill(0xab);

test('round-trips to the intended recipient', () => {
  const sealed = seal(groupKey, alice.publicKey, new Uint8Array(32).fill(1));
  assert.deepEqual(sealOpen(sealed, alice.publicKey, alice.secretKey), groupKey);
});

test('overhead is the ephemeral public key plus a Poly1305 tag', () => {
  const sealed = seal(groupKey, alice.publicKey, new Uint8Array(32).fill(1));
  assert.equal(sealed.length, groupKey.length + SEALED_BOX_OVERHEAD);
});

test('another key cannot open it', () => {
  const sealed = seal(groupKey, alice.publicKey, new Uint8Array(32).fill(1));
  assert.throws(() => sealOpen(sealed, mallory.publicKey, mallory.secretKey), /failed to open/);
});

test('tampering with the ciphertext is detected', () => {
  const sealed = seal(groupKey, alice.publicKey, new Uint8Array(32).fill(1));
  sealed[sealed.length - 1] ^= 0x01;
  assert.throws(() => sealOpen(sealed, alice.publicKey, alice.secretKey), /failed to open/);
});

test('substituting the ephemeral public key is detected', () => {
  // The ephemeral key is inside the nonce derivation, so it is bound to the
  // ciphertext even though it travels in the clear.
  const sealed = seal(groupKey, alice.publicKey, new Uint8Array(32).fill(1));
  sealed[0] ^= 0x01;
  assert.throws(() => sealOpen(sealed, alice.publicKey, alice.secretKey), /failed to open/);
});

test('a fresh ephemeral seed produces a different sealed box for the same input', () => {
  // The seal is anonymous and randomised: two seals of the same key to the
  // same recipient must not be linkable by a server watching the blobs.
  const a = seal(groupKey, alice.publicKey, new Uint8Array(32).fill(1));
  const b = seal(groupKey, alice.publicKey, new Uint8Array(32).fill(2));
  assert.notDeepEqual(a, b);
  assert.deepEqual(sealOpen(a, alice.publicKey, alice.secretKey), sealOpen(b, alice.publicKey, alice.secretKey));
});

test('rejects malformed inputs rather than producing unusable output', () => {
  assert.throws(() => seal(groupKey, new Uint8Array(31), new Uint8Array(32)), /32 bytes/);
  assert.throws(() => seal(groupKey, alice.publicKey, new Uint8Array(16)), /32 bytes/);
  assert.throws(() => sealOpen(new Uint8Array(8), alice.publicKey, alice.secretKey), /too short/);
});
