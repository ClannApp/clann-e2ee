import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  DEK_WRAP_NONCE_SIZE,
  WRAPPED_DEK_SIZE,
  generateDek,
  isWellFormedEncMeta,
  unwrapDek,
  wrapDek,
} from '../src/keyWrap';
import { base64ToBytes } from '../src/bytes';
import { seededRandom } from './helpers';

const groupKey = new Uint8Array(32).fill(0x5a);
const otherGroupKey = new Uint8Array(32).fill(0x5b);

test('wraps and unwraps a data key', () => {
  const dek = generateDek(seededRandom());
  const meta = wrapDek(groupKey, dek, 3, seededRandom());
  assert.equal(meta.key_epoch, 3);
  assert.deepEqual(unwrapDek(groupKey, meta), dek);
});

test('the wrong group key cannot unwrap', () => {
  const meta = wrapDek(groupKey, generateDek(seededRandom()), 1, seededRandom());
  assert.throws(() => unwrapDek(otherGroupKey, meta));
});

test('a tampered wrap is rejected, not silently mis-decrypted', () => {
  const meta = wrapDek(groupKey, generateDek(seededRandom()), 1, seededRandom());
  const bytes = base64ToBytes(meta.wrapped_dek);
  bytes[0] ^= 0x01;
  assert.throws(() =>
    unwrapDek(groupKey, { ...meta, wrapped_dek: Buffer.from(bytes).toString('base64') }),
  );
});

test('each wrap draws a fresh nonce', () => {
  // Group keys are long-lived and wrap many DEKs; a repeated nonce here leaks
  // data keys across items. This is the library's most critical random draw.
  const random = seededRandom();
  const dek = generateDek(random);
  const a = wrapDek(groupKey, dek, 1, random);
  const b = wrapDek(groupKey, dek, 1, random);
  assert.notEqual(a.dek_wrap_nonce, b.dek_wrap_nonce);
  assert.notEqual(a.wrapped_dek, b.wrapped_dek);
});

test('rejects wrong-sized keys and invalid epochs', () => {
  const dek = generateDek(seededRandom());
  assert.throws(() => wrapDek(new Uint8Array(16), dek, 1, seededRandom()), /group key must be 32/);
  assert.throws(() => wrapDek(groupKey, new Uint8Array(16), 1, seededRandom()), /dek must be 32/);
  assert.throws(() => wrapDek(groupKey, dek, 0, seededRandom()), /epoch/);
});

test('structural validation accepts a real record and rejects malformed ones', () => {
  const meta = wrapDek(groupKey, generateDek(seededRandom()), 2, seededRandom());
  assert.equal(isWellFormedEncMeta(meta), true);
  assert.equal(base64ToBytes(meta.wrapped_dek).length, WRAPPED_DEK_SIZE);
  assert.equal(base64ToBytes(meta.dek_wrap_nonce).length, DEK_WRAP_NONCE_SIZE);

  assert.equal(isWellFormedEncMeta(null), false);
  assert.equal(isWellFormedEncMeta({ ...meta, v: 2 }), false);
  assert.equal(isWellFormedEncMeta({ ...meta, key_epoch: 0 }), false);
  assert.equal(isWellFormedEncMeta({ ...meta, wrapped_dek: 'AAAA' }), false);
});

test('structural validation is not a decryption check', () => {
  // Stated as a test because it is the easiest thing in this system to
  // over-claim: a server can confirm the shape and nothing more.
  const meta = wrapDek(groupKey, generateDek(seededRandom()), 1, seededRandom());
  const garbage = { ...meta, wrapped_dek: Buffer.alloc(WRAPPED_DEK_SIZE, 7).toString('base64') };
  assert.equal(isWellFormedEncMeta(garbage), true);
  assert.throws(() => unwrapDek(groupKey, garbage));
});
