import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  FIELD_NONCE_SIZE,
  FIELD_PAD_BLOCK,
  MAX_FIELD_BYTES,
  SEALED_FIELD_PREFIX,
  isSealedField,
  openField,
  parseSealedField,
  sealField,
} from '../src/sealedField';
import { base64ToBytes, bytesToBase64 } from '../src/bytes';
import { seededRandom } from './helpers';

const groupKey = new Uint8Array(32).fill(0x5a);
const otherGroupKey = new Uint8Array(32).fill(0x5b);
const ctx = { groupId: 'group-a', field: 'caption' };

test('seals and opens a caption', () => {
  const sealed = sealField(groupKey, 3, 'her first steps', ctx, seededRandom());
  assert.equal(sealed.startsWith(`${SEALED_FIELD_PREFIX}.3.`), true);
  assert.equal(openField(groupKey, sealed, ctx), 'her first steps');
});

test('survives a round trip through multi-byte text', () => {
  // Padding works in bytes and the length header is in bytes; a naive
  // implementation that counted characters would truncate emoji and accents.
  const text = 'Nollaig shona 🎄 — grá ó Máire';
  const sealed = sealField(groupKey, 1, text, ctx, seededRandom());
  assert.equal(openField(groupKey, sealed, ctx), text);
});

test('an empty field round-trips rather than collapsing to plaintext', () => {
  const sealed = sealField(groupKey, 1, '', ctx, seededRandom());
  assert.equal(isSealedField(sealed), true);
  assert.equal(openField(groupKey, sealed, ctx), '');
});

test('the wrong group key cannot open a field', () => {
  const sealed = sealField(groupKey, 1, 'private', ctx, seededRandom());
  assert.throws(() => openField(otherGroupKey, sealed, ctx));
});

test('a field cannot be replayed into another group', () => {
  // The whole point of the AAD: a server holding ciphertext from family A
  // must not be able to present it as family B's caption.
  const sealed = sealField(groupKey, 1, 'private', ctx, seededRandom());
  assert.throws(() => openField(groupKey, sealed, { ...ctx, groupId: 'group-b' }));
});

test('a caption cannot be presented as a comment', () => {
  const sealed = sealField(groupKey, 1, 'private', ctx, seededRandom());
  assert.throws(() => openField(groupKey, sealed, { ...ctx, field: 'comment' }));
});

test('a tampered field is rejected, not silently mis-decrypted', () => {
  const sealed = sealField(groupKey, 1, 'her first steps', ctx, seededRandom());
  const parts = sealed.split('.');
  const ct = base64ToBytes(parts[3]);
  ct[0] ^= 0x01;
  parts[3] = bytesToBase64(ct);
  assert.throws(() => openField(groupKey, parts.join('.'), ctx));
});

test('each seal draws a fresh nonce', () => {
  // A group key seals every caption and comment in a family for the life of an
  // epoch, so a repeated nonce here leaks the XOR of two members' text.
  const random = seededRandom();
  const a = sealField(groupKey, 1, 'same text', ctx, random);
  const b = sealField(groupKey, 1, 'same text', ctx, random);
  assert.notEqual(a, b);
  assert.notEqual(a.split('.')[2], b.split('.')[2]);
});

test('short fields of different lengths produce identical ciphertext sizes', () => {
  const short = sealField(groupKey, 1, 'ok', ctx, seededRandom());
  const longer = sealField(groupKey, 1, 'what a lovely photo!', ctx, seededRandom());
  assert.equal(
    base64ToBytes(short.split('.')[3]).length,
    base64ToBytes(longer.split('.')[3]).length,
  );
});

test('the epoch is readable without a key, so a reader knows which key to fetch', () => {
  const sealed = sealField(groupKey, 7, 'text', ctx, seededRandom());
  const parsed = parseSealedField(sealed);
  assert.equal(parsed?.keyEpoch, 7);
  assert.equal(parsed?.nonce.length, FIELD_NONCE_SIZE);
  assert.equal((parsed!.ciphertext.length - 16) % FIELD_PAD_BLOCK, 0);
});

test('plaintext is not mistaken for a sealed field', () => {
  // Groups mid-migration hold both, in the same column, so this distinction is
  // load-bearing for every read.
  for (const value of [
    'her first steps',
    '',
    'clnf1',
    'clnf1.1.short.short',
    'clnf1.0.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAA',
    'clnf2.1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAA',
    null,
    undefined,
    42,
  ]) {
    assert.equal(isSealedField(value), false, `treated ${String(value)} as sealed`);
  }
});

test('rejects wrong-sized keys, invalid epochs and delimiter injection', () => {
  assert.throws(
    () => sealField(new Uint8Array(16), 1, 'x', ctx, seededRandom()),
    /group key must be 32/,
  );
  assert.throws(() => sealField(groupKey, 0, 'x', ctx, seededRandom()), /epoch/);
  assert.throws(
    () => sealField(groupKey, 1, 'x', { groupId: 'a|b', field: 'caption' }, seededRandom()),
    /groupId/,
  );
  assert.throws(
    () => sealField(groupKey, 1, 'x', { groupId: 'a', field: 'cap|tion' }, seededRandom()),
    /field/,
  );
});

test('rejects text past the format limit rather than truncating it', () => {
  const tooLong = 'a'.repeat(MAX_FIELD_BYTES + 1);
  assert.throws(() => sealField(groupKey, 1, tooLong, ctx, seededRandom()), /limit is/);
});

test('opening something that is not an envelope fails loudly', () => {
  assert.throws(() => openField(groupKey, 'her first steps', ctx), /well-formed/);
});
