import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  deriveRecoveryKeys,
  generateRecoveryPhrase,
  isValidPhrase,
  normalizePhrase,
} from '../src/recovery';
import { safetyCode, digestToWords, deviceKeypairFromSeeds } from '../src/deviceKeys';
import { seededRandom } from './helpers';

// A fixed phrase, so a change to the derivation shows up as a failing test
// rather than as a silent lockout for everyone who already wrote theirs down.
const PHRASE = 'legal winner thank year wave sausage worth useful legal winner thank yellow';

test('derivation is deterministic', async () => {
  const a = await deriveRecoveryKeys(PHRASE);
  const b = await deriveRecoveryKeys(PHRASE);
  assert.equal(a.publicKeyBase64, b.publicKeyBase64);
  assert.equal(a.edPublicKeyBase64, b.edPublicKeyBase64);
});

test('derivation is pinned to a golden vector', async () => {
  // If this fails, every recovery phrase already in the wild is orphaned.
  const kp = await deriveRecoveryKeys(PHRASE);
  assert.equal(kp.publicKeyBase64, 'RIu6oxKWCJtxjWdcTf9l8NEtcE/B9CYVW8vIvpEdeHg=');
  assert.equal(kp.edPublicKeyBase64, 'dZUvTdBtbkYjO17WV+Jt0ueWocYM2ixdrOv+95obVi8=');
});

test('the two curve keys are separated by their HKDF labels', async () => {
  const kp = await deriveRecoveryKeys(PHRASE);
  assert.notDeepEqual(kp.secretKey, kp.edSecretKey);
});

test('normalisation tolerates how people actually type twelve words', async () => {
  const messy = `  LEGAL Winner  thank\tyear wave sausage worth useful legal winner thank YELLOW `;
  assert.equal(normalizePhrase(messy), PHRASE);
  const a = await deriveRecoveryKeys(messy);
  const b = await deriveRecoveryKeys(PHRASE);
  assert.equal(a.publicKeyBase64, b.publicKeyBase64);
});

test('a phrase failing its checksum is rejected before any derivation', async () => {
  const wrong = PHRASE.replace('yellow', 'zoo');
  assert.equal(isValidPhrase(wrong), false);
  await assert.rejects(() => deriveRecoveryKeys(wrong), /invalid recovery phrase/);
});

test('generated phrases are twelve valid words', () => {
  const phrase = generateRecoveryPhrase(seededRandom(42));
  assert.equal(phrase.split(' ').length, 12);
  assert.equal(isValidPhrase(phrase), true);
});

// --- fingerprints ----------------------------------------------------------

test('a safety code is six words and stable for a key', () => {
  const kp = deviceKeypairFromSeeds(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2));
  const code = safetyCode(kp.edPublicKeyBase64);
  assert.equal(code.split(' · ').length, 6);
  assert.equal(safetyCode(kp.edPublicKeyBase64), code);
});

test('different keys produce different safety codes', () => {
  const a = deviceKeypairFromSeeds(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2));
  const b = deviceKeypairFromSeeds(new Uint8Array(32).fill(3), new Uint8Array(32).fill(4));
  assert.notEqual(safetyCode(a.edPublicKeyBase64), safetyCode(b.edPublicKeyBase64));
});

test('word encoding consumes 11 bits per word, BIP39-style', () => {
  // An all-zero digest selects index 0 six times.
  assert.deepEqual(digestToWords(new Uint8Array(32), 6), Array(6).fill('abandon'));
});

test('a device keypair is fully determined by its seeds', () => {
  const a = deviceKeypairFromSeeds(new Uint8Array(32).fill(7), new Uint8Array(32).fill(8));
  const b = deviceKeypairFromSeeds(new Uint8Array(32).fill(7), new Uint8Array(32).fill(8));
  assert.equal(a.publicKeyBase64, b.publicKeyBase64);
  assert.equal(a.edPublicKeyBase64, b.edPublicKeyBase64);
  assert.throws(() => deviceKeypairFromSeeds(new Uint8Array(16), new Uint8Array(32)), /32 bytes/);
});
