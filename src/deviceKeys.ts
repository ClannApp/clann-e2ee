/**
 * Device keypairs and the human-readable fingerprints used to verify them.
 * Normative spec: PROTOCOL.md §3.1 and §5.4.
 *
 * A device's identity is two 32-byte seeds and nothing else. Everything
 * public — both public keys, the device fingerprint, the ability to unwrap
 * every group key ever sealed to this device — is derived from them. That is a
 * deliberate design property, not an accident of implementation: it means a
 * device can be *restored* rather than re-admitted. Move the seeds to a new
 * phone and it is cryptographically the same device, so the group keys already
 * sitting on the server unwrap with no approval, no phrase and nobody's
 * permission.
 *
 * Which is also the warning. The seeds are the whole account. Where a host
 * application chooses to keep them — device keystore only, or mirrored into
 * the user's own platform key sync — is the single biggest decision it makes
 * about this system's real-world security, and it is a host decision, not a
 * library one. See PROTOCOL.md §8.
 */

import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { wordlist } from '@scure/bip39/wordlists/english.js';

import { bytesToBase64, base64ToBytes } from './bytes';
import { draw, type RandomSource } from './random';
import type { Base64, DeviceKeypair } from './types';

export const SEED_SIZE = 32;

/**
 * Derive both keypairs from their seeds.
 *
 * Both curves take a 32-byte seed directly, so this is pure derivation with no
 * stretching: these are machine-generated seeds with full entropy, not
 * passwords. (The recovery phrase, which *is* human-sized, goes through PBKDF2
 * and HKDF instead — see recovery.ts.)
 */
export function deviceKeypairFromSeeds(
  x25519Seed: Uint8Array,
  ed25519Seed: Uint8Array,
): DeviceKeypair {
  if (x25519Seed.length !== SEED_SIZE || ed25519Seed.length !== SEED_SIZE) {
    throw new Error(`deviceKeys: seeds must be ${SEED_SIZE} bytes`);
  }
  const publicKey = x25519.getPublicKey(x25519Seed);
  const edPublicKey = ed25519.getPublicKey(ed25519Seed);
  return {
    secretKey: x25519Seed,
    publicKey,
    publicKeyBase64: bytesToBase64(publicKey),
    edSecretKey: ed25519Seed,
    edPublicKey,
    edPublicKeyBase64: bytesToBase64(edPublicKey),
  };
}

/** Draw a fresh pair of device seeds. Persist both, or the identity is lost. */
export function generateDeviceSeeds(random: RandomSource): {
  x25519Seed: Uint8Array;
  ed25519Seed: Uint8Array;
} {
  return {
    x25519Seed: draw(random, SEED_SIZE),
    ed25519Seed: draw(random, SEED_SIZE),
  };
}

/**
 * Words shown in a safety code. 6 × 11 bits = 66 bits of fingerprint.
 *
 * Enough that forging a collision is out of reach, short enough that one
 * family member will actually read it down the phone to another. A 256-bit hex
 * fingerprint is stronger and nobody compares it, which makes it weaker.
 */
export const SAFETY_WORD_COUNT = 6;

/**
 * Map a digest to N words from the BIP39 English list by consuming 11-bit
 * chunks — the same encoding BIP39 itself uses. The list is chosen for
 * unambiguous pronunciation and distinct 4-letter prefixes, which is exactly
 * what reading a code aloud needs.
 */
export function digestToWords(digest: Uint8Array, count: number): string[] {
  if (digest.length * 8 < count * 11) {
    throw new Error(`deviceKeys: digest too short for ${count} words`);
  }
  const words: string[] = [];
  let buf = 0;
  let bits = 0;
  let i = 0;
  while (words.length < count) {
    while (bits < 11) {
      buf = (buf << 8) | digest[i++];
      bits += 8;
    }
    bits -= 11;
    words.push(wordlist[(buf >> bits) & 0x7ff]);
    buf &= (1 << bits) - 1; // drop consumed high bits so buf never overflows
  }
  return words;
}

/**
 * The safety code for a device: SHA-256 of its public key, rendered as
 * {@link SAFETY_WORD_COUNT} BIP39 words.
 *
 * Both sides of a verification must fingerprint the *same* key — pass the
 * Ed25519 identity key where one exists (see
 * {@link import('./identity').identityFingerprintInput}), or the two screens
 * show different codes and every legitimate grant looks like an attack.
 *
 * What comparing codes actually buys is narrow but real: it moves first-contact
 * trust off the server and onto a channel the server does not control. It is
 * only as good as the humans doing it, which is why §5.2 treats it as a
 * detection aid rather than a gate.
 */
export function safetyCode(publicKeyBase64: Base64, separator = ' · '): string {
  const digest = sha256(base64ToBytes(publicKeyBase64));
  return digestToWords(digest, SAFETY_WORD_COUNT).join(separator);
}
