/**
 * Recovery phrase → a deterministic keypair. Normative spec: PROTOCOL.md §7.2.
 *
 * The design in one line: a 12-word BIP39 phrase derives a keypair that is
 * registered as an ordinary device — a *virtual* one, flagged as such, with no
 * hardware behind it. From then on it needs no special handling anywhere. Every
 * enable and every rotation seals the group key to it because it is simply in
 * the active device list, so it always holds the current epoch. Recovery is
 * then not a separate protocol: derive the keypair, unwrap the keys already
 * sealed to it, and use that identity to grant to the new phone along the same
 * path a family member's approval would take.
 *
 * The phrase itself is never stored, never transmitted, and never derivable
 * from anything the server holds. A user who loses it loses only this recovery
 * path, not their data.
 *
 * On the KDF: BIP39's `mnemonicToSeed` is PBKDF2-HMAC-SHA512 with 2048
 * iterations. That is weak stretching by modern standards, and it is fine here
 * *only* because the input already carries 128 bits of machine-generated
 * entropy — it is not a password. HKDF then separates the two curve keys with
 * distinct labels so neither reveals the other. Do not reuse this construction
 * for anything a human chose.
 *
 * The labels are versioned and load-bearing: changing either orphans every
 * phrase already in the wild, with no migration path, because the phrase is
 * the only copy of the key.
 */

import { entropyToMnemonic, mnemonicToSeed, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { x25519, ed25519 } from '@noble/curves/ed25519.js';

import { bytesToBase64 } from './bytes';
import { draw, type RandomSource } from './random';
import type { DeviceKeypair } from './types';

/** HKDF labels — versioned. Changing either orphans every existing phrase. */
const X25519_INFO = new TextEncoder().encode('clann-recovery-x25519-v1');
const ED25519_INFO = new TextEncoder().encode('clann-recovery-ed25519-v1');

/** 12 words = 128 bits of entropy. */
export const RECOVERY_ENTROPY_BYTES = 16;

/** Mint a fresh 12-word recovery phrase. */
export function generateRecoveryPhrase(random: RandomSource): string {
  return entropyToMnemonic(draw(random, RECOVERY_ENTROPY_BYTES), wordlist);
}

/** Tolerate the ways people actually type twelve words: case, stray spaces. */
export function normalizePhrase(phrase: string): string {
  return phrase.trim().toLowerCase().split(/\s+/).join(' ');
}

/** Checksum-validate a phrase before doing anything expensive with it. */
export function isValidPhrase(phrase: string): boolean {
  return validateMnemonic(normalizePhrase(phrase), wordlist);
}

/**
 * Derive the recovery keypair from a phrase. Same phrase → same keys, forever.
 *
 * That determinism is the entire design: the server stores nothing secret
 * because the phrase *is* the key.
 */
export async function deriveRecoveryKeys(phrase: string): Promise<DeviceKeypair> {
  const normalized = normalizePhrase(phrase);
  if (!validateMnemonic(normalized, wordlist)) {
    throw new Error('invalid recovery phrase');
  }
  const seed = await mnemonicToSeed(normalized); // 64 bytes, BIP39 PBKDF2
  const secretKey = hkdf(sha256, seed, undefined, X25519_INFO, 32);
  const edSecretKey = hkdf(sha256, seed, undefined, ED25519_INFO, 32);
  const publicKey = x25519.getPublicKey(secretKey);
  const edPublicKey = ed25519.getPublicKey(edSecretKey);
  return {
    secretKey,
    publicKey,
    publicKeyBase64: bytesToBase64(publicKey),
    edSecretKey,
    edPublicKey,
    edPublicKeyBase64: bytesToBase64(edPublicKey),
  };
}
