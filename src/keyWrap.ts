/**
 * The middle tier of the key hierarchy: per-item data encryption keys (DEKs)
 * wrapped under a group key. Normative spec: PROTOCOL.md §3.3.
 *
 * Every photo or video gets its own random 32-byte DEK. That DEK encrypts all
 * of the item's variants (original, medium, thumbnail — each with its own CLN1
 * envelope and therefore its own nonce prefix), and is then wrapped
 * AES-256-GCM under the group key of a specific epoch. The wrap travels with
 * the item as `enc_meta`; the server stores it verbatim and cannot open it.
 *
 * Why a DEK at all, rather than encrypting files directly under the group key:
 *
 *  - Key rotation stays cheap. Rotating a group mints a new epoch and re-seals
 *    a 32-byte key to each device. Existing media is untouched — its enc_meta
 *    still names the epoch it was written under, and members who held that
 *    epoch keep reading it.
 *  - Sharing a single item does not mean sharing the group. Re-wrapping one
 *    DEK is enough.
 *  - It bounds nonce reuse. A group key that directly encrypted every file for
 *    years would accumulate (key, nonce) pairs across an unbounded number of
 *    files; a per-item DEK confines that budget to one item's few variants.
 *
 * The wrap is unauthenticated as to *who* produced it — see PROTOCOL.md §9.1
 * for the resulting griefing gap, which is a real accepted limitation.
 */

import { gcm } from '@noble/ciphers/aes.js';

import { bytesToBase64, base64ToBytes } from './bytes';
import { draw, type RandomSource } from './random';
import type { Base64 } from './types';

/** DEK wrap version: v1 = AES-256-GCM, 12-byte nonce, no AAD. */
export const ENC_META_VERSION = 1;
/** Wrap algorithm id: 1 = AES-256-GCM. */
export const ENC_META_ALG_AES_GCM = 1;

/** Sizes a server can validate structurally without holding any key. */
export const DEK_SIZE = 32;
export const DEK_WRAP_NONCE_SIZE = 12;
/** 32-byte DEK + 16-byte GCM tag. */
export const WRAPPED_DEK_SIZE = DEK_SIZE + 16;

/**
 * The per-item key record stored alongside the ciphertext, server-readable but
 * server-useless. `key_epoch` tells a reader which group key to fetch; it is
 * also written into the CLN1 header, and the two must agree.
 */
export interface EncMeta {
  v: number;
  alg: number;
  key_epoch: number;
  wrapped_dek: Base64;
  dek_wrap_nonce: Base64;
}

/** Generate a fresh per-item data encryption key. */
export function generateDek(random: RandomSource): Uint8Array {
  return draw(random, DEK_SIZE);
}

/**
 * Wrap a DEK under the group key of `keyEpoch`.
 *
 * The nonce is drawn fresh per wrap. Group keys are long-lived and wrap many
 * DEKs, so a repeated nonce here would leak DEKs across items — this is the
 * single most safety-critical random draw in the library.
 */
export function wrapDek(
  groupKey: Uint8Array,
  dek: Uint8Array,
  keyEpoch: number,
  random: RandomSource,
): EncMeta {
  if (groupKey.length !== 32) throw new Error(`keyWrap: group key must be 32 bytes, got ${groupKey.length}`);
  if (dek.length !== DEK_SIZE) throw new Error(`keyWrap: dek must be ${DEK_SIZE} bytes, got ${dek.length}`);
  if (!Number.isInteger(keyEpoch) || keyEpoch < 1) {
    throw new Error(`keyWrap: key epoch must be an integer >= 1, got ${keyEpoch}`);
  }
  const nonce = draw(random, DEK_WRAP_NONCE_SIZE);
  const wrapped = gcm(groupKey, nonce).encrypt(dek);
  return {
    v: ENC_META_VERSION,
    alg: ENC_META_ALG_AES_GCM,
    key_epoch: keyEpoch,
    wrapped_dek: bytesToBase64(wrapped),
    dek_wrap_nonce: bytesToBase64(nonce),
  };
}

/**
 * Unwrap an item's DEK with the group key named by `encMeta.key_epoch`.
 * Throws if the group key is wrong or the record was tampered with — GCM
 * authenticates, so there is no such thing as a silently wrong DEK.
 */
export function unwrapDek(groupKey: Uint8Array, encMeta: EncMeta): Uint8Array {
  if (groupKey.length !== 32) throw new Error(`keyWrap: group key must be 32 bytes, got ${groupKey.length}`);
  return gcm(groupKey, base64ToBytes(encMeta.dek_wrap_nonce)).decrypt(
    base64ToBytes(encMeta.wrapped_dek),
  );
}

/**
 * Structural validation of an `enc_meta` record — the most a server can do.
 *
 * This is worth stating precisely because it is easy to over-claim: passing
 * this check means the record is the right *shape*, not that the wrap opens to
 * anything. A server holds no key and can never learn the difference. The
 * client-side equivalent that does have teeth is a decrypt canary: after
 * writing ciphertext, re-derive the DEK from the enc_meta you are about to
 * persist (not the one in memory) and confirm it reproduces the plaintext.
 */
export function isWellFormedEncMeta(meta: unknown): meta is EncMeta {
  if (typeof meta !== 'object' || meta === null) return false;
  const m = meta as Partial<EncMeta>;
  if (m.v !== ENC_META_VERSION || m.alg !== ENC_META_ALG_AES_GCM) return false;
  if (!Number.isInteger(m.key_epoch) || (m.key_epoch as number) < 1) return false;
  if (typeof m.wrapped_dek !== 'string' || typeof m.dek_wrap_nonce !== 'string') return false;
  try {
    return (
      base64ToBytes(m.wrapped_dek).length === WRAPPED_DEK_SIZE &&
      base64ToBytes(m.dek_wrap_nonce).length === DEK_WRAP_NONCE_SIZE
    );
  } catch {
    return false;
  }
}
