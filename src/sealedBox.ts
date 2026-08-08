/**
 * libsodium-compatible anonymous sealed boxes (crypto_box_seal /
 * crypto_box_seal_open) built from @noble primitives.
 *
 * Wire format (identical to libsodium, so any future native/libsodium
 * implementation interoperates):
 *
 *   sealed = ephemeral_pk(32) || xsalsa20poly1305(
 *     key   = hsalsa20(x25519(ephemeral_sk, recipient_pk))   // beforenm
 *     nonce = blake2b-192(ephemeral_pk || recipient_pk)
 *   )(message)
 *
 * Used for wrapping 32-byte group keys to member device public keys, so
 * payloads are tiny — pure JS is plenty fast.
 *
 * "Anonymous" is the operative word: the ephemeral secret is discarded after
 * one use, so a sealed box carries no evidence of who sealed it and the sender
 * cannot open it again afterwards. That is the right shape for key
 * distribution — the server routing these blobs learns nothing from them, and
 * `wrapped_by_device_id` (an ordinary, forgeable database column) is
 * bookkeeping, not proof.
 *
 * Wire-compatible with libsodium, so a native or WASM implementation can
 * replace this one without a migration. No libsodium code is included; the
 * construction is rebuilt from @noble primitives. The caller injects CSPRNG
 * bytes for the ephemeral key (see random.ts).
 */

import { xsalsa20poly1305, hsalsa } from '@noble/ciphers/salsa.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { blake2b } from '@noble/hashes/blake2.js';

export const SEALED_BOX_OVERHEAD = 32 + 16; // ephemeral pk + poly1305 tag

// "expand 32-byte k" as little-endian u32 words (Salsa20 sigma constants).
const SIGMA = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

function u32(bytes: Uint8Array): Uint32Array {
  // A fresh copy guarantees 4-byte alignment for the Uint32Array view.
  const copy = new Uint8Array(bytes);
  return new Uint32Array(copy.buffer, 0, copy.length / 4);
}

/** crypto_box_beforenm: X25519 shared secret run through HSalsa20. */
function boxSharedKey(secretKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const shared = x25519.getSharedSecret(secretKey, publicKey);
  const out = new Uint32Array(8);
  hsalsa(SIGMA, u32(shared), new Uint32Array(4), out);
  return new Uint8Array(out.buffer, 0, 32);
}

/** The sealed-box nonce: blake2b-192 of both public keys. */
function sealNonce(ephemeralPk: Uint8Array, recipientPk: Uint8Array): Uint8Array {
  const input = new Uint8Array(64);
  input.set(ephemeralPk, 0);
  input.set(recipientPk, 32);
  return blake2b(input, { dkLen: 24 });
}

/**
 * Seal a message to a recipient X25519 public key. `ephemeralSeed` must be
 * 32 fresh CSPRNG bytes (Crypto.getRandomBytes(32) on device); it is used
 * once and discarded, giving the seal its anonymity.
 */
export function seal(
  message: Uint8Array,
  recipientPk: Uint8Array,
  ephemeralSeed: Uint8Array,
): Uint8Array {
  if (recipientPk.length !== 32) throw new Error('sealedBox: recipient pk must be 32 bytes');
  if (ephemeralSeed.length !== 32) throw new Error('sealedBox: ephemeral seed must be 32 bytes');
  const ephemeralSk = ephemeralSeed;
  const ephemeralPk = x25519.getPublicKey(ephemeralSk);
  const key = boxSharedKey(ephemeralSk, recipientPk);
  const nonce = sealNonce(ephemeralPk, recipientPk);
  const box = xsalsa20poly1305(key, nonce).encrypt(message);

  const out = new Uint8Array(32 + box.length);
  out.set(ephemeralPk, 0);
  out.set(box, 32);
  return out;
}

/** Open a sealed box with the recipient's X25519 keypair. */
export function sealOpen(
  sealed: Uint8Array,
  recipientPk: Uint8Array,
  recipientSk: Uint8Array,
): Uint8Array {
  if (sealed.length < SEALED_BOX_OVERHEAD) throw new Error('sealedBox: too short');
  const ephemeralPk = sealed.subarray(0, 32);
  const key = boxSharedKey(recipientSk, ephemeralPk);
  const nonce = sealNonce(ephemeralPk, recipientPk);
  try {
    return xsalsa20poly1305(key, nonce).decrypt(sealed.subarray(32));
  } catch {
    throw new Error('sealedBox: failed to open (wrong key or corrupt data)');
  }
}
