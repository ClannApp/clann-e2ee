/**
 * Short text sealed directly under a group key. Normative spec: PROTOCOL.md §3.4.
 *
 * Captions and comments are the counterexample to the DEK design in
 * {@link ./keyWrap}. A photo is megabytes and gets its own data key so that
 * rotation stays cheap and a single item can be re-shared without re-sharing
 * the group; a caption is forty characters, and giving it a wrapped DEK would
 * make the envelope larger than the plaintext for no gain — there is no
 * per-item sharing story for a caption, and rotation never has to rewrite one
 * because the epoch travels inside the envelope.
 *
 * So these are encrypted with the group key itself, and the nonce budget
 * question is the same one {@link ./keyWrap.wrapDek} already answers: a group
 * key encrypts one record per caption, comment and edit, with a fresh 96-bit
 * random nonce each time. That is the same order of magnitude as the DEK wraps
 * a family already accumulates, and far below the ~2^32 birthday bound for
 * random GCM nonces under one key.
 *
 * Two properties are deliberate and worth stating plainly, because both are
 * easy to assume and neither is true:
 *
 *  - **The envelope binds to a group and a field, not to a record.** The AAD
 *    covers the family group id and the field name, so the server cannot move
 *    a caption into another family or replay it as a comment. It CANNOT stop a
 *    malicious server moving a caption from one photo to another *within* the
 *    same group — see PROTOCOL.md §9.5. Record ids would fix that, but photo
 *    and comment ids are minted server-side after the client has already
 *    sealed the text, so binding to them is not available at the moment of
 *    encryption without handing clients id generation.
 *
 *  - **Length is bucketed, not hidden.** Plaintext is padded to a multiple of
 *    {@link FIELD_PAD_BLOCK} bytes, so "ok" and "lovely photo" are
 *    indistinguishable, but a two-paragraph comment still looks longer than a
 *    one-word one. Hiding length entirely would mean a fixed maximum-size
 *    record for every caption, which is not worth the storage.
 */

import { gcm } from '@noble/ciphers/aes.js';

import { bytesToBase64, base64ToBytes } from './bytes';
import { draw, type RandomSource } from './random';

/**
 * Envelope discriminator and version. Sealed fields live in the same database
 * columns as the plaintext they replace, so a reader needs to tell the two
 * apart by looking at the value — hence a prefix rather than a side-channel
 * column. Bump the digit, never the letters, for a format change.
 */
export const SEALED_FIELD_PREFIX = 'clnf1';

/** Nonce size for the field wrap. 96 bits, drawn fresh per seal. */
export const FIELD_NONCE_SIZE = 12;

/**
 * Plaintext is zero-padded up to a multiple of this many bytes before
 * encryption, so short fields do not leak their exact length. 32 bytes keeps
 * the floor small — a one-word comment costs 48 ciphertext bytes.
 */
export const FIELD_PAD_BLOCK = 32;

/**
 * Longest field this format can carry, in UTF-8 bytes. Bounded by the 2-byte
 * length header in the padded plaintext. Captions and comments are far below
 * it; anything approaching it does not belong in a text column.
 */
export const MAX_FIELD_BYTES = 0xffff;

/** The pieces of a parsed envelope. Ciphertext includes the GCM tag. */
export interface SealedField {
  keyEpoch: number;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

/**
 * What a sealed field is bound to. Both parts are authenticated, not
 * encrypted — the server already knows which group and field a row belongs
 * to, so there is nothing to hide and everything to gain from binding it.
 */
export interface FieldContext {
  /** Family group id the record belongs to. */
  groupId: string;
  /**
   * Stable name of the field being sealed — `caption`, `comment`. Distinct
   * names stop the server presenting one kind of text as another.
   */
  field: string;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Additional authenticated data for a field seal.
 *
 * Fixed-order, delimiter-joined, with the delimiter forbidden in both parts so
 * the encoding is unambiguous — otherwise a group id containing the delimiter
 * could impersonate a different (group, field) pair.
 */
export function fieldAad(ctx: FieldContext): Uint8Array {
  if (!ctx.groupId || ctx.groupId.includes('|')) {
    throw new Error('sealedField: groupId must be non-empty and contain no "|"');
  }
  if (!ctx.field || ctx.field.includes('|')) {
    throw new Error('sealedField: field must be non-empty and contain no "|"');
  }
  return textEncoder.encode(`clann-field-v1|${ctx.groupId}|${ctx.field}`);
}

/** 2-byte big-endian length header, then the UTF-8 bytes, then zeros. */
function padPlaintext(bytes: Uint8Array): Uint8Array {
  const total = Math.ceil((bytes.length + 2) / FIELD_PAD_BLOCK) * FIELD_PAD_BLOCK;
  const out = new Uint8Array(total);
  out[0] = (bytes.length >> 8) & 0xff;
  out[1] = bytes.length & 0xff;
  out.set(bytes, 2);
  return out;
}

function unpadPlaintext(padded: Uint8Array): Uint8Array {
  if (padded.length < 2) throw new Error('sealedField: padded plaintext is truncated');
  const len = (padded[0] << 8) | padded[1];
  if (len + 2 > padded.length) {
    throw new Error('sealedField: declared length exceeds the padded record');
  }
  return padded.subarray(2, 2 + len);
}

/**
 * Seal one text field under the group key of `keyEpoch`.
 *
 * Returns an ASCII envelope safe to store in the same `TEXT` column the
 * plaintext used: `clnf1.<epoch>.<nonce>.<ciphertext>`, both binary parts
 * standard base64 — whose alphabet excludes `.`, so the split is unambiguous.
 */
export function sealField(
  groupKey: Uint8Array,
  keyEpoch: number,
  plaintext: string,
  ctx: FieldContext,
  random: RandomSource,
): string {
  if (groupKey.length !== 32) {
    throw new Error(`sealedField: group key must be 32 bytes, got ${groupKey.length}`);
  }
  if (!Number.isInteger(keyEpoch) || keyEpoch < 1) {
    throw new Error(`sealedField: key epoch must be an integer >= 1, got ${keyEpoch}`);
  }
  const bytes = textEncoder.encode(plaintext);
  if (bytes.length > MAX_FIELD_BYTES) {
    throw new Error(`sealedField: field is ${bytes.length} bytes, limit is ${MAX_FIELD_BYTES}`);
  }
  const nonce = draw(random, FIELD_NONCE_SIZE);
  const ciphertext = gcm(groupKey, nonce, fieldAad(ctx)).encrypt(padPlaintext(bytes));
  return `${SEALED_FIELD_PREFIX}.${keyEpoch}.${bytesToBase64(nonce)}.${bytesToBase64(ciphertext)}`;
}

/**
 * Split an envelope into its parts without needing a key, so a caller can
 * learn which epoch to fetch before it has one. Returns null for anything that
 * is not a well-formed envelope — including ordinary plaintext, which is the
 * common case on a group that has not finished migrating.
 */
export function parseSealedField(value: unknown): SealedField | null {
  if (typeof value !== 'string') return null;
  const parts = value.split('.');
  if (parts.length !== 4 || parts[0] !== SEALED_FIELD_PREFIX) return null;
  const keyEpoch = Number(parts[1]);
  if (!Number.isInteger(keyEpoch) || keyEpoch < 1) return null;
  try {
    const nonce = base64ToBytes(parts[2]);
    const ciphertext = base64ToBytes(parts[3]);
    // A GCM tag alone is 16 bytes and the smallest padded record is one block,
    // so anything shorter cannot have come from sealField.
    if (nonce.length !== FIELD_NONCE_SIZE) return null;
    if (ciphertext.length < FIELD_PAD_BLOCK + 16) return null;
    if ((ciphertext.length - 16) % FIELD_PAD_BLOCK !== 0) return null;
    return { keyEpoch, nonce, ciphertext };
  } catch {
    return null;
  }
}

/**
 * Whether a stored value is a sealed field rather than plaintext.
 *
 * Structural only: a user who types an envelope-shaped string by hand produces
 * a true here and an authentication failure at {@link openField}. Callers
 * render that as unreadable text rather than falling back to showing the raw
 * value, because a silent fallback is exactly how ciphertext ends up on screen.
 */
export function isSealedField(value: unknown): boolean {
  return parseSealedField(value) !== null;
}

/**
 * Open a sealed field with the group key named by its epoch.
 *
 * Throws if the key is wrong, the context does not match the one it was sealed
 * under, or the record was tampered with. GCM authenticates, so there is no
 * such thing as a silently wrong plaintext.
 */
export function openField(groupKey: Uint8Array, envelope: string, ctx: FieldContext): string {
  if (groupKey.length !== 32) {
    throw new Error(`sealedField: group key must be 32 bytes, got ${groupKey.length}`);
  }
  const parsed = parseSealedField(envelope);
  if (!parsed) throw new Error('sealedField: not a well-formed sealed field');
  const padded = gcm(groupKey, parsed.nonce, fieldAad(ctx)).decrypt(parsed.ciphertext);
  return textDecoder.decode(unpadPlaintext(padded));
}
