/**
 * Profile keys: one key per person, shared with every group they are in.
 * Normative spec: PROTOCOL.md §3.5.
 *
 * A photo belongs to one group, so its data key is wrapped under that group's
 * key ({@link ./keyWrap}). An avatar belongs to a *person*, and a person —
 * adult or child — is in several groups at once. So there is one more layer:
 *
 *   group key  ──AES-GCM──▶  profile key  ──AES-GCM──▶  avatar DEK  ──CLN1──▶  image
 *
 * The profile key is wrapped once per group the person is in. A reader who
 * holds it, through any shared group, opens the avatar without knowing which
 * group the screen is showing; a member of two groups can wrap it into the
 * second one.
 *
 * Unlike photo DEK wraps and sealed fields, both wraps here are bound to the
 * person in their AAD. That binding is available because person ids exist
 * before anything is encrypted (a photo id is minted by the server after the
 * client has sealed). Without it a server could hand Alice's wrap and avatar
 * to a reader as Bob's — both open, both are faces, and nothing would look
 * wrong. With it, a substituted wrap fails to open and the reader shows
 * initials.
 */

import { gcm } from '@noble/ciphers/aes.js';

import { bytesToBase64, base64ToBytes } from './bytes';
import { DEK_SIZE, DEK_WRAP_NONCE_SIZE, ENC_META_ALG_AES_GCM, ENC_META_VERSION, type EncMeta } from './keyWrap';
import { draw, type RandomSource } from './random';

/** Profile keys are 32 random bytes, like group keys and DEKs. */
export const PROFILE_KEY_SIZE = 32;

export type ProfileSubjectType = 'user' | 'child';

/** Whose profile key this is. */
export interface ProfileSubject {
  type: ProfileSubjectType;
  /** The user or child id. Must not contain `|`. */
  id: string;
}

/**
 * A profile key wrapped under one group's key. The host stores it with the
 * subject, profile key version and group id it was made for — all three are
 * authenticated, so a wrap only opens in the place it was written for.
 */
export interface ProfileKeyWrap {
  /** The GROUP epoch whose key wraps the profile key. */
  key_epoch: number;
  wrapped_key: string;
  wrap_nonce: string;
}

const textEncoder = new TextEncoder();

function part(name: string, value: string): string {
  if (!value || value.includes('|')) {
    throw new Error(`profileKey: ${name} must be non-empty and contain no "|"`);
  }
  return value;
}

function checkVersion(version: number): void {
  if (!Number.isInteger(version) || version < 1) {
    throw new Error(`profileKey: version must be an integer >= 1, got ${version}`);
  }
}

function checkSubject(subject: ProfileSubject): void {
  if (subject.type !== 'user' && subject.type !== 'child') {
    throw new Error(`profileKey: subject type must be user or child, got ${String(subject.type)}`);
  }
  part('subject id', subject.id);
}

/** AAD for a profile key wrapped under a group key. */
export function profileKeyWrapAad(subject: ProfileSubject, version: number, groupId: string): Uint8Array {
  checkSubject(subject);
  checkVersion(version);
  return textEncoder.encode(
    `clann-profile-key-v1|${subject.type}|${subject.id}|${version}|${part('groupId', groupId)}`,
  );
}

/** AAD for an avatar DEK wrapped under a profile key. */
export function avatarDekAad(subject: ProfileSubject, version: number): Uint8Array {
  checkSubject(subject);
  checkVersion(version);
  return textEncoder.encode(`clann-avatar-v1|${subject.type}|${subject.id}|${version}`);
}

export function generateProfileKey(random: RandomSource): Uint8Array {
  return draw(random, PROFILE_KEY_SIZE);
}

/** Wrap a profile key under the group key of `groupEpoch` in `groupId`. */
export function wrapProfileKey(
  groupKey: Uint8Array,
  groupEpoch: number,
  profileKey: Uint8Array,
  subject: ProfileSubject,
  version: number,
  groupId: string,
  random: RandomSource,
): ProfileKeyWrap {
  if (groupKey.length !== 32) throw new Error(`profileKey: group key must be 32 bytes, got ${groupKey.length}`);
  if (profileKey.length !== PROFILE_KEY_SIZE) {
    throw new Error(`profileKey: profile key must be ${PROFILE_KEY_SIZE} bytes, got ${profileKey.length}`);
  }
  if (!Number.isInteger(groupEpoch) || groupEpoch < 1) {
    throw new Error(`profileKey: group epoch must be an integer >= 1, got ${groupEpoch}`);
  }
  const aad = profileKeyWrapAad(subject, version, groupId);
  const nonce = draw(random, DEK_WRAP_NONCE_SIZE);
  const wrapped = gcm(groupKey, nonce, aad).encrypt(profileKey);
  return { key_epoch: groupEpoch, wrapped_key: bytesToBase64(wrapped), wrap_nonce: bytesToBase64(nonce) };
}

/**
 * Open a profile key wrap with the group key named by `wrap.key_epoch`.
 * Throws if the key is wrong, the wrap was tampered with, or it was written for
 * a different person, version or group.
 */
export function unwrapProfileKey(
  groupKey: Uint8Array,
  wrap: ProfileKeyWrap,
  subject: ProfileSubject,
  version: number,
  groupId: string,
): Uint8Array {
  if (groupKey.length !== 32) throw new Error(`profileKey: group key must be 32 bytes, got ${groupKey.length}`);
  const aad = profileKeyWrapAad(subject, version, groupId);
  return gcm(groupKey, base64ToBytes(wrap.wrap_nonce), aad).decrypt(base64ToBytes(wrap.wrapped_key));
}

/**
 * Wrap an avatar's DEK under a profile key. The result is an ordinary
 * {@link EncMeta} whose `key_epoch` is the PROFILE KEY VERSION — so hosts can
 * store and shape-check it exactly as they do a photo's — and the same version
 * must be stamped into the avatar's CLN1 header.
 */
export function wrapAvatarDek(
  profileKey: Uint8Array,
  version: number,
  dek: Uint8Array,
  subject: ProfileSubject,
  random: RandomSource,
): EncMeta {
  if (profileKey.length !== PROFILE_KEY_SIZE) {
    throw new Error(`profileKey: profile key must be ${PROFILE_KEY_SIZE} bytes, got ${profileKey.length}`);
  }
  if (dek.length !== DEK_SIZE) throw new Error(`profileKey: dek must be ${DEK_SIZE} bytes, got ${dek.length}`);
  const aad = avatarDekAad(subject, version);
  const nonce = draw(random, DEK_WRAP_NONCE_SIZE);
  const wrapped = gcm(profileKey, nonce, aad).encrypt(dek);
  return {
    v: ENC_META_VERSION,
    alg: ENC_META_ALG_AES_GCM,
    key_epoch: version,
    wrapped_dek: bytesToBase64(wrapped),
    dek_wrap_nonce: bytesToBase64(nonce),
  };
}

/**
 * Open an avatar's DEK with the profile key of version `encMeta.key_epoch`.
 * Throws if the avatar was written for someone else.
 */
export function unwrapAvatarDek(profileKey: Uint8Array, encMeta: EncMeta, subject: ProfileSubject): Uint8Array {
  if (profileKey.length !== PROFILE_KEY_SIZE) {
    throw new Error(`profileKey: profile key must be ${PROFILE_KEY_SIZE} bytes, got ${profileKey.length}`);
  }
  const aad = avatarDekAad(subject, encMeta.key_epoch);
  return gcm(profileKey, base64ToBytes(encMeta.dek_wrap_nonce), aad).decrypt(base64ToBytes(encMeta.wrapped_dek));
}
