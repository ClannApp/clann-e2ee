/**
 * Group key exchange — who gets the key, verified how, sealed to what.
 * Normative spec: PROTOCOL.md §6.
 *
 * This is the part of a group E2EE system that is worth reading closely,
 * because it is where the interesting failures live. The file cipher is
 * standard and the sealed box is libsodium's; neither is where an
 * implementation goes wrong. Membership is.
 *
 * The model:
 *
 *   A group has one 32-byte symmetric key, versioned by an integer *epoch*.
 *   Distribution is a fan-out: the key is sealed once per recipient device, to
 *   that device's X25519 public key, using an anonymous sealed box. The server
 *   stores the resulting blobs and can open none of them. There is no group
 *   ratchet and no forward secrecy within an epoch — a deliberate trade
 *   discussed in PROTOCOL.md §6.5, made because the product is a shared photo
 *   library that new members are expected to be able to read backwards, which
 *   is precisely what forward secrecy is designed to prevent.
 *
 * Everything in this file is pure. Given the same devices, attestations, roots
 * and randomness it produces the same bytes; it performs no I/O and consults no
 * ambient state. That is what makes the trust decisions testable in isolation,
 * and it is why the policy argument below is explicit rather than inferred —
 * a fan-out that silently picked its own verification strength would be
 * impossible to audit at the call site.
 *
 * The security of every function here rests on one precondition: `devices` must
 * be the group's real member device set. This library verifies the *keys* in
 * that set; it cannot verify the set itself. Membership is the host
 * application's responsibility, and PROTOCOL.md §6.1 states the obligation
 * precisely.
 *
 * Note the asymmetry, because it is the sharpest thing to know about this file:
 * the outbound path verifies recipients carefully, while the inbound path
 * ({@link openGroupKey}) adopts a key with no provenance check at all. Sealed
 * boxes are anonymous, so a successful open says only "this was sealed to me",
 * never "a member sealed this". PROTOCOL.md §9.2.
 */

import { seal, sealOpen } from './sealedBox';
import { computeTrustedDevices, pinOwnDevice, verifyDeviceBinding } from './identity';
import { bytesToBase64, base64ToBytes } from './bytes';
import { draw, type RandomSource } from './random';
import type {
  AttestationRecord,
  Base64,
  DeviceKeypair,
  DevicePublicKeys,
  DeviceRecord,
  EpochWrappedGroupKey,
  WrappedGroupKey,
} from './types';

export const GROUP_KEY_SIZE = 32;
/** Ephemeral X25519 secret consumed by one sealed box. */
const EPHEMERAL_SEED_SIZE = 32;

/**
 * How hard a fan-out verifies its recipients.
 *
 * - `self-signature` — every device must carry a valid self-signature, and
 *   nothing more. Correct only when a human is vouching for the recipient set
 *   in the same breath: at *enable*, an admin is looking at a list of their own
 *   family's devices and choosing to encrypt for them. It catches a partial key
 *   swap (§5.2) but not a server-minted identity, and it must never be used for
 *   a fan-out nobody is looking at.
 *
 * - `attestation-chain` — every device must additionally chain, through valid
 *   attestations, back to a trusted root. This is the correct policy for any
 *   *automatic* fan-out, above all rotation: rotation happens in the background
 *   after a member is removed, with no human reviewing the recipient list, so
 *   an unrecognised device must block it rather than quietly receive the new
 *   key.
 *
 *   Know its ceiling: it blocks devices nobody has vouched for, but does not
 *   revisit devices somebody already did. Since a grant attests its recipient
 *   on a self-signature alone, a device admitted once is chain-verified from
 *   then on. See PROTOCOL.md §9.3.
 */
export type FanoutPolicy = 'self-signature' | 'attestation-chain';

/**
 * Thrown when a fan-out would have sealed the group key to a device that could
 * not be verified.
 *
 * There is deliberately no "seal anyway" option, and no partial fan-out that
 * skips the bad device. Both would be worse than failing: sealing to an
 * unverified key is the exact attack this code exists to stop, and silently
 * omitting a device locks a real family member out of everything uploaded
 * afterwards, with no signal to anyone. Failing loudly puts the decision in
 * front of a human.
 */
export class UnverifiedDevicesError extends Error {
  readonly deviceIds: string[];
  constructor(deviceIds: string[]) {
    super(`refusing to seal the group key to ${deviceIds.length} unverified device(s)`);
    this.name = 'UnverifiedDevicesError';
    this.deviceIds = deviceIds;
  }
}

/** Mint a fresh group key. */
export function generateGroupKey(random: RandomSource): Uint8Array {
  return draw(random, GROUP_KEY_SIZE);
}

/** Seal a group key to one device's X25519 public key. */
export function sealGroupKeyTo(
  groupKey: Uint8Array,
  recipientPublicKeyB64: Base64,
  random: RandomSource,
): Base64 {
  return bytesToBase64(
    seal(groupKey, base64ToBytes(recipientPublicKeyB64), draw(random, EPHEMERAL_SEED_SIZE)),
  );
}

/**
 * Open a group key sealed to this device. Throws if it was not ours to open.
 *
 * **This authenticates nothing about where the key came from.** A sealed box is
 * anonymous: it proves the contents were not altered after sealing, not who did
 * the sealing. Any party holding this device's X25519 public key — including the
 * server, which stores and serves it — can construct a blob this opens. Callers
 * must not treat a successful open as evidence that a member device minted the
 * key. See PROTOCOL.md §9.2 for the consequence and the signed-commitment fix.
 */
export function openGroupKey(
  wrappedKeyB64: Base64,
  kp: Pick<DeviceKeypair, 'publicKey' | 'secretKey'>,
): Uint8Array {
  return sealOpen(base64ToBytes(wrappedKeyB64), kp.publicKey, kp.secretKey);
}

export interface FanoutRequest<T extends DeviceRecord> {
  /** The key being distributed. Callers mint it with {@link generateGroupKey}. */
  groupKey: Uint8Array;
  /** The group's member device set, as reported by the server. */
  devices: T[];
  /** Attestations over those devices. Required by `attestation-chain`. */
  attestations?: AttestationRecord[];
  /** This install's device id, or null if it has not registered yet. */
  ownDeviceId: string | null;
  /** This install's own public keys, read from local storage — never from the server. */
  ownPublicKeys: DevicePublicKeys;
  /** Trust roots for `attestation-chain`: typically this device, plus the verified founder. */
  rootDeviceIds?: string[];
  policy: FanoutPolicy;
  random: RandomSource;
}

export interface FanoutResult<T extends DeviceRecord> {
  /** The verified recipient set, with this device's record pinned to local keys. */
  devices: T[];
  /** One sealed copy of the group key per recipient, ready to send. */
  wrappedKeys: WrappedGroupKey[];
}

/**
 * Verify a recipient set and seal the group key to every device in it.
 *
 * The order of operations is load-bearing, and is the thing to check when
 * reviewing this function:
 *
 *  1. **Pin this device first.** Our own record arrives from the server like
 *     any other, and under `attestation-chain` it is also a *root*. Verifying
 *     before pinning would let a substituted own-key seed the trust walk with
 *     the attacker's identity — every subsequent check would then be measuring
 *     the attack against itself. Pinning first turns that into a hard failure.
 *  2. **Verify every recipient**, to the requested policy.
 *  3. **Seal only then**, and only to keys that survived both.
 *
 * Throws {@link OwnDeviceKeyMismatchError} at step 1 or
 * {@link UnverifiedDevicesError} at step 2; on either, nothing is sealed and
 * the caller must not proceed.
 */
export function prepareGroupKeyFanout<T extends DeviceRecord>(
  req: FanoutRequest<T>,
): FanoutResult<T> {
  if (req.groupKey.length !== GROUP_KEY_SIZE) {
    throw new Error(`groupKey: key must be ${GROUP_KEY_SIZE} bytes, got ${req.groupKey.length}`);
  }
  if (req.devices.length === 0) {
    throw new Error('groupKey: refusing to distribute a key to an empty device set');
  }

  // 1. Pin — see the note above on why this precedes verification.
  const devices = pinOwnDevice(req.devices, req.ownDeviceId, req.ownPublicKeys);

  // 2. Verify.
  let unverified: T[];
  if (req.policy === 'attestation-chain') {
    const roots = req.rootDeviceIds ?? [];
    if (roots.length === 0) {
      // An empty root set trusts nothing, so the fan-out would fail anyway —
      // but as a misconfiguration rather than an attack, and the two must not
      // look alike to whoever reads the error.
      throw new Error('groupKey: attestation-chain policy requires at least one trust root');
    }
    const trusted = computeTrustedDevices(devices, req.attestations ?? [], roots);
    unverified = devices.filter((d) => !trusted.has(d.id));
  } else {
    unverified = devices.filter((d) => !verifyDeviceBinding(d));
  }
  if (unverified.length > 0) {
    throw new UnverifiedDevicesError(unverified.map((d) => d.id));
  }

  // 3. Seal.
  const wrappedKeys = devices.map((d) => ({
    device_id: d.id,
    wrapped_key: sealGroupKeyTo(req.groupKey, d.x25519_public_key, req.random),
  }));

  return { devices, wrappedKeys };
}

/** A device asking to be let into a group, as the granting device sees it. */
export interface GrantRecipient {
  user_id: string;
  x25519_public_key: Base64;
  ed25519_public_key?: Base64;
  self_signature?: Base64;
}

/**
 * Whether a key request's claimed identity is internally consistent.
 *
 * The guarantee is specific. A passing check means the requester's encryption
 * key is bound by signature to its identity key and account, which rejects a
 * server that reuses a real device's identity while substituting its own
 * encryption key. It does not by itself establish who the requester is (§5.2).
 * For a device the granter has never seen, this check is the floor; out-of-band
 * comparison (§5.4) and post-hoc detection (§5.7) carry the rest.
 */
export function verifyGrantRecipient(recipient: GrantRecipient): boolean {
  return verifyDeviceBinding(recipient);
}

/**
 * Seal the epochs this device holds to a verified requester.
 *
 * `epochs` must be **every** epoch the group has, not merely the latest.
 * Granting a subset produces the nastiest availability failure in the system:
 * the requester activates, appears to work, and silently cannot read anything
 * from the epochs it missed — which is to say, the family's older photos. A
 * granting device that is itself behind should therefore refresh before calling
 * this, or defer to a device that is current. The server can enforce
 * completeness because epoch *numbers* are public even though the keys are not.
 *
 * Note which way this cuts: since the grant covers all epochs, it reaches the
 * group's history rather than only its future, and the recipient was verified
 * by {@link verifyGrantRecipient} — a self-signature, not proof of ownership.
 * The human approval preceding this call is the real boundary; an out-of-band
 * safety-code comparison is what strengthens it. PROTOCOL.md §9.3.
 */
export function sealEpochsToRequester(
  epochs: Array<{ epoch: number; key: Uint8Array }>,
  requesterPublicKeyB64: Base64,
  random: RandomSource,
): EpochWrappedGroupKey[] {
  if (epochs.length === 0) {
    throw new Error('groupKey: this device holds no keys for the group');
  }
  return epochs.map(({ epoch, key }) => ({
    epoch,
    wrapped_key: sealGroupKeyTo(key, requesterPublicKeyB64, random),
  }));
}

/**
 * Open a batch of epoch-wrapped keys addressed to this device.
 *
 * Blobs that fail to open are reported rather than thrown on, because a single
 * bad wrap must not cost a device the epochs it *can* read. A bad wrap is a
 * real possibility here and worth understanding: the server cannot verify that
 * a wrap decrypts (it holds no keys), so a buggy or malicious member client can
 * store a blob that opens to nothing. That is an availability problem, not a
 * confidentiality one — see PROTOCOL.md §9.1.
 */
export function openEpochKeys(
  wrapped: EpochWrappedGroupKey[],
  kp: Pick<DeviceKeypair, 'publicKey' | 'secretKey'>,
): { opened: Array<{ epoch: number; key: Uint8Array }>; failed: number[] } {
  const opened: Array<{ epoch: number; key: Uint8Array }> = [];
  const failed: number[] = [];
  for (const w of wrapped) {
    try {
      opened.push({ epoch: w.epoch, key: openGroupKey(w.wrapped_key, kp) });
    } catch {
      failed.push(w.epoch);
    }
  }
  return { opened, failed };
}
