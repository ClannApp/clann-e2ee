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
 * Both directions are verified, and it is worth knowing why each needs its own
 * mechanism. Outbound, the question is *who may receive* this key, answered by
 * the device trust graph (§5). Inbound, the question is *who produced* it —
 * which the trust graph cannot answer, because a sealed box is anonymous and a
 * successful open says only "this was sealed to me". That gap is closed by an
 * epoch commitment: the minting device signs the key it minted, and adopters
 * refuse a key whose signer they do not already trust. PROTOCOL.md §6.6.
 */

import { seal, sealOpen } from './sealedBox';
import {
  computeTrustedDevices,
  pinOwnDevice,
  signEpochCommitment,
  verifyDeviceBinding,
  verifyEpochCommitment,
} from './identity';
import { bytesToBase64, base64ToBytes } from './bytes';
import { draw, type RandomSource } from './random';
import type {
  AttestationRecord,
  Base64,
  DeviceKeypair,
  DevicePublicKeys,
  DeviceRecord,
  EpochCommitment,
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
 *   then on. See PROTOCOL.md §9.2.
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

/** How a key failed to prove where it came from. Diagnostics only. */
export type EpochProvenanceFailure =
  | 'missing'
  | 'mismatched-epoch'
  | 'mismatched-group'
  | 'bad-signature'
  | 'untrusted-signer';

/**
 * Thrown when a group key opened correctly but cannot be shown to have been
 * minted inside the group.
 *
 * Deliberately distinct from a failed unseal. A blob that will not open is
 * usually a bookkeeping problem — the wrong device's copy, a botched migration.
 * A blob that opens but carries no trustworthy provenance is the shape of an
 * actual attack, and the two must not be handled by the same catch.
 *
 * `reason` is for diagnostics and support, not for control flow. Every value
 * means the same thing operationally: this key must not be adopted.
 */
export class EpochProvenanceError extends Error {
  readonly epoch: number;
  readonly reason: EpochProvenanceFailure;
  constructor(epoch: number, reason: EpochProvenanceFailure, detail: string) {
    super(`refusing to adopt the group key for epoch ${epoch}: ${detail}`);
    this.name = 'EpochProvenanceError';
    this.epoch = epoch;
    this.reason = reason;
  }
}

/**
 * What a device needs in order to judge where a group key came from.
 *
 * This is the same material a fan-out verifies recipients against, and for the
 * same reason: deciding whether to believe the signer of an epoch is exactly
 * the question of whether that device is in the group's trust graph.
 *
 * One obligation follows from `devices` that is easy to miss. An epoch minted
 * years ago may have been minted by a device since removed or replaced, and its
 * signature must still verify — so this set has to include the historical
 * devices that signed the epochs being opened, not merely current membership. A
 * host that serves only current devices will find old epochs stop opening after
 * a member leaves, which is a data-loss bug rather than a security one.
 * PROTOCOL.md §10.
 */
export interface EpochTrustContext {
  /** The group whose key this is. Checked against the commitment. */
  groupId: string;
  /** Every device that could legitimately have signed an epoch, past or present. */
  devices: DeviceRecord[];
  attestations?: AttestationRecord[];
  /** Trust roots: typically this device, plus the founder verified through genesis. */
  rootDeviceIds: string[];
}

/**
 * Check that a commitment shows this key was minted inside the group.
 *
 * The order is load-bearing. Epoch and group are checked before the signature,
 * so a commitment lifted from another epoch or another group is rejected as the
 * replay it is, rather than passing a signature check it would genuinely
 * satisfy. The signer's trust is then checked separately from the signature's
 * validity, because a perfectly valid signature from a device nobody has
 * vouched for is precisely what a server injecting a key would produce.
 */
function assertEpochProvenance(
  groupKey: Uint8Array,
  epoch: number,
  commitment: EpochCommitment | undefined,
  ctx: EpochTrustContext,
): void {
  if (!commitment?.signature || !commitment.signer_device_id) {
    throw new EpochProvenanceError(epoch, 'missing', 'it carries no signed commitment');
  }
  if (commitment.epoch !== epoch) {
    throw new EpochProvenanceError(
      epoch,
      'mismatched-epoch',
      `the commitment covers epoch ${commitment.epoch}`,
    );
  }
  if (commitment.group_id !== ctx.groupId) {
    throw new EpochProvenanceError(
      epoch,
      'mismatched-group',
      `the commitment covers group ${commitment.group_id}, not ${ctx.groupId}`,
    );
  }
  if (ctx.rootDeviceIds.length === 0) {
    // As in the fan-out: an empty root set trusts nothing, so this would fail
    // anyway — but as a misconfiguration, and it must not read like an attack.
    throw new Error('groupKey: adopting a group key requires at least one trust root');
  }

  const signer = ctx.devices.find((d) => d.id === commitment.signer_device_id);
  const signatureOk =
    !!signer &&
    verifyEpochCommitment(
      commitment.signature,
      commitment.group_id,
      commitment.epoch,
      groupKey,
      signer.ed25519_public_key,
    );
  if (!signatureOk) {
    throw new EpochProvenanceError(
      epoch,
      'bad-signature',
      `no valid signature from device ${commitment.signer_device_id}`,
    );
  }

  const trusted = computeTrustedDevices(ctx.devices, ctx.attestations ?? [], ctx.rootDeviceIds);
  if (!trusted.has(signer.id)) {
    throw new EpochProvenanceError(
      epoch,
      'untrusted-signer',
      `device ${signer.id} signed it, and no trusted device vouches for that one`,
    );
  }
}

/**
 * Open and adopt a group key sealed to this device.
 *
 * Two independent things must hold, and both are enforced. The blob must open,
 * which proves it was sealed to this device; and the commitment must show that
 * a *trusted member device* minted the key. The first without the second is
 * worth nothing — any party holding this device's X25519 public key, the server
 * included, can seal a key of its own choosing that opens perfectly well.
 *
 * Throws {@link EpochProvenanceError} if provenance fails, after a successful
 * unseal. There is no "adopt anyway" path: catching this and proceeding hands
 * the group to whoever produced the key.
 */
export function openGroupKey(
  wrappedKeyB64: Base64,
  kp: Pick<DeviceKeypair, 'publicKey' | 'secretKey'>,
  epoch: number,
  commitment: EpochCommitment | undefined,
  ctx: EpochTrustContext,
): Uint8Array {
  const groupKey = sealOpen(base64ToBytes(wrappedKeyB64), kp.publicKey, kp.secretKey);
  assertEpochProvenance(groupKey, epoch, commitment, ctx);
  return groupKey;
}

export interface FanoutRequest<T extends DeviceRecord> {
  /** The key being distributed. Callers mint it with {@link generateGroupKey}. */
  groupKey: Uint8Array;
  /** The group this key belongs to. Bound into the epoch commitment. */
  groupId: string;
  /** The epoch this key becomes. Bound into the epoch commitment. */
  epoch: number;
  /** The group's member device set, as reported by the server. */
  devices: T[];
  /** Attestations over those devices. Required by `attestation-chain`. */
  attestations?: AttestationRecord[];
  /** This install's device id. Required: an epoch is signed by the device minting it. */
  ownDeviceId: string;
  /** This install's own public keys, read from local storage — never from the server. */
  ownPublicKeys: DevicePublicKeys;
  /** This install's Ed25519 secret key, used to sign the epoch commitment. */
  ownEdSecretKey: Uint8Array;
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
  /**
   * This device's signature over the key it just minted. Must be stored with
   * the epoch and served alongside every wrapped copy — without it, no
   * recipient can adopt the key.
   */
  commitment: EpochCommitment;
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
 *  4. **Sign the epoch**, so recipients can tell this key came from a member
 *     device rather than from the server (§6.6).
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
  if (!req.ownDeviceId) {
    // An unregistered device has no published identity, so nothing it signed
    // could be verified by anyone. It cannot mint an epoch — register first.
    throw new Error('groupKey: minting an epoch requires a registered own device id');
  }
  if (!Number.isInteger(req.epoch) || req.epoch < 0) {
    throw new Error(`groupKey: epoch must be a non-negative integer, got ${req.epoch}`);
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

  // 4. Sign. One commitment for the epoch, not one per recipient: it covers the
  // key itself, so it stays valid however many times the key is later re-sealed.
  const commitment: EpochCommitment = {
    group_id: req.groupId,
    epoch: req.epoch,
    signer_device_id: req.ownDeviceId,
    signature: signEpochCommitment(req.ownEdSecretKey, req.groupId, req.epoch, req.groupKey),
  };

  return { devices, wrappedKeys, commitment };
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
 * safety-code comparison is what strengthens it. PROTOCOL.md §9.2.
 */
export function sealEpochsToRequester(
  epochs: Array<{ epoch: number; key: Uint8Array }>,
  requesterPublicKeyB64: Base64,
  random: RandomSource,
): EpochWrappedGroupKey[] {
  if (epochs.length === 0) {
    throw new Error('groupKey: this device holds no keys for the group');
  }
  // Only the sealed keys travel. An epoch's provenance is per-epoch state that
  // the host already holds against the epoch itself (§6.6), so a grant has no
  // business re-stating it — and re-signing here would be worse than useless,
  // since this device did not mint these epochs and must not claim it did.
  return epochs.map(({ epoch, key }) => ({
    epoch,
    wrapped_key: sealGroupKeyTo(key, requesterPublicKeyB64, random),
  }));
}
