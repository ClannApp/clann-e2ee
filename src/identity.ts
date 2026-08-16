/**
 * Device identity and the trust graph. Normative spec: PROTOCOL.md §5.
 *
 * The problem this file exists to solve: group keys are sealed to public keys
 * that a client learns *from the server*. If the server can substitute a key,
 * it can have every member seal the group key to the server instead, and
 * end-to-end encryption becomes theatre. Nothing else in the library matters if
 * this part is wrong.
 *
 * Three mechanisms, in increasing order of strength:
 *
 *  1. **Self-signature.** Each device holds an Ed25519 identity key beside its
 *     X25519 encryption key and signs `(user_id, x25519_pk)` with it. This
 *     catches a *partial* swap — a server that keeps a victim's identity key
 *     but substitutes its own encryption key produces a record that will not
 *     verify. It does NOT prove ownership: a server can mint both halves of a
 *     fresh pair and sign a perfectly valid self-signature. Read §5.2 before
 *     relying on it.
 *  2. **Attestation chain.** A device that already holds keys signs the
 *     identity of a device it is granting to. Members walk that graph from a
 *     known root, so trust propagates along human decisions ("I let Grandma's
 *     new phone in") rather than along server assertions. Its limit is easy to
 *     miss: a grant attests its recipient after checking only a self-signature,
 *     so the graph inherits that admission rather than re-deriving it. See
 *     PROTOCOL.md §9.2.
 *  3. **Genesis.** The root itself is signed by the founding device. Without
 *     this, the server chooses the root of the graph — and whoever chooses the
 *     root chooses the graph.
 *
 * On top of that sits {@link pinOwnDevice}, which handles the case the other
 * three miss: a server substituting *your own* device's key back to you.
 *
 * Signed message formats are byte-exact and cross-verified against an
 * independent Go implementation. Changing any of these strings is a protocol
 * break that invalidates every existing signature.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { bytesToBase64, base64ToBytes } from './bytes';
import type {
  AttestationRecord,
  Base64,
  DevicePublicKeys,
  DeviceRecord,
  GroupGenesis,
} from './types';

const utf8 = (s: string) => new TextEncoder().encode(s);

/** `clann-e2ee-device-v1|{user_id}|{x25519_pk_b64}` */
export function deviceBindingMessage(userId: string, x25519PkB64: Base64): Uint8Array {
  return utf8(`clann-e2ee-device-v1|${userId}|${x25519PkB64}`);
}

/** `clann-e2ee-attest-v1|{device_id}|{x25519_pk_b64}|{ed25519_pk_b64}` */
export function attestationMessage(
  deviceId: string,
  x25519PkB64: Base64,
  ed25519PkB64: Base64,
): Uint8Array {
  return utf8(`clann-e2ee-attest-v1|${deviceId}|${x25519PkB64}|${ed25519PkB64}`);
}

/** `clann-e2ee-genesis-v1|{genesis_id}|{founder_device_id}|{founder_user_id}` */
export function genesisMessage(
  genesisId: string,
  founderDeviceId: string,
  founderUserId: string,
): Uint8Array {
  return utf8(`clann-e2ee-genesis-v1|${genesisId}|${founderDeviceId}|${founderUserId}`);
}

/**
 * A commitment to a group key's *identity*, without revealing it.
 *
 * `clann-e2ee-epoch-v1|{group_id}|{epoch}|{b64(sha256(group_key))}`
 *
 * The digest rather than the key itself, so that signing never puts key
 * material into a value designed to be published. The group id and epoch are
 * both bound because neither alone is enough: without the group id a
 * commitment could be replayed into another group the signer belongs to, and
 * without the epoch it could be replayed as a later epoch of the same group.
 */
export function epochCommitmentMessage(
  groupId: string,
  epoch: number,
  groupKeyDigestB64: Base64,
): Uint8Array {
  return utf8(`clann-e2ee-epoch-v1|${groupId}|${epoch}|${groupKeyDigestB64}`);
}

/** The digest a group key is committed to by {@link epochCommitmentMessage}. */
export function groupKeyDigest(groupKey: Uint8Array): Base64 {
  return bytesToBase64(sha256(groupKey));
}

function verify(sigB64: Base64, message: Uint8Array, pkB64: Base64): boolean {
  try {
    return ed25519.verify(base64ToBytes(sigB64), message, base64ToBytes(pkB64));
  } catch {
    // Malformed base64 or a wrong-length key reaches here. A signature that
    // cannot be parsed is a signature that does not verify — never a throw
    // that a caller might catch and treat as "unknown, proceed anyway".
    return false;
  }
}

/** Sign this device's own (user, encryption key) binding. */
export function signSelfBinding(
  edSecretKey: Uint8Array,
  userId: string,
  x25519PkB64: Base64,
): Base64 {
  return bytesToBase64(ed25519.sign(deviceBindingMessage(userId, x25519PkB64), edSecretKey));
}

/** Vouch for another device's identity, extending the trust graph to it. */
export function signAttestation(
  edSecretKey: Uint8Array,
  target: Pick<DeviceRecord, 'id' | 'x25519_public_key' | 'ed25519_public_key'>,
): Base64 {
  return bytesToBase64(
    ed25519.sign(
      attestationMessage(target.id, target.x25519_public_key, target.ed25519_public_key ?? ''),
      edSecretKey,
    ),
  );
}

/**
 * Sign a group key on minting it, so adopters can tell where it came from.
 *
 * This is what makes a group key more than an anonymous 32 bytes: a sealed box
 * proves only that the contents reached the right device, never who sealed
 * them. A device that verifies this signature, and that its signer is trusted,
 * knows the key was minted inside the group rather than handed to it by the
 * server. See PROTOCOL.md §6.6.
 */
export function signEpochCommitment(
  edSecretKey: Uint8Array,
  groupId: string,
  epoch: number,
  groupKey: Uint8Array,
): Base64 {
  return bytesToBase64(
    ed25519.sign(epochCommitmentMessage(groupId, epoch, groupKeyDigest(groupKey)), edSecretKey),
  );
}

/**
 * Whether a commitment really covers this key, for this group and epoch.
 *
 * This checks the signature only. It says nothing about whether the *signer*
 * should be believed — that is a trust-graph question, and
 * {@link import('./groupKey').openGroupKey} answers both together. Verifying
 * one without the other is the mistake worth guarding against: a signature
 * from the server's own device verifies perfectly well.
 */
export function verifyEpochCommitment(
  signatureB64: Base64,
  groupId: string,
  epoch: number,
  groupKey: Uint8Array,
  signerEd25519PkB64: Base64 | undefined,
): boolean {
  if (!signatureB64 || !signerEd25519PkB64) return false;
  return verify(
    signatureB64,
    epochCommitmentMessage(groupId, epoch, groupKeyDigest(groupKey)),
    signerEd25519PkB64,
  );
}

/** Founder-sign a group's genesis, binding its trust root to this device. */
export function signGenesis(
  edSecretKey: Uint8Array,
  genesisId: string,
  founderDeviceId: string,
  founderUserId: string,
): Base64 {
  return bytesToBase64(
    ed25519.sign(genesisMessage(genesisId, founderDeviceId, founderUserId), edSecretKey),
  );
}

/**
 * Verify a device's self-signature binds its encryption key to its identity
 * key and account.
 *
 * Returns false — not throws — for records missing the signing fields, so a
 * legacy row registered before signed identities existed is treated as
 * unverified rather than as an error to be swallowed.
 */
export function verifyDeviceBinding(d: {
  user_id: string;
  x25519_public_key: Base64;
  ed25519_public_key?: Base64;
  self_signature?: Base64;
}): boolean {
  if (!d.ed25519_public_key || !d.self_signature) return false;
  return verify(
    d.self_signature,
    deviceBindingMessage(d.user_id, d.x25519_public_key),
    d.ed25519_public_key,
  );
}

/**
 * Verify a group's genesis against the founder device's identity key.
 *
 * `founder_ed25519_public_key` must come from the group's device list, not
 * from the genesis record itself — a self-describing genesis would prove
 * nothing at all.
 */
export function verifyGenesis(
  g: GroupGenesis & { founder_ed25519_public_key?: Base64 },
): boolean {
  if (
    !g.genesis_id ||
    !g.founder_device_id ||
    !g.founder_user_id ||
    !g.genesis_signature ||
    !g.founder_ed25519_public_key
  ) {
    return false;
  }
  return verify(
    g.genesis_signature,
    genesisMessage(g.genesis_id, g.founder_device_id, g.founder_user_id),
    g.founder_ed25519_public_key,
  );
}

/** Thrown when a group's genesis is absent or fails to verify. */
export class GenesisVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GenesisVerificationError';
  }
}

/**
 * Resolve the attestation-chain root for an existing encrypted group.
 *
 * Returns the founder device id once its genesis signature verifies, or null
 * when the founder device is no longer in the group (removed or replaced) — in
 * which case the caller still has its own device as a root and the chain
 * carries the rest.
 *
 * Throws rather than degrading if the genesis is missing or bad. A group whose
 * root cannot be authenticated has no trust root at all, and falling back to
 * "whatever the server says the root is" would silently reintroduce exactly
 * the substitution this defends against.
 */
export function resolveGenesisRoot(
  genesis: GroupGenesis,
  devices: DeviceRecord[],
): string | null {
  if (
    !genesis.genesis_id ||
    !genesis.founder_device_id ||
    !genesis.founder_user_id ||
    !genesis.genesis_signature
  ) {
    throw new GenesisVerificationError('encrypted group is missing its genesis trust root');
  }
  const founder = devices.find((d) => d.id === genesis.founder_device_id);
  if (!founder) return null;
  if (
    !verifyGenesis({
      genesis_id: genesis.genesis_id,
      founder_device_id: genesis.founder_device_id,
      founder_user_id: genesis.founder_user_id,
      genesis_signature: genesis.genesis_signature,
      founder_ed25519_public_key: founder.ed25519_public_key,
    })
  ) {
    throw new GenesisVerificationError(
      'group genesis failed to verify — refusing to key against an unauthenticated trust root',
    );
  }
  return genesis.founder_device_id;
}

/**
 * Thrown when the server's record for THIS device's own id carries keys that
 * do not match the keypair held locally — an active key-substitution attempt.
 */
export class OwnDeviceKeyMismatchError extends Error {
  constructor() {
    super(
      'own device key mismatch: the server returned a different key for this device than the one held locally — refusing to seal the group key',
    );
    this.name = 'OwnDeviceKeyMismatchError';
  }
}

/**
 * Pin this device's own record to the keypair held locally, before any
 * group-key fan-out.
 *
 * This closes a hole the signature machinery cannot: a server that substitutes
 * *your own* device's public key. Self-signatures do not help, because a server
 * minting a full fake identity signs it cleanly (§5.2); the attestation chain
 * does not help, because your own device is a root and roots are not attested.
 * The only defence is that the phone already holds its own keypair and must
 * never accept the server's word about it.
 *
 * For the record whose id matches `ownDeviceId` this (1) hard-fails on any
 * mismatch and (2) forces the LOCAL keys into the returned record, so
 * downstream sealing targets the key actually held rather than a server-supplied
 * copy. Every other device passes through untouched. A null `ownDeviceId`
 * (this install has not registered yet) is a no-op.
 */
export function pinOwnDevice<T extends DeviceRecord>(
  devices: T[],
  ownDeviceId: string | null,
  kp: DevicePublicKeys,
): T[] {
  if (!ownDeviceId) return devices;
  return devices.map((d) => {
    if (d.id !== ownDeviceId) return d;
    const x25519Ok = d.x25519_public_key === kp.publicKeyBase64;
    // Legacy rows may predate Ed25519 identities; only enforce the identity
    // match when the server actually carries one. The X25519 match is the
    // security-critical check — that is the key the group key is sealed to.
    const edOk = !d.ed25519_public_key || d.ed25519_public_key === kp.edPublicKeyBase64;
    if (!x25519Ok || !edOk) throw new OwnDeviceKeyMismatchError();
    return {
      ...d,
      x25519_public_key: kp.publicKeyBase64,
      ed25519_public_key: kp.edPublicKeyBase64,
    };
  });
}

/**
 * Compute the trusted subset of a group's devices by walking the attestation
 * graph outward from a set of roots.
 *
 * A device is trusted when its self-signature is valid AND either it is a root
 * or some already-trusted device signed a valid attestation over it. Note the
 * ordering: `bindingOk` is computed first and gates every node, so an
 * attestation cannot launder a device whose own self-signature is broken.
 *
 * Returns the set of trusted device ids. Anything outside that set is
 * unverified, and callers must not seal keys to it silently.
 *
 * BFS to fixpoint. At family scale — tens of devices, tens of attestations —
 * the quadratic loop is irrelevant, and the naive form is far easier to audit
 * than an incremental one.
 */
export function computeTrustedDevices(
  devices: DeviceRecord[],
  attestations: AttestationRecord[],
  rootDeviceIds: string[],
): Set<string> {
  const byId = new Map(devices.map((d) => [d.id, d]));
  const bindingOk = new Set(devices.filter((d) => verifyDeviceBinding(d)).map((d) => d.id));

  const trusted = new Set<string>();
  for (const root of rootDeviceIds) {
    if (bindingOk.has(root)) trusted.add(root);
  }

  let grew = true;
  while (grew) {
    grew = false;
    for (const a of attestations) {
      if (trusted.has(a.attested_device_id)) continue;
      if (!trusted.has(a.attester_device_id)) continue;
      const target = byId.get(a.attested_device_id);
      const attester = byId.get(a.attester_device_id);
      if (!target || !attester || !bindingOk.has(target.id)) continue;
      const msg = attestationMessage(
        target.id,
        target.x25519_public_key,
        target.ed25519_public_key ?? '',
      );
      if (verify(a.signature, msg, attester.ed25519_public_key ?? '')) {
        trusted.add(target.id);
        grew = true;
      }
    }
  }
  return trusted;
}

/**
 * A device fingerprint for out-of-band comparison, as raw bytes.
 *
 * Rendered to words by {@link import('./deviceKeys').safetyCode}; kept separate
 * so a host can render it however it likes.
 */
export function identityFingerprintInput(d: {
  ed25519_public_key?: Base64;
  x25519_public_key: Base64;
}): Base64 {
  // Prefer the Ed25519 identity — it is the long-term key, and both sides of a
  // verification must fingerprint the same one or every legitimate grant looks
  // like an attack.
  return d.ed25519_public_key || d.x25519_public_key;
}
