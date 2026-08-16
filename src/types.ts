/**
 * The shapes this library reasons about.
 *
 * These are deliberately *structural* and deliberately minimal: they describe
 * only the fields the cryptography depends on, so a host application can pass
 * its own richer record types straight in without adapters. Everything here is
 * public data — it is exactly what an honest-but-curious server already holds.
 */

/** Base64 (standard alphabet, with padding), the encoding used on the wire. */
export type Base64 = string;

/**
 * A device's public record as published to the server.
 *
 * `x25519_public_key` is the encryption key group keys are sealed to.
 * `ed25519_public_key` is the long-term identity used for signatures, and
 * `self_signature` binds the two together under a user id (see identity.ts).
 * The signing fields are optional only to tolerate legacy rows registered
 * before signed identities shipped; a record missing them can never be
 * verified, and `verifyDeviceBinding` returns false for it.
 */
export interface DeviceRecord {
  id: string;
  user_id: string;
  x25519_public_key: Base64;
  ed25519_public_key?: Base64;
  self_signature?: Base64;
}

/**
 * One device vouching for another: `attester_device_id` signed the identity of
 * `attested_device_id`. Attestations are the edges of the trust graph that
 * `computeTrustedDevices` walks.
 */
export interface AttestationRecord {
  attested_device_id: string;
  attester_device_id: string;
  signature: Base64;
}

/**
 * A group's trust root, signed by the device that founded it.
 *
 * Without this a client would have to take the server's word for which device
 * roots the attestation graph — and a server that can choose the root can
 * choose the whole graph. The founder signs `(genesis_id, founder_device_id,
 * founder_user_id)` once, at group creation, and every member verifies that
 * signature before rooting anything in `founder_device_id`.
 */
export interface GroupGenesis {
  genesis_id?: string;
  founder_device_id?: string;
  founder_user_id?: string;
  genesis_signature?: Base64;
}

/**
 * The minting device's signature over a group key, carried alongside it.
 *
 * One per epoch rather than one per recipient: it commits to the key, not to
 * any particular sealing of it, so the same record travels with every copy and
 * survives being re-sealed to a device admitted years later. `signature` is
 * over `epochCommitmentMessage(group_id, epoch, sha256(key))`, and
 * `signer_device_id` says whose Ed25519 identity to check it against — a claim
 * the verifier resolves through the trust graph rather than believing.
 */
export interface EpochCommitment {
  group_id: string;
  epoch: number;
  signer_device_id: string;
  signature: Base64;
}

/** A group key sealed to one device, ready to hand to the server. */
export interface WrappedGroupKey {
  device_id: string;
  wrapped_key: Base64;
}

/** A group key sealed for one epoch, as stored and returned per device. */
export interface EpochWrappedGroupKey {
  epoch: number;
  wrapped_key: Base64;
  /** Provenance for this epoch's key. Required to adopt it (§6.6). */
  commitment: EpochCommitment;
}

/** An X25519 encryption keypair plus its Ed25519 identity keypair. */
export interface DeviceKeypair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyBase64: Base64;
  edSecretKey: Uint8Array;
  edPublicKey: Uint8Array;
  edPublicKeyBase64: Base64;
}

/** The public half of a {@link DeviceKeypair} — what a fan-out is pinned against. */
export interface DevicePublicKeys {
  publicKeyBase64: Base64;
  edPublicKeyBase64: Base64;
}
