/**
 * @clann/e2ee — the end-to-end encryption core of the Clann family photo app.
 *
 * Read PROTOCOL.md first. It is the normative description of the scheme; this
 * code is one implementation of it, and where the two disagree the spec is
 * what other implementations should follow.
 *
 * The API is namespaced by layer, roughly bottom-up:
 *
 *   cln1        the encrypted file envelope (§4)
 *   keyWrap     per-item data keys, wrapped under a group key (§3.3)
 *   sealedBox   anonymous public-key sealing, libsodium-compatible (§3.2)
 *   deviceKeys  device keypairs and human-comparable fingerprints (§3.1, §5.4)
 *   identity    signatures, attestations, genesis, the trust graph (§5)
 *   groupKey    who gets the group key, verified how (§6)
 *   recovery    phrase-derived virtual device (§7.2)
 *
 * Everything here is pure: no I/O, no ambient randomness, no platform
 * dependencies. Randomness is injected as a {@link RandomSource}. What this
 * package does *not* contain is equally deliberate — no transport, no storage,
 * no membership logic, no server. Those live in the host application, and
 * PROTOCOL.md §10 lists the obligations a host takes on.
 */

export * as bytes from './bytes';
export * as cln1 from './cln1';
export * as deviceKeys from './deviceKeys';
export * as groupKey from './groupKey';
export * as identity from './identity';
export * as keyWrap from './keyWrap';
export * as recovery from './recovery';
export * as sealedBox from './sealedBox';

export { draw, webCryptoRandom, type RandomSource } from './random';

export type {
  AttestationRecord,
  Base64,
  DeviceKeypair,
  DevicePublicKeys,
  DeviceRecord,
  EpochCommitment,
  EpochWrappedGroupKey,
  GroupGenesis,
  WrappedGroupKey,
} from './types';

export { OwnDeviceKeyMismatchError, GenesisVerificationError } from './identity';
export { UnverifiedDevicesError, EpochProvenanceError } from './groupKey';
export type { EncMeta } from './keyWrap';
export type { Cln1Header } from './cln1';
export type {
  EpochProvenanceFailure,
  EpochTrustContext,
  FanoutPolicy,
  FanoutRequest,
  FanoutResult,
  GrantRecipient,
} from './groupKey';
