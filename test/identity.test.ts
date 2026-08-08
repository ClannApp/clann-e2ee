import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  GenesisVerificationError,
  OwnDeviceKeyMismatchError,
  computeTrustedDevices,
  pinOwnDevice,
  resolveGenesisRoot,
  signAttestation,
  signGenesis,
  verifyDeviceBinding,
  verifyGenesis,
} from '../src/identity';
import type { AttestationRecord, DeviceRecord } from '../src/types';
import { makeDevice, pubKeys } from './helpers';

const own = makeDevice('D1', 'U1', 0x01);
const other = makeDevice('D2', 'U1', 0x02);
const attacker = makeDevice('D-evil', 'U1', 0xee);

// --- self-signatures -------------------------------------------------------

test('a well-formed self-signature verifies', () => {
  assert.equal(verifyDeviceBinding(own.record), true);
});

test('a partial key swap is rejected', () => {
  // The server keeps the victim's Ed25519 identity but substitutes its own
  // X25519 encryption key. This is the attack self-signatures exist to catch:
  // the signature covers both, so the tampered record will not verify.
  const swapped: DeviceRecord = {
    ...own.record,
    x25519_public_key: attacker.publicKeyBase64,
  };
  assert.equal(verifyDeviceBinding(swapped), false);
});

test('a self-signature is not proof of ownership', () => {
  // Documented limitation, asserted so it cannot be quietly forgotten: a
  // server that mints BOTH keys signs a record that verifies perfectly. Only
  // the trust graph or out-of-band comparison catches this one.
  const forged = makeDevice('D-forged', 'U1', 0x77);
  assert.equal(verifyDeviceBinding(forged.record), true);
});

test('records missing signing fields are unverified, not errors', () => {
  assert.equal(verifyDeviceBinding({ user_id: 'U1', x25519_public_key: own.publicKeyBase64 }), false);
});

test('a malformed signature returns false rather than throwing', () => {
  assert.equal(verifyDeviceBinding({ ...own.record, self_signature: 'not base64 !!' }), false);
});

// --- pinning our own device ------------------------------------------------

test('pinOwnDevice passes a matching record through and leaves others alone', () => {
  const out = pinOwnDevice([own.record, other.record], 'D1', pubKeys(own));
  assert.equal(out.length, 2);
  assert.equal(out[0].x25519_public_key, own.publicKeyBase64);
  assert.deepEqual(out[1], other.record);
});

test('pinOwnDevice throws when the server substitutes our own key', () => {
  const substituted: DeviceRecord = { ...own.record, x25519_public_key: attacker.publicKeyBase64 };
  assert.throws(
    () => pinOwnDevice([substituted, other.record], 'D1', pubKeys(own)),
    OwnDeviceKeyMismatchError,
  );
});

test('pinOwnDevice throws when the server substitutes our identity key', () => {
  const substituted: DeviceRecord = { ...own.record, ed25519_public_key: attacker.edPublicKeyBase64 };
  assert.throws(() => pinOwnDevice([substituted], 'D1', pubKeys(own)), OwnDeviceKeyMismatchError);
});

test('pinOwnDevice forces the local keys into the returned record', () => {
  // Even on a match, downstream code must seal to the key we hold, not to the
  // string the server sent us that happened to compare equal.
  const [pinned] = pinOwnDevice([own.record], 'D1', pubKeys(own));
  assert.equal(pinned.x25519_public_key, own.publicKeyBase64);
  assert.equal(pinned.ed25519_public_key, own.edPublicKeyBase64);
});

test('pinOwnDevice tolerates a legacy record with no identity key', () => {
  const legacy: DeviceRecord = { ...own.record, ed25519_public_key: undefined };
  const [pinned] = pinOwnDevice([legacy], 'D1', pubKeys(own));
  assert.equal(pinned.ed25519_public_key, own.edPublicKeyBase64);
});

test('pinOwnDevice is a no-op for an unregistered install', () => {
  const devices = [own.record, other.record];
  assert.deepEqual(pinOwnDevice(devices, null, pubKeys(own)), devices);
});

// --- genesis ---------------------------------------------------------------

const GENESIS_ID = 'genesis-1';
const genesisSignature = signGenesis(own.edSecretKey, GENESIS_ID, 'D1', 'U1');
const genesis = {
  genesis_id: GENESIS_ID,
  founder_device_id: 'D1',
  founder_user_id: 'U1',
  genesis_signature: genesisSignature,
};

test('a founder-signed genesis verifies against the founder device', () => {
  assert.equal(
    verifyGenesis({ ...genesis, founder_ed25519_public_key: own.edPublicKeyBase64 }),
    true,
  );
});

test('resolveGenesisRoot returns the founder device id', () => {
  assert.equal(resolveGenesisRoot(genesis, [own.record, other.record]), 'D1');
});

test('resolveGenesisRoot returns null when the founder device is gone', () => {
  // No root to add, but the caller still has its own device and the chain.
  assert.equal(resolveGenesisRoot(genesis, [other.record]), null);
});

test('resolveGenesisRoot throws when a different device claims to be the founder', () => {
  // A server naming its own device as the root is the whole reason genesis
  // exists. It must fail closed, never fall back to the server's claim.
  const forged = { ...genesis, founder_device_id: attacker.record.id };
  assert.throws(
    () => resolveGenesisRoot(forged, [own.record, attacker.record]),
    GenesisVerificationError,
  );
});

test('resolveGenesisRoot throws when the genesis is missing entirely', () => {
  assert.throws(() => resolveGenesisRoot({}, [own.record]), GenesisVerificationError);
});

// --- the trust graph -------------------------------------------------------

function attest(from: ReturnType<typeof makeDevice>, to: ReturnType<typeof makeDevice>): AttestationRecord {
  return {
    attested_device_id: to.record.id,
    attester_device_id: from.record.id,
    signature: signAttestation(from.edSecretKey, to.record),
  };
}

test('a root is trusted; an unattested stranger is not', () => {
  const trusted = computeTrustedDevices([own.record, other.record], [], ['D1']);
  assert.deepEqual([...trusted], ['D1']);
});

test('trust propagates along valid attestations', () => {
  const third = makeDevice('D3', 'U2', 0x03);
  const trusted = computeTrustedDevices(
    [own.record, other.record, third.record],
    [attest(own, other), attest(other, third)],
    ['D1'],
  );
  assert.deepEqual([...trusted].sort(), ['D1', 'D2', 'D3']);
});

test('an attestation signed by an untrusted device grants nothing', () => {
  // Otherwise a server could inject a device and have it vouch for itself.
  const trusted = computeTrustedDevices(
    [own.record, attacker.record, other.record],
    [attest(attacker, other)],
    ['D1'],
  );
  assert.deepEqual([...trusted], ['D1']);
});

test('an attestation cannot launder a device whose own self-signature is broken', () => {
  const broken: DeviceRecord = { ...other.record, self_signature: attacker.record.self_signature };
  const trusted = computeTrustedDevices([own.record, broken], [attest(own, other)], ['D1']);
  assert.deepEqual([...trusted], ['D1']);
});

test('an attestation over different keys than the device now presents is rejected', () => {
  // The attestation covers (device id, encryption key, identity key). If the
  // server later swaps the keys, the old signature stops matching.
  const swapped = makeDevice('D2', 'U1', 0x42); // same id, new keys
  const trusted = computeTrustedDevices(
    [own.record, swapped.record],
    [attest(own, other)], // signed over the ORIGINAL D2 keys
    ['D1'],
  );
  assert.deepEqual([...trusted], ['D1']);
});

test('a root with a broken self-signature is not trusted', () => {
  const broken: DeviceRecord = { ...own.record, self_signature: undefined };
  assert.equal(computeTrustedDevices([broken], [], ['D1']).size, 0);
});
