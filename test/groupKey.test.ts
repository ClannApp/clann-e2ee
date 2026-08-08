/**
 * Group key exchange under adversarial conditions.
 *
 * These tests are written from the server's point of view — assume it is
 * hostile and controls every device record a client sees — because that is the
 * only threat model under which a group E2EE scheme means anything.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  UnverifiedDevicesError,
  generateGroupKey,
  openEpochKeys,
  openGroupKey,
  prepareGroupKeyFanout,
  sealEpochsToRequester,
  sealGroupKeyTo,
  verifyGrantRecipient,
} from '../src/groupKey';
import { OwnDeviceKeyMismatchError, signAttestation } from '../src/identity';
import type { AttestationRecord, DeviceRecord } from '../src/types';
import { keypair, makeDevice, pubKeys, seededRandom } from './helpers';

const founder = makeDevice('D-founder', 'U-mum', 0x01);
const dad = makeDevice('D-dad', 'U-dad', 0x02);
const gran = makeDevice('D-gran', 'U-gran', 0x03);
/** A device the server minted: real keys, valid self-signature, no attestation. */
const injected = makeDevice('D-server', 'U-dad', 0xee);

function attest(from: typeof founder, to: typeof dad): AttestationRecord {
  return {
    attested_device_id: to.record.id,
    attester_device_id: from.record.id,
    signature: signAttestation(from.edSecretKey, to.record),
  };
}

const baseReq = {
  ownDeviceId: founder.record.id,
  ownPublicKeys: pubKeys(founder),
  random: seededRandom(),
};

// --- the happy path --------------------------------------------------------

test('seals one copy per device, and each device can open its own', () => {
  const groupKey = generateGroupKey(seededRandom(9));
  const { wrappedKeys } = prepareGroupKeyFanout({
    ...baseReq,
    groupKey,
    devices: [founder.record, dad.record, gran.record],
    policy: 'self-signature',
    random: seededRandom(),
  });

  assert.equal(wrappedKeys.length, 3);
  for (const [i, device] of [founder, dad, gran].entries()) {
    assert.equal(wrappedKeys[i].device_id, device.record.id);
    assert.deepEqual(openGroupKey(wrappedKeys[i].wrapped_key, keypair(device)), groupKey);
  }
});

test('a device cannot open a copy sealed to someone else', () => {
  const groupKey = generateGroupKey(seededRandom(9));
  const { wrappedKeys } = prepareGroupKeyFanout({
    ...baseReq,
    groupKey,
    devices: [founder.record, dad.record],
    policy: 'self-signature',
    random: seededRandom(),
  });
  assert.throws(() => openGroupKey(wrappedKeys[1].wrapped_key, keypair(gran)), /failed to open/);
});

test('every recipient gets a distinct sealed blob', () => {
  // Same plaintext key, same call — if two blobs matched, the ephemeral seed
  // was being reused and the seals would be linkable.
  const { wrappedKeys } = prepareGroupKeyFanout({
    ...baseReq,
    groupKey: generateGroupKey(seededRandom(9)),
    devices: [founder.record, dad.record, gran.record],
    policy: 'self-signature',
    random: seededRandom(),
  });
  assert.equal(new Set(wrappedKeys.map((w) => w.wrapped_key)).size, 3);
});

// --- key substitution ------------------------------------------------------

test('substituting our own device key aborts the fan-out entirely', () => {
  // The attack pinOwnDevice exists for: we would seal the group key to the
  // attacker while believing we sealed it to ourselves. Note that NOTHING is
  // sealed — the throw happens before any encryption.
  const tampered: DeviceRecord = {
    ...founder.record,
    x25519_public_key: injected.publicKeyBase64,
  };
  assert.throws(
    () =>
      prepareGroupKeyFanout({
        ...baseReq,
        groupKey: generateGroupKey(seededRandom(9)),
        devices: [tampered, dad.record],
        policy: 'self-signature',
        random: seededRandom(),
      }),
    OwnDeviceKeyMismatchError,
  );
});

test('a partially swapped co-member device is refused under either policy', () => {
  const swapped: DeviceRecord = { ...dad.record, x25519_public_key: injected.publicKeyBase64 };
  for (const policy of ['self-signature', 'attestation-chain'] as const) {
    assert.throws(
      () =>
        prepareGroupKeyFanout({
          ...baseReq,
          groupKey: generateGroupKey(seededRandom(9)),
          devices: [founder.record, swapped],
          attestations: [attest(founder, dad)],
          rootDeviceIds: [founder.record.id],
          policy,
          random: seededRandom(),
        }),
      UnverifiedDevicesError,
      `policy ${policy}`,
    );
  }
});

test('a server-minted device passes the self-signature policy — the documented gap', () => {
  // Asserted deliberately. `self-signature` is only safe when a human is
  // looking at the recipient list in the same moment; this test is what that
  // sentence means in practice.
  const { wrappedKeys } = prepareGroupKeyFanout({
    ...baseReq,
    groupKey: generateGroupKey(seededRandom(9)),
    devices: [founder.record, injected.record],
    policy: 'self-signature',
    random: seededRandom(),
  });
  assert.equal(wrappedKeys.length, 2);
});

test('a server-minted device is refused by the attestation-chain policy', () => {
  // Which is why every unattended fan-out — rotation above all — must use it.
  try {
    prepareGroupKeyFanout({
      ...baseReq,
      groupKey: generateGroupKey(seededRandom(9)),
      devices: [founder.record, dad.record, injected.record],
      attestations: [attest(founder, dad)],
      rootDeviceIds: [founder.record.id],
      policy: 'attestation-chain',
      random: seededRandom(),
    });
    assert.fail('expected the injected device to be refused');
  } catch (err) {
    assert.ok(err instanceof UnverifiedDevicesError);
    assert.deepEqual(err.deviceIds, [injected.record.id]);
  }
});

test('a group key carries no provenance — anyone can seal one we accept (§9.2)', () => {
  // Sealed boxes are anonymous. `injected` here stands in for a malicious
  // server: it holds only gran's PUBLIC key, which the server stores and
  // serves, and yet it can produce a blob gran opens as a group key.
  //
  // Nothing in the adopt path distinguishes this from a key minted by a real
  // member device, so the server can publish it as the next epoch and read
  // everything written under it. Pinned because §2.2's table would otherwise
  // read as if key substitution were covered generally.
  //
  // If this starts failing, provenance checking landed and §9.2 is stale.
  const forged = new Uint8Array(32).fill(0x99);
  const blob = sealGroupKeyTo(forged, gran.publicKeyBase64, seededRandom(77));

  assert.deepEqual(openGroupKey(blob, keypair(gran)), forged);

  const { opened, failed } = openEpochKeys([{ epoch: 9, wrapped_key: blob }], keypair(gran));
  assert.deepEqual(failed, []);
  assert.deepEqual(opened[0].key, forged);
});

test('an attested device stays chain-trusted in later fan-outs (§9.3)', () => {
  // Above, the injected device is refused by attestation-chain because nobody
  // vouched for it. But granting keys attests the recipient after checking only
  // a self-signature (verifyGrantRecipient), so one approval promotes it to
  // chain-verified and later rotations include it without further review.
  //
  // Pinned here because it qualifies the §2.2 protection claim. If this ever
  // starts failing, the trust model got stronger and §9.2 needs rewriting.
  const grantAttestation: AttestationRecord = {
    attested_device_id: injected.record.id,
    attester_device_id: founder.record.id,
    signature: signAttestation(founder.edSecretKey, injected.record),
  };

  const { wrappedKeys } = prepareGroupKeyFanout({
    ...baseReq,
    groupKey: generateGroupKey(seededRandom(9)),
    devices: [founder.record, injected.record],
    attestations: [grantAttestation],
    rootDeviceIds: [founder.record.id],
    policy: 'attestation-chain', // the strictest policy available
    random: seededRandom(),
  });

  const toInjected = wrappedKeys.find((w) => w.device_id === injected.record.id);
  assert.ok(toInjected, 'attestation-chain admitted the injected device');
  // And it really can read the group key — this is a confidentiality loss, not
  // a bookkeeping curiosity.
  assert.equal(openGroupKey(toInjected.wrapped_key, keypair(injected)).length, 32);
});

test('attestation-chain accepts a device vouched for transitively', () => {
  const { wrappedKeys } = prepareGroupKeyFanout({
    ...baseReq,
    groupKey: generateGroupKey(seededRandom(9)),
    devices: [founder.record, dad.record, gran.record],
    attestations: [attest(founder, dad), attest(dad, gran)],
    rootDeviceIds: [founder.record.id],
    policy: 'attestation-chain',
    random: seededRandom(),
  });
  assert.equal(wrappedKeys.length, 3);
});

test('attestation-chain refuses to run with no trust root', () => {
  // A misconfiguration, not an attack — and it must not read like one.
  assert.throws(
    () =>
      prepareGroupKeyFanout({
        ...baseReq,
        groupKey: generateGroupKey(seededRandom(9)),
        devices: [founder.record],
        attestations: [],
        rootDeviceIds: [],
        policy: 'attestation-chain',
        random: seededRandom(),
      }),
    /trust root/,
  );
});

test('an empty recipient set is refused', () => {
  // Committing an epoch nobody holds silently bricks the group.
  assert.throws(
    () =>
      prepareGroupKeyFanout({
        ...baseReq,
        groupKey: generateGroupKey(seededRandom(9)),
        devices: [],
        policy: 'self-signature',
        random: seededRandom(),
      }),
    /empty device set/,
  );
});

test('a wrong-sized group key is refused', () => {
  assert.throws(
    () =>
      prepareGroupKeyFanout({
        ...baseReq,
        groupKey: new Uint8Array(16),
        devices: [founder.record],
        policy: 'self-signature',
        random: seededRandom(),
      }),
    /32 bytes/,
  );
});

// --- granting to a new device ----------------------------------------------

test('a grant recipient with a partially swapped key is rejected', () => {
  assert.equal(verifyGrantRecipient(gran.record), true);
  assert.equal(
    verifyGrantRecipient({ ...gran.record, x25519_public_key: injected.publicKeyBase64 }),
    false,
  );
});

test('a grant covers every epoch, and the recipient can open them all', () => {
  // Granting only the latest epoch is the classic half-grant bug: the device
  // activates, looks fine, and cannot read the family's older photos.
  const epochs = [
    { epoch: 1, key: new Uint8Array(32).fill(1) },
    { epoch: 2, key: new Uint8Array(32).fill(2) },
    { epoch: 3, key: new Uint8Array(32).fill(3) },
  ];
  const wrapped = sealEpochsToRequester(epochs, gran.publicKeyBase64, seededRandom());
  assert.deepEqual(wrapped.map((w) => w.epoch), [1, 2, 3]);

  const { opened, failed } = openEpochKeys(wrapped, keypair(gran));
  assert.deepEqual(failed, []);
  assert.deepEqual(opened, epochs);
});

test('granting nothing is an error, not an empty success', () => {
  assert.throws(() => sealEpochsToRequester([], gran.publicKeyBase64, seededRandom()), /holds no keys/);
});

test('one unopenable wrap does not cost a device the epochs it can read', () => {
  // The server cannot verify that a wrap decrypts, so a buggy client can store
  // a blob that opens to nothing. It must degrade, not cascade.
  const good = sealEpochsToRequester(
    [{ epoch: 1, key: new Uint8Array(32).fill(1) }],
    gran.publicKeyBase64,
    seededRandom(),
  );
  const bad = sealEpochsToRequester(
    [{ epoch: 2, key: new Uint8Array(32).fill(2) }],
    dad.publicKeyBase64, // sealed to the wrong device
    seededRandom(),
  );
  const { opened, failed } = openEpochKeys([...good, ...bad], keypair(gran));
  assert.deepEqual(opened.map((o) => o.epoch), [1]);
  assert.deepEqual(failed, [2]);
});

// --- rotation --------------------------------------------------------------

test('rotation excludes a removed device without disturbing the old epoch', () => {
  // The property that makes removal meaningful: gran keeps what she already
  // had, and can read nothing written afterwards.
  const epoch1 = generateGroupKey(seededRandom(1));
  const before = prepareGroupKeyFanout({
    ...baseReq,
    groupKey: epoch1,
    devices: [founder.record, dad.record, gran.record],
    policy: 'self-signature',
    random: seededRandom(),
  });

  const epoch2 = generateGroupKey(seededRandom(2));
  const after = prepareGroupKeyFanout({
    ...baseReq,
    groupKey: epoch2,
    devices: [founder.record, dad.record], // gran removed
    attestations: [attest(founder, dad)],
    rootDeviceIds: [founder.record.id],
    policy: 'attestation-chain',
    random: seededRandom(),
  });

  const granEpoch1 = before.wrappedKeys.find((w) => w.device_id === gran.record.id)!;
  assert.deepEqual(openGroupKey(granEpoch1.wrapped_key, keypair(gran)), epoch1);
  assert.equal(after.wrappedKeys.some((w) => w.device_id === gran.record.id), false);
  for (const w of after.wrappedKeys) {
    assert.throws(() => openGroupKey(w.wrapped_key, keypair(gran)), /failed to open/);
  }
});
