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
  EpochProvenanceError,
  UnverifiedDevicesError,
  generateGroupKey,
  openGroupKey,
  prepareGroupKeyFanout,
  sealEpochsToRequester,
  sealGroupKeyTo,
  verifyGrantRecipient,
} from '../src/groupKey';
import {
  OwnDeviceKeyMismatchError,
  signAttestation,
  signEpochCommitment,
} from '../src/identity';
import type { AttestationRecord, DeviceRecord, EpochCommitment } from '../src/types';
import { sealOpen } from '../src/sealedBox';
import { base64ToBytes } from '../src/bytes';
import { keypair, makeDevice, pubKeys, seededRandom } from './helpers';

const GROUP = 'G-oshea';

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
  groupId: GROUP,
  epoch: 1,
  ownDeviceId: founder.record.id,
  ownPublicKeys: pubKeys(founder),
  ownEdSecretKey: founder.edSecretKey,
  random: seededRandom(),
};

/** What a device consults to decide whether to believe an epoch's signer. */
function trustCtx(devices: DeviceRecord[], attestations: AttestationRecord[] = []) {
  return { groupId: GROUP, devices, attestations, rootDeviceIds: [founder.record.id] };
}

const everyone = trustCtx(
  [founder.record, dad.record, gran.record],
  [attest(founder, dad), attest(founder, gran)],
);

// --- the happy path --------------------------------------------------------

test('seals one copy per device, and each device can open its own', () => {
  const groupKey = generateGroupKey(seededRandom(9));
  const { wrappedKeys, commitment } = prepareGroupKeyFanout({
    ...baseReq,
    groupKey,
    devices: [founder.record, dad.record, gran.record],
    policy: 'self-signature',
    random: seededRandom(),
  });

  assert.equal(wrappedKeys.length, 3);
  for (const [i, device] of [founder, dad, gran].entries()) {
    assert.equal(wrappedKeys[i].device_id, device.record.id);
    assert.deepEqual(
      openGroupKey(wrappedKeys[i].wrapped_key, keypair(device), 1, commitment, everyone),
      groupKey,
    );
  }
});

test('the epoch is signed by the device that minted it', () => {
  const { commitment } = prepareGroupKeyFanout({
    ...baseReq,
    epoch: 7,
    groupKey: generateGroupKey(seededRandom(9)),
    devices: [founder.record, dad.record],
    policy: 'self-signature',
    random: seededRandom(),
  });
  assert.equal(commitment.signer_device_id, founder.record.id);
  assert.equal(commitment.group_id, GROUP);
  assert.equal(commitment.epoch, 7);
});

test('a device cannot open a copy sealed to someone else', () => {
  const groupKey = generateGroupKey(seededRandom(9));
  const { wrappedKeys, commitment } = prepareGroupKeyFanout({
    ...baseReq,
    groupKey,
    devices: [founder.record, dad.record],
    policy: 'self-signature',
    random: seededRandom(),
  });
  assert.throws(
    () => openGroupKey(wrappedKeys[1].wrapped_key, keypair(gran), 1, commitment, everyone),
    /failed to open/,
  );
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

// --- key injection: provenance on the adopt path (§6.6) ---------------------

test('a key sealed by the server, with no commitment, is refused', () => {
  // The core of §6.6. Sealed boxes are anonymous, so the server — holding only
  // gran's PUBLIC key, which it stores and serves — can produce a blob gran
  // opens as a group key. What it cannot produce is a signature from a device
  // gran trusts, so the key is unsealed and then thrown away.
  const forged = new Uint8Array(32).fill(0x99);
  const blob = sealGroupKeyTo(forged, gran.publicKeyBase64, seededRandom(77));

  assert.throws(
    () => openGroupKey(blob, keypair(gran), 9, undefined, everyone),
    (err: unknown) => err instanceof EpochProvenanceError && err.reason === 'missing',
  );
});

test('a key the server signed with its own device is refused', () => {
  // The obvious next move: mint a key AND a commitment. It fails on trust, not
  // on the signature — which is valid — because nobody has vouched for the
  // signing device.
  const forged = new Uint8Array(32).fill(0x99);
  const blob = sealGroupKeyTo(forged, gran.publicKeyBase64, seededRandom(77));
  const selfSigned: EpochCommitment = {
    group_id: GROUP,
    epoch: 9,
    signer_device_id: injected.record.id,
    signature: signEpochCommitment(injected.edSecretKey, GROUP, 9, forged),
  };

  assert.throws(
    () =>
      openGroupKey(blob, keypair(gran), 9, selfSigned, trustCtx([...everyone.devices, injected.record], everyone.attestations)),
    (err: unknown) => err instanceof EpochProvenanceError && err.reason === 'untrusted-signer',
  );
});

test('a real commitment cannot be reused to launder a substituted key', () => {
  // The server keeps the founder's genuine commitment for epoch 5 but seals a
  // key of its own. The commitment covers a digest of the real key, so it no
  // longer verifies against what was actually delivered.
  const real = generateGroupKey(seededRandom(5));
  const { commitment } = prepareGroupKeyFanout({
    ...baseReq,
    epoch: 5,
    groupKey: real,
    devices: [founder.record, gran.record],
    policy: 'self-signature',
    random: seededRandom(),
  });

  const forged = new Uint8Array(32).fill(0x99);
  const blob = sealGroupKeyTo(forged, gran.publicKeyBase64, seededRandom(77));

  assert.throws(
    () => openGroupKey(blob, keypair(gran), 5, commitment, everyone),
    (err: unknown) => err instanceof EpochProvenanceError && err.reason === 'bad-signature',
  );
});

test('a commitment from another epoch is refused as a replay', () => {
  const key = generateGroupKey(seededRandom(3));
  const { wrappedKeys, commitment } = prepareGroupKeyFanout({
    ...baseReq,
    epoch: 3,
    groupKey: key,
    devices: [founder.record, gran.record],
    policy: 'self-signature',
    random: seededRandom(),
  });
  const granCopy = wrappedKeys.find((w) => w.device_id === gran.record.id)!;

  // Same key, same signer, replayed as a later epoch.
  assert.throws(
    () => openGroupKey(granCopy.wrapped_key, keypair(gran), 4, commitment, everyone),
    (err: unknown) => err instanceof EpochProvenanceError && err.reason === 'mismatched-epoch',
  );
});

test('a commitment from another group is refused', () => {
  const key = generateGroupKey(seededRandom(3));
  const { wrappedKeys, commitment } = prepareGroupKeyFanout({
    ...baseReq,
    groupId: 'G-elsewhere',
    groupKey: key,
    devices: [founder.record, gran.record],
    policy: 'self-signature',
    random: seededRandom(),
  });
  const granCopy = wrappedKeys.find((w) => w.device_id === gran.record.id)!;

  assert.throws(
    () => openGroupKey(granCopy.wrapped_key, keypair(gran), 1, commitment, everyone),
    (err: unknown) => err instanceof EpochProvenanceError && err.reason === 'mismatched-group',
  );
});

test('adopting refuses to run with no trust root', () => {
  // A misconfiguration, not an attack — and it must not read like one.
  const key = generateGroupKey(seededRandom(3));
  const { wrappedKeys, commitment } = prepareGroupKeyFanout({
    ...baseReq,
    groupKey: key,
    devices: [founder.record, gran.record],
    policy: 'self-signature',
    random: seededRandom(),
  });
  const granCopy = wrappedKeys.find((w) => w.device_id === gran.record.id)!;

  assert.throws(
    () =>
      openGroupKey(granCopy.wrapped_key, keypair(gran), 1, commitment, {
        ...everyone,
        rootDeviceIds: [],
      }),
    /trust root/,
  );
});

test('an epoch signed by a transitively trusted device is adopted', () => {
  // Dad mints, having been attested by the founder. Gran has never met dad's
  // device directly and still adopts, because the chain reaches him.
  const key = generateGroupKey(seededRandom(4));
  const { wrappedKeys, commitment } = prepareGroupKeyFanout({
    groupId: GROUP,
    epoch: 2,
    ownDeviceId: dad.record.id,
    ownPublicKeys: pubKeys(dad),
    ownEdSecretKey: dad.edSecretKey,
    groupKey: key,
    devices: [founder.record, dad.record, gran.record],
    policy: 'self-signature',
    random: seededRandom(),
  });
  const granCopy = wrappedKeys.find((w) => w.device_id === gran.record.id)!;

  assert.deepEqual(openGroupKey(granCopy.wrapped_key, keypair(gran), 2, commitment, everyone), key);
});

test('an attested device stays chain-trusted in later fan-outs (§9.2)', () => {
  // Above, the injected device is refused by attestation-chain because nobody
  // vouched for it. But granting keys attests the recipient after checking only
  // a self-signature (verifyGrantRecipient), so one approval promotes it to
  // chain-verified and later rotations include it without further review.
  //
  // Pinned here because it qualifies the §2.2 protection claim: epoch
  // commitments stop the server minting keys, not a device admitted by a bad
  // approval. If this ever starts failing, the trust model got stronger.
  const grantAttestation: AttestationRecord = {
    attested_device_id: injected.record.id,
    attester_device_id: founder.record.id,
    signature: signAttestation(founder.edSecretKey, injected.record),
  };

  const { wrappedKeys, commitment } = prepareGroupKeyFanout({
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
  const ctx = trustCtx([founder.record, injected.record], [grantAttestation]);
  assert.equal(
    openGroupKey(toInjected.wrapped_key, keypair(injected), 1, commitment, ctx).length,
    32,
  );
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

test('an unregistered device cannot mint an epoch', () => {
  // Nothing it signed could be verified by anyone, so the commitment would be
  // dead on arrival. Better to say so than to emit an unusable epoch.
  assert.throws(
    () =>
      prepareGroupKeyFanout({
        ...baseReq,
        ownDeviceId: '' as unknown as string,
        groupKey: generateGroupKey(seededRandom(9)),
        devices: [founder.record],
        policy: 'self-signature',
        random: seededRandom(),
      }),
    /registered own device id/,
  );
});

// --- granting to a new device ----------------------------------------------

/**
 * Open a grant's sealed blob directly.
 *
 * Grants carry keys and nothing else, so there is no commitment to check here —
 * the recipient adopts through openGroupKey, against the commitment its host
 * serves with the epoch. These tests are only asserting the sealing.
 */
function sealedBoxOpen(wrappedKeyB64: string, device: typeof gran): Uint8Array {
  return sealOpen(base64ToBytes(wrappedKeyB64), device.publicKey, device.secretKey);
}

/** Epochs as a granting device holds them. */
function heldEpochs(epochs: number[]) {
  return epochs.map((epoch) => ({ epoch, key: new Uint8Array(32).fill(epoch) }));
}

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
  const epochs = heldEpochs([1, 2, 3]);
  const wrapped = sealEpochsToRequester(epochs, gran.publicKeyBase64, seededRandom());
  assert.deepEqual(wrapped.map((w) => w.epoch), [1, 2, 3]);

  for (const [i, w] of wrapped.entries()) {
    assert.deepEqual(
      sealedBoxOpen(w.wrapped_key, gran),
      epochs[i].key,
      `epoch ${w.epoch}`,
    );
  }
});

test('a grant carries only sealed keys, never provenance', () => {
  // Provenance is per-epoch state the host already holds against the epoch, and
  // the granting device did not mint these epochs anyway — a grant that
  // re-stated it would be claiming something this device cannot know.
  const wrapped = sealEpochsToRequester(heldEpochs([2]), gran.publicKeyBase64, seededRandom());
  assert.deepEqual(Object.keys(wrapped[0]).sort(), ['epoch', 'wrapped_key']);
});

test('granting nothing is an error, not an empty success', () => {
  assert.throws(() => sealEpochsToRequester([], gran.publicKeyBase64, seededRandom()), /holds no keys/);
});

test('a wrap sealed to the wrong device does not open here', () => {
  // The server cannot verify that a wrap decrypts, so a buggy client can store
  // a blob that opens to nothing. A recipient must fail on that one blob rather
  // than lose the epochs it can read.
  const bad = sealEpochsToRequester(
    heldEpochs([2]),
    dad.publicKeyBase64, // sealed to the wrong device
    seededRandom(),
  );
  assert.throws(() => sealedBoxOpen(bad[0].wrapped_key, gran), /failed to open/);
});

// --- rotation --------------------------------------------------------------

test('rotation excludes a removed device without disturbing the old epoch', () => {
  // The property that makes removal meaningful: gran keeps what she already
  // had, and can read nothing written afterwards.
  const epoch1 = generateGroupKey(seededRandom(1));
  const before = prepareGroupKeyFanout({
    ...baseReq,
    epoch: 1,
    groupKey: epoch1,
    devices: [founder.record, dad.record, gran.record],
    policy: 'self-signature',
    random: seededRandom(),
  });

  const epoch2 = generateGroupKey(seededRandom(2));
  const after = prepareGroupKeyFanout({
    ...baseReq,
    epoch: 2,
    groupKey: epoch2,
    devices: [founder.record, dad.record], // gran removed
    attestations: [attest(founder, dad)],
    rootDeviceIds: [founder.record.id],
    policy: 'attestation-chain',
    random: seededRandom(),
  });

  const granEpoch1 = before.wrappedKeys.find((w) => w.device_id === gran.record.id)!;
  assert.deepEqual(
    openGroupKey(granEpoch1.wrapped_key, keypair(gran), 1, before.commitment, everyone),
    epoch1,
  );
  assert.equal(after.wrappedKeys.some((w) => w.device_id === gran.record.id), false);
  for (const w of after.wrappedKeys) {
    assert.throws(
      () => openGroupKey(w.wrapped_key, keypair(gran), 2, after.commitment, everyone),
      /failed to open/,
    );
  }
});

test('an epoch stays openable after its minting device leaves the group', () => {
  // The migration hazard worth a test. Dad mints, then leaves. Gran must still
  // be able to open that epoch, which she can only do if the host keeps serving
  // dad's device record. See EpochTrustContext.
  const key = generateGroupKey(seededRandom(6));
  const { wrappedKeys, commitment } = prepareGroupKeyFanout({
    groupId: GROUP,
    epoch: 4,
    ownDeviceId: dad.record.id,
    ownPublicKeys: pubKeys(dad),
    ownEdSecretKey: dad.edSecretKey,
    groupKey: key,
    devices: [founder.record, dad.record, gran.record],
    policy: 'self-signature',
    random: seededRandom(),
  });
  const granCopy = wrappedKeys.find((w) => w.device_id === gran.record.id)!;

  const withHistory = trustCtx(
    [founder.record, gran.record, dad.record], // dad retained as a past signer
    [attest(founder, dad), attest(founder, gran)],
  );
  assert.deepEqual(
    openGroupKey(granCopy.wrapped_key, keypair(gran), 4, commitment, withHistory),
    key,
  );

  // Drop dad from the set a host serves and the epoch stops opening — the
  // failure this test exists to warn about. It reports 'untrusted-signer'
  // rather than 'bad-signature': there is no key to check against, so the
  // problem is that nobody in the group is this device, not that the bytes are
  // wrong. Reading it the other way sends you hunting corruption.
  const currentOnly = trustCtx([founder.record, gran.record], [attest(founder, gran)]);
  assert.throws(
    () => openGroupKey(granCopy.wrapped_key, keypair(gran), 4, commitment, currentOnly),
    (err: unknown) => err instanceof EpochProvenanceError && err.reason === 'untrusted-signer',
  );
});

test('a signer the group has never heard of is refused as untrusted', () => {
  // The distinction the reason codes have to keep straight: an unknown signer
  // is a trust failure. `injected` here has real keys and signs correctly — it
  // is simply not one of this group's devices.
  const forged = new Uint8Array(32).fill(0x99);
  const blob = sealGroupKeyTo(forged, gran.publicKeyBase64, seededRandom(77));
  const commitment: EpochCommitment = {
    group_id: GROUP,
    epoch: 9,
    signer_device_id: injected.record.id,
    signature: signEpochCommitment(injected.edSecretKey, GROUP, 9, forged),
  };

  assert.throws(
    () => openGroupKey(blob, keypair(gran), 9, commitment, everyone),
    (err: unknown) => err instanceof EpochProvenanceError && err.reason === 'untrusted-signer',
  );
});
