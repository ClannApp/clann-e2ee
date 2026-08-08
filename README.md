# @clann/e2ee

The end-to-end encryption core of [Clann](https://getclann.com), a family photo
app. Extracted from the shipping client so it can be read, tested and argued
with on its own.

**→ [PROTOCOL.md](PROTOCOL.md) is the specification.** It describes the scheme,
the threat model, the trust model, and the scope of protection. Read it before
the code.

---

## What this is

A group end-to-end encryption scheme for a shared photo library, in about 900
lines of dependency-light TypeScript:

- **CLN1** — a chunked AES-256-GCM file envelope with an authenticated header,
  detectable truncation, and random access for streaming video.
- **Sealed boxes** — anonymous public-key sealing, wire-compatible with
  libsodium's `crypto_box_seal`, rebuilt from [@noble](https://github.com/paulmillr/noble-curves)
  primitives.
- **Signed device identities** — Ed25519 self-signatures, attestation chains,
  and a founder-signed trust root, which together are what stops a malicious
  server from substituting keys during distribution.
- **Group key exchange** — epoch-versioned group keys, fan-out with an explicit
  verification policy, and rotation that excludes removed members.
- **Recovery** — a BIP39 phrase that derives a virtual device, so a locked-out
  user can let their own new phone in.

Everything is pure: no I/O, no ambient randomness, no platform dependencies. The
same code runs under Hermes, Node and browsers.

## What this is not

No transport, no storage, no server, no membership logic, no UI. Those live in
the host application. [PROTOCOL.md §10](PROTOCOL.md#10-obligations-of-a-host-application)
lists the obligations a host takes on; several are load-bearing, so read them
before integrating.

This library has not yet been externally audited. Reports and review are
welcome — see [SECURITY.md](SECURITY.md).

## Install

```bash
npm install @clann/e2ee
```

Peer requirements: a real CSPRNG, supplied by you (see below), and Node 20+ if
you are running it server-side.

## Use

Randomness is injected rather than imported — the library runs on platforms with
incompatible CSPRNGs, and one that silently degraded on a single platform would
be catastrophic in a way no test would catch.

```ts
import { cln1, keyWrap, groupKey, webCryptoRandom } from '@clann/e2ee';

// On React Native, pass expo-crypto's getRandomBytes instead.
const random = webCryptoRandom;
```

### Encrypt a photo

```ts
const dek = keyWrap.generateDek(random);
const header = cln1.makeHeader(cln1.CLN1_MEDIA_JPEG, epoch, random(16));
const ciphertext = cln1.encryptWithHeader(dek, header, photoBytes);

// Travels with the ciphertext; the server stores it and cannot open it.
const encMeta = keyWrap.wrapDek(currentGroupKey, dek, epoch, random);
```

### Decrypt it

```ts
const dek = keyWrap.unwrapDek(groupKeyForEpoch(encMeta.key_epoch), encMeta);
const photoBytes = cln1.decrypt(dek, ciphertext);
```

### Distribute a group key

```ts
const gk = groupKey.generateGroupKey(random);

const { wrappedKeys } = groupKey.prepareGroupKeyFanout({
  groupKey: gk,
  devices,             // the group's member devices, from your server
  attestations,        // who has vouched for whom
  ownDeviceId,         // this install
  ownPublicKeys,       // read from LOCAL storage, never from the server
  rootDeviceIds: [ownDeviceId, verifiedFounderDeviceId],
  policy: 'attestation-chain',
  random,
});
```

The `policy` argument is the interesting one, and it is explicit because a
fan-out that picked its own verification strength would be impossible to audit
at the call site:

- `'self-signature'` — every recipient must carry a valid self-signature. Use
  this only where a human is reviewing the recipient list at that moment, since
  a self-signature establishes consistency rather than ownership
  ([§5.2](PROTOCOL.md#52-the-scope-of-a-self-signature)).
- `'attestation-chain'` — recipients must additionally chain back to a trusted
  root. Required for anything unattended, above all key rotation.

Verification failures throw. `UnverifiedDevicesError`,
`OwnDeviceKeyMismatchError` and `GenesisVerificationError` are all fail-closed;
there is no "seal anyway" path, and catching one to proceed defeats the scheme.

## API

| Module | What it covers | Spec |
|---|---|---|
| `cln1` | the encrypted file envelope | [§4](PROTOCOL.md#4-cln1-the-file-envelope) |
| `keyWrap` | per-item data keys, wrapped under a group key | [§3.3](PROTOCOL.md#33-why-a-per-item-data-key) |
| `sealedBox` | anonymous public-key sealing | [§3.1](PROTOCOL.md#31-primitives) |
| `deviceKeys` | device keypairs, safety codes | [§3.1](PROTOCOL.md#31-primitives), [§5.4](PROTOCOL.md#54-safety-codes) |
| `identity` | signatures, attestations, genesis, the trust graph | [§5](PROTOCOL.md#5-device-identity-and-trust) |
| `groupKey` | who gets the group key, verified how | [§6](PROTOCOL.md#6-group-key-exchange) |
| `recovery` | phrase-derived virtual device | [§7.2](PROTOCOL.md#72-recovery-phrase--a-virtual-device) |

## Tests

```bash
npm test
```

The CLN1 vectors are generated by an independent Go implementation and
reproduced byte-for-byte here — a round-trip test only proves a codec agrees
with itself, which is the bug that matters least. The suite also asserts the
negative properties directly: that truncation fails, that chunks cannot be
spliced between files, that a server-minted device passes the `self-signature`
policy and is refused by `attestation-chain`, and that a removed member cannot
open a post-rotation epoch.

## Design decisions

Three choices a reviewer is most likely to ask about, answered up front:

- **AES-GCM, not XChaCha20-Poly1305.** XChaCha is preferable on most axes.
  AES-GCM is used because it is the only AEAD `crypto.subtle` offers, so a
  browser can decrypt with no dependencies. The format is cipher-agnostic; a
  future `alg` value can change it.
- **No forward secrecy within a group.** The central trade in the design. A
  member admitted today must be able to read eight years of family photos —
  which is what forward secrecy is built to prevent — and no design provides
  both. [§6.5](PROTOCOL.md#65-on-forward-secrecy).
- **Trust on first use.** The model iMessage and comparable systems use:
  prevention where it is possible, detection where it is not
  ([§5.2](PROTOCOL.md#52-the-scope-of-a-self-signature)). Because a grant
  attests its recipient, the attestation chain inherits that decision
  ([§9.2](PROTOCOL.md#93-grant-time-trust-propagates-into-the-chain)).

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
