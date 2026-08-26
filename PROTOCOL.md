# The Clann E2EE protocol

**Version 1.2 · Status: shipped, in staged rollout · Last revised August 2026**

This document specifies the end-to-end encryption scheme used by [Clann](https://getclann.com),
a family photo-sharing app. It is normative: where the implementation in this
repository disagrees with this document, treat the disagreement as a bug in one
of them and say so.

It is written for anyone evaluating the scheme or implementing a compatible
client. It specifies the primitives, the key hierarchy, the trust model, and
the scope of protection — what the scheme covers, and what it deliberately
leaves to other layers.

---

## Contents

1. [Scope and design goals](#1-scope-and-design-goals)
2. [Threat model](#2-threat-model)
3. [Primitives and key hierarchy](#3-primitives-and-key-hierarchy)
4. [CLN1: the file envelope](#4-cln1-the-file-envelope)
5. [Device identity and trust](#5-device-identity-and-trust)
6. [Group key exchange](#6-group-key-exchange)
7. [Recovery](#7-recovery)
8. [What is encrypted, and what is not](#8-what-is-encrypted-and-what-is-not)
9. [Scope boundaries](#9-scope-boundaries)
10. [Obligations of a host application](#10-obligations-of-a-host-application)
11. [Conformance and test vectors](#11-conformance-and-test-vectors)

---

## 1. Scope and design goals

Clann is a shared photo library for a family. A "group" is one family. Members
join over years, on devices they replace, and expect to see the *entire* history
of the library from the moment they are let in — including photos taken before
they joined.

That last sentence is the design constraint that shapes everything else, and it
is worth sitting with, because it is the opposite of what a messaging protocol
optimises for. Signal works hard to ensure that a compromise today cannot
decrypt yesterday's messages. Clann must ensure that a phone admitted today
*can* decrypt eight years of photographs. The two goals are in direct
opposition, and this protocol chooses the second one deliberately (§6.5).

**Goals.**

- Photo and video bytes are readable only on member devices. A server that is
  fully compromised — application, database and object storage — learns nothing
  about image content.
- A member's own new phone recovers access without another human being
  involved, and without any key reaching Clann's servers.
- A removed member cannot read anything uploaded after their removal.
- The scheme resists a *malicious* server, not merely a breached one. A server
  cannot substitute a device's encryption or identity key without being
  prevented or detected by the mechanisms in §5, and cannot mint a group key
  clients will adopt, because an epoch is signed by the device that minted it
  and verified against the trust graph before adoption (§6.6). What this goal
  does not cover is a device wrongly admitted by a human approval: the scheme
  authenticates keys, not people, and §9.2 is precise about the difference.

**Non-goals.**

- Forward secrecy and post-compromise security within a group (§6.5).
- Hiding metadata (§8). The server knows who is in which family, when they
  upload, and how large the files are.
- Protecting against a compromised member device. A device that legitimately
  holds the group key can read the library; this is true of every group E2EE
  system and is not a limitation the cryptography can address.
- Deniability. Attestations are signed and durable, and are meant to be.

---

## 2. Threat model

### 2.1 The adversary

The primary adversary is **the server operator**, in two flavours:

- **Honest-but-curious** — an operator, an attacker who has obtained a database
  dump or object-storage credentials, or a legal demand. This adversary reads
  everything at rest.
- **Actively malicious** — an operator who modifies what clients see. This one
  matters more, because it is the adversary most "end-to-end encrypted" products
  quietly fail to consider. A server that clients trust to report public keys can
  simply report its own.

We also consider a **malicious member** of a group, limited to what they can do
beyond their legitimate access (§9.1).

We do **not** consider a compromised member device, or an adversary who
controls the client build. Nothing below survives either, and any protocol that
claims otherwise is mistaken about where its trust actually sits.

### 2.2 What is protected

Every row is a thing a malicious server can attempt and what stops it. The
common thread: no key is believed on the server's word, whether it is a device's
key or a group's.

| Against | By what | Where |
|---|---|---|
| Server reads photo/video content at rest | Media encrypted client-side under keys the server never holds | §3, §4 |
| Server substitutes a co-member's encryption key while reusing their identity | Ed25519 self-signature binding both keys to a user id | §5.1 |
| Server substitutes **your own** device's key back to you | Local pinning; the client never accepts the server's word about its own keypair | §5.3 |
| Server injects a device into a rotation fan-out | Attestation chain from a signed root: a device no trusted device has attested blocks the rotation. Qualified by §9.2 | §5.5, §6.4 |
| Server names itself the trust root of a group | Founder-signed genesis, verified before any root is honoured | §5.6 |
| Server mints a group key and publishes it as the next epoch | Epoch commitment: the minting device signs the key, and adopters refuse a signer outside the trust graph. Qualified by §9.2 | §6.6 |
| Server replays a real epoch key as a different epoch or into another group | Group id and epoch bound into the commitment | §6.6 |
| A removed member reads new uploads | Key epochs; rotation excludes them from the new epoch | §6.4 |
| Truncation or splicing of encrypted files | Header-as-AAD and last-chunk-in-nonce | §4.3 |

### 2.3 Outside the scheme's scope

These are deliberate boundaries, discussed where they arise.

- **First-contact identity.** A self-signature proves a record is internally
  consistent, not that it belongs to a particular person. Clann uses the same
  trust-on-first-use model as iMessage; §5.2.
- **Metadata.** Captions, comments, filenames, timestamps, sizes, membership
  and the key-request graph are server-visible. §8.
- **Availability against a malicious member.** A member can upload an
  undecryptable key wrap. §9.1.
- **A compromised member device**, as above.

---

## 3. Primitives and key hierarchy

### 3.1 Primitives

| Purpose | Algorithm |
|---|---|
| Bulk encryption | AES-256-GCM, 1 MiB chunks, OAE2 STREAM |
| Key wrapping (asymmetric) | `crypto_box_seal` — X25519 + XSalsa20-Poly1305 + BLAKE2b |
| Key wrapping (symmetric) | AES-256-GCM, 96-bit nonce |
| Signatures | Ed25519 |
| Fingerprints | SHA-256, rendered as BIP39 words |
| Phrase derivation | BIP39 → PBKDF2-HMAC-SHA512 (2048) → HKDF-SHA256 |

**On AES-GCM.** XChaCha20-Poly1305 would be the better choice on most axes —
larger nonces, no timing hazards in software implementations. AES-GCM is used
instead for exactly one reason: it is the only AEAD `crypto.subtle` offers, so a
browser can decrypt Clann media with no dependencies and no WASM. The format is
otherwise cipher-agnostic and a future `alg` value can change it.

**On randomness.** No function in this library reads ambient randomness. Every
operation that needs entropy takes a `RandomSource` (`(n: number) => Uint8Array`).
This is not an aesthetic choice: the library runs under Hermes, which has no
`crypto.getRandomValues`, and a library that silently fell back to a weak source
on one platform would be catastrophic in a way that no test would catch.
Injection also makes every operation reproducible under a fixed generator, which
is how the vectors in §11 exist at all.

### 3.2 The hierarchy

Three tiers. Each layer is wrapped by the one above it; the server holds
ciphertext at every layer and a private key at none.

```
Device identity  ──  X25519 keypair (encryption) + Ed25519 keypair (signing)
   │                 32-byte seeds, generated on-device, never transmitted
   │
   │  crypto_box_seal(GK, device_x25519_pk)          one blob per device
   ▼
Group key (GK)   ──  32 random bytes per group, versioned by epoch (1, 2, 3…)
   │                 held only on member devices; rotated on member removal
   │
   │  AES-256-GCM(GK_epoch, DEK)                     stored as `enc_meta`
   ▼
Data key (DEK)   ──  32 random bytes per photo or video
   │                 encrypts all variants of that item
   │
   │  CLN1 envelope, AES-256-GCM STREAM
   ▼
Media bytes
```

### 3.3 Why a per-item data key

Encrypting files directly under the group key would be simpler and worse:

- **Rotation would rewrite the library.** With a DEK indirection, rotating a
  group means minting a new epoch and re-sealing 32 bytes per device. Existing
  media is untouched — each item records the epoch it was written under, and
  anyone holding that epoch keeps reading it.
- **Sharing one item would mean sharing the group.** Re-wrapping one DEK does
  not.
- **Nonce budget.** A group key directly encrypting every file for years
  accumulates (key, nonce) pairs across an unbounded number of files. A per-item
  DEK confines that to one item's handful of variants.

The wrap is stored as `enc_meta` alongside the ciphertext:

```json
{
  "v": 1,
  "alg": 1,
  "key_epoch": 3,
  "wrapped_dek": "<base64, 48 bytes: 32-byte DEK + 16-byte GCM tag>",
  "dek_wrap_nonce": "<base64, 12 bytes>"
}
```

`key_epoch` also appears in the CLN1 header (§4.2), where it is authenticated.
The two MUST agree; a reader SHOULD treat disagreement as corruption.

A server can validate this record's *shape* and nothing else. It holds no key
and can never determine whether the wrap opens. See §9.1.

### 3.4 Sealed fields: short text under the group key

Captions and comments are the exception to §3.3. They are encrypted with the
group key **directly**, with no DEK indirection, because every argument for the
indirection evaporates at forty bytes: rotation never has to rewrite a caption,
since the epoch travels inside the envelope; there is no per-item sharing story
for one comment; and the nonce budget is the same either way, because a group
key that wraps one DEK per photo already accumulates records at the same rate.
An envelope larger than its plaintext would be the only thing a DEK bought.

The ciphertext is an ASCII envelope, stored in the same column the plaintext
occupied:

```
clnf1.<key_epoch>.<base64 12-byte nonce>.<base64 ciphertext‖tag>
```

`clnf1` is the discriminator and version. The separator is `.`, which is absent
from the base64 alphabet, so the split is unambiguous. Storing the envelope in
the plaintext's own column is deliberate: a group part-way through converting
its backlog holds both shapes side by side, and a reader tells them apart by
the prefix rather than by a second column that would have to be kept in step.

**AAD.** Each field is authenticated against the group and the field name:

```
clann-field-v1|<family group id>|<field>
```

where `<field>` is a stable name — `caption`, `comment` — and neither part may
contain `|`. This binds a caption to one family and one kind of field: the
server cannot present family A's caption as family B's, nor a caption as a
comment. It does **not** bind the record id; see §9.5.

**Padding.** Plaintext is prefixed with a 2-byte big-endian byte length and
zero-padded to a multiple of 32 bytes before encryption, so "ok" and "lovely
photo" are indistinguishable in size. Length is bucketed, not hidden — a long
comment still looks longer than a short one. Fields longer than 65535 UTF-8
bytes cannot be represented and MUST be rejected rather than truncated.

Implementations MUST NOT fall back to displaying the raw stored value when an
envelope fails to open. A reader that does will put ciphertext on screen the
first time a rotation outruns a key sync.

---

## 4. CLN1: the file envelope

Every encrypted photo, video and thumbnail is a CLN1 file. Reference
implementation: [`src/cln1.ts`](src/cln1.ts).

### 4.1 Overview

```
┌────────────────────────────┐
│ header (32 bytes, plain)   │  also the AAD for every chunk below
├────────────────────────────┤
│ chunk 0   (n + 16 bytes)   │  AES-256-GCM
│ chunk 1   (n + 16 bytes)   │
│ …                          │
│ chunk k   (≤ n + 16 bytes) │  final chunk; flagged in its nonce
└────────────────────────────┘
```

### 4.2 Header

32 bytes, unencrypted, big-endian:

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 4 | magic | `43 4C 4E 31` (`"CLN1"`) |
| 4 | 1 | version | `1` |
| 5 | 1 | alg | `1` = AES-256-GCM STREAM |
| 6 | 1 | media | `1` = JPEG, `2` = MP4 |
| 7 | 1 | reserved | MUST be `0` |
| 8 | 4 | chunk_size | plaintext bytes per chunk; default `1048576` |
| 12 | 4 | key_epoch | group key version; MUST be ≥ 1 |
| 16 | 8 | nonce_prefix | fresh CSPRNG bytes, per file |
| 24 | 8 | file_id | fresh CSPRNG bytes, per file |

A parser MUST reject: bad magic, unknown version or alg, unknown media, a
`chunk_size` of zero or above 64 MiB, and a `key_epoch` of zero.

`nonce_prefix` MUST be drawn fresh for every file. Every file starts its chunk
counter at zero, so two files sharing both a DEK and a nonce prefix would reuse
(key, nonce) pairs — the one failure that breaks AES-GCM outright. Per-item DEKs
make this hard to reach; a fresh prefix makes it unreachable.

`file_id` is not used by the cryptography. It exists so that two files with
identical content and key are still distinguishable at rest.

### 4.3 Body

The plaintext is split into `ceil(len / chunk_size)` chunks, and always at least
one — a zero-length file produces a single empty authenticated chunk, so that
"empty" and "deleted" are distinguishable.

For chunk `i`:

```
nonce_i = nonce_prefix (8 bytes) ‖ uint32be(i | (is_last ? 0x80000000 : 0))
aad     = the full 32-byte header
chunk_i = AES-256-GCM-Encrypt(DEK, nonce_i, aad, plaintext_i)
```

Two properties follow, and they are the reason for the construction:

- **The header is authenticated.** Using it as AAD binds every chunk to the file
  it belongs to. A server cannot edit `key_epoch` to point a reader at the wrong
  key, cannot alter `media`, and cannot move chunks between files — the nonce
  prefix differs, and so does the AAD.
- **Truncation is detected.** The final-chunk flag lives inside the nonce, so a
  file cut short at a chunk boundary does not decrypt to a shorter, plausible
  file. It fails to authenticate. Without this, an adversary could silently trim
  the tail of a video.

Because chunks are fixed-size and unprefixed, a chunk at index `i` begins at byte
`32 + i × (chunk_size + 16)`. That is what makes seeking and ranged fetches of
encrypted video possible without downloading the whole file.

### 4.4 Streaming

`Cln1StreamDecryptor` decrypts as bytes arrive. Note one subtlety: a buffered
full-size block cannot be opened until at least one further byte exists, because
until then it might be the final chunk and the final chunk uses a different
nonce. The final chunk is therefore only decryptable at EOF.

---

## 5. Device identity and trust

This is the section to read closely. The file cipher is standard and the sealed
box is libsodium's; neither is where a group E2EE implementation goes wrong.
Key distribution is.

The problem: group keys are sealed to public keys that a client learns *from the
server*. If the server can substitute a key, it can have every member seal the
group key to the server, and the encryption becomes theatre that survives audit.

### 5.1 Self-signatures

Each device holds two keypairs derived from two 32-byte seeds: X25519 for
encryption, Ed25519 for signing. On registration it publishes both public keys
plus a signature over

```
clann-e2ee-device-v1|{user_id}|{x25519_public_key_base64}
```

made with its Ed25519 key. The server verifies this at registration; peers
re-verify before sealing anything.

This catches a **partial substitution**: a server that keeps a real device's
Ed25519 identity but swaps in its own X25519 encryption key produces a record
that does not verify, because the signature covers both.

### 5.2 The scope of a self-signature

A self-signature proves a record is internally consistent — it does not prove
ownership. A server can mint its own Ed25519 and X25519 pair and sign a valid
self-signature over them, so the signature alone does not establish that a
device belongs to the person it claims. This property is asserted directly in
[`test/identity.test.ts`](test/identity.test.ts) so that implementations do not
over-rely on it.

For a device some member has *already* met, the trust graph (§5.5) resolves
this. For a device at **first contact**, Clann uses the trust-on-first-use model
that iMessage and comparable systems use: keys may be granted before a human has
cryptographic assurance, and three mechanisms carry that moment instead.

1. The granting human is looking at a named family member, in an app that says
   who is asking.
2. An optional out-of-band safety-code comparison (§5.4).
3. Detection afterwards (§5.7) — the device owner is notified whenever a device
   is added to their account, which a server cannot suppress.

### 5.3 Pinning your own device

There is one substitution the signature machinery structurally cannot catch: a
server substituting **your own** device's key back to you. Self-signatures do not
help, because a full fake identity self-signs cleanly. The trust graph does not
help, because your own device is a *root*, and roots are not attested.

The defence is that the phone already holds its own keypair and must never
accept the server's word about it. Before any fan-out, `pinOwnDevice`:

1. compares the server's record for this device id against the locally held
   keys, and throws `OwnDeviceKeyMismatchError` on any difference; and
2. forces the local keys into the record, so downstream sealing targets the key
   actually held, not a string that happened to compare equal.

Without this, a malicious server could have a phone seal the group key to the
attacker while believing it sealed to itself — no fake co-member device
required. This applies to every fan-out that includes the caller (enable,
create, rotate), and it MUST run **before** trust is computed: under an
attestation-chain policy, our own record is a root, so verifying before pinning
would seed the trust walk with the attacker's identity and every subsequent
check would be measuring the attack against itself.

### 5.4 Safety codes

A device fingerprint is `SHA-256(ed25519_public_key)`, with the leading 66 bits
rendered as six BIP39 English words:

```
absorb · gravity · pelican · thumb · winner · zebra
```

Both sides of a verification MUST fingerprint the same key, or the two screens
show different codes and every legitimate grant looks like an attack.

Six words is 66 bits. A 256-bit hex fingerprint is stronger on paper and nobody
compares it, which makes it weaker in practice. The BIP39 list is chosen for
unambiguous pronunciation and distinct four-letter prefixes — it is designed to
be read down a phone line, which is exactly the channel in use when one family
member is letting another in.

### 5.5 Attestations and the trust graph

When a device grants group keys to another, it also signs the recipient's
identity:

```
clann-e2ee-attest-v1|{device_id}|{x25519_public_key_base64}|{ed25519_public_key_base64}
```

These signatures form a directed graph. `computeTrustedDevices` walks it from a
set of roots to a fixpoint. A device is trusted when its **own self-signature is
valid** *and* either it is a root or an already-trusted device signed a valid
attestation over it.

The ordering matters: self-signature validity gates every node, so an
attestation cannot launder a device whose own binding is *broken*. And because
the attestation covers the device's keys, an attestation signed over one set of
keys stops verifying if the server later swaps them.

Trust propagates along human decisions — "I let Grandma's new phone in" — rather
than along server assertions. Note the boundary of that claim: an attestation
cannot admit a device whose own binding is broken, but a valid binding is not
proof of ownership (§5.2), and a grant attests its recipient (§6.3). The graph
therefore inherits the grant path's admission decisions. §9.2 covers what
follows.

### 5.6 Genesis: signing the root

A graph is only as trustworthy as its roots, and a server that chooses the root
chooses the graph. So the root is signed too. At group creation the founding
device signs:

```
clann-e2ee-genesis-v1|{genesis_id}|{founder_device_id}|{founder_user_id}
```

`genesis_id` is chosen by the client, before the group exists, so it does not
depend on a server-assigned identifier.

Every member verifies this signature — against the founder device's Ed25519 key
taken from the group's *device list*, never from the genesis record itself —
before rooting anything in `founder_device_id`. A group whose genesis fails to
verify has **no** trusted root, and clients MUST fail closed rather than falling
back to a server-reported root. Falling back would reintroduce exactly the
substitution this prevents.

If the founder's device has since been removed, there is no root to add; the
caller's own device plus the existing chain carry the group forward.

### 5.7 Trust on first use, and detection

Clients pin the devices they have seen in a group. On foreground and on group
switch they reconcile the pinned set against the server's:

- a **new** device in the group produces a quiet notice;
- a device whose identity has **changed** produces a loud one — that is the
  genuine tamper signal, and it resolves to one human question: *is that
  expected?* Answering no blocks the device from the group and flags a key
  rotation.

Separately, whenever a device is added to an account, that account's owner is
notified. A server can lie about many things but cannot suppress the fact that
the person whose account was targeted is being told.

First contact is therefore carried by detection alongside prevention — the same
division of labour used by every deployed TOFU system.

---

## 6. Group key exchange

Reference implementation: [`src/groupKey.ts`](src/groupKey.ts).

### 6.1 The membership boundary

**This library verifies keys, not membership.** Given a device set it will
verify identities and seal correctly; it cannot know whether that set is the
group's real membership. Deciding who is a member is the host application's job,
and it is a genuine part of the security boundary — §10 states the obligation.

Key distribution follows membership and never grants it. A request to be keyed
into a group is not a request to join it.

### 6.2 Epochs

A group key is 32 random bytes, versioned by an integer epoch starting at 1. All
epochs remain valid forever: a member who held epoch 1 keeps reading epoch-1
media after a rotation to epoch 2.

Epoch *numbers* are public even though the keys are not, which is what lets a
server enforce the completeness rule in §6.3 without holding anything secret.

### 6.3 Distribution

The group key is distributed by **fan-out**: sealed once per recipient device to
that device's X25519 public key, using an anonymous sealed box. The server
stores the blobs and can open none of them.

"Anonymous" is load-bearing, and it cuts both ways. The ephemeral secret is
discarded after one use, so a sealed blob carries no evidence of who produced
it, and the producer cannot re-open it either. Any "sealed by" field a server
records is ordinary, forgeable bookkeeping — never proof. Provenance therefore
has to be carried by a signature over the key itself rather than by the sealing,
which is what §6.6 specifies; a fan-out emits one and an adopting device
requires it.

`prepareGroupKeyFanout` takes an explicit **policy**, because a fan-out that
silently picked its own verification strength would be impossible to audit at
the call site:

| Policy | Requires | Correct for |
|---|---|---|
| `self-signature` | valid self-signature on every recipient | fan-outs a human is reviewing *at that moment* — enabling encryption on a group, where an admin is looking at their own family's device list |
| `attestation-chain` | additionally, a valid chain from a trusted root | every unattended fan-out, above all rotation |

The distinction is the whole point. `self-signature` accepts a server-minted
device (§5.2); that is tolerable only while a human is vouching for the list in
the same breath. Rotation happens in the background with nobody watching, so an
unrecognised device must **block** it rather than quietly receive the new key.

There is deliberately no "seal anyway" escape and no partial fan-out that skips
a failing device. Both are worse than failing: sealing to an unverified key is
the attack itself, and silently omitting a device locks a real family member out
of everything uploaded afterwards, with no signal to anyone.

**Granting to a new device** seals *every* epoch the group has, not merely the
latest. A partial grant is the nastiest failure mode available here — the device
activates, appears to work, and cannot read the family's older photos. A granting
device that is itself behind MUST refresh first or defer to one that is current;
Clann's server rejects incomplete fulfilments outright.

Two server-side rules complete the picture: the first seal for a
`(group, epoch, device)` wins, so a member cannot overwrite an existing blob;
and a device blocked from a group is excluded from fan-outs *and* refused at
every group-scoped key operation, so that it cannot re-admit itself by
fulfilling a request or triggering a rotation.

### 6.4 Rotation

When a member is removed, the group is flagged for rotation. The next capable
member device mints a fresh key at epoch `latest + 1` and fans it out to the
remaining devices under the `attestation-chain` policy.

The removed member keeps every epoch they already held — they have already seen
those photos, and revoking access to them would be a fiction — and holds nothing
for anything uploaded afterwards.

Rotation is performed by *a member's device*, because the server has no key to
rotate with. Racing devices are serialised by the server: only epoch `latest + 1`
commits, and the loser fails cleanly.

### 6.5 On forward secrecy

The scheme deliberately does not provide forward secrecy within a group, and
the reason is structural rather than incidental.

A ratchet gives forward secrecy by ensuring that later key material cannot
decrypt earlier ciphertext. Clann's central requirement is that a member
admitted today can read the entire library, including everything from before
they joined. These are the same property viewed from opposite ends, and no
design provides both.

This protocol therefore optimises for the risk families actually face. The
realistic catastrophe is not an adversary decrypting a photo from 2019; it is a
grandmother getting a new phone and losing eight years of her grandchildren.
§7 is where most of the design effort went, which is the correct allocation for
this product.

The compensating control is epoch rotation, which bounds what a compromised
device retains going forward.

### 6.6 Epoch commitments: where a group key came from

Sealing establishes that a key reached the right device. It establishes nothing
about who sent it, because the seal is anonymous (§6.3): any party holding a
device's X25519 public key — the server included, since it stores and serves
that key — can construct a blob that device opens. Without a further check, a
server could generate 32 bytes of its own, seal them to every member, publish
them as the next epoch, and read everything written under it.

The §5 machinery does not close this by itself. Self-signatures, own-device
pinning, the attestation chain and genesis all authenticate *which device a key
belongs to*; none of them says anything about where a *group* key came from, and
an attack that substitutes no device key passes all of them.

So a group key is signed by the device that mints it. The signature covers:

```
clann-e2ee-epoch-v1|{group_id}|{epoch}|{base64(sha256(group_key))}
```

The digest rather than the key, so that committing to a key never puts key
material into a value meant to be published. Both `group_id` and `epoch` are
bound, and neither is redundant: without the group id a commitment could be
replayed into another group its signer belongs to, and without the epoch it
could be replayed as a later epoch of the same group. In each case the server
would be re-serving a real key, which is why a signature over the key alone
would not catch it.

The result travels as an **epoch commitment** — `group_id`, `epoch`,
`signer_device_id`, `signature` — stored once per epoch and served alongside
every wrapped copy of that key. One per epoch, not one per recipient: it commits
to the key, so it stays valid however many times the key is later re-sealed to
devices admitted afterwards.

`group_id` here means whatever identifier the host treats as the group's
authenticated identity, and the choice matters. It must be one the server cannot
reassign, and it must exist before the key is minted — otherwise a group created
encrypted from birth has nothing to commit to, because its id does not exist
until the server answers. Clann binds the **genesis id** (§5.6) for exactly
these reasons: client-chosen, immutable, and signed by the founder before the
group row exists. A server-assigned row id would satisfy neither.

Where the commitment travels is the host's business — alongside each wrapped
copy, or stored once against the epoch and served with it. What is not
negotiable is that a client has one before adopting.

Before adopting a key, a client MUST establish all of the following, and MUST
fail closed if any fails:

1. the blob opens with this device's X25519 secret key;
2. the commitment's `group_id` and `epoch` are the ones being requested;
3. the signature verifies against the Ed25519 identity of `signer_device_id`,
   over the digest of the key that actually opened;
4. `signer_device_id` is **trusted**, by the same trust-graph walk a fan-out
   uses on its recipients (§5.5) — a valid signature from a device nobody has
   vouched for is precisely what an injecting server would produce.

Checks 3 and 4 are separate and both required. This is the step that is easy to
get wrong: verifying a signature without asking whose it is leaves the attack
completely intact.

A server holding no trusted device's Ed25519 secret key cannot satisfy 3 and 4
together, and so cannot mint an epoch that any client will adopt.

Two consequences worth stating. **A grant forwards the original minter's
commitment** rather than re-signing (§6.3): the granting device did not mint
those epochs and must not claim to, or the recipient loses sight of who actually
produced a key. And because commitments must verify years later, the device set
a client checks against has to include the devices that *signed past epochs*,
even after they leave the group — an obligation on the host, in §10, and a
data-loss bug if missed rather than a security one.

What this does not cover is a device that was wrongly let in by a human. Such a
device is in the trust graph, so keys it mints verify normally. That boundary is
§9.2, and it is a property of the admission decision rather than of this
mechanism.

**Scope.** Provenance is a property a group has from birth. A group encrypted
with a signed epoch-1 commitment requires one on **every** epoch thereafter; a
group encrypted before this mechanism existed keeps its former behaviour, and
the injection described above remains possible there. The two are distinguished
explicitly rather than guessed at.

Hosts MUST record which kind a group is at the moment it is encrypted, MUST
refuse an uncommitted epoch for a group that requires them — otherwise a member
on an older build can rotate it back into ambiguity — and MUST NOT allow the
property to be cleared once set. Clients should pin it locally on first sight,
since a server able to report "this group does not require commitments" could
otherwise downgrade a protected group onto the unverified path.

---

## 7. Recovery

Losing access is the dominant real-world risk in this system. It is far more
likely than any attack in §2, and it is unrecoverable in a way that a breach is
not — nobody can restore what nobody can decrypt. Three paths exist, tried in
order of decreasing convenience.

### 7.1 Device seed sync — the user's own phone

A device's entire identity is two 32-byte seeds. Everything else derives from
them, which means a device can be *restored* rather than re-admitted: move the
seeds to a new phone and it is cryptographically the same device, so the group
keys already sitting on the server unwrap with no approval and nobody's
permission.

Clann mirrors the seeds into the user's own platform key sync — iOS Keychain
with `kSecAttrSynchronizable` (iCloud Keychain), Android via Google Block Store
with cloud backup. Both are end-to-end encrypted to the user's platform account.

This is a deliberate threat-model shift and should be read as one: the seed now
exists in the user's iCloud or Google account. It never reaches Clann's servers,
and the trade is made knowingly — it converts the most common catastrophic
outcome into a non-event.

The corollary is that **the seeds are the whole account**. Where a host
application keeps them is the single largest decision it makes about this
system's real-world security, and it is a host decision, not a library one.

### 7.2 Recovery phrase — a virtual device

A 12-word BIP39 phrase (128 bits) deterministically derives a keypair:

```
seed      = BIP39 mnemonicToSeed(phrase)              // PBKDF2-HMAC-SHA512, 2048 iterations
x25519_sk = HKDF-SHA256(seed, info = "clann-recovery-x25519-v1",  32 bytes)
ed25519_sk = HKDF-SHA256(seed, info = "clann-recovery-ed25519-v1", 32 bytes)
```

with no HKDF salt. The labels are versioned and load-bearing: changing either
orphans every phrase already written down, with no migration path, because the
phrase is the only copy of the key.

PBKDF2 with 2048 iterations is weak stretching by modern standards. It is
adequate here *only* because the input carries 128 bits of machine-generated
entropy — it is not a password, and this construction must not be reused for
anything a human chose.

The derived keypair is registered as an ordinary device, flagged as virtual.
From then on it needs no special handling anywhere: every enable and every
rotation seals to it because it is simply in the active device list, so it always
holds the current epoch. Recovery is then not a separate protocol — derive the
keypair, unwrap the keys already sealed to it, and use that identity to grant to
the new phone along the same path a family member's approval would take.

The phrase is never stored, never transmitted, and not derivable from anything
the server holds. One phrase per account; registering a new one revokes the old.

### 7.3 Social recovery — asking a family member

The universal fallback: a device that holds keys grants them to a device that
does not, after the granting human approves. This is the path the whole
key-request mechanism exists to serve, and it is the only one that works for a
user who has lost both their phone and their phrase.

Because it is a human decision, the permission rules are about human roles
rather than cryptography. In Clann: letting a *new person* into a group is an
admin decision; approving *another member's* new device is an admin decision;
approving your *own* second device can be done by any accepted member — which is
what lets the recovery phrase self-serve.

---

## 8. What is encrypted, and what is not

**Encrypted end-to-end:**

- Photo bytes — original, medium and thumbnail variants.
- Video bytes and video poster images.
- Voice notes: the audio is a CLN1 file like any other (§4).
- Captions and comments, as sealed fields (§3.4).
- EXIF and GPS data are **stripped client-side** for encrypted groups and never
  uploaded at all.

**Not encrypted — visible to the server:**

- Group names, member names, avatars and the membership graph.
- Who wrote which caption or comment, and when. Only the text is sealed; the
  authorship and timing of every one of them is in the clear.
- Reactions — which emoji a member put on which item.
- Subject tags: which people and children appear in which item. These drive
  server-side filtering ("photos of Aoife"), so encrypting them would move that
  query onto the client; the trade is deliberate and unresolved.
- Which groups and which items are encrypted; epoch numbers; upload times;
  ciphertext sizes; media type; image dimensions.
- All device public keys, attestations, and the key-request graph — who asked to
  be let in, who approved, and when.
- Push notification metadata. Encrypted groups lose push image previews
  entirely, because the operating system fetches those and cannot decrypt them.
  For the same reason a comment's text cannot appear in a push body: the OS
  renders that string and holds no key. Encrypted groups get a generic body and
  the sealed text in the payload, which the app opens once it is running.
- For groups that enabled encryption *after* uploading, any location and
  subject metadata attached to those older photos, unless separately purged.

**Scope of claims.** The server can tell that a family exists, who is in it, how
often they post and how large their photos are; it cannot see the photos.
Product copy built on this scheme should scope its claims to image content
accordingly.

Older photos in a group that switches on encryption stay plaintext until
migrated. This is deliberate: encryption takes effect going forward
immediately, and rewriting the backlog is a separate, optional operation that
rewrites existing files and so requires every member to be keyed first.

The same is true of text. Captions and comments written before a group was
encrypted stay plaintext until a keyed member device seals them in place — the
server cannot do it, holding no key. Until that sweep finishes, a group holds
both shapes in the same columns, which is exactly what §3.4's prefix is for. A
group whose members never open the app again keeps its old text in the clear
indefinitely; there is no server-side path that would change that, and claims
made about a family's history should account for it.

---

## 9. Scope boundaries

Consequences of the design, with the reasoning behind each.

### 9.1 Wrap integrity is verified by clients, not the server

The server validates that `enc_meta` has the right *shape* — 48-byte wrapped
DEK, 12-byte nonce — and nothing more. Holding no key, it cannot determine
whether the wrap opens. This follows directly from the scheme working: a server
that could check would be a server that could read.

Verification therefore happens client-side, and is applied where the stakes are
highest — migrating an existing library. Before committing, the client decrypts
the ciphertext it just produced using the DEK **unwrapped from the `enc_meta` it
is about to persist**, not the DEK still in memory, and asserts it reproduces the
original. Plaintext is retained for a grace period before deletion.

The residual case is a buggy or malicious member client storing a wrap that does
not open, leaving other members with media they cannot decrypt. That is an
availability concern rather than a confidentiality one, and on the ordinary
upload path it costs a single photo.

### 9.2 Grant-time trust propagates into the chain

Granting keys (§6.3) verifies the recipient's self-signature, seals it every
epoch the group holds, and then attests it — entering it into the trust graph.

Since a self-signature is not proof of ownership (§5.2), the attestation chain
inherits whatever the grant admitted and afterwards treats it as settled. A
device admitted at first contact is therefore included in later rotations
automatically. Put precisely: the chain blocks devices nobody has vouched for;
it does not re-examine devices somebody has, so it does not by itself prevent
server key injection. Its strength is that of the human approval at its edge.

The out-of-band safety-code comparison (§5.4) is the one check here that does
not route through the server, and is what an implementation should make
mandatory for first-contact grants if it wants that approval to be more than
social friction. Detection (§5.7) covers the rest, after the fact.

Granting all epochs rather than only the current one is a deliberate trade for
availability — a partial grant silently leaves a real member unable to read old
photos — but it does mean a bad approval reaches the group's history, not just
its future.

### 9.3 Metadata

Covered in §8. What is left in the clear there — authorship, timing, reactions,
subject tags, the membership graph — is out of scope for this protocol.

### 9.4 One wrapped key per item, per group

An item's `enc_meta` carries exactly one DEK wrapped under one group's key.
Sharing an encrypted item into a *second* encrypted group is therefore not
possible without a device that belongs to both re-wrapping the DEK, and Clann
currently blocks the operation rather than doing so.

### 9.5 Sealed fields bind to a group, not to a record

A sealed field's AAD (§3.4) covers the family group and the field name, so a
malicious server cannot move a caption into another family or replay it as a
comment. It CANNOT stop that server moving a caption from one photo to another
*within* the same group, or attaching a comment to a different photo.

The reason is availability of the identifier, not oversight: photo and comment
ids are minted server-side, after the client has already sealed the text.
Binding to them would mean handing clients id generation, with the forgery
surface that implies. The residual capability is the same class as reordering a
feed — an integrity gap within a group whose members already trust each other,
not a confidentiality break — and it is accepted on those terms.

### 9.6 Rotation is performed by member devices

The server cannot rotate, having no key. Rotation is carried out by the first
member device that both holds the current epoch and has permission, so a group
continues on its existing epoch until such a device comes online. Removal of a
member takes effect for new uploads from that point; the interval is a function
of app usage rather than of the protocol.

### 9.7 Server-side media operations require plaintext

Operations that read pixels server-side — rotation, blur-on-the-fly, print
fulfilment — are not available for encrypted groups, and the equivalent work is
done on the client. This is a functional consequence of the design rather than a
security one, noted here so implementers plan for it.

---

## 10. Obligations of a host application

This library is the cryptographic core. It performs no I/O, holds no state, and
makes no network calls. A host application taking it on assumes the following,
and the scheme's security depends on all of them:

1. **Provide a real CSPRNG.** Everything rests on this.
2. **Own membership.** The library verifies keys, not membership (§6.1). The
   device set handed to a fan-out must be the group's real member device set.
3. **Store seeds appropriately.** The device seeds are the account (§7.1).
4. **Choose the fan-out policy correctly.** `self-signature` only where a human
   is reviewing the list in that moment; `attestation-chain` everywhere else
   (§6.3).
5. **Never fall back on a verification failure.** `UnverifiedDevicesError`,
   `OwnDeviceKeyMismatchError`, `GenesisVerificationError` and
   `EpochProvenanceError` are all fail-closed signals. Catching one and
   proceeding defeats the entire scheme.
6. **Store and serve epoch commitments.** Every epoch's commitment must be
   persisted when it is minted and returned alongside every wrapped copy of that
   key (§6.6). A key served without one cannot be adopted by anyone. Bind an
   identifier the server cannot reassign and that exists before the key is
   minted. Record at encryption time whether a group requires commitments,
   refuse an uncommitted epoch for one that does, and never clear the flag.
7. **Serve historical device records.** Provenance checks resolve
   `signer_device_id` years after the fact, so the device set a client verifies
   against must include devices that signed past epochs even once they have left
   the group. Serving only current members makes old epochs unopenable — a
   data-loss bug, and one that surfaces long after the change that caused it.
8. **Surface trust changes to humans.** The first-contact gap is closed by
   detection (§5.7), which only works if a person is actually told.
9. **Grant all epochs.** Never a subset (§6.3).
10. **Strip EXIF and location data client-side** before encrypting, if the
    claims in §8 are to hold.
11. **Never render an unopened sealed field.** A field that fails to open is
    `locked` or `unreadable`, never the raw stored value (§3.4). Two seams make
    this easy to get wrong. A push notification body is rendered by the
    operating system with no key available at all, so it must be generic for an
    encrypted group. And a *mixed-version fleet* will contain clients that
    decrypt media but not fields: a host MUST be able to tell those apart —
    a boolean "supports E2EE" signal cannot — and MUST redact sealed text
    server-side for the ones that cannot open it. There is no fallback to offer
    them, because the plaintext no longer exists and the server holds no key.
12. **Guard the write side of a backlog sweep.** Sealing a field that is already
    sealed produces a doubly-wrapped value that opens to ciphertext. A host that
    lets several devices sweep the same group concurrently MUST make the write
    conditional on the stored value still being plaintext, and SHOULD reject a
    replacement that is not envelope-shaped — otherwise a buggy client can write
    plaintext back and the row will look converted forever.

---

## 11. Conformance and test vectors

The CLN1 vectors in [`test/vectors.json`](test/vectors.json) are generated by an
**independent Go implementation** and reproduced byte-for-byte by this one. That
matters more than it might appear: a round-trip test proves only that a codec
agrees with itself, which is exactly the bug that matters least. Two
independently written implementations agreeing on bytes is what pins a format.

Each vector supplies a key, a header, a plaintext and the expected file. A
conforming implementation MUST reproduce `file_hex` exactly from
`(key, header, plaintext)`, and MUST recover `plain_hex` from `(key, file)`.

The recovery-phrase derivation is pinned by a golden vector in
[`test/recovery.test.ts`](test/recovery.test.ts). A change that breaks it
orphans every phrase in the wild, so it is asserted rather than assumed.

The suite also asserts several *negative* properties directly — that truncation
fails, that chunks cannot be spliced between files, that a partially swapped key
is refused under both policies, that a server-minted device passes the
`self-signature` policy and is refused by `attestation-chain`, that a removed
member cannot open a post-rotation epoch, and — for §6.6 — that a key with no
commitment, a key signed by an untrusted device, a genuine commitment reused
over a substituted key, and a commitment replayed from another epoch or another
group are each refused.

Run it with `npm test`.

---

## Changelog

| Version | Date | Change |
|---|---|---|
| 1.2 | August 2026 | **Sealed fields (§3.4).** Captions, comments and voice notes are now inside the encryption boundary: short text is sealed directly under the group key as a `clnf1.` envelope stored in the plaintext's own column, and voice-note audio becomes an ordinary CLN1 file. §8 is rewritten accordingly, and is now explicit about what remains in the clear — authorship, timing, reactions and subject tags. New scope boundary §9.5 records that a sealed field binds to a group and a field name but not to a record id, with the reasoning; the later boundaries are renumbered. New host obligations 11 and 12 cover never rendering an unopened field — including server-side redaction for clients in a mixed-version fleet that decrypt media but not fields — and guarding concurrent backlog sweeps. Additive: no existing envelope, wrap or signature changes, and a reader that predates this version sees text it cannot interpret rather than text it misreads. |
| 1.1 | August 2026 | **Epoch commitments (§6.6).** Group keys are now signed by the device that mints them and verified against the trust graph before adoption, closing the group-key injection gap that version 1 documented as a known weakness, for groups encrypted from this version onward; the remaining boundaries in §9 are renumbered accordingly. Breaking: `prepareGroupKeyFanout` requires `groupId`, `epoch` and `ownEdSecretKey` and returns the epoch's commitment; `openGroupKey` requires the commitment and a trust context; `openEpochKeys` is removed, since a batch open cannot verify what it adopts. Hosts must store commitments against the epoch and retain historical device records (§10). |
| 1 | August 2026 | Initial public specification of the shipped scheme. |

---

## Reporting problems

Security issues: see [SECURITY.md](SECURITY.md). Corrections and clarifications
to this document are welcome as ordinary issues or pull requests.
