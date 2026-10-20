# Security policy

## Reporting a vulnerability

Please report security issues privately, by email to **support@getclann.com**,
or through GitHub's private vulnerability reporting on this repository. Please
do not open a public issue for anything you believe is exploitable.

Useful things to include, in rough order of value:

- what an attacker gains, and what they need in order to get it;
- which file and function the problem is in;
- a proof of concept, or a failing test — the test suite in `test/` is a good
  template, and a failing test is the fastest possible route to a fix.

We will acknowledge within a few working days and keep you updated as we
investigate. If you would like credit in the changelog, say so; if you would
prefer not to be named, that is fine too.

## Scope

**In scope** — anything in this repository: the CLN1 envelope, the sealed-box
construction, the identity and attestation logic, the group key exchange, the
epoch commitments that authenticate it, and the recovery derivation. Also in
scope: any place where the code does not deliver a property
[PROTOCOL.md](PROTOCOL.md) specifies.

A group key that a client will adopt without a valid commitment from a trusted
device ([§6.6](PROTOCOL.md#66-epoch-commitments-where-a-group-key-came-from)) is
the highest-value finding in this repository.

**Known already** — please still report these if you have something new, but we
are aware of them and they are documented in
[PROTOCOL.md §9](PROTOCOL.md#9-scope-boundaries) and
[§2.3](PROTOCOL.md#23-outside-the-schemes-scope):

- Grant-time trust propagates into the attestation chain, so a device admitted
  by a bad human approval is treated as trusted from then on — including for the
  epoch commitments it signs
  ([§9.2](PROTOCOL.md#92-grant-time-trust-propagates-into-the-chain)).
- Metadata is not encrypted (captions, comments, membership, timing, sizes).
- Client-side rather than server-side wrap verification.
- No forward secrecy within a group.
- A compromised member device can read its groups.

If you think the reasoning behind one of these is wrong, or you can sharpen one
into something more serious than we have it, an ordinary issue is the right
place.

Also out of scope: the Clann application, its servers and its infrastructure.
Those are separate from this library — send anything about them to the same
address and we will route it.

## What this library assumes

This is the cryptographic core, not a complete system. It depends on the host
application meeting the obligations in
[PROTOCOL.md §10](PROTOCOL.md#10-obligations-of-a-host-application) — a real
CSPRNG, correct membership, appropriate seed storage, the right fan-out policy,
and never proceeding past a verification failure. A report showing that one of
those is easy to get wrong, or that the API invites getting it wrong, is a
legitimate finding about this library.

## Audit status

This library has not yet been externally audited. Independent review is welcome.
