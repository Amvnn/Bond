# Cryptographic Design

**Status:** Selected, **not yet validated** (see [Validation status](#validation-status))
**Date:** 2026-09-27
**Phase:** 1 — Secure 1-to-1 text messenger

This document satisfies the rule that the cryptographic protocol and implementation are
documented and justified *before* implementation begins. No cryptography is invented here.
Every primitive, ratchet and key-agreement step comes from the selected library.

---

## 1. Selected protocol

**Signal Protocol** — X3DH key agreement plus the Double Ratchet, as implemented by Signal.

| Property | Value |
|---|---|
| Protocol | X3DH (key agreement) + Double Ratchet (message encryption) |
| Implementation | [`signalapp/libsignal`](https://github.com/signalapp/libsignal) (Rust) |
| Dart access | pub [`libsignal`](https://pub.dev/packages/libsignal) `7.3.1` |
| Binding mechanism | `flutter_rust_bridge` `>=2.13.0 <2.13.1` (FFI) |
| Licence | AGPL-3.0 **with an app-store exception** |
| Upstream maintainer | Signal Messenger |
| Binding maintainer | Unverified pub.dev uploader |

### Why this one

1. **The reviewed scope covers the part that matters.** The security of a Signal-style
   messenger lives as much in key distribution and identity trust decisions as in the
   ratchet itself. `libsignal` ships X3DH, signed prekeys, one-time prekeys, the identity
   store, the session store and the Double Ratchet as one reviewed unit. We do not
   hand-write any of it.
2. **It is the reference implementation**, maintained by Signal and deployed at scale in
   Signal's own clients, not a third-party reimplementation of it.
3. **Platform coverage matches our targets** — Android (SDK 24+), iOS (13.0+),
   macOS (10.15+), Linux (arm64/x64), Windows (x64). Web is unsupported for
   `dart2wasm`; web is explicitly out of Phase 1 scope, so this does not bind us.
4. **Licensing is workable.** AGPL-3.0's app-store exception keeps future store
   distribution possible. Our deployment model is private and self-hosted, so the
   copyleft obligation is not a practical constraint today.

### What we take on by choosing it

The binding, not the cryptography, is the weak point. See
[Known limitations](#7-known-limitations).

---

## 2. Alternatives considered and rejected

### vodozemac / Olm (rejected)

[`flutter_vodozemac`](https://pub.dev/packages/flutter_vodozemac) `0.8.1` +
[`vodozemac`](https://pub.dev/packages/vodozemac) `0.8.0`, famedly.com (verified
publisher), AGPL-3.0, over [`matrix-org/vodozemac`](https://github.com/matrix-org/vodozemac)
(Apache-2.0). Audited once by Least Authority
([report, March 2022](https://matrix.org/media/Least%20Authority%20-%20Matrix%20vodozemac%20Final%20Audit%20Report.pdf))
with no significant findings, and in production in FluffyChat and the Matrix Dart SDK.
Its binding is better vetted than the one we chose.

Rejected on **audit scope**, not on the audit's result. In February 2026 Soatok published
[cryptographic issues in vodozemac](https://soatok.blog/2026/02/17/cryptographic-issues-in-matrixs-rust-library-vodozemac/);
Matrix replied in
[Analysis of reported issues in vodozemac](https://matrix.org/blog/2026/02/analysis-of-reported-issues-in-vodozemac/).
Assessing that exchange on its merits:

| Reported issue | Our reading |
|---|---|
| X25519 accepts the all-zero public key (non-contributory DH) | **Acknowledged by Matrix, still unfixed.** `vodozemac` 0.11.0 (2026-09-11) does not list the check. Matrix committed to adding it as defence-in-depth with no release named. |
| Olm V2 to V1 downgrade to 64-bit MACs | **Largely answered.** Olm V2 is unspecified and undeployed, so the downgrade is moot, and Signal truncates MACs comparably. Not a deciding factor. |
| ECIES CheckCode ~6 bits; keys dropped after 40 skipped messages; deterministic pickle IV; non-strict Ed25519 by default | Real sharp edges, mostly avoidable by configuration. Not deciding factors. |

The deciding point is what Matrix's own defence rests on: *identity keys and prekeys are
signed by device keys and verified before session establishment*. That verification logic
lives in `matrix-sdk-crypto`, which **has no Dart equivalent**. Matrix's own audit
commentary notes roughly 80% of the security-critical complexity sits in the SDK rather
than in the Olm implementation. Choosing vodozemac therefore means writing, ourselves and
unaudited, exactly the layer that mitigates its one acknowledged unfixed gap. `libsignal`
gives us that layer from upstream instead.

### OpenMLS / MLS RFC 9420 (rejected for Phase 1)

[`openmls`](https://pub.dev/packages/openmls) `3.2.0`, MIT, over audited OpenMLS Rust.
The only permissively licensed candidate, and the group state machine lives upstream.
Rejected because the bindings are the least mature of the three (unverified publisher,
5 likes, ~1.2k weekly downloads), its post-quantum suites are documented as experimental
and unregistered with IANA, and MLS is group-shaped — a 1-to-1 conversation becomes a
two-member group, which is more machinery than Phase 1 needs. Worth revisiting at Phase 3
(groups), especially if licensing constraints change.

### libsignal_protocol_dart (rejected)

[`libsignal_protocol_dart`](https://pub.dev/packages/libsignal_protocol_dart) `0.8.2`,
mixin.dev (verified publisher), GPL-3.0, ~10.5k weekly downloads, all five targets, no
native toolchain. Attractive operationally.

Rejected because it is a **pure-Dart reimplementation** of the superseded
`libsignal-protocol-java`, with the primitives themselves reimplemented in Dart over
`pointycastle`, `ed25519_edwards` and `x25519`, and **no independent security audit**.
Our requirement is an independently reviewed *implementation*, not merely an independently
reviewed *protocol*. A reimplementation inherits the protocol's design review but none of
the implementation review.

### Hand-written FFI to libsignal (rejected)

Same upstream, but we would author and maintain the bridge. Rejected as strictly worse
than an existing maintained binding: the glue is unreviewed either way, and ours would
additionally be unused by anyone else.

---

## 3. Three kinds of encryption — not interchangeable

Stated explicitly because conflating these is the most common way a system gets
described as more private than it is.

| Layer | What it protects | Who can still read plaintext |
|---|---|---|
| **Transport encryption** (TLS) | Bytes on the wire between client and server | The server, fully. Any operator, any DB reader. |
| **Application-level encryption** (server-side encryption at rest, one app-wide key) | Data on stolen disks | The server, fully — it holds the key. |
| **End-to-end encryption** (this design) | Message content between two devices | Only the sender device and recipient device. |

This project uses TLS **and** E2EE. TLS is not a substitute for E2EE, and E2EE is not a
substitute for TLS: E2EE alone would leave metadata and API traffic exposed on the wire.
Neither protects a compromised endpoint. See [threat-model.md](threat-model.md).

---

## 4. Key types and lifecycle

All private key material is generated on the device and never transmitted. Terminology
follows libsignal.

| Key | Scope | Lifetime | Server sees |
|---|---|---|---|
| Identity key pair | Per **device** | Life of the device installation | Public part only |
| Signed prekey | Per device | Rotated periodically (days) | Public part + signature |
| One-time prekeys | Per device, batch | Consumed once each, replenished | Public parts only |
| Kyber prekeys (PQ) | Per device | See [limitations](#7-known-limitations) | Public parts only |
| Session state (ratchet) | Per **device pair** | Life of the conversation | Never |
| Message keys | Per message | Single message, then deleted | Never |

### Lifecycle

1. **Device install** — generate identity key pair, signed prekey, a batch of one-time
   prekeys. Private material goes straight to platform secure storage.
2. **Registration** — publish only the public identity key, the public signed prekey plus
   its signature, and public one-time prekeys. Server assigns an opaque device ID.
3. **Session establishment** — sender fetches the recipient device's prekey bundle,
   verifies the signed prekey's signature against the identity key, runs X3DH.
   *The signature check is mandatory and fail-closed.*
4. **Messaging** — Double Ratchet advances per message; forward secrecy and
   post-compromise recovery follow from the ratchet.
5. **Replenishment** — client tops up one-time prekeys as the server reports depletion.
6. **Revocation** — see [section 6](#6-device-revocation).

### Prekey exhaustion

One-time prekeys are a consumable resource, so fetching a prekey bundle is an
attacker-triggerable drain. Consumption must be atomic server-side (one bundle hands out
at most one one-time prekey, under a transaction) and rate-limited per requesting user.
Running out must degrade to a signed-prekey-only X3DH rather than failing open or reusing
a one-time prekey.

---

## 5. Identity verification

The server distributes public keys, and is **not** an authority on whether a key belongs
to the person you think it does. A key arriving from the server is *unverified* by
definition, however it is displayed.

- A **safety number / fingerprint** is derived from both parties' identity public keys
  via libsignal, displayed as digits and as a QR code.
- Verification methods: read the digits aloud out of band, compare visually, or scan
  the QR code.
- Verification state is a **client-local trust decision**, persisted on the device.
  `friendships.verified_at` on the server is advisory metadata only — convenient for UI
  hints across reinstalls, never the basis for a trust decision. A server that flips that
  column must not be able to make a client display "verified".
- An identity key change for a known contact is a **security event**: the client warns,
  marks the contact unverified, and requires explicit re-verification. It is never
  silently accepted.

---

## 6. Device revocation

Revocation has both a server-side and a cryptographic consequence, and neither alone is
sufficient.

- **Server-side:** `devices.revoked_at` is set; the device's sessions and refresh tokens
  are invalidated; its WebSocket connections are closed; it may no longer send or receive;
  its prekeys are withdrawn so no new session can be established with it.
- **Cryptographically:** revocation does **not** retroactively protect messages already
  delivered to and decrypted by that device. Those plaintexts exist inside its local
  store. Revocation prevents future sessions; it is not remote deletion.
- **Peers are informed:** contacts' clients are notified so they can drop sessions to the
  revoked device and surface it in the UI.

Stated plainly because "revoke" implies more than it delivers: a revoked device that an
attacker physically holds, with its local store intact, still holds its message history.
Local-store encryption is what limits that, not revocation.

---

## 7. Known limitations

Recorded now rather than discovered later.

1. **The binding is the weakest link.** The Rust core is Signal's reviewed
   implementation; the Dart binding is from an *unverified* pub.dev publisher with 4 likes
   and ~1.75k weekly downloads. The cryptography is not in question — the FFI marshalling
   around it is. Mitigations: pin `7.3.1` exactly, commit lock files, read the binding's
   generated surface as part of review, and treat any binding upgrade as a
   security-relevant change.
2. **Store durability is a correctness requirement, not an optimisation.** The binding
   documents that a store write must reach stable storage before the operation's output is
   released. Violating this can reuse ratchet state after a crash. In-memory stores are
   for tests only and must never ship.
3. **No metadata privacy.** E2EE protects content, not the social graph. The server still
   learns who talks to whom, when, how often, ciphertext size, IP address and online
   status. Sealed sender is available in libsignal but is **out of scope for Phase 1**;
   until then, sender identity is visible to the server. Do not describe this system as
   metadata-private.
4. **Post-quantum status undecided.** libsignal supports Kyber prekeys. Phase 1 neither
   enables nor rules this out; it is a follow-up decision, and until taken, sessions are
   classical-only.
5. **Compromised endpoint defeats everything.** Malware on either device reads plaintext
   after decryption. No messaging protocol addresses this.
6. **Web is unsupported** (`flutter build web --wasm` is blocked upstream in
   `flutter_rust_bridge`). Out of scope, but it forecloses a web client without a
   protocol rethink.
7. **Single audit, upstream only.** Signal's implementation being reviewed says nothing
   about *our* usage of it. Misuse of a correct library is our most likely failure mode.
8. **Backup and multi-device are unsolved here.** Phase 1 has one cryptographic identity
   per installation and no key backup. Losing a device loses its history. Adding
   multi-device later is a protocol-level change, not a UI feature.

---

## Validation status

**Validated on Windows x64, 2026-09-28.** Flutter 3.47.5 / Dart 3.13.4,
`libsignal` pinned to exactly `7.3.1`. Eleven adversarial tests pass. The suite
deliberately asserts that things *fail*: a library that passes a happy path but
accepts a tampered ciphertext is worse than no library.

| Check | Result |
|---|---|
| Native library loads; keys and signatures generate | pass |
| Encrypt/decrypt round trip between two independent identities | pass |
| Ratchet transition (PreKey then Signal message) behaves as specified | pass |
| Replay of an identical ciphertext is rejected | pass |
| Wrong recipient cannot decrypt | pass |
| Tampered ciphertext fails authentication (raises, returns nothing) | pass |
| Truncated ciphertext fails | pass |
| **Prekey bundle signed by the wrong identity key is rejected** | pass |
| Safety numbers agree between both parties (60 digits) | pass |
| Safety number changes when an identity key changes | pass |
| Changed identity key for a known contact is not trusted | pass |
| No private key material present in the published prekey bundle | pass |

### Still outstanding

Not done, and not to be counted as validated:

- [ ] Build on a mobile target. Only the Windows host has been exercised. Android needs
      the SDK installed; iOS needs macOS hardware.

### Closed since: ratchet survival across a restart

**Done, 2026-10-10.** Previously open because the step-4 suite used in-memory stores. Now
covered by `client/test/crypto_service_test.dart` against the real persistent stores
(SQLCipher-backed), 18/18 passing:

- A session survives closing and reopening both participants' databases, as a process exit
  would: Bob replies after the restart, Alice decrypts it, and her next message drops the
  prekey preamble — proving the ratchet was *reloaded*, not rebuilt.
- The outgoing sequence counter stays monotonic across a restart, so a resumed client
  cannot reuse a sequence number the server would reject as a duplicate.
- A one-time prekey consumed during session setup stays consumed after a restart; a lost
  consumption write would let it serve a second session.

Two further properties of the local store are tested there as well, both of which would
otherwise have failed silently:

- `PRAGMA cipher_version` is non-empty, so the sqlite3 build really is SQLCipher. Without
  this check, `PRAGMA key` would be a no-op and the database plaintext.
- The database file is unreadable after swapping the key, and a stored message body does
  not appear in the raw file bytes. That is the strongest available proof that encryption
  is actually on rather than merely configured.

### Verified library behaviour

Facts established by running the library, not by reading about it. Each one changes the
design.

1. **PQXDH is mandatory, not optional.** `PreKeyBundle` requires `kyberPreKeyId`,
   `kyberPreKeyPublic` and `kyberPreKeySignature`; a bundle cannot be assembled without
   them. This settles open question O1: post-quantum is not a decision to defer. The
   schema carries a `device_kyber_prekeys` table accordingly.
2. **Protocol device IDs must be 1–127.** `ProtocolAddress` rejects anything outside that
   range, so our opaque UUID device IDs cannot serve as protocol addresses. Devices
   therefore carry a small per-user `device_index` used *only* for libsignal addressing,
   never as an external identifier.
3. **Store writes must be durable before the output is used.** The library persists the
   advanced ratchet through the store callbacks before returning ciphertext, so the
   ordering is correct by construction — but if a callback resolves before the write is
   durable, a crash rewinds the ratchet and the next send reuses a message key and IV.
4. **Operations for one remote address must be serialised.** `load → ratchet → store` is
   the critical section, so two concurrent `encrypt` calls for the same address derive the
   same message key with no crash required. A lock inside the store does not help; the
   lock must wrap the whole call.
5. **The bundled in-memory identity store is trust-on-first-use.** It accepts any new key
   silently and only rejects a *changed* one. We must supply our own identity store that
   surfaces changes to the user, per [section 5](#5-identity-verification).
6. **`deserialize` parses but does not authenticate.** Reading a field off a message is
   not verification. Authentication happens at decrypt.
7. **`dispose()` bounds secret residency but does not wipe it.** Native handles hold key
   material until GC, which is non-deterministic; `dispose()` frees promptly but the bytes
   are not zeroised (libsignal's extractable key types have no `Drop`). Call it promptly
   on secret-bearing types and do not claim erasure.
8. **No Rust toolchain is required.** Native binaries are fetched by build hooks with
   fail-closed download verification, so the supply-chain surface is the binary fetch
   rather than a local compile.

Validation suite: `client/test/libsignal_validation_test.dart`. Decisions in
[decisions.md](decisions.md).
