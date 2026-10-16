# Decision Log

Security-sensitive decisions, recorded before implementation. Each entry states the
decision, why, and what it costs. Reversing one of these is a design change, not a
refactor.

---

## D1 — Cryptographic protocol and implementation

**Date:** 2026-09-27 · **Status:** Accepted, validation outstanding

**Decision:** Signal Protocol (X3DH + Double Ratchet) via pub `libsignal` `7.3.1`, an
FFI binding over `signalapp/libsignal` (Rust).

**Why:** the reviewed upstream covers not just the ratchet but X3DH, prekeys and the
identity/session stores — the trust-decision layer we would otherwise hand-write.

**Rejected:** vodozemac/Olm (audit does not cover the key-authentication layer, which has
no Dart equivalent, and the acknowledged all-zero-key gap is still unfixed as of 0.11.0);
OpenMLS (immature bindings, experimental PQ suites, group-shaped); `libsignal_protocol_dart`
(unaudited pure-Dart reimplementation); hand-written FFI (unreviewed glue, no other users).

**Cost:** the Dart binding is from an unverified pub.dev publisher. Pinned exactly; any
upgrade is a security-relevant review. Full analysis in [crypto-design.md](crypto-design.md).

**Note:** this reverses an initial lean toward vodozemac, which was based on its audit
without accounting for that audit's *scope*.

---

## D2 — Distribution model

**Date:** 2026-09-27 · **Status:** Accepted

**Decision:** private, self-hosted, small known user base.

**Why:** it is the actual intent, and it makes AGPL-3.0/GPL-3.0 copyleft a non-constraint.

**Cost:** if public app-store distribution is ever wanted, revisit D1 — AGPL-3.0's
app-store exception helps, but the choice was made without store distribution as a
requirement.

---

## D3 — Invitation model

**Date:** 2026-09-27 · **Status:** Accepted

**Decision:** one invitation both authorises registration and creates the pending
friendship. An `invitations.purpose` column is added now so registration-only invites can
exist later without a migration. A seed script, gated by an environment flag, creates
user #1.

**Why:** resolves a genuine gap in the brief — registration was required to be
invite-controlled with no stated issuer for the first account, and the `invitations` table
had no way to distinguish invite types.

**Cost:** one invitation carries two meanings, so its rate limits and abuse surface cover
both. The bootstrap flag is a privileged path and must be off in normal operation.

---

## D4 — Verification authority is the client

**Date:** 2026-09-28 · **Status:** Accepted

**Decision:** verification state is a client-local trust decision. `friendships.verified_at`
is advisory server metadata only.

**Why:** the brief requires that the server not be the sole authority for identity
verification. If a client trusted a server-set flag, a compromised server could display
"verified" for a key it substituted — defeating the one defence against key substitution.

**Cost:** verification does not survive a reinstall without re-verification. Correct, and
worth the friction.

---

## D5 — The server does not retain delivered messages

**Date:** 2026-09-28 · **Status:** Accepted

**Decision:** envelopes are deleted once delivery is acknowledged; undelivered messages
expire after a bounded window.

**Why:** the largest available reduction in exposure from a stolen database or compromised
server. History belongs on devices.

**Cost:** no server-side history restore. A user who loses a device loses its history,
since Phase 1 has no key backup. Makes device-side backup a real Phase 2+ requirement
rather than an optional extra.

---

## D6 — Crypto selection validated; PQXDH is mandatory

**Date:** 2026-09-28 · **Status:** Accepted

**Decision:** D1 stands. `libsignal` `7.3.1` passed an eleven-test adversarial suite on
Windows x64 (Flutter 3.47.5 / Dart 3.13.4), including the checks that matter most — a
prekey bundle signed by the wrong identity key is rejected, tampered and truncated
ciphertext fail authentication, replays are rejected, and no private key material appears
in a published bundle.

**Consequences that changed the design:**

- **O1 is closed, not deferred.** `PreKeyBundle` *requires* Kyber fields, so the protocol
  is PQXDH. Post-quantum was never ours to enable. Schema gains `device_kyber_prekeys`.
- Protocol device IDs are limited to 1–127, so devices carry a small per-user
  `device_index` for libsignal addressing, separate from the opaque UUID `id`.
- The client must implement its own identity store; the bundled in-memory one is
  trust-on-first-use and would silently accept a substituted key.
- Ratchet operations per remote address must be serialised, and store writes must be
  durable before the output is released. Both failure modes are silent.

**Still outstanding:** no mobile-target build, and no test of ratchet survival across a
real process restart with a persistent store. Recorded in
[crypto-design.md](crypto-design.md).

**Cost:** none beyond D1. The binding's documentation quality was materially better than
its unverified-publisher status suggested, which raises confidence but does not replace
the pinning and review discipline in D1.

---

## D7 — Messaging is allowed before verification

**Date:** 2026-10-09 · **Status:** Accepted

**Decision:** a friendship becomes `active` the moment an invitation is accepted, and
messaging is permitted while unverified. Verification is separate state, and the client
must display an explicit unverified warning.

**Why:** creating an invitation is already the inviter's consent, so a second consent step
adds friction without adding security. The alternative — blocking messages until both
sides mark each other verified — would rest on a *client-reported* flag, since the server
cannot tell whether a human actually compared digits. Trusting that flag would be the
server-as-authority mistake D4 exists to prevent.

**Cost:** a first-contact key substitution is possible against users who never verify.
That risk is inherent to any system whose server distributes keys (threat T2) and is
mitigated by detection, not prevention: an identity key *change* revokes verified state and
warns loudly. The UI carries the weight here, so an unverified conversation must look
different from a verified one.

---

## D8 — Several devices per user, with client-side fan-out

**Date:** 2026-10-09 · **Status:** Accepted

**Decision:** a user may register multiple devices. The sender encrypts separately per
recipient device and submits one envelope per device in a single request; the server
authorises each envelope independently. Cross-device history sync stays out of scope.

**Why:** the `messages` table was already per-recipient-device, so this costs almost
nothing now, whereas retrofitting it later would touch the prekey endpoints, the message
API, the connection registry and the client's send path.

**Consequences:** device indexes are allocated monotonically and **never reused**, even
after revocation — a peer caches sessions by `(userId, deviceIndex)`, so handing a retired
index to a new installation would route messages to the wrong identity key. Registering a
second device rebinds the current session, so a client provisioning two devices must log in
again between them.

**Cost:** your own second device sees no history. Phase 1 has no key backup, so that is
expected rather than a regression.

---

## D9 — Invitation tokens never appear in a URL

**Date:** 2026-10-09 · **Status:** Accepted

**Decision:** two deviations from the endpoint names in the brief, which permits adjusting
them:

| Brief | Implemented |
|---|---|
| `POST /invitations/{token}/accept` | `POST /invitations/accept` with the token in the body |
| `POST /invitations/{token}/revoke` | `POST /invitations/{invitationId}/revoke` |

**Why:** an invitation token is a credential. A credential in a URL path lands in access
logs, proxy logs and error reports, and our request logger would need a special case for
it. In the body it is covered by the existing redaction rules.

**Cost:** divergence from the brief's API listing, recorded here and in
[api.md](api.md).

---

## D10 — Windows secure storage via DPAPI now, package later

**Date:** 2026-10-10 · **Status:** Accepted

**Decision:** implement `SecureKeyStore` with a small `dart:ffi` binding to Win32
`CryptProtectData`/`CryptUnprotectData` for Windows now, behind the interface. Adopt
`flutter_secure_storage` when mobile targets are added.

**Why:** `flutter_secure_storage` is the better long-term choice — one API across Android
Keystore, iOS/macOS Keychain, Linux Secret Service and Windows — but it requires the C++
ATL libraries, which need an elevated Visual Studio Installer run that this session cannot
perform. DPAPI is an OS service rather than cryptography we invent, it is exactly what the
brief names for Windows, and it needs no install.

**Cost and limits, stated rather than implied:** DPAPI ties protection to the Windows user
account, so anything running as that user can unprotect the blobs. It defends against
another user on the machine and against an offline disk copy, **not** against malware
running as the user — which is threat T16, undefended by design. The FFI layer (~50 lines)
is code we own and must review. Other platforms each need their own backend;
`UnavailableSecureKeyStore` throws rather than degrading, so adding a target cannot
silently fall back to unprotected storage.

**This resolves O3** (encrypted local DB choice) too: `package:sqlite3` 3.x with the
`source: sqlcipher` build hook, keyed by a 256-bit key held in the above store.
`sqlcipher_flutter_libs` is EOL and does nothing since 0.7.0.

---

## D11 — Repository path must not contain `&`

**Date:** 2026-10-10 · **Status:** Accepted and **done** — moved 2026-10-10; the client builds and the suite passes 30/30 at the new path

**Decision:** the repository moves from `C:\kaam_kaach\For-me&claude\Private-conv` to
`C:\kaam_kaach\Private-conv`.

**Why:** the `&` breaks tooling that builds shell commands without quoting. It first
showed up as a nuisance — `npm run <script>` resolving `C:\kaam_kaach\tsx\dist\cli.mjs` —
and then as a hard blocker: Dart's native-assets hook runner invokes
`dart compile kernel` with the unquoted path, so `package:sqlite3`'s build hook fails and
**the Flutter client cannot build or test at all**.

Proven by elimination: the identical code builds and passes 18/18 at a path without `&`.
A directory junction does not help, because Dart resolves it back to the real path.

**Cost:** VS Code must be reopened at the new path, and the move cannot happen while VS
Code holds the directory.

---

## D12 — The project is named Bond

**Date:** 2026-10-10 · **Status:** Accepted

**Decision:** the project's official name is **Bond**. `PrivateMessenger` was a working
title. Applied to the Dart package (`bond`), the Windows binary and product strings
(`bond.exe`, "Bond"), the server package (`bond-server`), and all prose.

**Why:** a name was needed before anything user-visible ships — the Windows window title
and executable name are baked into the build, and changing them later invalidates
installers and desktop shortcuts.

**Not renamed, deliberately:** the DPAPI entropy tag
`dev.privateconv.private_messenger.v1` in `dpapi_secure_key_store.dart`. It is an opaque
versioned constant mixed into every DPAPI seal; changing it would make every key already
sealed on a machine permanently unopenable. It is renamed only alongside a `v2` bump with
a migration path. The `dev.privateconv` company identifier and the repository folder name
are likewise unchanged for now.

---

## D13 — Verifying a contact pins the key that was compared

**Date:** 2026-10-10 · **Status:** Accepted

**Decision:** marking a contact verified records the specific identity key the displayed
safety number was derived from, inserting a `peer_identities` row if none exists yet.
Verifying a key that differs from one already pinned is REFUSED and routed to the
identity-change acknowledgement path instead.

**Why:** verification used to be an `UPDATE` on `peer_identities`, and that table has no
row for a contact until a cryptographic operation creates one. So a user who opened the
verification screen before exchanging any message, compared 60 digits out of band and
pressed "the numbers match" recorded **nothing** — silently. Worse, first contact then
behaved as trust-on-first-use: whatever key the server supplied for the first message was
accepted, and the comparison the user had actually performed bought them nothing.

Pinning at verification time is the stronger reading of what the user asserted. They
checked a particular key; that key becomes the trusted one. If the server later serves a
different key, `saveIdentity` sees a change and sending fails closed, exactly as it would
have after a message had been exchanged.

Refusing to verify over a *different* pinned key matters too: otherwise the
identity-change warning could be cleared by pressing "verified" rather than by
acknowledging the change, which is the one path that is supposed to be deliberate.

**Found by:** the vertical-slice test, which verifies before sending because that is the
order a careful user would follow.

**Cost:** a key can now be pinned from the contact list rather than from a completed
handshake. That is not a downgrade — a malicious server could already have supplied that
key for the first message — but it does mean the pinned key for a never-messaged contact
came from the server, and the safety number is what establishes otherwise.

---

## Open questions

Not yet decided; each needs an answer before the phase it belongs to.

| # | Question | Needed by |
|---|---|---|
| ~~O1~~ | ~~Enable Kyber (post-quantum) prekeys?~~ | **Closed by D6 — mandatory, not optional** |
| O2 | Account credential: password, or something else? | Before auth implementation |
| ~~O3~~ | ~~Encrypted local DB choice~~ | **Closed by D10 — sqlite3 3.x + `source: sqlcipher`** |
| O4 | Exact retention windows (30/90 days are current targets) | Before Phase 1 is called done |
| O5 | Sealed sender, to reduce sender metadata | Phase 2+ |
| O6 | Push notifications without content leakage | Phase 2+ |
| O7 | Key backup and multi-device enrolment | Phase 3 |
