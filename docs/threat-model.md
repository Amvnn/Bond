# Threat Model

**Date:** 2026-09-27
**Phase:** 1 — Secure 1-to-1 text messenger
**Deployment assumption:** privately operated, self-hosted, small number of known users.

This document states what the system defends against, what it does not, and what remains
exposed after the defences work as designed. It is written to be falsifiable: each threat
has a mitigation and a residual risk, and where the answer is "not defended", it says so.

---

## 1. What "private" means here

Five distinct levels are often collapsed into the single word "secure". This system's
target is stated per level.

| Level | Protects against | Mechanism | Phase 1 status |
|---|---|---|---|
| 1 | Network / Wi-Fi attacker | TLS 1.2+ (prefer 1.3) | **In scope** |
| 2 | Curious server operator reading content | E2EE (Signal Protocol) | **In scope** |
| 3 | Actively compromised server | E2EE + authenticated device identity + out-of-band key verification | **In scope** |
| 4 | Stolen database | No plaintext stored; minimal metadata; hashed invite tokens | **In scope** |
| 5 | Compromised endpoint (malware on a user's device) | — | **Out of scope, undefendable at protocol level** |

**Metadata privacy is a sixth axis and is not addressed in Phase 1.** E2EE protects
content, not the fact of communication. See [section 7](#7-residual-risks).

---

## 2. Assets

Ordered by consequence of loss.

| Asset | Where it lives | Consequence if lost |
|---|---|---|
| Device private identity key | Device secure storage only | Impersonation of that device; session compromise |
| Session / ratchet state | Device local store only | Decryption of live conversations |
| Message plaintext | Sender and recipient devices only | Direct content disclosure |
| Local message history | Device local store | Historical content disclosure |
| Account credentials (password hash, refresh tokens) | Server DB (hashed) / device secure storage | Account takeover, new device enrolment |
| Invitation tokens | Shown once to creator; **hash only** in DB | Unauthorised registration; unwanted contact |
| Social graph and timing metadata | Server DB | Who talks to whom, when, how often |
| Ciphertext envelopes | Server DB (queued), devices | Little alone; valuable combined with key compromise |

---

## 3. Trust boundaries

```
+---------------------------------------------------------------+
|  TRUSTED                                                      |
|  User's device: OS secure storage, libsignal, local store,    |
|  plaintext, private keys                                      |
+---------------------------------------------------------------+
                 |  TLS  (boundary 1: transport)
                 v
+---------------------------------------------------------------+
|  PARTIALLY TRUSTED (honest-but-curious; assume compromise)     |
|  Reverse proxy -> Node/Fastify backend -> PostgreSQL, Redis    |
|  Sees: ciphertext, metadata, public keys. Never: plaintext,    |
|  private keys, decryption keys.                                |
+---------------------------------------------------------------+
                 |  (boundary 2: E2EE holds across this)
                 v
+---------------------------------------------------------------+
|  UNTRUSTED                                                     |
|  Internet, other users, unknown devices, hostile networks      |
+---------------------------------------------------------------+
```

The critical property: **boundary 2 is crossed by ciphertext only.** The backend performs
no operation that requires plaintext. If it ever does, the design has regressed.

---

## 4. Attackers

| Attacker | Capability | Motivation |
|---|---|---|
| **A1 Passive network observer** | Reads traffic on a shared network | Content, metadata |
| **A2 Active network attacker** | Intercepts, modifies, replays, MITM attempts | Content, impersonation |
| **A3 Curious operator** | Full read access to DB, Redis, logs, server memory | Content, social graph |
| **A4 Malicious operator / compromised server** | Full control of backend code and key distribution | Content via key substitution |
| **A5 Database thief** | Offline copy of PostgreSQL, no live server | Content, credentials |
| **A6 Authenticated abusive user** | Valid account, attacks other users via the API | IDOR, spam, enumeration, DoS |
| **A7 Unauthenticated remote attacker** | API access only | Auth bypass, injection, resource exhaustion |
| **A8 Device thief** | Physical possession of a locked or unlocked device | Local history, identity key |
| **A9 Endpoint malware** | Code execution on a user device | Everything on that device |

---

## 5. Attack surfaces

1. REST API (all endpoints, authenticated and not)
2. WebSocket endpoint (upgrade, auth, message frames)
3. Prekey distribution endpoints — the key-substitution surface
4. Invitation creation and acceptance
5. Authentication and refresh-token rotation
6. PostgreSQL and Redis (if ever reachable from outside)
7. Device secure storage and local database
8. The dependency supply chain, including the `libsignal` Dart binding
9. Logs and error responses (leak surface)
10. Push notifications (deferred; a known content-leak surface when added)

---

## 6. Threats and mitigations

### T1 — Server reads message content (A3, A4)
**Mitigation:** Signal Protocol E2EE; the server stores only `ciphertext` and metadata. No
`plaintext_message` or `message_search_text` column may exist. No server-side search over
content. Backend logic never decrypts.
**Residual:** metadata remains visible.

### T2 — Malicious server substitutes a public key to MITM a conversation (A4)
The central attack on any E2EE system whose server distributes keys.
**Mitigation:** signed prekeys verified against the identity key before session
establishment (fail-closed); out-of-band safety-number verification; identity-key change
detection with an explicit warning and loss of verified state; verification is a
client-local decision that the server cannot assert.
**Residual:** users who never verify out of band are exposed to a first-contact
substitution. The system can detect *changes*; it cannot validate a *first* key without
user action. This is inherent, not a defect — but it means an unverified conversation is
weaker than a verified one, and the UI must say so.

### T3 — Stolen database (A5)
**Mitigation:** no plaintext at rest; no private keys; password hashes only; invitation
tokens stored as hashes; minimal metadata retention; queued ciphertext expires per policy.
**Residual:** the social graph, timestamps and ciphertext sizes are disclosed. Ciphertext
is disclosed, but useless without device private keys.

### T4 — Ciphertext tampering (A2, A4)
**Mitigation:** authenticated encryption in the protocol; a modified ciphertext fails
authentication on the recipient and is never displayed. Failures are surfaced as security
events, not silently swallowed or retried.
**Residual:** an attacker with write access can *delete* or *withhold* messages. E2EE
gives integrity, not availability.

### T5 — Replay (A2, A4)
**Mitigation:** Double Ratchet message numbering rejects replayed ciphertext; opaque
unpredictable message IDs with a uniqueness constraint; clients deduplicate by message ID.
**Residual:** reordering and selective delay remain possible for an attacker controlling
the relay.

### T6 — Impersonation via a new identity key (A4, A8)
**Mitigation:** identity-key change detection; previously verified contacts become
unverified with a visible warning; never silently trusted.
**Residual:** a user who dismisses the warning accepts the risk. Detection depends on
having seen the prior key.

### T7 — Revoked device keeps operating (A8)
**Mitigation:** `devices.revoked_at` checked server-side on every authenticated request
and WebSocket upgrade; sessions and refresh tokens invalidated; prekeys withdrawn; active
sockets closed; peers notified.
**Residual:** messages already decrypted on that device remain in its local store.
Revocation is not remote wipe.

### T8 — Authentication and authorisation bypass (A6, A7)
**Mitigation:** every protected endpoint authenticates; all authorisation decided
server-side from the token subject, never from client-supplied IDs; ownership checks on
devices; friendship checks before a message may be addressed; short-lived access tokens
with refresh rotation and server-side revocation.
**Residual:** a stolen unexpired access token works until expiry. Keep that window short.

### T9 — IDOR / enumeration (A6)
**Mitigation:** opaque random user and device IDs, never sequential; no public directory;
no user-search endpoint; contacts reachable only through an accepted invitation;
authorisation checked per object, not per route.
**Residual:** none significant if IDs stay opaque and checks stay server-side.

### T10 — Injection (A6, A7)
**Mitigation:** parameterised queries only, no string-built SQL; strict schema validation
on every endpoint; ciphertext treated as opaque bytes and never interpreted.

### T11 — Resource exhaustion and abuse (A6, A7)
**Mitigation:** rate limits on registration, login, invitation creation, invitation
acceptance, prekey fetches, message send and WebSocket connections; request body size
limits; atomic one-time-prekey consumption to bound prekey drain; queue depth limits and
expiry for undelivered messages.
**Residual:** a determined authenticated user can still generate load. Limits reduce, not
eliminate.

### T12 — Secret leakage through logs and errors (A3, A5)
**Mitigation:** structured logging with an explicit deny-list — never plaintext, private
keys, passwords, access or refresh tokens, invitation tokens, session secrets; ciphertext
not logged routinely; production error responses carry no stack traces; secrets from
environment only, never source; `.gitignore` blocks `.env` and key material.
**Residual:** a log misconfiguration is always possible. Reviewing logs for accidental
secrets is a required step before Phase 1 is called done.

### T13 — Transport downgrade / MITM on the wire (A1, A2)
**Mitigation:** HTTPS and WSS in production, TLS 1.2 minimum preferring 1.3, HSTS,
certificate verification never disabled, no arbitrary self-signed certificates accepted in
production, CORS restricted.
**Residual:** a compromised device CA store defeats TLS. E2EE is the second line, which is
the point of having both.

### T14 — Malicious or compromised dependency (supply chain)
**Mitigation:** committed lock files; exact pin of the `libsignal` binding; dependency
vulnerability scanning; binding upgrades treated as security-relevant review.
**Residual:** real and unresolved. An unverified-publisher crypto binding is the single
largest non-endpoint risk in this design. See crypto-design.md limitation 1.

### T15 — Stolen device (A8)
**Mitigation:** private keys in platform secure storage (Keystore / Keychain / DPAPI /
Secret Service); encrypted local message store; safe logout that destroys local key
material and session state.
**Residual:** an unlocked device gives up its history. Secure storage protects at rest,
not against a logged-in attacker holding the phone.

### T16 — Compromised endpoint (A9)
**Mitigation:** none at protocol level.
**Residual:** total, for that device. Must be stated in user-facing security
documentation rather than implied away.

---

## 7. Residual risks

Accepted, and not to be described as solved.

1. **Metadata is not protected.** The server knows who communicates with whom, when, how
   often, message sizes, IP addresses, device platforms and online status. Sealed sender
   is deferred past Phase 1.
2. **First-contact key substitution** is detectable only by out-of-band verification. An
   unverified conversation trusts the server's first answer.
3. **Availability is not protected.** The operator can drop or delay messages. E2EE is
   confidentiality and integrity, not delivery.
4. **Endpoint compromise defeats the system** for the affected device.
5. **The crypto binding is from an unverified publisher.** The upstream Rust is Signal's;
   the Dart FFI layer is not independently reviewed.
6. **No key backup.** Losing a device loses its history — a deliberate Phase 1 trade,
   since backup is the usual place E2EE guarantees quietly leak.
7. **A malicious operator can serve a backdoored client build.** Self-hosting with
   self-built clients narrows this; it does not close it for anyone installing a binary
   they did not build.

---

## 8. Scenario expectations (test targets)

These become automated tests, not aspirations. Tracked against `testing` in the project
brief.

| # | Attack | Expected outcome |
|---|---|---|
| 1 | Attacker steals PostgreSQL | No plaintext, no device private keys obtainable |
| 2 | Attacker intercepts network traffic | TLS protects transport; content independently E2EE |
| 3 | Attacker obtains server credentials | No historical plaintext exposed |
| 4 | Attacker modifies ciphertext | Recipient detects authentication failure; nothing displayed |
| 5 | Attacker presents a new identity key for a contact | Change detected; user warned; verified state lost |
| 6 | Attacker uses a revoked device credential | Server rejects it on REST and WebSocket |

---

## 9. The twenty design questions

Answered explicitly, because unanswered versions of these are where designs fail. Items
marked **deferred** are out of Phase 1 scope and must not be assumed to work.

| # | Question | Phase 1 answer |
|---|---|---|
| 1 | Who can create an account? | Only a holder of a valid, unexpired, unused invitation. Bootstrap: a seed script or env-gated first account creates user #1. |
| 2 | Who can invite someone? | Any authenticated user, rate-limited. |
| 3 | What does the server know? | Account and device IDs, public keys, ciphertext, timestamps, delivery state, social graph, IP. See security-model.md. |
| 4 | What does the server never know? | Plaintext, private keys, message keys, session state, verification decisions. |
| 5 | Database stolen? | Ciphertext and metadata exposed; content and keys are not. |
| 6 | Server compromised? | No historical plaintext. Future key substitution is possible and is what verification detects. |
| 7 | Phone stolen? | Keys in secure storage, history in an encrypted store. An unlocked device is compromised. |
| 8 | Laptop stolen? | Same, with weaker OS guarantees on desktop; documented rather than glossed. |
| 9 | How are devices verified? | Safety number / fingerprint compared out of band; client-local trust decision. |
| 10 | How are keys backed up? | They are not. **Deferred.** |
| 11 | How does a new device join an account? | It registers as a separate cryptographic device. Cross-device history sync is **deferred**. |
| 12 | Device revoked? | Server rejects it; prekeys withdrawn; sockets closed; peers notified; prior local plaintext remains on it. |
| 13 | Offline delivery? | Store-and-forward of ciphertext, delivered on reconnect, never decrypted server-side. |
| 14 | Multi-device sync? | **Deferred to Phase 3.** |
| 15 | Attachments? | **Deferred to Phase 2** (per-file random key, encrypt locally, upload blob, ship the key inside the E2EE message). |
| 16 | Disappearing messages? | **Deferred.** |
| 17 | Metadata retained? | Minimum to operate, with documented retention and expiry of queued messages. |
| 18 | Spam / invite abuse? | Invite-only, single-use expiring revocable tokens, rate limits on creation and acceptance. |
| 19 | Push notifications without leaking content? | **Deferred.** When added, notifications must carry no plaintext and no preview. |
| 20 | What does "private" mean here? | Levels 1-4 of section 1. Not level 5, and not metadata privacy. |
