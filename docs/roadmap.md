# Roadmap

**Last verified:** 2026-10-10 against the working tree, not from memory.
**Current position:** Phase 1, steps 1–16 of 20 complete, and the MVP vertical slice
(1.6) passes end to end against a live server. 98 tests green: 43 client, 55 server.
What remains is hardening (17–19) and the completion review (20).

Legend: `[x]` done and verified · `[~]` partially done · `[ ]` not started
A box is only `[x]` when something was *run* and passed, not when code exists.

---

## Phase 0 — Foundation `[x]`

```
Phase 0
├── [x] 1. Repository structure
│   ├── [x] client/ server/ docs/ security/ infra/ scripts/ tests/
│   ├── [x] .gitignore (secrets, key material, local DBs)
│   └── [x] .env.example with no real secrets
├── [x] 2. Architecture documentation ....... docs/architecture.md
│   ├── [x] System + client/server structure
│   ├── [x] Trust boundaries, data flow
│   └── [x] All 9 flows (auth, device reg, invite, verify, message, offline)
├── [x] 3. Threat model .................... docs/threat-model.md
│   ├── [x] Assets, 9 attacker profiles, 10 attack surfaces
│   ├── [x] 16 threats with mitigations
│   ├── [x] 7 named residual risks
│   └── [x] All 20 design questions answered explicitly
├── [x] Server-visibility inventory ........ docs/security-model.md
└── [x] Decision log ....................... docs/decisions.md
```

**Conflicts in the brief found and resolved:** invite-bootstrap gap (nobody could invite
user #1); server-side `verified_at` treated as authoritative when verification must be
client-local; `friendships` needed canonical pair ordering; one-time prekeys are
attacker-drainable.

---

## Phase 1 — Secure 1-to-1 text messenger `[~]`

### 1.1 Cryptography `[~]` — step 4

```
├── [x] Protocol selected ............ Signal Protocol (X3DH + Double Ratchet)
│   ├── [x] Library: pub libsignal 7.3.1, FFI over signalapp/libsignal (Rust)
│   ├── [x] Pinned to an exact version (unverified publisher)
│   ├── [x] Licence reviewed: AGPL-3.0 + app-store exception
│   └── [x] Alternatives documented and rejected with reasons
│           (vodozemac, OpenMLS, libsignal_protocol_dart, hand-rolled FFI)
├── [x] Validated — 11/11 adversarial tests pass (Windows x64)
│   ├── [x] Native library loads; keys and signatures generate
│   ├── [x] Encrypt/decrypt round trip + ratchet transition
│   ├── [x] Replay of identical ciphertext rejected
│   ├── [x] Wrong recipient cannot decrypt
│   ├── [x] Tampered ciphertext fails authentication
│   ├── [x] Truncated ciphertext fails
│   ├── [x] Prekey bundle signed by wrong identity key REJECTED
│   ├── [x] Safety numbers agree both sides, change on key change
│   ├── [x] Changed identity key not trusted
│   └── [x] No private key material in published bundle
└── [ ] Validation gaps still open
    ├── [ ] Build on a mobile target (needs Android SDK / macOS)
    └── [ ] Ratchet survives a real process restart with a PERSISTENT store
            ← silent failure mode: skipping this risks message-key reuse
```

**Findings that changed the design:** PQXDH is mandatory (not optional); protocol device
IDs capped at 1–127 so UUIDs cannot be libsignal addresses; the bundled identity store is
trust-on-first-use so we must write our own.

### 1.2 Backend — data layer `[x]`

```
├── [x] Schema applied to real PostgreSQL 18 (12 tables)
│   ├── [x] users, user_credentials, devices, auth_sessions
│   ├── [x] device_signed_prekeys, device_one_time_prekeys, device_kyber_prekeys
│   ├── [x] invitations, friendships, messages, security_events
│   └── [x] Zero forbidden columns (no plaintext, no search index, no private keys)
├── [x] Constraints proven to REJECT bad data (5/5)
│   ├── [x] Bare password where an Argon2id hash belongs
│   ├── [x] Non-canonical friendship pair / self-friendship
│   ├── [x] delivered state with null timestamp
│   └── [x] Invitation both used and revoked
├── [x] Migration runner with immutable-checksum enforcement
└── [x] Dev stack: Docker Compose (Postgres 18 + Redis 8, both 127.0.0.1-only)
```

### 1.3 Backend — authentication `[x]` — step 5

```
├── [x] POST /auth/register   invite-controlled + env-gated bootstrap for user #1
├── [x] POST /auth/login      Argon2id, timing-equalised failure
├── [x] POST /auth/refresh    rotation + reuse detection (revokes whole family)
├── [x] POST /auth/logout     idempotent, server-side revocation
├── [x] GET  /health          db + redis readiness
├── [x] Access-token guard    session + device + account-status revalidated per request
├── [x] Error taxonomy        generic client messages, detail to logs only
├── [x] Log redaction         centralised deny-list, not per-call-site
├── [x] Security audit log    with metadata sanitiser
└── [x] 20/20 integration tests green; typecheck clean; server boots
```

**Two real security bugs caught by these tests and fixed:** `additionalProperties: false`
was a no-op because Fastify's Ajv silently strips unknown fields; reuse detection was
rolled back because the revoke and the throw shared one transaction.

### 1.4 Backend — remaining modules `[x]` — steps 6–13

Complete. 53/53 integration tests green, typecheck clean, and a runnable demo
(`server/scripts/demo-journey.ts`) walks the whole journey end to end.

```
├── [x] 6. Devices
│   ├── [x] POST /devices/register — publish PUBLIC key material only
│   ├── [x] Assign device_index (1–127), monotonic, NEVER reused
│   ├── [~] Structural validation only — signature check is the CLIENT's job
│   │       (XEdDSA is not verifiable in Node; see architecture.md s6 correction)
│   ├── [x] GET /devices — own devices only
│   ├── [x] POST /devices/{id}/revoke — sessions, prekeys, live sockets
│   └── [x] Bind a session to a device (device-scoped access tokens)
├── [x] 7. Invitations
│   ├── [x] POST /invitations — high-entropy token, HMAC-hash-only storage
│   ├── [x] Token returned exactly once, never logged
│   ├── [x] POST /invitations/accept — atomic single-use (token in BODY, D9)
│   ├── [x] POST /invitations/{id}/revoke
│   ├── [x] Rate limits on create AND accept
│   └── [ ] Scheduled expiry sweep (expiry is enforced on use; no sweeper yet)
├── [x] 8. Prekey distribution
│   ├── [x] GET /devices/{id}/public-keys — contacts only, 404 otherwise
│   ├── [x] ATOMIC one-time prekey consumption (FOR UPDATE SKIP LOCKED)
│   ├── [x] Degrades to signed-prekey-only when exhausted, never fails open
│   ├── [x] Rate-limited bundle fetches (drain protection)
│   ├── [x] Replenishment never overwrites a published prekey
│   └── [x] Mandatory Kyber prekey (PQXDH)
├── [x] 9. Contacts + verification metadata
│   ├── [x] GET /contacts — accepted friendships, with device identity keys
│   ├── [x] POST /contacts/{id}/verify — ADVISORY only
│   ├── [x] No search, no directory, no lookup-by-username anywhere
│   └── [ ] Identity-change detection surfaced to peers (client-side work)
├── [x] 10. Encrypted envelope
│   ├── [x] Versioned envelope, opaque authenticated ciphertext
│   ├── [x] Unpredictable message IDs; 64 KiB size bound
│   ├── [x] message_type (prekey|signal) for the recipient's decrypt path
│   └── [x] No preview/plaintext field exists to carry
├── [x] 11. Message API
│   ├── [x] POST /messages — per-envelope authorisation, batch is not a trust boundary
│   ├── [x] GET /messages — queued for THIS device only
│   ├── [x] POST /messages/{id}/delivered and /read — recipient only, idempotent
│   └── [x] Duplicate/replay returns `duplicate` via unique (sender, recipient, sequence)
├── [x] 12. WebSocket delivery
│   ├── [x] Authenticated upgrade via Authorization header, pre-upgrade authz
│   ├── [x] Revoked devices rejected, and live sockets closed on revocation
│   ├── [x] Redis presence + pub/sub connection registry (multi-instance)
│   ├── [x] Heartbeat / ping-pong / unresponsive-socket teardown
│   ├── [x] Oversized frames closed unparsed
│   └── [x] Duplicate connections designed out: notifications only, idempotent acks
└── [x] 13. Offline queue
    ├── [x] Store-and-forward, server never decrypts
    ├── [x] Per-sender sequence ordering on drain
    ├── [x] At-least-once + duplicate rejection
    ├── [x] Retention sweep implemented (`sweepMessages`)
    └── [ ] Sweep not yet scheduled — needs a timer or cron
```

### 1.5 Client — Flutter `[~]` — steps 14–16

**Complete** as of 2026-10-10. The repository was moved out of the path containing `&`
(D11), and the client now builds and tests in place. Networking, UI and client-side
revocation are written and exercised by the vertical slice in 1.6.

```
├── [x] Scaffold
│   ├── [x] flutter create (Windows target, Dart package `bond`)
│   ├── [x] libsignal PINNED to 7.3.1; sqlite3 with source: sqlcipher hook
│   └── [x] Layered structure; crypto reachable only via services/crypto
├── [x] Crypto service — the ONLY caller of libsignal
│   ├── [x] OWN persistent identity store with change detection
│   │       (bundled one is TOFU and loses state on restart)
│   ├── [x] Asymmetric trust policy: changed key BLOCKS sending (fail closed),
│   │       allows receiving so the user can still read and be warned
│   ├── [x] Identity-change warning is DURABLE across restarts
│   ├── [x] Acknowledging a change unblocks sending but does NOT re-verify
│   ├── [x] Per-remote-address locking (AddressLock) around the whole
│   │       load→ratchet→store critical section
│   ├── [x] One transaction per operation, committed before output is released
│   ├── [x] synchronous = FULL, so a crash cannot rewind the ratchet
│   ├── [x] Persisted monotonic send-sequence counter
│   ├── [x] Safety-number derivation (60 digits, agrees on both sides)
│   ├── [x] Verifying BEFORE first contact PINS the compared key, so it is
│   │       not a silent no-op and first contact is no longer TOFU (D13)
│   └── [ ] QR encoding of the safety number (scannable form)
├── [x] 15. Secure storage
│   ├── [x] SecureKeyStore interface; UnavailableSecureKeyStore FAILS rather
│   │       than degrading to unprotected storage on an unimplemented platform
│   ├── [x] Windows DPAPI backend via dart:ffi (D10)
│   ├── [x] Encrypted local message store (SQLCipher), key held by DPAPI
│   ├── [x] FAIL-CLOSED cipher probe — PRAGMA key is a SILENT no-op on a
│   │       non-SQLCipher build and would leave the database plaintext
│   ├── [x] Proven encrypted: wrong key cannot open the file; a stored body
│   │       does not appear in the raw bytes
│   ├── [x] auth_state separate from device_identity / sessions
│   ├── [x] wipe() for logout
│   └── [x] DPAPI backend has its own suite (7 tests, real Win32):
│           round trip, blob does not contain the secret, survives a new
│           instance, damaged blob throws instead of reading as absent,
│           key-name traversal rejected
├── [x] Networking: REST + WebSocket clients, reconnect handling
│   ├── [x] ApiClient: every route, typed errors from the documented envelope
│   ├── [x] Single-flight refresh on 401 — concurrent refreshes would each
│   │       rotate, and every rotation after the first looks like token theft
│   │       to the server, which revokes the whole session family
│   ├── [x] RealtimeClient over dart:io, token in the Authorization HEADER
│   │       (a token in a query string lands in access logs)
│   ├── [x] Reconnect with exponential backoff + full jitter; heartbeat ping
│   ├── [x] Stops reconnecting on device.revoked rather than hammering a
│   │       server that is correctly refusing
│   └── [x] Fresh token fetched before every connect attempt
├── [x] Outgoing envelopes are PERSISTED before transmission
│       A retry must replay identical bytes: re-encrypting advances the
│       ratchet and changes the sequence, so the server's duplicate detection
│       would not recognise it and the message would arrive twice.
├── [x] 14. Minimal UI for the slice
│   ├── [x] Register / login / device setup
│   ├── [x] Invite + accept (token shown once, copyable, never logged)
│   ├── [x] Contacts + verification screen (safety-number compare, grouped
│   │       in fives so reading 60 digits aloud is not error-prone)
│   ├── [x] 1-to-1 conversation with send/sent/delivered/read states, as
│   │       WORDS not ticks — "sent" and "delivered" differ and are routinely
│   │       conflated
│   ├── [x] Identity-changed warning: not dismissible, composer disabled
│   │       while it shows, and "accept without checking" requires a second
│   │       confirmation that says what is being given up
│   ├── [x] Connection state surfaced whenever it is not "connected"
│   ├── [x] Security screen: what the server can and cannot see, the three
│   │       kinds of encryption, known limits, decryption failures
│   └── [x] Verified badge rendered ONLY from the local record of a human
│           comparison, never from the server's advisory field (D4)
└── [x] 16. Device revocation (client side; server side is done)
    ├── [x] Revoke from device-management screen, with a confirmation that
    │       states the history is unrecoverable rather than "are you sure?"
    └── [x] Handle the device.revoked socket frame: wipe local state
```

### 1.6 MVP vertical slice `[x]` — PASSING

`client/test/vertical_slice_test.dart` drives two independent installations
through the whole journey against a live server. Nothing in it is stubbed: real
libsignal, real SQLCipher databases, real Windows DPAPI, real HTTP and a real
WebSocket, real PostgreSQL and Redis.

This closes a seam the two earlier suites left open. The server suite exercises
the API with an AES-GCM **stand-in** for the protocol; the client crypto suite
exercises the real protocol with **no server**. Neither proved the two halves
fit together, and three defects were found the moment they were made to.

```
├── [x] Alice registers (bootstrap) → Bob registers via invite
├── [x] Both register devices and publish prekeys
├── [x] A spent invitation is refused the second time
├── [x] Both sides derive the SAME 60-digit safety number, and verify
├── [x] Alice sends an encrypted message → Bob decrypts it
├── [x] Read receipt reaches Alice over her own socket
├── [x] Ciphertext inspected: the plaintext is absent from the bytes that
│       were actually transmitted, read back out of Alice's own database
├── [x] Server database inspected: a full pg_dump contains no occurrence of
│       the message text, and none of the password
├── [x] Bob offline → Alice sends → Bob RESTARTS → delivered and decrypted
│       (store-and-forward and ratchet durability in one step, over the real
│       network path rather than an in-process store)
└── [x] Device revoked → local secrets destroyed, contact unaddressable
        (server-side refusal of the credential is the server suite's job)
```

**Defects this slice found, each now fixed and covered by a test:**

1. `GET /messages?limit=N` was rejected as `validation_failed` for every value.
   Query parameters are strings and Ajv runs with `coerceTypes: false`, so the
   `Integer` schema could never match. No test had ever passed the parameter.
2. Verifying a contact BEFORE exchanging a message silently did nothing: there
   was no `peer_identities` row yet, so the UPDATE matched nothing. The user
   would compare digits, press "they match", and have recorded nothing — and
   first contact would then trust-on-first-use whatever key the server sent.
   Verification now pins the compared key (D13).
3. `accessTokenExpiresIn` is a duration spec like `15m`, not a number of
   seconds. The client model had it as an int and threw on the first response.
4. A freshly registered account was signed out again on the next launch. The
   tokens and the user id are persisted at two different moments — tokens by
   the API layer's callback, the user id from the call's result — and the
   second write clobbered the first. Device registration happened to rewrite
   the tokens, so every path that provisioned immediately masked it. The
   regression test restarts between registering and provisioning, and was
   confirmed to fail without the fix.

### 1.6b Running two clients on one machine

Each installation keeps its own database and key blobs under a profile:

```powershell
flutter run -d windows --dart-define=BOND_PROFILE=alice
flutter run -d windows --dart-define=BOND_PROFILE=bob
```

`--dart-define=BOND_SERVER=https://host` points them at a different server.

### 1.7 Hardening `[~]` — steps 17–19

```
├── [~] 17. Automated tests — 98 total (43 client + 55 server)
│   ├── [x] Crypto validation suite (11 tests, real libsignal)
│   ├── [x] Silent-failure suite (18 tests, real libsignal + real SQLCipher)
│   ├── [x] DPAPI key-store suite (7 tests, real Win32)
│   ├── [x] Client UI invariants (6 tests): fail-closed startup, the fatal
│   │       screen offering no way past it, form rules matching the server
│   ├── [x] Vertical slice (1 test, 13 stages) — the only test that exercises
│   │       the real protocol and the real server together
│   ├── [x] Auth integration suite (20 tests)
│   ├── [x] Journey suite (24 tests): devices, invitations, prekeys, contacts,
│   │       messages, fan-out, revocation, authorisation boundaries, and the
│   │       `limit` parameter the slice found broken
│   ├── [x] Realtime suite (11 tests): WS auth, delivery, receipts, offline
│   │       reconnect, concurrent connections, oversized frames, revocation
│   ├── [~] Security coverage so far: authz bypass, IDOR (404-not-403),
│   │       WS auth bypass, replay, duplicate, oversized frames, strict
│   │       schemas, query-parameter validation
│   ├── [ ] Still missing: SQL injection, rate-limit bypass, malformed
│   │       protocol messages, deliberate token tampering
│   └── [ ] 6 threat-model scenarios as named executable tests
├── [ ] 18. Threat-model review against the built system
└── [ ] 19. Dependency + security audit (npm audit, dart pub outdated, log sweep)
```

### 1.8 Phase 1 completion gates `[ ]` — step 20

Your `definition_of_done`. **12 of 12 functional items now pass end to end**, proven by
the vertical slice. The security column is where the remaining work is.

```
Functional                                    Security
├── [x] Two users can register                ├── [x] Private keys stay client-side
├── [x] Each registers a device               ├── [x] No plaintext in the database
├── [x] A user can invite another             ├── [x] Authentication enforced
├── [x] The invitee can accept                ├── [x] Authorisation enforced
├── [x] Users verify each other's identity    ├── [ ] TLS enforced in production
├── [x] Encrypted 1-to-1 session established  ├── [x] Tampering detected
├── [x] Alice sends Bob an encrypted message  ├── [x] Identity changes detected
├── [x] Bob decrypts locally                  ├── [x] Invite tokens high-entropy, single-use
├── [x] Server never receives plaintext       ├── [~] No secrets in logs
├── [x] Offline messages delivered            └── [~] Security tests pass
├── [x] Messages survive WS reconnects
└── [x] Devices can be revoked
```

The four that are not `[x]`, stated honestly rather than rounded up:

* **TLS in production** — the config refuses to start in production without an https
  `PUBLIC_ORIGIN`, and the client never disables certificate verification. But no
  production deployment exists to have enforced it on, so this is unproven rather
  than done.
* **No secrets in logs** — there is a centralised deny-list redactor and it is tested,
  but nobody has swept a real log file from a full session yet (step 19).
* **Security tests pass** — the ones that exist pass. Four named categories are still
  missing, listed under 1.7.
* Phase 1 is therefore **not** complete: step 20 is a review, and reviewing against
  four open items would be theatre.

---

## Phase 2 — Encrypted attachments `[ ]`

```
├── [ ] Per-file random key generated on the client
├── [ ] Encrypt locally → upload opaque blob (MinIO/S3)
├── [ ] Ship the file key INSIDE the E2EE message, never beside the blob
├── [ ] Recipient downloads ciphertext, decrypts locally
├── [ ] Images and documents
└── [ ] Object store learns nothing about file contents or type
```

## Phase 3 — Multi-device and groups `[ ]`

```
├── [ ] Key backup / recovery design (currently: lose device = lose history)
├── [ ] New device joins an existing account
├── [ ] Cross-device history sync
├── [ ] Group messaging (revisit MLS/OpenMLS here)
└── [ ] Sender keys / fan-out
```

## Phase 4 — Voice and video `[ ]`

```
└── [ ] WebRTC, STUN/TURN, NAT traversal, ICE, media encryption
    ← an entirely different problem class; deliberately last
```

## Deferred across all phases `[ ]`

```
├── [ ] Sealed sender (sender metadata currently visible to the server)
├── [ ] Push notifications without content leakage
├── [ ] Disappearing messages
├── [ ] Metadata privacy (padding, cover traffic)
└── [ ] Web client (blocked: flutter_rust_bridge has no dart2wasm support)
```

---

## Open risks and chores

```
├── [x] Repo path fixed — moved to C:\kaam_kaach\Private-conv; the client builds
│       and npm scripts work again (D11)
├── [ ] NOTHING IS COMMITTED — main has zero commits, all files untracked
├── [ ] .gitignore has no pattern for recovery-phrase / key-material files;
│       add one before the first `git add -A`
├── [ ] WINDOWS DEVELOPER MODE must be ON to build the desktop app.
│       Flutter needs symlink support for plugins; without it `flutter build
│       windows` and `flutter run -d windows` both refuse. Needs an elevated
│       `start ms-settings:developers`. Tests do NOT need it, which is why
│       everything else here is verifiable without it.
├── [ ] Docker Desktop must be running before the server suite can run
├── [ ] Retention windows still placeholders (30/90 days)
└── [ ] Account credential mechanism not revisited (O2 in decisions.md)
```
