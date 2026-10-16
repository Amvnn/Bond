# Architecture

**Date:** 2026-09-28
**Phase:** 1 — Secure 1-to-1 text messenger

Companion documents: [crypto-design.md](crypto-design.md) (protocol selection),
[threat-model.md](threat-model.md) (attackers and residual risk),
[security-model.md](security-model.md) (exactly what the server sees).

---

## 1. System architecture

```
   Android    iOS    Windows    Linux    macOS
      |        |        |         |        |
      +--------+--------+---------+--------+
                        |
              Flutter client (Dart)
      Presentation / Application / Domain
      Cryptography / Networking / Secure storage / Local DB
                        |
             plaintext never leaves here
                        |
                 [ E2EE envelope ]
                        |
                 TLS 1.3 / WSS
                        |
                 Reverse proxy (Caddy)
                        |
            Node.js + TypeScript + Fastify
         REST API        |       WebSocket hub
                        |
        +---------------+----------------+
        |                                |
   PostgreSQL                          Redis
   users, devices, public keys,    presence, connection
   invitations, friendships,       registry, rate limits,
   ciphertext envelopes,           ephemeral session state
   delivery state, security events
```

The backend is a **relay and encrypted store-and-forward service**. It routes envelopes,
tracks delivery state, distributes public key material and enforces authorisation. It
performs no operation requiring plaintext. If a future feature appears to need plaintext
server-side, that is a design conflict to raise, not to implement.

### Component responsibilities

| Component | Owns | Must never hold |
|---|---|---|
| Flutter client | Plaintext, private keys, session state, verification decisions, local history | — |
| Fastify backend | Routing, authn/authz, delivery state, rate limiting, key distribution | Plaintext, private keys, session state |
| PostgreSQL | Metadata, public keys, ciphertext, delivery state, audit events | Plaintext, private keys |
| Redis | Presence, connection registry, rate-limit counters, short-lived queues | Plaintext, long-term secrets |
| Reverse proxy | TLS termination, HSTS, request limits | Anything decrypted beyond TLS |

---

## 2. Trust boundaries

Two boundaries, with different guarantees. See [threat-model.md](threat-model.md) section 3
for the diagram.

- **Boundary 1 (device to server) is protected by TLS.** Defeating TLS exposes metadata
  and API traffic — not message content.
- **Boundary 2 (device to device, across the server) is protected by E2EE.** The server sits
  inside this boundary as an untrusted relay. Compromising it exposes metadata and
  ciphertext, not content.

The two are independent. Losing one does not lose the other, which is why both exist.

---

## 3. Client architecture

Layered so that cryptography is reachable only through one abstraction, never from UI code.

```
lib/
  core/                      config, errors, result types, logging
  features/
    auth/                    register, login, token lifecycle
    devices/                 device identity, device list, revocation
    invitations/             create, share, accept, revoke
    contacts/                contact list, verification state
    messaging/               conversations, send/receive, delivery state
    security/                fingerprints, warnings, security info screens
  services/
    crypto/                  the ONLY caller of libsignal
    network/                 REST + WebSocket clients
    storage/                 platform secure storage + encrypted local DB
```

Rules:

- **Widgets never call the crypto service directly.** UI to application to domain to
  crypto. A widget importing `libsignal` is a defect.
- **`services/crypto` is the sole boundary to libsignal.** Swapping protocol
  implementation must not require touching any feature module.
- **Authentication state and cryptographic identity state are stored separately.** An
  account session is not a device identity; conflating them is the mistake this
  separation exists to prevent.

### Secure storage per platform

| Platform | Private key storage | Notes |
|---|---|---|
| Android | Keystore | Hardware-backed where available |
| iOS | Keychain (Secure Enclave where applicable) | |
| macOS | Keychain | |
| Windows | DPAPI / Credential Manager | Weaker isolation than mobile; document, do not pretend |
| Linux | Secret Service / keyring | Depends on a running keyring daemon |

If a platform cannot provide equivalent protection, the app **fails securely or documents
the reduced guarantee**. It never silently writes private keys to plain storage.

---

## 4. Server architecture

```
server/src/
  modules/
    auth/          registration, login, refresh rotation, logout, revocation
    users/         account records
    devices/       registration, listing, revocation, prekey publication
    invitations/   creation, acceptance, revocation, expiry
    contacts/      friendships, verification metadata
    messages/      envelope intake, queueing, delivery + read state
    security/      audit event recording
  realtime/        WebSocket auth, connection registry, dispatch, heartbeat
  database/        schema, migrations, parameterised queries
  middleware/      authn, authz, rate limiting, validation, headers, error mapping
  config/          environment-based configuration, no literals
```

Invariants:

- Authorisation derives from the authenticated token subject. A client-supplied user or
  device ID is input to validate, never a fact to trust.
- Every endpoint validates its body and params against a strict schema before handling.
- Message routing is separate from any crypto concern; the backend treats `ciphertext` as
  opaque bytes.
- Revocation is checked on every authenticated request and every WebSocket upgrade.

---

## 5. Authentication flow

Account authentication is deliberately separate from device cryptographic identity.

```
Client                                  Server
  |  POST /auth/register                  |
  |  (invitation token, credentials)      |
  |-------------------------------------->|  validate token hash, expiry,
  |                                       |  single-use; create user; consume
  |<--------------------------------------|  opaque user_id
  |                                       |
  |  POST /auth/login                     |
  |-------------------------------------->|  verify credential hash
  |<--------------------------------------|  short-lived access token
  |                                       |  + refresh token (rotating)
  |                                       |
  |  POST /auth/refresh                   |
  |-------------------------------------->|  rotate: old refresh invalidated,
  |<--------------------------------------|  reuse detected => revoke session family
  |                                       |
  |  POST /auth/logout                    |
  |-------------------------------------->|  server-side session revocation
```

- Access tokens are short-lived; refresh tokens rotate, and reuse of a consumed refresh
  token invalidates the whole session family (theft detection).
- Refresh tokens live in platform secure storage on the client, never in plain
  preferences.
- Login, registration and refresh are rate-limited. Failures are logged as security
  events **without** credentials or tokens in the log.

---

## 6. Device registration flow

```
1. User authenticates (account-level).
2. Client generates, on-device:
     identity key pair
     signed prekey (+ signature over it)
     batch of one-time prekeys
3. Private key material -> platform secure storage. It never leaves the device.
4. Client publishes PUBLIC material only:
     POST /devices/register   { device_name, platform,
                                public_identity_key, signed_prekey,
                                signed_prekey_signature, one_time_prekeys[] }
5. Server assigns an opaque device_id, stores public material.
6. Client stores device_id securely; records this device as "this device" for UI.
7. Device is now addressable for encrypted messaging.
```

**Correction to an earlier version of this document.** It previously claimed the server
rejects a registration whose signed-prekey signature does not verify against the submitted
identity key. It does not, and cannot: libsignal signs prekeys with XEdDSA over Curve25519,
which Node's standard library cannot verify, and pulling a cryptographic library into the
relay to do it would contradict the principle that the server runs no part of the protocol.

What the server actually does at registration is **structural** validation: canonical
base64, exact key and signature lengths, registration-id and prekey-id ranges, a mandatory
Kyber prekey, and a minimum supply of one-time prekeys. See `core/encoding.ts`.

The signature check that matters happens on the **recipient's client**, when it processes
the prekey bundle — libsignal enforces it, and the validation suite proves a bundle signed
by the wrong identity key is rejected there. That is the right place for it: a server-side
check would be defence in depth at best, and trusting it would be exactly the
server-as-authority mistake the threat model warns about.

---

## 7. Invitation flow

One invitation both authorises registration and establishes the friendship. An
`invitations.purpose` column distinguishes a combined invite from a registration-only one
so the second case can exist later without a migration.

```
Alice (authenticated)                    Server                        Bob
  |  POST /invitations                     |                            |
  |--------------------------------------->|  generate high-entropy      |
  |                                        |  random token; store ONLY   |
  |<---------------------------------------|  its hash + expiry          |
  |  token shown ONCE, plaintext           |                            |
  |                                        |                            |
  |  share out of band (Signal, in person, etc.) ------------------->    |
  |                                        |                            |
  |                                        |  POST /auth/register        |
  |                                        |  or /invitations/{t}/accept |
  |                                        |<---------------------------|
  |                                        |  hash lookup; check expiry,
  |                                        |  unused, unrevoked; mark used
  |                                        |  atomically; create Bob;
  |                                        |  create PENDING friendship
  |                                        |                            |
  |  both clients fetch each other's prekey bundles                     |
  |  out-of-band safety-number verification                             |
  |  friendship becomes ACTIVE / verified                               |
```

Properties: cryptographically random tokens, stored hashed, expiring, single-use
(consumed atomically so a race cannot use one twice), revocable, and rate-limited on both
creation and acceptance. Token plaintext is never logged and never persisted server-side.

**Bootstrap:** user #1 cannot be invited by anyone. A seed script, gated by an
environment flag and intended to be run once by the operator, creates the first account.
The flag must be off in normal operation.

---

## 8. Key verification flow

```
Alice's client                                          Bob's client
  fetch Bob's public identity key
  derive safety number from BOTH identity keys  <--->   derive the same number
                            |
        compare out of band: read aloud / visual / QR scan
                            |
        match?  --- yes -->  mark verified (LOCAL trust decision)
                |            server notified for advisory metadata only
                +--- no  -->  do not proceed; possible MITM
```

Later, if Bob's identity key changes:

```
  client detects key != stored key
        |
        +-> verified state REVOKED locally
        +-> visible warning shown
        +-> security event recorded
        +-> re-verification required; never silently accepted
```

The server is never the authority. It supplies keys; users establish trust. A key the
server vouches for is still unverified.

---

## 9. Message flow

```
Alice device                     Server                      Bob device
 compose plaintext
 get/establish session
   (fetch prekey bundle,
    verify signature, X3DH)
 encrypt locally  ------- Double Ratchet -------
 build envelope
   { version, message_id, sender_device_id,
     recipient_device_id, protocol, ciphertext,
     protocol_metadata, created_at }
        |
        |  POST /messages  (TLS)
        +------------------------>
                              validate schema + metadata
                              authorise: friendship exists,
                                devices not revoked
                              store ciphertext, state=queued
                              never inspect ciphertext
                                     |
                              if Bob online: push over WSS
                                     +------------------------>
                                                        verify + decrypt
                                                        locally; display
                                                        plaintext (only here)
                                     <------------------------
                              POST /messages/{id}/delivered
                              state=delivered
                                     <------------------------
                              POST /messages/{id}/read
                              state=read
```

Envelope rules: versioned; ciphertext authenticated; message IDs opaque and unpredictable
with a uniqueness constraint; **no plaintext preview field**; ciphertext not routinely
logged. Acknowledgements carry IDs and state only.

---

## 10. Offline delivery flow

```
Bob offline
  Alice encrypts and POSTs ciphertext -> stored, state=queued
  ... time passes; server never decrypts anything ...
Bob reconnects
  WSS upgrade: authenticate, bind connection to device_id, reject if revoked
  server streams queued envelopes in explicit order
  Bob decrypts locally, deduplicates by message_id
  Bob acknowledges -> state=delivered
  queue drained; expiry policy applies to anything undelivered
```

Guarantees and their limits:

- Ordering is explicit, not incidental — clients order deterministically rather than
  relying on arrival time.
- Duplicate delivery is safe: at-least-once transport plus client-side deduplication by
  message ID.
- Reconnection is expected, not exceptional: heartbeat/ping-pong, connection timeout, and
  a connection registry that prevents a stale duplicate connection from consuming a
  message the live one needs.
- Undelivered messages expire per the documented retention policy in
  [security-model.md](security-model.md).

---

## 11. Data flow summary

| Data | Client | Wire | Server | Notes |
|---|---|---|---|---|
| Message plaintext | yes | **never** | **never** | Device only |
| Private keys | yes | **never** | **never** | Secure storage only |
| Session / ratchet state | yes | **never** | **never** | Device only |
| Public identity key | yes | yes | yes | Required for the protocol |
| Prekeys (public) | yes | yes | yes | One-time keys consumed atomically |
| Ciphertext envelope | yes | yes | yes | Opaque to the server |
| Delivery / read state | yes | yes | yes | No plaintext |
| Verification decision | yes | advisory only | advisory only | Authority is the client |
