# API Reference

**Status:** implemented and covered by tests (steps 5–13). Last verified 2026-10-09.
**Base:** all paths are relative to `PUBLIC_ORIGIN`. HTTPS in production, WSS for `/ws`.

Rules that hold for every route, enforced centrally rather than per handler:

- **Strict schemas.** Every body, param and query is validated against a schema with
  `additionalProperties: false`, and Ajv runs with `removeAdditional: false` and
  `coerceTypes: false` — so an unknown field is a 400, not a silently dropped field.
- **Authorisation from the token only.** Handlers read the verified token subject, never a
  client-supplied id. There is no endpoint that takes "whose data" as a parameter.
- **Revocation checked per request.** A revoked device is rejected before the session and
  account checks, so it gets an actionable `device_revoked` rather than a generic 401.
- **Uninformative errors.** Responses carry `{ error: { code, message, requestId } }`.
  Never a stack trace, a driver message or an internal identifier.
- **Not-found over forbidden.** Where a 403 would confirm that an id exists, the answer is
  404 instead. Noted per route below.

## Token model

Two different credentials, deliberately not interchangeable:

| | Lifetime | Stored server-side | Carries |
|---|---|---|---|
| Access token | short (`ACCESS_TOKEN_TTL`, default 15m) | no | `sub`, `sid`, `typ:'access'`, optional `did` |
| Refresh token | long (`REFRESH_TOKEN_TTL_DAYS`, default 30d) | HMAC hash only | opaque, 256 bits |

An access token is **account-scoped** until the device registers, then **device-scoped**
(`did`). Messaging and `/ws` require device scope; an account-scoped token gets 403 there.

---

## Authentication

### `POST /auth/register`
Invite-controlled. `invitationToken` may be omitted **only** on the env-gated bootstrap
path, which can create user #1 and nobody else.

```json
{ "username": "alice", "password": "...", "invitationToken": "<43 chars>" }
```
→ `201 { userId, accessToken, refreshToken, accessTokenExpiresIn, refreshTokenExpiresAt }`

`410 invitation_unusable` covers unknown, expired, already-used and revoked invitations
identically, so probing learns nothing. Rate limit: `RATE_LIMIT_REGISTER_PER_HOUR`.

### `POST /auth/login`
`{ username, password }` → `200` same shape.

A wrong password and an unknown username return **identical** status and body, and the
unknown-username path spends comparable time hashing, so neither content nor timing is a
username oracle. Rate limit: `RATE_LIMIT_AUTH_PER_15M`.

### `POST /auth/refresh`
`{ refreshToken }` → `200` same shape, with a new refresh token.

Rotation with theft detection: presenting an already-consumed token revokes the **entire
session family**, including the legitimate successor. Returns `401` without saying why.

### `POST /auth/logout`
`{ refreshToken }` → `204`, always, whether or not the token existed.

---

## Devices

### `POST /devices/register`
Account-scoped token. Publishes **public** key material only.

```json
{
  "deviceName": "alice-windows",
  "platform": "windows",
  "registrationId": 4211,
  "publicIdentityKey": "<base64, 32-33 bytes>",
  "signedPreKey": { "id": 1, "publicKey": "<base64>", "signature": "<base64, 64 bytes>" },
  "kyberPreKey":  { "id": 1, "publicKey": "<base64, 800-2048 bytes>", "signature": "<base64>", "isLastResort": true },
  "oneTimePreKeys": [ { "id": 1, "publicKey": "<base64>" } ]
}
```
→ `201 { deviceId, deviceIndex, accessToken }`

- `kyberPreKey` is **required**: libsignal mandates PQXDH, so a bundle cannot be assembled
  without one.
- `oneTimePreKeys` must contain 10–100 entries.
- `deviceIndex` (1–127) is the libsignal protocol address. Allocated monotonically and
  **never reused**, including after revocation.
- The returned `accessToken` is device-scoped and replaces the account-scoped one.
- Validation is **structural only** — canonical base64, exact lengths, id ranges. The
  server does not verify the prekey signature; the recipient's client does. See
  [architecture.md](architecture.md) section 6.

### `GET /devices`
→ `200 [ { deviceId, deviceIndex, deviceName, platform, publicIdentityKey, registrationId,
createdAt, lastSeenAt, revokedAt, availableOneTimePreKeys } ]`

Scoped to the token subject; there is no parameter for whose devices to list.

### `POST /devices/{deviceId}/revoke`
→ `204`. Idempotent. `404` for a device the caller does not own.

Sets `revoked_at`, deletes unused one-time prekeys, retires the signed prekey, revokes the
device's sessions, and closes its live WebSocket on whichever instance holds it.

### `POST /devices/{deviceId}/key-material`
`{ oneTimePreKeys: [...] }` → `200 { availableOneTimePreKeys }`

Own device only (`404` otherwise). Re-sending an existing prekey id is a **no-op**: an
already-published key is never overwritten, since substituting one could downgrade a
session that is mid-establishment.

### `GET /devices/{deviceId}/public-keys`
Device-scoped token. → `200`

```json
{
  "deviceId": "...", "userId": "...", "deviceIndex": 1, "registrationId": 4211,
  "publicIdentityKey": "...",
  "signedPreKey": { "id": 1, "publicKey": "...", "signature": "..." },
  "kyberPreKey":  { "id": 1, "publicKey": "...", "signature": "..." },
  "oneTimePreKey": { "id": 7, "publicKey": "..." }
}
```

The most security-sensitive route in the system — it is where a malicious server would
substitute a key.

- Authorised to **active contacts only**. A non-contact gets `404`, identical to a device
  that does not exist.
- Each call **consumes one one-time prekey** atomically (`FOR UPDATE SKIP LOCKED`); a key
  is never handed out twice.
- When the supply is exhausted, `oneTimePreKey` is `null` and the bundle is still usable
  (signed-prekey-only X3DH). It never fails open and never recycles a spent key.
- Rate-limited (`RATE_LIMIT_PREKEY_FETCH_PER_HOUR`) because each call drains a consumable.

---

## Invitations

### `POST /invitations`
`{ purpose?: "register_and_befriend" | "register_only" | "befriend_only" }`
→ `201 { invitationId, token, expiresAt, purpose }`

`token` is returned **exactly once**. Only its HMAC-SHA256 is stored, so no endpoint can
return it again. Rate limit: `RATE_LIMIT_INVITE_CREATE_PER_DAY`.

### `GET /invitations`
→ `200 [ { invitationId, purpose, createdAt, expiresAt, usedAt, revokedAt, status } ]`

Never includes the token or its hash.

### `POST /invitations/accept`
`{ token }` → `200 { contactUserId, invitationId }`

For an account that **already exists**; a new user accepts implicitly by registering with
the token. Consumption is atomic, so two concurrent redemptions cannot both succeed.
Self-acceptance is refused without burning the invitation.

### `POST /invitations/{invitationId}/revoke`
→ `204`. `404` if it does not exist, belongs to someone else, or is already spent — all
indistinguishable.

> **Deviation from the brief** (see [decisions.md](decisions.md) D9): the brief lists
> `/invitations/{token}/accept` and `/invitations/{token}/revoke`. A token is a credential,
> and a credential in a URL path lands in access and proxy logs, so it travels in the body
> and revocation is by id.

---

## Contacts

### `GET /contacts`
→ `200 [ { contactUserId, username, status, verifiedAt, createdAt, devices: [...] } ]`

Each contact includes their **active** devices with `publicIdentityKey`, which the client
needs to derive safety numbers and to notice an identity change. Revoked devices are
omitted, so they cannot be addressed.

There is no search, no directory and no lookup-by-username anywhere in the API: contacts
exist only through an accepted invitation.

### `GET /contacts/{contactId}`
→ `200` one contact. `404` for a non-contact, identical to a user that does not exist.

### `POST /contacts/{contactId}/verify`
`{ verified: boolean }` → `200 { verifiedAt }`

**Advisory metadata only.** A client must never render "verified" because this field is
set — a compromised server could set it for a key it substituted. Authority is client-local
([decisions.md](decisions.md) D4).

---

## Messages

All device-scoped.

### `POST /messages`
One envelope **per recipient device**: the client encrypts separately for each, so a
message to a multi-device contact arrives as several envelopes in one request.

```json
{ "envelopes": [ {
  "recipientDeviceId": "...",
  "envelopeVersion": 1,
  "messageType": "prekey" | "signal",
  "ciphertext": "<base64, 1-65536 bytes>",
  "senderSequence": 0,
  "protocolMetadata": {}
} ] }
```
→ `201 { results: [ { recipientDeviceId, status: "accepted" | "duplicate", messageId? } ] }`

- 1–20 envelopes, each authorised **independently**; a batch is not a trust boundary.
- A repeated recipient within one batch is a 400.
- `403 not_contacts` for a non-contact or unknown device — identical answers.
- A resent `(senderDevice, recipientDevice, senderSequence)` returns `duplicate` rather
  than storing a second row, which makes replay and client retry both harmless.
- `ciphertext` is opaque. The server never parses it; the test suite proves this by
  sending bytes that are not valid UTF-8 and reading them back unchanged.

### `GET /messages?limit=50`
→ `200 [ { messageId, envelopeVersion, senderDeviceId, senderUserId, senderDeviceIndex,
recipientDeviceId, protocol, messageType, ciphertext, protocolMetadata, senderSequence,
createdAt } ]`

Scoped to the calling device; one device cannot drain another's queue. Per sending device,
order follows the sender's own sequence; across senders, arrival order.

`limit` is optional and defaults to 50. It is validated as a **numeric string** matching
`^[1-9][0-9]{0,2}$`, then clamped to `MAX_QUEUE_FETCH` (200) server-side.

> It is a string rather than an integer for a reason worth knowing before "fixing" it:
> query parameters always arrive as strings, and Ajv runs with `coerceTypes: false`
> globally, so an `Integer` schema here can never match — the parameter was rejected as
> `validation_failed` for *every* value until the client's vertical-slice test became the
> first caller to pass it. Enabling coercion would have fixed this one route and weakened
> every other schema in the API, where `"1"` would then satisfy a number and `"true"` a
> boolean. Covered by `journey.integration.test.ts`.

### `POST /messages/{messageId}/delivered` · `POST /messages/{messageId}/read`
→ `200 { deliveryState }`

Recipient device only (`404` otherwise, not 403). Idempotent, forward-only: `read` implies
delivered and never moves backwards. Acknowledgements carry no plaintext, and each
notifies the sender over its socket.

---

## Realtime

### `GET /ws` (WebSocket upgrade)
Device-scoped token in the **`Authorization` header**, not a query parameter — a token in a
URL lands in access logs. Both auth hooks run **before** the upgrade, so an unauthorised
handshake never becomes an open socket.

Server frames:

| `type` | Meaning |
|---|---|
| `ready` | Connected. `hasQueuedMessages` tells the client whether to drain. |
| `message.queued` | Something arrived; fetch it over HTTPS. |
| `message.delivered` / `message.read` | Receipt for a message this device sent. |
| `device.revoked` | This device was revoked; the socket closes immediately after. |
| `pong` | Reply to a client `{"type":"ping"}`. |

Client frames: `{"type":"ping"}` only. Anything else is ignored rather than interpreted, so
the socket is not a second command surface. Frames over 4 KiB close the connection unparsed.

**The socket carries notifications, never message bodies.** Two consequences: there is one
authorisation path for content instead of two, and duplicate or stale connections cannot
corrupt delivery — both sockets are notified, both fetch, and acknowledgement is idempotent.
Up to 4 concurrent connections per device; heartbeat every 30s, two missed pongs closes it.

---

## Health

### `GET /health`
→ `200 { status: "ok" }` or `503 { status: "degraded" }`. Unauthenticated and deliberately
uninformative: up or down, never versions or connection details.
