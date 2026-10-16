# Database Schema

**Status:** implemented and applied. Last verified 2026-10-09 against PostgreSQL 18.
**Migrations:** `server/src/database/migrations/` — forward-only, applied once, checksummed.
Editing an applied migration is a hard failure; add a new one instead.

```bash
cd server && ./node_modules/.bin/tsx --env-file=.env src/database/migrate.ts
```

## Hard rules, enforced by the schema itself

These are not conventions. The constraints below were tested by inserting deliberately
invalid rows and confirming PostgreSQL rejected every one.

- **No column holds message plaintext**, a plaintext-derived index, a preview, or a private
  key. Verified by a test that queries `information_schema.columns` for those names.
- **Invitation and refresh tokens are stored as 32-byte HMAC-SHA256 hashes only.** The
  peppers live in the environment, so a stolen database cannot mint or verify a token.
- **State validity is a CHECK constraint**, not application hope: a `delivered` message
  without a `delivered_at`, an invitation both used and revoked, a non-canonical friendship
  pair and a bare password in the credential column are all rejected by the database.
- **Primary keys are `gen_random_uuid()` (v4).** PostgreSQL 18 offers `uuidv7()`, but it is
  time-ordered, which makes ids partially predictable and leaks creation order. The brief
  requires opaque unpredictable ids, so random v4 is correct here.

## Tables

### `users`
`id` · `username` · `status` · `invited_by_user_id` · `created_at` · `deleted_at`

Account identity only. **No email address is collected** — it is not needed to operate the
system. `username` is a login handle and never a cryptographic identity. Unique on
`lower(username)`.

### `user_credentials`
`user_id` (PK) · `password_hash` · `algorithm` · `updated_at`

Separate table so the authentication mechanism can change without touching identity.
`CHECK (password_hash LIKE '$argon2id$%' AND length >= 32)` makes storing a bare password a
constraint violation rather than a code review question.

### `devices`
`id` · `user_id` · `device_name` · `platform` · `public_identity_key` · `registration_id` ·
`device_index` · `protocol` · `protocol_metadata` · `created_at` · `last_seen_at` ·
`revoked_at`

One row per installation, holding **public** key material only.

`device_index` (1–127) exists because libsignal's `ProtocolAddress` rejects anything outside
that range, so the opaque UUID cannot serve as the protocol address. It is allocated
monotonically and **never reused**, including after revocation: a peer caches sessions by
`(userId, deviceIndex)`, so handing a retired index to a new installation would route
messages to a different identity key. Unique on `(user_id, device_index)`.

### `device_signed_prekeys`
`(device_id, prekey_id)` PK · `public_key` · `signature` · `created_at` · `retired_at`

Partial unique index enforces at most one non-retired signed prekey per device.

### `device_one_time_prekeys`
`(device_id, prekey_id)` PK · `public_key` · `created_at` · `consumed_at` ·
`consumed_by_device_id`

A consumable resource, so handing one out is attacker-triggerable. Consumption is atomic
(`FOR UPDATE SKIP LOCKED`), the consuming device is recorded for audit, and exhaustion
degrades to signed-prekey-only X3DH rather than reusing a key.

### `device_kyber_prekeys`
`(device_id, prekey_id)` PK · `public_key` · `signature` · `is_last_resort` · `created_at` ·
`consumed_at`

**Not optional.** libsignal's `PreKeyBundle` requires Kyber fields, so the protocol is
PQXDH. A last-resort key is reusable and may never be marked consumed (CHECK); at most one
per device.

### `invitations`
`id` · `creator_user_id` · `token_hash` · `purpose` · `expires_at` · `used_at` ·
`used_by_user_id` · `revoked_at` · `created_at`

`purpose` is one of `register_and_befriend`, `register_only`, `befriend_only`. Constraints
enforce single use (`used_at` ⇔ `used_by_user_id`), that an invitation cannot be both used
and revoked, and that expiry is after creation.

### `friendships`
`id` · `user_a_id` · `user_b_id` · `status` · `invitation_id` · `created_at` ·
`accepted_at` · `verified_at` · `blocked_at`

`CHECK (user_a_id < user_b_id)` plus `UNIQUE (user_a_id, user_b_id)` means one relationship
cannot be stored twice in opposite orders. Writers use `LEAST`/`GREATEST` to normalise.

`verified_at` is **advisory metadata only**. Verification is a client-local trust decision
([decisions.md](decisions.md) D4), and a client that trusted this column could be told
"verified" about a key the server substituted.

### `auth_sessions`
`id` · `user_id` · `device_id` · `family_id` · `refresh_token_hash` · `created_at` ·
`expires_at` · `rotated_at` · `revoked_at` · `revoked_reason` · `user_agent`

Refresh rotation with theft detection. Sessions share a `family_id`; presenting an
already-rotated token revokes the whole family. `revoked_reason` is constrained to a known
set, so an unexplained revocation cannot be written.

### `messages`
`id` · `envelope_version` · `sender_device_id` · `recipient_device_id` · `protocol` ·
`ciphertext` · `protocol_metadata` · `message_type` · `delivery_state` · `sender_sequence` ·
`created_at` · `delivered_at` · `read_at` · `expires_at`

Encrypted envelopes. `ciphertext` is opaque bytes, bounded to 64 KiB — an unbounded blob
column is a denial-of-service surface. `message_type` (`prekey` | `signal`) is routing
metadata the recipient needs to pick the right libsignal decrypt path; it says nothing
about the plaintext.

Constraints keep state and timestamps consistent, forbid self-addressing, and
`UNIQUE (sender_device_id, recipient_device_id, sender_sequence)` makes replay and client
retry a no-op rather than a duplicate row.

### `security_events`
`id` · `user_id` · `device_id` · `event_type` · `severity` · `metadata` · `created_at`

`metadata` passes through a sanitiser that replaces any key whose name resembles a secret
(`token`, `password`, `ciphertext`, `hash`, …) before it reaches the database — defence in
depth alongside the logger's own redaction.

### `schema_migrations`
`filename` (PK) · `checksum` · `applied_at`

## Indexes

Beyond the primary keys and uniqueness constraints:

| Index | Serves |
|---|---|
| `devices_user_active_idx` (partial) | "active devices of this user" — the fan-out path |
| `device_one_time_prekeys_available_idx` (partial) | prekey bundle assembly |
| `messages_recipient_queue_idx` (partial) | queue drain for one device |
| `messages_expiry_idx` (partial) | retention sweep |
| `invitations_pending_idx` (partial) | expiry sweep |
| `auth_sessions_family_idx` | family revocation on reuse detection |
| `security_events_*` | audit queries by user, type and time |

## Retention

The server is a relay, not an archive. Delivered messages are deleted once acknowledged,
and queued messages expire after `QUEUED_MESSAGE_TTL_DAYS`. Full policy in
[security-model.md](security-model.md) section 3.
