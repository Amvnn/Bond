# Security Model — What the Server Can and Cannot See

**Date:** 2026-09-28
**Phase:** 1 — Secure 1-to-1 text messenger

This is the honest inventory. If a future change adds a row to the "can see" table, that is
a privacy regression and must be a deliberate, documented decision — not a side effect.

---

## 1. What the server CAN see

### Account and device metadata

| Item | Why it exists | Sensitivity |
|---|---|---|
| Opaque user ID | Addressing | Low alone |
| Account status | Suspension, deletion | Low |
| Account credential hash | Authentication | High if weakly hashed |
| Opaque device ID | Routing to a device | Low alone |
| Device name (user-supplied) | UI: "which device is this" | **User-chosen; may leak** ("Ali's work iPhone") |
| Platform | Compatibility, UI | Low |
| `created_at`, `last_seen_at` | Operations, presence | Activity pattern |
| `revoked_at` | Enforcement | Low |

### Public cryptographic material

Public identity keys, public signed prekeys plus signatures, public one-time prekeys,
and protocol metadata required for session establishment. All public by design. The server
needs these to distribute; holding them grants no decryption ability.

### Message envelopes

| Field | Server sees | Can it read content? |
|---|---|---|
| `message_id` | yes | no |
| `sender_device_id` | yes | no |
| `recipient_device_id` | yes | no |
| `ciphertext` | yes, as opaque bytes | **no** |
| `protocol_metadata` | yes | no |
| `created_at`, `delivered_at`, `read_at` | yes | no |

### Relationship and operational data

Friendships and their status; invitation records (hash, expiry, used/revoked state, and
who created them); delivery and read state; security events; connection events; rate-limit
counters; IP addresses and user agents as seen by the proxy.

### The metadata the server unavoidably learns

Stated bluntly, because this is the gap between "encrypted" and "private":

- **Who talks to whom** — the social graph, from the friendship table and envelope routing.
- **When, and how often** — timestamps on every message.
- **Approximate message length** — ciphertext size correlates with plaintext size.
- **Who is online, and when** — presence and `last_seen_at`.
- **Where from** — IP addresses, hence approximate location and network.
- **What devices exist** — platform, count, names.
- **Who invited whom** — invitation creator to accepted user.

E2EE does not address any of these. Phase 1 does not attempt to. Sealed sender, padding
and cover traffic are the mitigations, all deferred.

---

## 2. What the server CANNOT see

Design guarantees, each enforced by a specific mechanism.

| Never available | Enforced by |
|---|---|
| Message plaintext | Encryption happens on-device before transmission |
| Device private identity keys | Generated on-device, stored in platform secure storage, never transmitted |
| Session / ratchet state | Held on-device only |
| Per-message keys | Derived on-device from the ratchet |
| Plaintext search | No plaintext and no derived index exists to search |
| Invitation token plaintext | Only a hash is stored; the token is shown to the creator once |
| Local message history | Lives in the device's encrypted store |
| Whether a user truly verified a contact | Verification is a client-local decision; the server field is advisory |
| Account password | Only a hash is stored |

### Forbidden by construction

These must never exist. Their presence means the model has been broken:

- a `plaintext_message` column, or any column holding decrypted content
- a `message_search_text` column or any plaintext-derived index
- any column holding a private key
- a message preview or notification title derived from plaintext
- an application-wide or shared master encryption key for message content
- any server code path that decrypts message content

---

## 3. Database retention

| Data | Retention | Rationale |
|---|---|---|
| Queued (undelivered) messages | Deleted after a bounded window (target: 30 days) | Store-and-forward needs a limit; unbounded queues are a liability |
| Delivered messages | Deleted from the server once delivery is acknowledged | The server is a relay, not an archive. History lives on devices. |
| Read receipts / delivery state | Retained with the message record while it exists | |
| Invitation records | Retained while pending; hash retained briefly after use for audit, then purged | Replay and abuse investigation |
| Security events | Bounded retention (target: 90 days) | Audit without building a permanent behaviour log |
| Connection / presence state (Redis) | Ephemeral, TTL-bound | Never durable |
| Rate-limit counters (Redis) | Window-bound TTL | |
| Account and device records | Until the user deletes the account or revokes the device | |

**The server deliberately does not keep message history.** Once delivered and
acknowledged, the envelope is removed. This is the single most effective metadata and
content-exposure reduction available, and it is why device-side backup is a Phase 2+
question rather than a server feature.

---

## 4. Logging policy

### Never logged, under any level, in any environment

Message plaintext; ciphertext (beyond size, and not routinely); private keys; passwords;
access tokens; refresh tokens; invitation token plaintext; session secrets; any decrypted
payload.

### Permitted

Request ID; endpoint and method; response status; latency; device ID; user ID where
operationally necessary; authentication failure events (without the submitted credential);
rate-limit events; security events; connection and disconnection events; error class
(never a stack trace in a production response body).

### Enforcement

- Structured logging with an explicit redaction deny-list, applied at the logger rather
  than at each call site — per-call-site discipline fails eventually.
- A pre-completion review step greps logs for accidental secrets. Listed under
  `agent_behavior.after_coding` in the brief and required before Phase 1 is called done.
- Production error responses return an error code and request ID, never internals.

---

## 5. Metadata collected — full inventory

Everything the system stores about a user, in one list, so a privacy claim can be checked
against it rather than assumed.

**Per account:** opaque ID, credential hash, status, creation time, inviting user.
**Per device:** opaque ID, owning user, user-supplied name, platform, public key material,
creation time, last-seen time, revocation time.
**Per relationship:** the two user IDs, status, creation time, advisory verification time.
**Per invitation:** creator, token hash, expiry, used time, revoked time, creation time, purpose.
**Per message (while queued):** message ID, sender device, recipient device, ciphertext,
protocol metadata, created/delivered/read times.
**Per security event:** user, device, event type, time, non-sensitive context.
**Transient (Redis):** presence, active connections, rate-limit counters.
**Incidental (proxy/infrastructure):** IP addresses, user agents, TLS metadata, access logs.

Nothing here is advertising or analytics data, because there is none: no analytics SDK, no
telemetry, no crash reporting that could carry plaintext or key material.

---

## 6. Claims we may and may not make

**Supportable:**

- Message content is end-to-end encrypted; the server cannot read it.
- Private keys never leave the device.
- A stolen database yields no message content and no private keys.
- Message tampering is detected by the recipient.
- Identity key changes are detected and surfaced.

**Not supportable, and not to be implied:**

- "Anonymous" — accounts are invite-linked and IP-visible.
- "Metadata-private" or "zero-knowledge" — see section 1.
- "Secure because it uses HTTPS" — TLS is transport only.
- "Secure because it uses encryption" — the kind, scope and key custody are what matter.
- "Safe on a compromised device" — nothing here defends that.
- "Audited" — the upstream crypto library is audited. This application is not.
