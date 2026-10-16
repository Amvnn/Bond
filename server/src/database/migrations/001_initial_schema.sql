-- ============================================================================
-- 001_initial_schema.sql
-- PrivateMessenger Phase 1 schema.
--
-- HARD RULES enforced by this schema:
--   * No column holds message plaintext.
--   * No column holds a plaintext-derived search index.
--   * No column holds a private key of any kind.
--   * Invitation tokens are stored as hashes only.
--   * State validity is enforced by CHECK constraints, not by application hope.
--
-- All primary keys use gen_random_uuid() (UUIDv4) deliberately. UUIDv7 is
-- available in PostgreSQL 18 but is time-ordered, which makes identifiers
-- partially predictable and leaks creation order. The brief requires opaque,
-- unpredictable IDs, so random v4 is the correct trade here.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- users
-- Account identity only. Deliberately holds no email address: it is not needed
-- to operate the system, so it is not collected (privacy: minimum metadata).
-- The username is a login handle and is NEVER a cryptographic identity.
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username            TEXT        NOT NULL,
    status              TEXT        NOT NULL DEFAULT 'active',
    invited_by_user_id  UUID        REFERENCES users (id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ,

    CONSTRAINT users_status_valid
        CHECK (status IN ('active', 'suspended', 'deleted')),
    CONSTRAINT users_username_shape
        CHECK (username ~ '^[a-z0-9_]{3,32}$'),
    CONSTRAINT users_deleted_consistency
        CHECK ((status = 'deleted') = (deleted_at IS NOT NULL))
);

-- Case-insensitive uniqueness without relying on the citext extension.
CREATE UNIQUE INDEX users_username_key ON users (lower(username));

COMMENT ON TABLE  users IS 'Account identity. Separate from device cryptographic identity.';
COMMENT ON COLUMN users.username IS 'Login handle only. Never a cryptographic identity.';

-- ---------------------------------------------------------------------------
-- user_credentials
-- Kept in its own table so the authentication mechanism can be replaced
-- without touching account identity. Holds a verifier, never a password.
-- ---------------------------------------------------------------------------
CREATE TABLE user_credentials (
    user_id         UUID        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    password_hash   TEXT        NOT NULL,
    algorithm       TEXT        NOT NULL DEFAULT 'argon2id',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT user_credentials_algorithm_valid
        CHECK (algorithm IN ('argon2id')),
    -- Defence in depth: reject anything that is not a PHC-format hash string,
    -- which makes storing a bare password a constraint violation.
    CONSTRAINT user_credentials_hash_is_phc
        CHECK (password_hash LIKE '$argon2id$%' AND length(password_hash) >= 32)
);

COMMENT ON COLUMN user_credentials.password_hash IS 'Argon2id PHC string. Never a password, never reversible.';

-- ---------------------------------------------------------------------------
-- devices
-- One row per application installation. Holds PUBLIC key material only.
-- ---------------------------------------------------------------------------
CREATE TABLE devices (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_name             TEXT        NOT NULL,
    platform                TEXT        NOT NULL,
    -- Signal Protocol public identity key. PUBLIC half only.
    public_identity_key     BYTEA       NOT NULL,
    -- libsignal registration id, required for session addressing.
    registration_id         INTEGER     NOT NULL,
    -- libsignal ProtocolAddress requires a device id in the range 1..127, so
    -- the opaque UUID above cannot serve as the protocol-level address. This is
    -- a small per-user index used ONLY for libsignal addressing; it is never an
    -- external identifier and must never replace `id` in an API response.
    -- Verified against the library, not assumed: see the validation spike.
    device_index            SMALLINT    NOT NULL,
    protocol                TEXT        NOT NULL DEFAULT 'signal',
    protocol_metadata       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at            TIMESTAMPTZ,
    revoked_at              TIMESTAMPTZ,

    CONSTRAINT devices_platform_valid
        CHECK (platform IN ('android', 'ios', 'windows', 'linux', 'macos')),
    CONSTRAINT devices_name_length
        CHECK (char_length(device_name) BETWEEN 1 AND 64),
    CONSTRAINT devices_identity_key_length
        CHECK (octet_length(public_identity_key) BETWEEN 32 AND 33),
    CONSTRAINT devices_registration_id_range
        CHECK (registration_id BETWEEN 1 AND 16383),
    CONSTRAINT devices_index_range
        CHECK (device_index BETWEEN 1 AND 127),
    CONSTRAINT devices_protocol_valid
        CHECK (protocol IN ('signal')),
    -- One protocol address per user. Reusing an index for a different device
    -- would let messages route to the wrong session.
    CONSTRAINT devices_user_index_unique
        UNIQUE (user_id, device_index)
);

CREATE INDEX devices_user_id_idx ON devices (user_id);
-- Partial index: the hot path is "active devices of this user".
CREATE INDEX devices_user_active_idx ON devices (user_id) WHERE revoked_at IS NULL;

COMMENT ON TABLE  devices IS 'One row per installation. PUBLIC key material only; private keys never leave the device.';
COMMENT ON COLUMN devices.public_identity_key IS 'PUBLIC identity key. Storing a private key here is a security incident.';

-- ---------------------------------------------------------------------------
-- device_signed_prekeys
-- Signed prekey plus its signature. The signature is verified against the
-- device identity key at registration time and again by the recipient client.
-- ---------------------------------------------------------------------------
CREATE TABLE device_signed_prekeys (
    device_id       UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    prekey_id       INTEGER     NOT NULL,
    public_key      BYTEA       NOT NULL,
    signature       BYTEA       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at      TIMESTAMPTZ,

    PRIMARY KEY (device_id, prekey_id),
    CONSTRAINT device_signed_prekeys_id_range
        CHECK (prekey_id BETWEEN 0 AND 16777215),
    CONSTRAINT device_signed_prekeys_public_key_length
        CHECK (octet_length(public_key) BETWEEN 32 AND 33),
    CONSTRAINT device_signed_prekeys_signature_length
        CHECK (octet_length(signature) = 64)
);

-- At most one current (non-retired) signed prekey per device.
CREATE UNIQUE INDEX device_signed_prekeys_current_idx
    ON device_signed_prekeys (device_id) WHERE retired_at IS NULL;

-- ---------------------------------------------------------------------------
-- device_one_time_prekeys
-- A consumable resource. Handing one out is an attacker-triggerable drain, so
-- consumption is atomic (SELECT ... FOR UPDATE SKIP LOCKED) and rate-limited
-- in the application layer. Running out must degrade to signed-prekey-only
-- X3DH, never reuse a key. See docs/crypto-design.md section 4.
-- ---------------------------------------------------------------------------
CREATE TABLE device_one_time_prekeys (
    device_id       UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    prekey_id       INTEGER     NOT NULL,
    public_key      BYTEA       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at     TIMESTAMPTZ,
    consumed_by_device_id UUID  REFERENCES devices (id) ON DELETE SET NULL,

    PRIMARY KEY (device_id, prekey_id),
    CONSTRAINT device_one_time_prekeys_id_range
        CHECK (prekey_id BETWEEN 0 AND 16777215),
    CONSTRAINT device_one_time_prekeys_public_key_length
        CHECK (octet_length(public_key) BETWEEN 32 AND 33),
    CONSTRAINT device_one_time_prekeys_consumption_consistency
        CHECK ((consumed_at IS NULL) = (consumed_by_device_id IS NULL))
);

-- Hot path: find an unconsumed prekey for a device.
CREATE INDEX device_one_time_prekeys_available_idx
    ON device_one_time_prekeys (device_id) WHERE consumed_at IS NULL;

-- ---------------------------------------------------------------------------
-- device_kyber_prekeys
-- Post-quantum (Kyber) prekeys for PQXDH.
--
-- These are NOT optional. libsignal 0.103's PreKeyBundle requires
-- kyber_pre_key_id, kyber_pre_key_public and kyber_pre_key_signature, so the
-- protocol is PQXDH and a bundle cannot be assembled without them. This was
-- verified against the library in the validation spike, and it settles open
-- question O1 in docs/decisions.md: post-quantum is mandatory, not a choice.
--
-- A last-resort key may be reused when the one-time supply is exhausted; a
-- non-last-resort key is consumed once, like a one-time prekey.
-- ---------------------------------------------------------------------------
CREATE TABLE device_kyber_prekeys (
    device_id       UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    prekey_id       INTEGER     NOT NULL,
    public_key      BYTEA       NOT NULL,
    signature       BYTEA       NOT NULL,
    is_last_resort  BOOLEAN     NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at     TIMESTAMPTZ,

    PRIMARY KEY (device_id, prekey_id),
    CONSTRAINT device_kyber_prekeys_id_range
        CHECK (prekey_id BETWEEN 0 AND 16777215),
    -- Kyber-1024 public keys are far larger than X25519 keys; bound the column
    -- generously but not unboundedly.
    CONSTRAINT device_kyber_prekeys_public_key_length
        CHECK (octet_length(public_key) BETWEEN 800 AND 2048),
    CONSTRAINT device_kyber_prekeys_signature_length
        CHECK (octet_length(signature) = 64),
    -- A last-resort key is reusable, so it must never be marked consumed.
    CONSTRAINT device_kyber_prekeys_last_resort_not_consumed
        CHECK (NOT is_last_resort OR consumed_at IS NULL)
);

CREATE INDEX device_kyber_prekeys_available_idx
    ON device_kyber_prekeys (device_id) WHERE consumed_at IS NULL;
-- At most one last-resort key per device.
CREATE UNIQUE INDEX device_kyber_prekeys_last_resort_idx
    ON device_kyber_prekeys (device_id) WHERE is_last_resort;

-- ---------------------------------------------------------------------------
-- invitations
-- Token is stored as a hash ONLY. The plaintext token is returned to the
-- creator exactly once and is never persisted or logged.
-- purpose distinguishes a combined registration+friendship invite from a
-- registration-only one, so the second can exist later without a migration.
-- See docs/decisions.md D3.
-- ---------------------------------------------------------------------------
CREATE TABLE invitations (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    creator_user_id     UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash          BYTEA       NOT NULL UNIQUE,
    purpose             TEXT        NOT NULL DEFAULT 'register_and_befriend',
    expires_at          TIMESTAMPTZ NOT NULL,
    used_at             TIMESTAMPTZ,
    used_by_user_id     UUID        REFERENCES users (id) ON DELETE SET NULL,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT invitations_purpose_valid
        CHECK (purpose IN ('register_and_befriend', 'register_only', 'befriend_only')),
    -- SHA-256 of the token.
    CONSTRAINT invitations_token_hash_length
        CHECK (octet_length(token_hash) = 32),
    CONSTRAINT invitations_expiry_after_creation
        CHECK (expires_at > created_at),
    -- Single-use: consumption must record who consumed it.
    CONSTRAINT invitations_use_consistency
        CHECK ((used_at IS NULL) = (used_by_user_id IS NULL)),
    -- An invitation cannot be both used and revoked.
    CONSTRAINT invitations_not_used_and_revoked
        CHECK (used_at IS NULL OR revoked_at IS NULL)
);

CREATE INDEX invitations_creator_idx ON invitations (creator_user_id);
CREATE INDEX invitations_pending_idx ON invitations (expires_at)
    WHERE used_at IS NULL AND revoked_at IS NULL;

COMMENT ON COLUMN invitations.token_hash IS 'SHA-256 of the token. The token itself is never stored or logged.';

-- ---------------------------------------------------------------------------
-- friendships
-- Canonical pair ordering (user_a_id < user_b_id) plus a unique constraint, so
-- one relationship cannot be represented twice in opposite orders.
-- verified_at is ADVISORY METADATA ONLY. Verification authority is the client;
-- a server that sets this column must not be able to make a client display
-- "verified". See docs/decisions.md D4.
-- ---------------------------------------------------------------------------
CREATE TABLE friendships (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_a_id       UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    user_b_id       UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    status          TEXT        NOT NULL DEFAULT 'pending',
    invitation_id   UUID        REFERENCES invitations (id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    accepted_at     TIMESTAMPTZ,
    verified_at     TIMESTAMPTZ,
    blocked_at      TIMESTAMPTZ,

    CONSTRAINT friendships_status_valid
        CHECK (status IN ('pending', 'active', 'blocked')),
    CONSTRAINT friendships_canonical_order
        CHECK (user_a_id < user_b_id),
    CONSTRAINT friendships_no_self
        CHECK (user_a_id <> user_b_id),
    CONSTRAINT friendships_active_has_accepted_at
        CHECK (status <> 'active' OR accepted_at IS NOT NULL),
    CONSTRAINT friendships_blocked_has_blocked_at
        CHECK ((status = 'blocked') = (blocked_at IS NOT NULL)),
    CONSTRAINT friendships_unique_pair
        UNIQUE (user_a_id, user_b_id)
);

CREATE INDEX friendships_user_b_idx ON friendships (user_b_id);

COMMENT ON COLUMN friendships.verified_at IS 'ADVISORY ONLY. Real verification state is a client-local trust decision.';

-- ---------------------------------------------------------------------------
-- auth_sessions
-- Refresh-token rotation with theft detection. A session family shares a
-- family_id; reuse of an already-rotated refresh token revokes the whole
-- family. Tokens are stored as hashes only.
-- ---------------------------------------------------------------------------
CREATE TABLE auth_sessions (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id           UUID        REFERENCES devices (id) ON DELETE CASCADE,
    family_id           UUID        NOT NULL,
    refresh_token_hash  BYTEA       NOT NULL UNIQUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    rotated_at          TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    revoked_reason      TEXT,
    user_agent          TEXT,

    CONSTRAINT auth_sessions_token_hash_length
        CHECK (octet_length(refresh_token_hash) = 32),
    CONSTRAINT auth_sessions_expiry_after_creation
        CHECK (expires_at > created_at),
    CONSTRAINT auth_sessions_revoked_reason_valid
        CHECK (revoked_reason IS NULL OR revoked_reason IN
            ('logout', 'rotation', 'reuse_detected', 'device_revoked', 'admin', 'password_change'))
);

CREATE INDEX auth_sessions_user_idx ON auth_sessions (user_id);
CREATE INDEX auth_sessions_family_idx ON auth_sessions (family_id);
CREATE INDEX auth_sessions_active_idx ON auth_sessions (user_id)
    WHERE revoked_at IS NULL AND rotated_at IS NULL;

COMMENT ON COLUMN auth_sessions.refresh_token_hash IS 'SHA-256 of the refresh token. The token itself is never stored or logged.';

-- ---------------------------------------------------------------------------
-- messages
-- Encrypted envelopes. ciphertext is OPAQUE BYTES to this server.
--
-- There is deliberately NO plaintext column, NO preview column and NO
-- search index. Adding any of those breaks the security model.
-- ---------------------------------------------------------------------------
CREATE TABLE messages (
    id                      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    envelope_version        SMALLINT    NOT NULL DEFAULT 1,
    sender_device_id        UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    recipient_device_id     UUID        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    protocol                TEXT        NOT NULL DEFAULT 'signal',
    ciphertext              BYTEA       NOT NULL,
    protocol_metadata       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    delivery_state          TEXT        NOT NULL DEFAULT 'queued',
    -- Sender-assigned monotonic counter, used for deterministic ordering
    -- independent of server arrival time.
    sender_sequence         BIGINT      NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at            TIMESTAMPTZ,
    read_at                 TIMESTAMPTZ,
    expires_at              TIMESTAMPTZ NOT NULL,

    CONSTRAINT messages_envelope_version_supported
        CHECK (envelope_version = 1),
    CONSTRAINT messages_protocol_valid
        CHECK (protocol IN ('signal')),
    CONSTRAINT messages_delivery_state_valid
        CHECK (delivery_state IN ('queued', 'delivered', 'read', 'expired')),
    CONSTRAINT messages_not_self_addressed
        CHECK (sender_device_id <> recipient_device_id),
    -- Bound the envelope. A text message does not need megabytes, and an
    -- unbounded ciphertext column is a denial-of-service surface.
    CONSTRAINT messages_ciphertext_size
        CHECK (octet_length(ciphertext) BETWEEN 1 AND 65536),
    CONSTRAINT messages_sender_sequence_positive
        CHECK (sender_sequence >= 0),
    -- State and timestamps must agree.
    CONSTRAINT messages_delivered_consistency
        CHECK ((delivery_state IN ('delivered', 'read')) = (delivered_at IS NOT NULL)),
    CONSTRAINT messages_read_consistency
        CHECK ((delivery_state = 'read') = (read_at IS NOT NULL)),
    CONSTRAINT messages_read_after_delivered
        CHECK (read_at IS NULL OR delivered_at IS NULL OR read_at >= delivered_at),
    CONSTRAINT messages_expiry_after_creation
        CHECK (expires_at > created_at)
);

-- Queue drain: "give me this device's undelivered messages, in sender order".
CREATE INDEX messages_recipient_queue_idx
    ON messages (recipient_device_id, sender_device_id, sender_sequence)
    WHERE delivery_state = 'queued';
-- Retention sweep.
CREATE INDEX messages_expiry_idx ON messages (expires_at)
    WHERE delivery_state = 'queued';
-- Replay/duplicate protection: a sender device cannot reuse a sequence number
-- toward the same recipient device.
CREATE UNIQUE INDEX messages_sender_sequence_key
    ON messages (sender_device_id, recipient_device_id, sender_sequence);

COMMENT ON TABLE  messages IS 'Encrypted envelopes only. This server cannot decrypt ciphertext and must never try.';
COMMENT ON COLUMN messages.ciphertext IS 'Opaque authenticated ciphertext. Never logged, never parsed, never indexed by content.';

-- ---------------------------------------------------------------------------
-- security_events
-- Audit log. metadata is for non-sensitive context ONLY: never tokens, never
-- key material, never ciphertext, never plaintext.
-- ---------------------------------------------------------------------------
CREATE TABLE security_events (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        REFERENCES users (id) ON DELETE SET NULL,
    device_id       UUID        REFERENCES devices (id) ON DELETE SET NULL,
    event_type      TEXT        NOT NULL,
    severity        TEXT        NOT NULL DEFAULT 'info',
    metadata        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT security_events_severity_valid
        CHECK (severity IN ('info', 'warning', 'critical'))
);

CREATE INDEX security_events_user_idx ON security_events (user_id, created_at DESC);
CREATE INDEX security_events_type_idx ON security_events (event_type, created_at DESC);
CREATE INDEX security_events_created_idx ON security_events (created_at);

COMMENT ON COLUMN security_events.metadata IS 'Non-sensitive context only. Never tokens, keys, ciphertext or plaintext.';

COMMIT;
