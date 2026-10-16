-- ============================================================================
-- 002_message_type.sql
--
-- Adds messages.message_type.
--
-- The recipient must know whether an envelope is a PreKeySignalMessage (which
-- establishes a session) or a SignalMessage (which uses an existing one),
-- because libsignal has a separate decrypt entry point for each. The validation
-- spike confirmed the distinction is observable and load-bearing: a sender keeps
-- emitting PreKey messages until it receives a reply.
--
-- This is routing metadata, not content. It says nothing about the plaintext.
-- ============================================================================

BEGIN;

ALTER TABLE messages
    ADD COLUMN message_type TEXT NOT NULL DEFAULT 'signal';

ALTER TABLE messages
    ADD CONSTRAINT messages_message_type_valid
        CHECK (message_type IN ('prekey', 'signal'));

COMMENT ON COLUMN messages.message_type IS
    'prekey = session-establishing PreKeySignalMessage, signal = SignalMessage. Routing metadata only.';

COMMIT;
