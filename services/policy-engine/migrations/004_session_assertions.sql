-- FR023-11: once an owner registers a passkey, every session of theirs asks for a WebAuthn assertion of it.
-- A session records the passkey whose assertion opened it. NULL: it was opened without one, like every session before
-- this migration; such a session stops counting once its owner has registered a passkey (right away for the owners who
-- registered one before this migration), and registering a passkey deletes them.
ALTER TABLE policy_sessions ADD COLUMN IF NOT EXISTS credential_id text;
CREATE INDEX IF NOT EXISTS policy_sessions_pubkey_idx ON policy_sessions (pubkey);

-- A device may wait for a registration and for an assertion at once without one challenge replacing the other. The
-- challenges pending before this migration are registration ones.
ALTER TABLE policy_webauthn_challenges ADD COLUMN IF NOT EXISTS purpose text NOT NULL DEFAULT 'register' CHECK (purpose IN ('register', 'assert'));
ALTER TABLE policy_webauthn_challenges DROP CONSTRAINT IF EXISTS policy_webauthn_challenges_pkey;
ALTER TABLE policy_webauthn_challenges ADD PRIMARY KEY (device_id, purpose);
