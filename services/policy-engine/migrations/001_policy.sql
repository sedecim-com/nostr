-- Institutional policy core (spec §16, FR023-03). Own tables prefixed policy_ in the platform DB.
-- Only identities, roles, devices and decisions: never message plaintext. Times are epoch milliseconds.
CREATE TABLE IF NOT EXISTS policy_subjects (
  pubkey      text PRIMARY KEY CHECK (pubkey ~ '^[0-9a-f]{64}$'),
  roles       text[] NOT NULL DEFAULT '{}',
  attributes  jsonb NOT NULL DEFAULT '{}',
  suspended   boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS policy_resources (
  id           text PRIMARY KEY,
  kind         text NOT NULL CHECK (kind IN ('workspace','channel','group')),
  sensitivity  text NOT NULL CHECK (sensitivity IN ('public','internal','confidential','secret')),
  rules        jsonb NOT NULL DEFAULT '[]',
  members      text[]
);

CREATE TABLE IF NOT EXISTS policy_devices (
  id                     text PRIMARY KEY,
  owner_pubkey           text NOT NULL CHECK (owner_pubkey ~ '^[0-9a-f]{64}$'),
  trust                  text NOT NULL CHECK (trust IN ('unverified','registered','attested')),
  registered_at          bigint NOT NULL,
  revoked_at             bigint,
  -- WebAuthn (FR023-07): public key only; the private key never leaves the authenticator.
  credential_id          text UNIQUE,
  credential_public_key  jsonb,
  sign_count             bigint,
  attestation_format     text
);
CREATE INDEX IF NOT EXISTS policy_devices_owner_idx ON policy_devices (owner_pubkey);

-- Session tokens are stored hashed (sha256): a DB leak does not yield usable tokens.
CREATE TABLE IF NOT EXISTS policy_sessions (
  token_hash  text PRIMARY KEY,
  pubkey      text NOT NULL,
  device_id   text NOT NULL REFERENCES policy_devices(id),
  created_at  bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS policy_sessions_device_idx ON policy_sessions (device_id);

CREATE TABLE IF NOT EXISTS policy_rotations (
  id              text PRIMARY KEY,
  seq             bigserial UNIQUE,
  at              bigint NOT NULL,
  resource_id     text NOT NULL,
  reason          text NOT NULL,
  removed_pubkey  text NOT NULL,
  status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','done')),
  done_at         bigint
);

-- Append-only audit: UPDATE, DELETE and TRUNCATE are rejected by triggers.
CREATE TABLE IF NOT EXISTS policy_audit (
  id       bigserial PRIMARY KEY,
  at       bigint NOT NULL,
  actor    text NOT NULL,
  action   text NOT NULL,
  target   text NOT NULL,
  details  jsonb
);
CREATE OR REPLACE FUNCTION policy_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'policy_audit is append-only';
END
$$;
DROP TRIGGER IF EXISTS policy_audit_no_update ON policy_audit;
CREATE TRIGGER policy_audit_no_update BEFORE UPDATE OR DELETE ON policy_audit FOR EACH ROW EXECUTE FUNCTION policy_audit_append_only();
DROP TRIGGER IF EXISTS policy_audit_no_truncate ON policy_audit;
CREATE TRIGGER policy_audit_no_truncate BEFORE TRUNCATE ON policy_audit FOR EACH STATEMENT EXECUTE FUNCTION policy_audit_append_only();

-- FR023-06: optional organisational directory, admin-only (never published to relays).
CREATE TABLE IF NOT EXISTS policy_directory (
  pubkey  text PRIMARY KEY CHECK (pubkey ~ '^[0-9a-f]{64}$'),
  title   text,
  unit    text
);

-- FR023-08: retention of the mirror copy per workspace/channel, with legal hold.
CREATE TABLE IF NOT EXISTS policy_retention (
  resource_id  text PRIMARY KEY,
  days         integer CHECK (days IS NULL OR days > 0),
  legal_hold   boolean NOT NULL DEFAULT false
);

-- Pending WebAuthn registration challenges (single use, short-lived).
CREATE TABLE IF NOT EXISTS policy_webauthn_challenges (
  device_id   text PRIMARY KEY,
  challenge   text NOT NULL,
  expires_at  bigint NOT NULL
);
