-- Managed (custodial) key registry and usage log (FR-005, DEC-09). Metadata only: key material lives
-- exclusively in the vault (local envelope files or AWS Secrets Manager + KMS).
CREATE TABLE IF NOT EXISTS managed_keys (
  key_id              text PRIMARY KEY,
  -- Acceso user (`${issuer}#${sub}`) or, in legacy service mode, the SaaS account id.
  owner               text NOT NULL,
  pubkey              text NOT NULL CHECK (pubkey ~ '^[0-9a-f]{64}$'),
  provider            text NOT NULL,
  version             integer NOT NULL DEFAULT 1,
  state               text NOT NULL CHECK (state IN ('active','export-pending','migrated','deleted')),
  allowed_kinds       integer[],
  migration_challenge text,
  retention_days      integer NOT NULL CHECK (retention_days >= 0),
  created_at          timestamptz NOT NULL,
  last_used_at        timestamptz,
  migrated_at         timestamptz,
  -- Deleted by the user: unusable from then on; the material is destroyed after retention_days.
  deleted_at          timestamptz,
  destroyed_at        timestamptz
);
-- A pubkey can only be under managed custody once at a time.
CREATE UNIQUE INDEX IF NOT EXISTS managed_keys_live_pubkey ON managed_keys (pubkey) WHERE state <> 'deleted';
CREATE INDEX IF NOT EXISTS managed_keys_owner ON managed_keys (owner);
CREATE INDEX IF NOT EXISTS managed_keys_pending_destruction ON managed_keys (deleted_at) WHERE deleted_at IS NOT NULL AND destroyed_at IS NULL;

-- Usage log of every custodial operation, kept 12 months (DEC-09).
CREATE TABLE IF NOT EXISTS managed_key_usage (
  id        bigserial PRIMARY KEY,
  key_id    text NOT NULL REFERENCES managed_keys(key_id),
  at        timestamptz NOT NULL,
  action    text NOT NULL,
  kind      integer,
  event_id  text,
  principal text NOT NULL
);
CREATE INDEX IF NOT EXISTS managed_key_usage_key ON managed_key_usage (key_id, at);
CREATE INDEX IF NOT EXISTS managed_key_usage_at ON managed_key_usage (at);
