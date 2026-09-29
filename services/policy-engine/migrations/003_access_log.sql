-- FR023-12: access decisions (POST /v1/evaluate) move out of the append-only audit into a log of their own with a
-- retention (ACCESS_LOG_RETENTION_DAYS), except for resources under legal hold. Who read or published what, and when,
-- is metadata the organisation should not keep forever; what admins do stays in policy_audit.
CREATE TABLE IF NOT EXISTS policy_access_log (
  id           bigserial PRIMARY KEY,
  at           bigint NOT NULL,
  pubkey       text NOT NULL,
  device_id    text,
  resource_id  text NOT NULL,
  action       text NOT NULL,
  allow        boolean NOT NULL
);
CREATE INDEX IF NOT EXISTS policy_access_log_at_idx ON policy_access_log (at);
CREATE INDEX IF NOT EXISTS policy_access_log_resource_idx ON policy_access_log (resource_id, id);
