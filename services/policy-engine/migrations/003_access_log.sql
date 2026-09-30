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

-- Decisions logged before this migration stay in policy_audit: it is append-only and nothing deletes from it. A copy goes
-- to the access log so that it shows them too; the copy follows the access log's retention.
INSERT INTO policy_access_log (at, pubkey, resource_id, action, allow)
SELECT at, actor, target, coalesce(details->>'action', ''), coalesce((details->>'allow')::boolean, false)
FROM policy_audit
WHERE action = 'policy.evaluate' AND NOT EXISTS (SELECT 1 FROM policy_access_log)
ORDER BY id;
