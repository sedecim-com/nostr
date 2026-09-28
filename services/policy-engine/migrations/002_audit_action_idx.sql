-- FR024-04: GET /v1/revocations reads the audit by action from a cursor (the revocation propagator's).
-- The build blocks audit writes while it runs. On a very large audit, create the index beforehand with
-- CREATE INDEX CONCURRENTLY (same name): IF NOT EXISTS then makes this migration a no-op.
CREATE INDEX IF NOT EXISTS policy_audit_action_idx ON policy_audit (action, id);
