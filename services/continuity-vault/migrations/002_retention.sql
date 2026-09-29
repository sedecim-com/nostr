-- VAULT-05 (ADR 0011): retention. An account may keep its archives for fewer days than the operator's maximum
-- (VAULT_RETENTION_DAYS); a sweep deletes what was not written for longer. NULL: the operator's maximum, or
-- until deleted when the operator sets none.
ALTER TABLE vault_owners ADD COLUMN IF NOT EXISTS retention_days integer CHECK (retention_days IS NULL OR retention_days > 0);
CREATE INDEX IF NOT EXISTS vault_archives_updated_at ON vault_archives (updated_at);
