-- FR026-04: leaving managed custody. `exit_reason` says how a deleted key left: migrated to its owner's own custody
-- (FR026-03) or cancelled without migrating (ARCO cancellation). Keys deleted before this migration were all
-- migrated first, which was the only way to delete them.
ALTER TABLE managed_keys ADD COLUMN IF NOT EXISTS exit_reason text CHECK (exit_reason IN ('migrated', 'cancelled'));
UPDATE managed_keys SET exit_reason = 'migrated' WHERE state = 'deleted' AND exit_reason IS NULL;

-- Once its material is destroyed the key no longer exists, and neither may what tied it to its owner: the Acceso
-- user and the recorded consent are kept "while the key exists" (docs/legal/custodia-managed.md §3). The retention
-- job clears them and stamps scrubbed_at; the usage log keeps its own 12-month retention.
ALTER TABLE managed_keys ADD COLUMN IF NOT EXISTS scrubbed_at timestamptz;
ALTER TABLE managed_keys ALTER COLUMN owner DROP NOT NULL;
CREATE INDEX IF NOT EXISTS managed_keys_pending_scrub ON managed_keys (destroyed_at) WHERE destroyed_at IS NOT NULL AND scrubbed_at IS NULL;
