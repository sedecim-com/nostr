-- FR005-08: the consent a managed key was created (or imported) with: the version of the texts and terms the
-- owner accepted, and when. Written once at creation; keys created before this migration have none.
ALTER TABLE managed_keys ADD COLUMN IF NOT EXISTS consent_version text;
ALTER TABLE managed_keys ADD COLUMN IF NOT EXISTS consent_at timestamptz;
