-- IR-2026-09-15: sealed payloads bind their event id as AAD. NULL marks rows sealed before this change (no
-- AAD, or plain rows); the indexer reseals legacy rows in the background (PgEventRepository.resealLegacy).
ALTER TABLE events ADD COLUMN IF NOT EXISTS seal_version smallint;
CREATE INDEX IF NOT EXISTS events_legacy_seal_idx ON events (event_id) WHERE encrypted_payload IS NOT NULL AND seal_version IS NULL;
