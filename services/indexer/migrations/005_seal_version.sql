-- SEC-06 (IR-2026-09-15): format of encrypted_payload. NULL: sealed before SEC-06, without AAD (or a plain
-- row); 2: XChaCha20-Poly1305 whose AAD names the row's event_id, so a payload moved to another row does not
-- authenticate. The indexer re-seals the NULL rows at start (PgEventRepository.resealLegacy).
ALTER TABLE events ADD COLUMN IF NOT EXISTS seal_version smallint;
