-- IR-2026-09-04: NIP-98 event ids already accepted, shared by every service and replica on this database.
CREATE TABLE IF NOT EXISTS nip98_replay (
  event_id text PRIMARY KEY,
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS nip98_replay_expires ON nip98_replay (expires_at);
