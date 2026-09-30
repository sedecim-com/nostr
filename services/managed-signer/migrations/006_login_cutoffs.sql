-- IR-2026-10-11: when an owner closes their other sessions, an Acceso login signed in before that moment is refused
-- (refreshing it keeps its sign-in time), except the login that asked for it (keep_login: its origin_jti/event_id).
-- One row per owner, replaced on every cut; purged with the usage log (DEC-09: 12 months).
CREATE TABLE IF NOT EXISTS managed_signer_login_cutoffs (
  owner      text PRIMARY KEY,
  cut_at     timestamptz NOT NULL,
  keep_login text
);
CREATE INDEX IF NOT EXISTS managed_signer_login_cutoffs_at ON managed_signer_login_cutoffs (cut_at);
