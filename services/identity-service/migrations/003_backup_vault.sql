-- FR027-03: cloud vault of encrypted backups. Only the envelope produced by the client is stored:
-- key and contents are encrypted with the user's backup password, which the service never receives.
CREATE TABLE IF NOT EXISTS backup_vault (
  seq            bigserial PRIMARY KEY,
  backup_id      text NOT NULL UNIQUE,
  account_id     text NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
  format         text NOT NULL CHECK (format IN ('sedecim-identity-backup','acceso-nostr-key-backup')),
  format_version integer NOT NULL,
  size           integer NOT NULL CHECK (size > 0),
  sha256         text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  npub           text,
  envelope       text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS backup_vault_account ON backup_vault (account_id, seq DESC);
