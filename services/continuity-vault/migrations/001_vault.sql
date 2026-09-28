-- VAULT-01 (ADR 0011): Continuity Vault metadata. The sealed envelopes live in the object store; the
-- database only knows which account stores how many archives, how big and when. Never their content, and
-- never what an archive is: ids are opaque (an HMAC under the client's archive key).
CREATE TABLE IF NOT EXISTS vault_owners (
  owner    text PRIMARY KEY CHECK (owner ~ '^(nostr:[0-9a-f]{64}|acceso:.+#.+)$'),
  archives integer NOT NULL DEFAULT 0 CHECK (archives >= 0),
  bytes    bigint NOT NULL DEFAULT 0 CHECK (bytes >= 0)
);

CREATE TABLE IF NOT EXISTS vault_archives (
  owner      text NOT NULL REFERENCES vault_owners(owner) ON DELETE CASCADE,
  archive_id text NOT NULL CHECK (archive_id ~ '^[0-9a-f]{64}$'),
  key_id     text NOT NULL CHECK (key_id ~ '^[0-9a-f]{16}$'),
  size       integer NOT NULL CHECK (size > 0),
  sha256     text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  object_key text NOT NULL UNIQUE CHECK (object_key ~ '^[0-9a-f]{32}$'),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  PRIMARY KEY (owner, archive_id)
);
