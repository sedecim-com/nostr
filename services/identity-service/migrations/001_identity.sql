-- Identity graph (spec §19.3) and key custody metadata (§19.4). No secret material is ever stored here.
CREATE TABLE IF NOT EXISTS accounts (
  account_id  text PRIMARY KEY,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS identity_personas (
  persona_id         text PRIMARY KEY,
  account_id         text NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
  pubkey             text NOT NULL UNIQUE CHECK (pubkey ~ '^[0-9a-f]{64}$'),
  custody_mode       text NOT NULL CHECK (custody_mode IN ('local','offline','external','encrypted-backup','managed','managed-enclave')),
  linkage_visibility text NOT NULL DEFAULT 'private' CHECK (linkage_visibility IN ('private','selective','public')),
  label              text,
  created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS identity_links (
  link_id      text PRIMARY KEY,
  from_persona text NOT NULL REFERENCES identity_personas(persona_id) ON DELETE CASCADE,
  to_persona   text NOT NULL REFERENCES identity_personas(persona_id) ON DELETE CASCADE,
  visibility   text NOT NULL CHECK (visibility IN ('private','selective','public')),
  audience     text[] NOT NULL DEFAULT '{}',
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (from_persona, to_persona)
);

CREATE TABLE IF NOT EXISTS key_metadata (
  key_id          text PRIMARY KEY,
  persona_id      text NOT NULL REFERENCES identity_personas(persona_id) ON DELETE CASCADE,
  provider        text NOT NULL,
  version         integer NOT NULL DEFAULT 1,
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_used       timestamptz,
  recovery_state  text NOT NULL DEFAULT 'none'
);

CREATE TABLE IF NOT EXISTS identity_audit (
  id          bigserial PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  account_id  text NOT NULL,
  actor       text NOT NULL,
  action      text NOT NULL,
  details     jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS identity_audit_account_idx ON identity_audit (account_id, at);
