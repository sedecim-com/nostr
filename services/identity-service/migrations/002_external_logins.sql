-- External logins (Acceso / AWS Cognito) attached to an account by the user (ADR 0008).
-- Only the issuer and subject are kept: tokens are verified and discarded.
CREATE TABLE IF NOT EXISTS external_logins (
  account_id text NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
  provider   text NOT NULL CHECK (provider IN ('cognito')),
  issuer     text NOT NULL,
  subject    text NOT NULL,
  username   text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, provider),
  UNIQUE (provider, issuer, subject)
);
