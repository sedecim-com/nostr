-- FR024-03: devices revoked by the organisation (policy-engine) and signer sessions bound to a device.
-- Tokens are never stored: only their SHA-256.
CREATE TABLE IF NOT EXISTS managed_signer_revoked_devices (
  device_id  text PRIMARY KEY,
  revoked_at timestamptz NOT NULL,
  revoked_by text NOT NULL,
  reason     text
);

CREATE TABLE IF NOT EXISTS managed_signer_device_sessions (
  token_hash text PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  device_id  text NOT NULL,
  owner      text NOT NULL,
  principal  text NOT NULL,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS managed_signer_device_sessions_device ON managed_signer_device_sessions (device_id);
CREATE INDEX IF NOT EXISTS managed_signer_device_sessions_expiry ON managed_signer_device_sessions (expires_at);

-- Device that performed each custodial operation (when the call came through a device session).
ALTER TABLE managed_key_usage ADD COLUMN IF NOT EXISTS device_id text;
