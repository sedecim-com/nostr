-- FR005-11: owners list and close their own device sessions.
CREATE INDEX IF NOT EXISTS managed_signer_device_sessions_owner ON managed_signer_device_sessions (owner, expires_at);
