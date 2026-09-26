-- Per-reader read cursors for derived unread counts (FR-014). Messages with created_at <= read_until are
-- read. Reveals when a reader caught up on a channel: only served back to that reader (NIP-98).
CREATE TABLE IF NOT EXISTS read_cursors (
  reader_pubkey  text NOT NULL CHECK (reader_pubkey ~ '^[0-9a-f]{64}$'),
  h_tag          text NOT NULL,
  read_until     bigint NOT NULL CHECK (read_until >= 0),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (reader_pubkey, h_tag)
);
