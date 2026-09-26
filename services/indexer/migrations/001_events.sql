-- Event mirror (spec §19.1). The signed event is canonical; this table is a derived index/cache.
CREATE TABLE IF NOT EXISTS events (
  event_id           text PRIMARY KEY CHECK (event_id ~ '^[0-9a-f]{64}$'),
  pubkey             text NOT NULL,
  kind               integer NOT NULL,
  created_at         bigint NOT NULL,
  raw_event_json     jsonb,
  encrypted_payload  bytea,
  first_seen_at      timestamptz NOT NULL DEFAULT now(),
  last_seen_at       timestamptz NOT NULL DEFAULT now(),
  community_id       text,
  h_tag              text,
  p_tags             text[] NOT NULL DEFAULT '{}',
  sensitivity_class  text NOT NULL,
  deleted_tombstone  boolean NOT NULL DEFAULT false,
  CHECK (raw_event_json IS NOT NULL OR encrypted_payload IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS events_kind_created_idx ON events (kind, created_at DESC);
CREATE INDEX IF NOT EXISTS events_pubkey_created_idx ON events (pubkey, created_at DESC);
CREATE INDEX IF NOT EXISTS events_h_created_idx ON events (h_tag, created_at DESC) WHERE h_tag IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_p_tags_idx ON events USING gin (p_tags);

-- Which relays each event was observed on (replication evidence for the mirror).
CREATE TABLE IF NOT EXISTS event_sources (
  event_id      text NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
  relay_url     text NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (event_id, relay_url)
);
