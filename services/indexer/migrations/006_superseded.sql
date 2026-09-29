-- FR023-12: in institutional mode, the versions a replaceable/addressable event supersedes are moved here instead of
-- deleted, so a legal hold also covers what a newer version replaced (a channel's member list, a profile). The
-- retention job deletes those no hold covers. Canonical reads never see them.
CREATE TABLE IF NOT EXISTS events_superseded (
  event_id           text PRIMARY KEY CHECK (event_id ~ '^[0-9a-f]{64}$'),
  pubkey             text NOT NULL,
  kind               integer NOT NULL,
  created_at         bigint NOT NULL,
  raw_event_json     jsonb,
  encrypted_payload  bytea,
  seal_version       smallint,
  community_id       text,
  h_tag              text,
  d_tag              text,
  superseded_by      text NOT NULL,
  superseded_at      timestamptz NOT NULL DEFAULT now(),
  CHECK (raw_event_json IS NOT NULL OR encrypted_payload IS NOT NULL)
);
