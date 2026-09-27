-- NFR005-01: horizontally scaled indexer (N replicas over the same database).

-- Addressable `d` value as an index column: head selection no longer reads raw_event_json, so it also works
-- on a sealed mirror. Plain rows are backfilled; pre-existing sealed addressable rows keep NULL and are not
-- considered heads (a newer version of their address is stored beside them).
ALTER TABLE events ADD COLUMN IF NOT EXISTS d_tag text;
UPDATE events SET d_tag = COALESCE((SELECT t ->> 1 FROM jsonb_array_elements(raw_event_json -> 'tags') t WHERE t ->> 0 = 'd' LIMIT 1), '')
  WHERE kind >= 30000 AND kind < 40000 AND raw_event_json IS NOT NULL AND d_tag IS NULL;
CREATE INDEX IF NOT EXISTS events_address_idx ON events (pubkey, kind, d_tag);

-- Live replicas (heartbeat on the database clock). Shards are assigned by rendezvous hashing over this set.
CREATE TABLE IF NOT EXISTS indexer_replicas (
  replica_id    text PRIMARY KEY,
  started_at    timestamptz NOT NULL DEFAULT now(),
  heartbeat_at  timestamptz NOT NULL DEFAULT now()
);

-- Per shard (relay, or relay + channel): every event with created_at <= synced_until was ingested. A replica
-- taking a shard over resubscribes from synced_until minus an overlap window. Only moves forward.
CREATE TABLE IF NOT EXISTS indexer_checkpoints (
  shard_key     text PRIMARY KEY,
  synced_until  bigint NOT NULL CHECK (synced_until >= 0),
  updated_by    text NOT NULL,
  updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Cluster-wide periodic jobs (retention): claimed atomically so one replica runs each interval.
CREATE TABLE IF NOT EXISTS indexer_jobs (
  job          text PRIMARY KEY,
  last_run_at  timestamptz NOT NULL,
  run_by       text NOT NULL
);
