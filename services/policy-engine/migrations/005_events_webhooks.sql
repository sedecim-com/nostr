-- OPS-16: signed events and webhooks (docs/institutional.md, «Eventos firmados y webhooks»).
-- While events are on (POLICY_EVENTS_SIGNING_KEY_FILE), each audit entry is also written as an event, in the same
-- transaction: signed when it is emitted and kept signed, so its signature still verifies after the key changes. `seq` is
-- the stream position: writers draw it under an advisory lock held until they commit, so they commit in seq order and a
-- reader paging by seq never sees a position before a lower one that commits later. Entries written before this
-- migration, or while events are off, have no event: the audit keeps them.
CREATE TABLE IF NOT EXISTS policy_events (
  seq         bigserial PRIMARY KEY,
  id          text NOT NULL UNIQUE,
  -- The entry it copies, written in the same transaction. No foreign key: TRUNCATE policy_audit must keep failing on the
  -- audit's own append-only trigger.
  audit_id    bigint NOT NULL UNIQUE,
  type        text NOT NULL,
  created_at  bigint NOT NULL,
  -- The signed envelope as canonical JSON, served and delivered as it was signed.
  envelope    text NOT NULL
);
-- Append-only, like the audit it copies.
CREATE OR REPLACE FUNCTION policy_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'policy_events is append-only';
END
$$;
DROP TRIGGER IF EXISTS policy_events_no_update ON policy_events;
CREATE TRIGGER policy_events_no_update BEFORE UPDATE OR DELETE ON policy_events FOR EACH ROW EXECUTE FUNCTION policy_events_append_only();
DROP TRIGGER IF EXISTS policy_events_no_truncate ON policy_events;
CREATE TRIGGER policy_events_no_truncate BEFORE TRUNCATE ON policy_events FOR EACH STATEMENT EXECUTE FUNCTION policy_events_append_only();

-- Every public key that signed events (JWK `x`, `kid` = its RFC 7638 thumbprint): GET /v1/events/keys keeps serving
-- the keys of before a rotation, so the events they signed still verify.
CREATE TABLE IF NOT EXISTS policy_event_keys (
  kid         text PRIMARY KEY,
  x           text NOT NULL,
  created_at  bigint NOT NULL
);

-- Webhook subscriptions. The signing secret is not stored: the engine derives it from POLICY_WEBHOOK_SECRETS_KEY, the
-- id and the salt (HMAC-SHA256), so neither this table nor its backups hold a secret.
CREATE TABLE IF NOT EXISTS policy_webhooks (
  id                    text PRIMARY KEY,
  url                   text NOT NULL,
  types                 text[] NOT NULL DEFAULT '{}',
  status                text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  salt                  text NOT NULL,
  created_at            bigint NOT NULL,
  created_by            text NOT NULL,
  consecutive_failures  integer NOT NULL DEFAULT 0,
  disabled_at           bigint,
  disabled_reason       text
);

-- One delivery per event and active subscription, written with the event. A dispatcher claims it with a lease
-- (locked_until, lease_id) and records each attempt: status, count, HTTP status and class of the last failure; never the
-- destination's response body or headers. Finished deliveries are pruned after POLICY_WEBHOOK_DELIVERY_RETENTION_DAYS.
CREATE TABLE IF NOT EXISTS policy_webhook_deliveries (
  id               bigserial PRIMARY KEY,
  webhook_id       text NOT NULL REFERENCES policy_webhooks (id) ON DELETE CASCADE,
  event_seq        bigint NOT NULL REFERENCES policy_events (seq),
  status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'failed')),
  attempts         integer NOT NULL DEFAULT 0,
  next_attempt_at  bigint NOT NULL,
  locked_until     bigint,
  lease_id         text,
  last_attempt_at  bigint,
  last_status      integer,
  last_error       text,
  finished_at      bigint,
  created_at       bigint NOT NULL,
  UNIQUE (webhook_id, event_seq)
);
CREATE INDEX IF NOT EXISTS policy_webhook_deliveries_due_idx ON policy_webhook_deliveries (next_attempt_at, id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS policy_webhook_deliveries_finished_idx ON policy_webhook_deliveries (finished_at) WHERE status <> 'pending';
CREATE INDEX IF NOT EXISTS policy_webhook_deliveries_webhook_idx ON policy_webhook_deliveries (webhook_id, id);
