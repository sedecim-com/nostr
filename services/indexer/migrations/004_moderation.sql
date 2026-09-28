-- FR014-05: NIP-29 moderation deletions (kind 9005) seen by the mirror. A deletion hides its target from every
-- read once it is authorized: the target's author, or an owner/admin in the channel's relay-signed kind 39001.
-- Kept apart so the order in which the deletion, its target and the admin list arrive does not matter.
CREATE TABLE IF NOT EXISTS moderation_deletions (
  deletion_id text NOT NULL,
  target_id   text NOT NULL,
  h_tag       text NOT NULL,
  actor       text NOT NULL,
  applied     boolean NOT NULL DEFAULT false,
  PRIMARY KEY (deletion_id, target_id)
);
CREATE INDEX IF NOT EXISTS moderation_deletions_target_idx ON moderation_deletions (target_id) WHERE NOT applied;
CREATE INDEX IF NOT EXISTS moderation_deletions_pending_idx ON moderation_deletions (h_tag) WHERE NOT applied;

-- Membership lookups (39001/39002 rows of a reader, by signer): the p_tags GIN index plus the kind.
CREATE INDEX IF NOT EXISTS events_group_access_idx ON events (kind, d_tag) WHERE kind IN (39001, 39002);
