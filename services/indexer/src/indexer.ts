import { randomUUID } from 'node:crypto';
import type { Filter, NostrEvent } from '@sedecim/nostr-core';
import { getTagValues } from '@sedecim/nostr-core';
import { normalizeRelayUrl, type RelayPool } from '@sedecim/relay-pool';
import type { Logger } from '@sedecim/telemetry-policy';
import { GROUP_DELETE_EVENT_KIND, type GroupAuthorities } from './groups';
import type { EventRepository } from './repository';
import { channelShard, MemoryShardCoordinator, relayShard, shardOwner, type ShardCoordinator } from './sharding';

/**
 * Default mirrored kinds: public + NIP-29 channel traffic. p-gated kinds (1059 gift wraps, 44100/44101)
 * are NOT requested: relays such as Buzz only serve them to their authenticated recipient, so the mirror
 * receives a user's gift wraps only through that user's own authenticated session (ciphertext-first).
 */
export const DEFAULT_MIRROR_KINDS = [0, 1, 3, 5, 6, 7, 9, 10, 11, 12, 16, 1111, 9000, 9001, 9002, 9005, 9007, 9008, 9009, 9021, 9022, 10002, 10050, 10063, 30023, 39000, 39001, 39002, 40002, 40003];

/**
 * NIP-29 channel traffic mirrored per channel (Buzz only fans out channel events to `#h` subscriptions), with the
 * moderation deletions (9005, FR014-05).
 */
export const CHANNEL_KINDS = [5, 7, 9, 10, 11, 12, 16, 1111, 9005, 40002, 40003];

export interface IndexerOptions {
  relays: string[];
  filters: Filter[];
  communityId?: string;
  logger?: Logger;
  /**
   * Discover visible channels (kind 39000) and keep a live `#h` subscription for them, refreshed every
   * intervalMs (39000 updates are channel-scoped too, so they are polled). 0 disables it.
   */
  channelRefreshMs?: number;
  /**
   * NFR005-01: coordinator shared by every replica (PgShardCoordinator over the mirror database). Default:
   * a private in-memory one, i.e. a single replica that owns every shard.
   */
  coordinator?: ShardCoordinator;
  /** Unique per replica (the pod name in Kubernetes). Default: a random id. */
  replicaId?: string;
  /** Heartbeat, checkpoint flush and rebalance period (default 5 s). */
  heartbeatMs?: number;
  /** A replica without a heartbeat for this long is considered gone (default 3 heartbeats). */
  memberTtlMs?: number;
  /**
   * Resubscriptions start this many seconds before the shard checkpoint (default 900): covers clock skew
   * between relay clients and events whose created_at is slightly in the past. Duplicates are ignored.
   */
  overlapSeconds?: number;
  /**
   * FR014-05: the relay keys whose NIP-29 lists count (admins for moderation deletions, and members for the read
   * API). When not configured, they are learned from each relay's NIP-11 `self` on every channel refresh.
   */
  authorities?: GroupAuthorities;
}

/** One relay subscription covering one or more shards that are checkpointed together. */
interface Stream {
  relay: string;
  shards: string[];
  channels: string[];
  sub?: { close(): void };
  eosed: boolean;
  eose: Promise<void>;
  closedAt?: number;
  /** created_at of events still being written (a checkpoint never passes them). */
  inflight: number[];
  failedAt?: number;
  reopen: boolean;
}

const nowSec = () => Math.floor(Date.now() / 1000);
/** Replay for channels kept across a resubscription (make-before-break, so only a safety margin). */
const RETAINED_REPLAY_SECONDS = 60;

/**
 * Mirror that follows the same relays as Buzz Desktop/Mobile (spec §15). It never decrypts content
 * and never alters the canonical event: derived views are rebuilt from the signed events.
 *
 * Horizontal scaling (NFR005-01): each relay's base subscription and each (relay, channel) pair is a shard
 * owned by one live replica (rendezvous hashing). Owners store per-shard checkpoints; whoever takes a shard
 * over resubscribes from its checkpoint minus the overlap window, so nothing published meanwhile is lost.
 */
export class Indexer {
  ingested = 0;
  readonly channels = new Set<string>();
  readonly replicaId: string;
  members: string[] = [];

  private readonly coord: ShardCoordinator;
  private readonly heartbeatMs: number;
  private readonly ttlMs: number;
  private readonly overlap: number;
  private readonly base = new Map<string, Stream>();
  private readonly channelStreams = new Map<string, Stream>();
  private channelTimer?: ReturnType<typeof setInterval>;
  private heartbeatTimer?: ReturnType<typeof setInterval>;
  private ticking?: Promise<void>;
  private channelSync: Promise<void> = Promise.resolve();
  private stopped = false;
  private offReconnect?: () => void;
  private warnedNoAuthorities = false;

  constructor(private readonly pool: RelayPool, private readonly repo: EventRepository, private readonly opts: IndexerOptions) {
    this.coord = opts.coordinator ?? new MemoryShardCoordinator();
    this.replicaId = opts.replicaId ?? randomUUID();
    this.heartbeatMs = opts.heartbeatMs ?? 5000;
    this.ttlMs = opts.memberTtlMs ?? this.heartbeatMs * 3;
    this.overlap = opts.overlapSeconds ?? 900;
  }

  async ingest(evt: NostrEvent, relay: string): Promise<boolean> {
    const isNew = await this.repo.upsert(evt, relay, this.opts.communityId);
    if (isNew) this.ingested++;
    if (isNew && evt.kind === 5) await this.repo.tombstone(getTagValues(evt, 'e'), evt.pubkey);
    // The event is stored either way; a deletion that could not be applied stays recorded for the next trigger.
    if (isNew) await this.moderate(evt).catch((err) => this.opts.logger?.warn('moderation step failed', { error: (err as Error).message }));
    return isNew;
  }

  /**
   * FR014-05: NIP-29 moderation, as Buzz applies it. A kind 9005 hides its target (same channel) when its actor is
   * the target's author or an owner/admin in the channel's relay-signed kind 39001, whichever arrives first: the
   * deletion, the target or the admin list that authorizes it.
   */
  private async moderate(evt: NostrEvent): Promise<void> {
    const authorities = this.opts.authorities?.list() ?? [];
    const h = getTagValues(evt, 'h')[0];
    if (evt.kind === GROUP_DELETE_EVENT_KIND) {
      if (!h) return;
      for (const targetId of getTagValues(evt, 'e')) await this.repo.recordModeration({ deletionId: evt.id, targetId, h, actor: evt.pubkey });
      await this.repo.applyModeration(h, authorities);
    } else if (evt.kind === 39001 && authorities.includes(evt.pubkey)) {
      const d = getTagValues(evt, 'd')[0];
      if (d) await this.repo.applyModeration(d, authorities);
    } else if (h) {
      await this.repo.applyModeration(h, authorities, evt.id);
    }
  }

  /** Joins the cluster, opens the owned relay subscriptions and resolves after their backfill and a channel refresh. */
  async start(): Promise<void> {
    this.stopped = false;
    this.offReconnect = this.pool.onReconnect((url) => {
      // The pool replays the original REQ; restart the stream from its checkpoint so EOSE is tracked again.
      for (const s of this.streams()) if (normalizeRelayUrl(s.relay) === url) s.reopen = true;
    });
    this.members = await this.coord.heartbeat(this.replicaId, this.ttlMs);
    await this.syncBase();
    await Promise.all([...this.base.values()].map((s) => s.eose));
    this.heartbeatTimer = setInterval(() => void this.tick(), this.heartbeatMs);
    (this.heartbeatTimer as { unref?: () => void }).unref?.();
    await this.refreshChannels();
    const every = this.opts.channelRefreshMs ?? 30_000;
    if (every > 0 && !this.channelTimer) {
      this.channelTimer = setInterval(() => void this.refreshChannels(), every);
      (this.channelTimer as { unref?: () => void }).unref?.();
    }
  }

  /** Shards this replica currently mirrors. */
  ownedShards(): string[] {
    return this.streams().flatMap((s) => s.shards);
  }

  /** Heartbeat, checkpoint flush, then rebalance to the new membership. Serialized. */
  tick(): Promise<void> {
    if (this.stopped) return Promise.resolve();
    this.ticking ??= (async () => {
      try {
        this.members = await this.coord.heartbeat(this.replicaId, this.ttlMs);
        await this.flush();
        await this.syncBase();
        await this.syncChannels();
      } catch (err) {
        this.opts.logger?.warn('shard coordination failed', { error: (err as Error).message });
      } finally {
        this.ticking = undefined;
      }
    })();
    return this.ticking;
  }

  /** Re-discover channels; resubscribe the owned channel shards when the set changes. */
  async refreshChannels(): Promise<string[]> {
    if ((this.opts.channelRefreshMs ?? 30_000) === 0 || this.stopped) return [];
    const learned = await this.opts.authorities?.discover(this.opts.relays);
    if (this.opts.authorities && !this.opts.authorities.list().length && !this.warnedNoAuthorities) {
      this.warnedNoAuthorities = true;
      this.opts.logger?.warn('no relay key for NIP-29 lists yet: channel reads are denied until a relay publishes NIP-11 self or INDEXER_GROUP_AUTHORITIES is set');
    }
    // FR014-05: with the metadata, the admin and member lists (Buzz does not fan them out live either).
    const state = await this.pool.query(this.opts.relays, [39000, 39001, 39002].map((k) => ({ kinds: [k], limit: 1000 })), 8000);
    for (const m of state) await this.ingest(m, this.opts.relays[0]!).catch(() => false);
    const metas = state.filter((m) => m.kind === 39000);
    metas.map((m) => getTagValues(m, 'd')[0]).filter((d): d is string => !!d).forEach((id) => this.channels.add(id));
    // A relay key learned only now can authorize deletions that were waiting for it.
    if (learned) for (const h of this.channels) await this.repo.applyModeration(h, this.opts.authorities!.list()).catch(() => 0);
    await this.syncChannels();
    return [...this.channels];
  }

  /**
   * Leaves the cluster. Graceful (default): flushes checkpoints and deregisters so the shards move at once.
   * `graceful: false` only drops the subscriptions, as a crash would (tests).
   */
  async stop(opts: { graceful?: boolean } = {}): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    if (this.channelTimer) clearInterval(this.channelTimer);
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    this.channelTimer = this.heartbeatTimer = undefined;
    this.offReconnect?.();
    const marks = opts.graceful === false ? undefined : this.watermarks();
    for (const s of this.streams()) s.sub?.close();
    this.base.clear();
    this.channelStreams.clear();
    if (!marks) return;
    try {
      await this.coord.saveCheckpoints(marks, this.replicaId);
      await this.coord.leave(this.replicaId);
    } catch (err) {
      this.opts.logger?.warn('graceful leave failed', { error: (err as Error).message });
    }
  }

  private streams(): Stream[] {
    return [...this.base.values(), ...this.channelStreams.values()];
  }

  private owns(key: string): boolean {
    return shardOwner(key, this.members) === this.replicaId;
  }

  private async syncBase(): Promise<void> {
    for (const relay of this.opts.relays) {
      const key = relayShard(relay);
      const cur = this.base.get(relay);
      if (!this.owns(key)) {
        if (cur) this.close(this.base, relay);
        continue;
      }
      if (cur && !this.stale(cur)) continue;
      if (cur) this.close(this.base, relay);
      const since = (await this.coord.checkpoints([key])).get(key);
      const filters = this.opts.filters.map((f) => (since === undefined ? f : { ...f, since: Math.max(f.since ?? 0, since - this.overlap) }));
      this.base.set(relay, this.open(relay, [key], [], filters));
    }
  }

  /** Serialized: called from both the heartbeat and the channel refresh. */
  private syncChannels(): Promise<void> {
    const run = this.channelSync.then(() => this.doSyncChannels());
    this.channelSync = run.catch(() => undefined);
    return run;
  }

  private async doSyncChannels(): Promise<void> {
    if (this.stopped || (this.opts.channelRefreshMs ?? 30_000) === 0) return;
    let moved = false;
    for (const relay of this.opts.relays) {
      const mine = [...this.channels].filter((h) => this.owns(channelShard(relay, h))).sort();
      const cur = this.channelStreams.get(relay);
      if (cur && !this.stale(cur) && cur.channels.join('\n') === mine.join('\n')) continue;
      if (!cur && !mine.length) continue;
      moved = true;
      // Channels the current stream already follows live (backfilled, healthy) only need a short replay: the new
      // stream is opened before the old one is closed, so nothing falls in between. The rest resume from
      // their checkpoint (taken over, or never synced).
      const live = cur && cur.eosed && !this.stale(cur) ? new Set(cur.channels) : new Set<string>();
      const retained = mine.filter((h) => live.has(h));
      const acquired = mine.filter((h) => !live.has(h));
      const cps = await this.coord.checkpoints(acquired.map((h) => channelShard(relay, h)));
      const cpOf = (h: string) => cps.get(channelShard(relay, h));
      const fresh = acquired.filter((h) => cpOf(h) === undefined);
      const synced = acquired.filter((h) => cpOf(h) !== undefined);
      const filters: Filter[] = [];
      if (retained.length) filters.push({ kinds: CHANNEL_KINDS, '#h': retained, since: nowSec() - RETAINED_REPLAY_SECONDS });
      if (fresh.length) filters.push({ kinds: CHANNEL_KINDS, '#h': fresh });
      if (synced.length) filters.push({ kinds: CHANNEL_KINDS, '#h': synced, since: Math.min(...synced.map((h) => cpOf(h)!)) - this.overlap });
      const next = mine.length ? this.open(relay, mine.map((h) => channelShard(relay, h)), mine, filters) : undefined;
      if (cur) {
        await this.flush([cur]);
        cur.sub?.close();
      }
      if (next) this.channelStreams.set(relay, next);
      else this.channelStreams.delete(relay);
    }
    if (moved) {
      const count = [...this.channelStreams.values()].reduce((n, s) => n + s.channels.length, 0);
      this.opts.logger?.info('mirroring channels', { count, of: this.channels.size, replicas: this.members.length });
    }
  }

  /** Needs a restart: relay reconnected, subscription refused a while ago, or an ingest failed. */
  private stale(s: Stream): boolean {
    return s.reopen || s.failedAt !== undefined || (s.closedAt !== undefined && Date.now() - s.closedAt > Math.max(this.heartbeatMs, 30_000));
  }

  private open(relay: string, shards: string[], channels: string[], filters: Filter[]): Stream {
    let done!: () => void;
    const s: Stream = { relay, shards, channels, eosed: false, eose: new Promise<void>((r) => (done = r)), inflight: [], reopen: false };
    s.sub = this.pool.subscribe([relay], filters, {
      onevent: (evt, from) => {
        s.inflight.push(evt.created_at);
        this.ingest(evt, from)
          .catch((err: Error) => {
            s.failedAt = Math.min(s.failedAt ?? Infinity, evt.created_at);
            this.opts.logger?.error('ingest failed', { error: err.message, event_id: evt.id });
          })
          .finally(() => s.inflight.splice(s.inflight.indexOf(evt.created_at), 1));
      },
      oneose: () => {
        s.eosed = true;
        done();
      },
      onclosed: (r, reason) => {
        s.closedAt = Date.now();
        this.opts.logger?.warn(channels.length ? 'channel subscription closed' : 'subscription closed', { relay: r, reason });
      },
      dedupe: false,
    });
    return s;
  }

  private close(map: Map<string, Stream>, relay: string) {
    map.get(relay)?.sub?.close();
    map.delete(relay);
  }

  private connected(relay: string): boolean {
    const url = normalizeRelayUrl(relay);
    return this.pool.health().some((h) => h.url === url && h.status === 'connected');
  }

  /** Per shard: the time up to which every event was written (live, connected, backfilled streams only). */
  private watermarks(streams = this.streams()): Map<string, number> {
    const out = new Map<string, number>();
    for (const s of streams) {
      if (!s.eosed || s.reopen || s.closedAt !== undefined || !this.connected(s.relay)) continue;
      const w = Math.min(nowSec(), ...s.inflight.map((c) => c - 1), s.failedAt !== undefined ? s.failedAt - 1 : Infinity);
      if (w <= 0) continue;
      for (const k of s.shards) out.set(k, Math.max(out.get(k) ?? 0, w));
    }
    return out;
  }

  private async flush(streams?: Stream[]): Promise<void> {
    await this.coord.saveCheckpoints(this.watermarks(streams), this.replicaId);
  }
}
