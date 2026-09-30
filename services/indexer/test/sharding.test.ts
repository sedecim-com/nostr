import { afterAll, describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';
import { eventAddress, finalizeEvent, generateSecretKey, getPublicKey, isAddressableKind, isReplaceableKind, selectHeads, toUnsigned, type NostrEvent } from '@sedecim/nostr-core';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { LocalSigner } from '@sedecim/signer';
import { createPgPool, migrate, type Pool } from '@sedecim/service-kit';
import {
  DEFAULT_MIRROR_KINDS,
  Indexer,
  MemoryEventRepository,
  MemoryShardCoordinator,
  PgEventRepository,
  PgShardCoordinator,
  channelShard,
  relayShard,
  sealedCodec,
  shardOwner,
  type EventRepository,
  type ShardCoordinator,
} from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const nowSec = () => Math.floor(Date.now() / 1000);

async function until(fn: () => Promise<boolean>, ms: number, what: string) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await sleep(50);
  }
  throw new Error(`timeout: ${what}`);
}

describe('rendezvous shard assignment (NFR005-01)', () => {
  const keys = Array.from({ length: 600 }, (_, i) => `channel:ws://r#c${i}`);

  it('is deterministic, independent of member order and roughly balanced', () => {
    const members = ['a', 'b', 'c'];
    const owners = keys.map((k) => shardOwner(k, members));
    expect(keys.map((k) => shardOwner(k, ['c', 'a', 'b']))).toEqual(owners);
    for (const m of members) expect(owners.filter((o) => o === m).length).toBeGreaterThan(120);
    expect(shardOwner('x', [])).toBeUndefined();
  });

  it('moves only the shards of the replica that joins or leaves', () => {
    const before = keys.map((k) => shardOwner(k, ['a', 'b', 'c']));
    const joined = keys.map((k) => shardOwner(k, ['a', 'b', 'c', 'd']));
    joined.forEach((o, i) => expect(o === before[i] || o === 'd').toBe(true));
    const left = keys.map((k) => shardOwner(k, ['a', 'c']));
    left.forEach((o, i) => expect(before[i] === 'b' || o === before[i]).toBe(true));
  });
});

/** Isolated Postgres schema per test file, so it can run next to the other indexer tests. */
async function pgScope(url: string) {
  const schema = `idx_shard_${Math.random().toString(36).slice(2, 10)}`;
  const pools: Pool[] = [];
  const admin = createPgPool(url);
  await admin.query(`CREATE SCHEMA ${schema}`);
  const make = async () => {
    const pool = createPgPool(`${url}${url.includes('?') ? '&' : '?'}options=${encodeURIComponent(`-c search_path=${schema}`)}`);
    pools.push(pool);
    return pool;
  };
  await migrate(await make(), fileURLToPath(new URL('../migrations', import.meta.url)), 'indexer');
  return {
    make,
    async close() {
      await Promise.all(pools.map((p) => p.end()));
      await admin.query(`DROP SCHEMA ${schema} CASCADE`);
      await admin.end();
    },
  };
}

interface Backend {
  /** One (repository, coordinator) per replica, as separate processes would have. */
  replica(): Promise<{ repo: EventRepository; coord: ShardCoordinator }>;
  close(): Promise<void>;
}

function memoryBackend(): Backend {
  const repo = new MemoryEventRepository();
  const coord = new MemoryShardCoordinator();
  return { replica: async () => ({ repo, coord }), close: async () => undefined };
}

async function pgBackend(url: string): Promise<Backend> {
  const scope = await pgScope(url);
  const key = new Uint8Array(32).fill(5);
  return {
    async replica() {
      const pool = await scope.make();
      return { repo: new PgEventRepository(pool, sealedCodec(key)), coord: new PgShardCoordinator(pool) };
    },
    close: () => scope.close(),
  };
}

/** Records every insert, whichever replica wrote it: an id written twice is a duplicate. */
function counting(repo: EventRepository, inserts: Map<string, number>): EventRepository {
  return new Proxy(repo, {
    get(target, prop, recv) {
      if (prop !== 'upsert') return Reflect.get(target, prop, recv);
      return async (evt: NostrEvent, relay: string, community?: string) => {
        const isNew = await target.upsert(evt, relay, community);
        if (isNew) inserts.set(evt.id, (inserts.get(evt.id) ?? 0) + 1);
        return isNew;
      };
    },
  });
}

function coordinatorContract(name: string, make: () => Promise<{ coords: ShardCoordinator[]; close(): Promise<void> }>) {
  describe(name, () => {
    it('tracks live members, graceful leaves and forward-only checkpoints', async () => {
      const { coords, close } = await make();
      const [a, b] = coords as [ShardCoordinator, ShardCoordinator];
      try {
        await a.heartbeat('r1', 400);
        expect(await b.heartbeat('r2', 400)).toEqual(['r1', 'r2']);
        await sleep(500);
        expect(await b.heartbeat('r2', 400)).toEqual(['r2']);
        await a.heartbeat('r1', 400);
        await a.leave('r1');
        expect(await b.heartbeat('r2', 400)).toEqual(['r2']);
        await a.saveCheckpoints(new Map([['k1', 100], ['k2', 50]]), 'r1');
        await b.saveCheckpoints(new Map([['k1', 90]]), 'r2');
        expect(Object.fromEntries(await b.checkpoints(['k1', 'k2', 'k3']))).toEqual({ k1: 100, k2: 50 });
      } finally {
        await close();
      }
    });

    it('lets exactly one replica claim a periodic job (retention runs once per interval)', async () => {
      const { coords, close } = await make();
      try {
        const claims = await Promise.all(coords.flatMap((c, i) => [c.claimJob('retention', 60_000, `r${i}`), c.claimJob('retention', 60_000, `r${i}`)]));
        expect(claims.filter(Boolean)).toHaveLength(1);
        expect(await coords[0]!.claimJob('retention', 60_000, 'r0')).toBe(false);
        await sleep(300);
        expect(await coords[1]!.claimJob('retention', 200, 'r1')).toBe(true);
      } finally {
        await close();
      }
    });
  });
}

function raceSuite(name: string, make: () => Promise<{ repos: EventRepository[]; close(): Promise<void> }>) {
  describe(name, () => {
    it('keeps exactly the NIP-01 head when replicas race on replaceable/addressable versions', async () => {
      const { repos, close } = await make();
      try {
        const sk = generateSecretKey();
        const pk = getPublicKey(sk);
        const t = nowSec();
        const versions = [0, 30023].flatMap((kind) =>
          Array.from({ length: 12 }, (_, v) => finalizeEvent(toUnsigned({ kind, content: `v${v}`, created_at: t - 100 + (v % 7), tags: kind === 30023 ? [['d', 'doc']] : [] }, pk), sk)),
        );
        const note = finalizeEvent(toUnsigned({ kind: 1, content: 'hola', created_at: t }, pk), sk);
        const writes = [...versions, note, note].flatMap((e) => repos.map((r, i) => ({ e, run: () => r.upsert(e, `ws://relay-${i}`) })));
        writes.sort(() => Math.random() - 0.5);
        const results = await Promise.all(writes.map((w) => w.run()));
        const stored = await repos[0]!.query({ authors: [pk], limit: 100 });
        const heads = selectHeads(versions);
        expect(stored.map((m) => m.event.id).sort()).toEqual([...heads.map((h) => h.id), note.id].sort());
        // the note was written by exactly one of the racing writers
        expect(results.filter((ok, i) => ok && writes[i]!.e.id === note.id)).toHaveLength(1);
        expect((await repos[0]!.get(note.id))!.relays.sort()).toEqual(repos.map((_, i) => `ws://relay-${i}`).sort());
      } finally {
        await close();
      }
    });
  });
}

function clusterSuite(name: string, makeBackend: () => Promise<Backend>) {
  describe(name, () => {
    const cleanups: Array<() => Promise<void> | void> = [];
    afterAll(async () => {
      for (const c of cleanups.reverse()) await c();
    });

    it('N replicas + crash/takeover + join/leave: exactly the published set, no duplicates, latest replaceable', async () => {
      const backend = await makeBackend();
      cleanups.push(() => backend.close());
      // relay A behaves like Buzz (NIP-42 required, channel traffic only fanned out to #h subscriptions).
      const relayA = new TestRelay({ requireAuth: true, authNoticeOnReq: true, channelScopedFanout: true });
      const relayB = new TestRelay();
      await relayA.start();
      await relayB.start();
      cleanups.push(() => relayA.stop(), () => relayB.stop());
      const relays = [relayA.url, relayB.url];

      const admin = new LocalSigner(generateSecretKey());
      const channels = Array.from({ length: 8 }, (_, i) => `canal-${i}`);
      const published: NostrEvent[] = [];
      for (const h of channels) {
        const meta = await admin.signEvent({ kind: 39000, content: '', tags: [['d', h], ['name', h]] });
        relayA.inject(meta);
        published.push(meta);
      }

      const inserts = new Map<string, number>();
      interface Replica { id: string; idx: Indexer; pool: RelayPool }
      const live: Replica[] = [];
      const startReplica = async (id: string) => {
        const { repo, coord } = await backend.replica();
        const pool = new RelayPool({ webSocketFactory: factory, signer: new LocalSigner(generateSecretKey()), authMode: 'auto' });
        const idx = new Indexer(pool, counting(repo, inserts), {
          relays,
          filters: [{ kinds: DEFAULT_MIRROR_KINDS }],
          coordinator: coord,
          replicaId: id,
          heartbeatMs: 100,
          memberTtlMs: 1500,
          channelRefreshMs: 200,
          overlapSeconds: 60,
        });
        await idx.start();
        const r = { id, idx, pool };
        live.push(r);
        cleanups.push(async () => {
          await idx.stop({ graceful: false });
          pool.close();
        });
        return r;
      };
      const reader = (await backend.replica()).repo;

      const writer = new RelayPool({ webSocketFactory: factory, signer: new LocalSigner(generateSecretKey()), authMode: 'auto' });
      cleanups.push(() => writer.close());
      const authors = Array.from({ length: 4 }, () => generateSecretKey());
      let round = 0;
      /** One burst of concurrent traffic: channel messages on both relays, notes, replaceable and addressable versions. */
      const burst = async () => {
        round++;
        const t = nowSec();
        const evts: Array<[NostrEvent, string[]]> = [];
        authors.forEach((sk, a) => {
          const pk = getPublicKey(sk);
          channels.forEach((h, c) => {
            evts.push([finalizeEvent(toUnsigned({ kind: 9, content: `r${round} a${a} ${h}`, tags: [['h', h]], created_at: t }, pk), sk), [relays[c % 2]!]]);
          });
          evts.push([finalizeEvent(toUnsigned({ kind: 1, content: `nota r${round} a${a}`, created_at: t }, pk), sk), [relays[a % 2]!]]);
          for (let v = 0; v < 3; v++) {
            evts.push([finalizeEvent(toUnsigned({ kind: 0, content: `{"name":"r${round}v${v}"}`, created_at: t - 5 + v }, pk), sk), relays]);
            evts.push([finalizeEvent(toUnsigned({ kind: 30023, content: `doc r${round}v${v}`, tags: [['d', 'perfil']], created_at: t - 5 + v }, pk), sk), relays]);
          }
        });
        evts.sort(() => Math.random() - 0.5);
        const res = await Promise.all(evts.map(([e, urls]) => writer.publish(e, urls)));
        expect(res.flat().every((r) => r.ok)).toBe(true);
        published.push(...evts.map(([e]) => e));
      };
      const expectedIds = () => {
        const regular = published.filter((e) => !isReplaceableKind(e.kind) && !isAddressableKind(e.kind));
        const heads = selectHeads(published.filter((e) => isReplaceableKind(e.kind) || isAddressableKind(e.kind)));
        return new Set([...regular, ...heads].map((e) => e.id));
      };
      const converged = async (what: string) => {
        await until(async () => {
          const want = expectedIds();
          const have = (await reader.query({ includeDeleted: true, limit: 5000 })).map((m) => m.event.id);
          return have.length === want.size && have.every((id) => want.has(id));
        }, 20_000, what);
      };
      /**
       * Once membership settled, every live replica sees the same members and mirrors exactly the shards rendezvous
       * hashing gives it, so ownership is a partition. A replica may own none: with 3 replicas and 18 shard keys (the
       * relay ports are random) that happens in ~0.2% of runs, and requiring every replica to own a shard made this
       * test time out there.
       */
      const partitioned = async () => {
        const keys = relays.flatMap((r) => [relayShard(r), ...channels.map((h) => channelShard(r, h))]);
        await until(async () => {
          const ids = live.map((r) => r.id).sort();
          const owned = live.map((r) => r.idx.ownedShards());
          const all = owned.flat();
          return (
            all.length === keys.length &&
            new Set(all).size === keys.length &&
            live.every((r, i) => {
              const want = keys.filter((k) => shardOwner(k, ids) === r.id).sort();
              return [...r.idx.members].sort().join() === ids.join() && [...owned[i]!].sort().join() === want.join();
            })
          );
        }, 10_000, 'shard partition');
      };

      await startReplica('replica-0');
      await startReplica('replica-1');
      await startReplica('replica-2');
      await partitioned();
      await burst();
      await converged('3 replicas');

      // crash: no checkpoint flush, no deregistration; its shards move after the TTL
      const crashed = live.shift()!;
      await crashed.idx.stop({ graceful: false });
      crashed.pool.close();
      await burst();
      await burst();
      await converged('after a crash');
      await partitioned();

      await startReplica('replica-3');
      await burst();
      await partitioned();
      await burst();
      // graceful leave
      const leaving = live.shift()!;
      await leaving.idx.stop();
      leaving.pool.close();
      await burst();
      await converged('after join and leave');
      await partitioned();

      const dupes = [...inserts].filter(([, n]) => n > 1);
      expect(dupes).toEqual([]);
      for (const id of expectedIds()) expect(inserts.get(id), id).toBe(1);
      // replaceable/addressable addresses end at their latest version
      const stored = (await reader.query({ kinds: [0, 30023], limit: 5000 })).map((m) => m.event);
      expect(new Set(stored.map(eventAddress)).size).toBe(stored.length);
      const heads = selectHeads(published.filter((e) => e.kind === 0 || e.kind === 30023));
      expect(stored.map((e) => e.id).sort()).toEqual(heads.map((e) => e.id).sort());
      expect(stored.every((e) => e.content.includes('v2'))).toBe(true);
    }, 90_000);
  });
}

coordinatorContract('shard coordinator (memory)', async () => {
  const c = new MemoryShardCoordinator();
  return { coords: [c, c, c], close: async () => undefined };
});
raceSuite('replaceable race (memory repository)', async () => {
  const r = new MemoryEventRepository();
  return { repos: [r, r, r], close: async () => undefined };
});
clusterSuite('indexer cluster (memory repository + coordinator)', async () => memoryBackend());

const PG = process.env.TEST_DATABASE_URL;
if (PG) {
  coordinatorContract('shard coordinator (postgres)', async () => {
    const scope = await pgScope(PG);
    return { coords: await Promise.all([0, 1, 2].map(async () => new PgShardCoordinator(await scope.make()))), close: () => scope.close() };
  });
  raceSuite('replaceable race (postgres repository, separate pools)', async () => {
    const scope = await pgScope(PG);
    return { repos: await Promise.all([0, 1, 2].map(async () => new PgEventRepository(await scope.make()))), close: () => scope.close() };
  });
  clusterSuite('indexer cluster (postgres, one pool per replica)', () => pgBackend(PG));
} else {
  describe.skip('indexer cluster (postgres) — set TEST_DATABASE_URL', () => {
    it('skipped', () => undefined);
  });
}
