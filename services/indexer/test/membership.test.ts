/**
 * FR014-05: the mirror serves a channel only to its members (as the relay's NIP-29 lists say, signed by the relay
 * key) and applies NIP-29 moderation deletions (kind 9005) as Buzz does: the target's author or a channel admin.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned, type NostrEvent } from '@sedecim/nostr-core';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { createPgPool, migrate, nip98Fetch, resetScope } from '@sedecim/service-kit';
import { createIndexerApi, GroupAuthorities, Indexer, MemoryEventRepository, PgEventRepository, sealedCodec, type EventRepository } from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
const INDEXER_TABLES = ['read_cursors', 'event_sources', 'events', 'events_superseded', 'indexer_checkpoints', 'indexer_jobs', 'indexer_replicas', 'moderation_deletions'];
const now = () => Math.floor(Date.now() / 1000);
let clock = now() - 1000;
/** Each signed event one second after the previous one: newer lists replace older ones. */
const sign = (sk: Uint8Array, kind: number, content: string, tags: string[][]) => finalizeEvent(toUnsigned({ kind, content, tags, created_at: ++clock }, getPublicKey(sk)), sk);
const pk = (sk: Uint8Array) => getPublicKey(sk);
const admins = (by: Uint8Array, h: string, who: Uint8Array[]) => sign(by, 39001, '', [['d', h], ...who.map((sk) => ['p', pk(sk), 'admin'])]);
const members = (by: Uint8Array, h: string, who: Uint8Array[]) => sign(by, 39002, '', [['d', h], ...who.map((sk) => ['p', pk(sk), '', 'member'])]);

async function until(fn: () => Promise<boolean>, ms = 5000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error('timeout');
}

async function rawPublish(url: string, evt: NostrEvent) {
  const ws = new WebSocket(url);
  await new Promise((r) => ws.once('open', r));
  const ok = new Promise<unknown[]>((r) => ws.on('message', (m) => {
    const msg = JSON.parse(m.toString());
    if (msg[0] === 'OK') r(msg);
  }));
  ws.send(JSON.stringify(['EVENT', evt]));
  const res = await ok;
  ws.close();
  return res;
}

function suite(name: string, makeRepo: () => Promise<EventRepository>) {
  describe(name, () => {
    const relaySk = generateSecretKey();
    const forgerSk = generateSecretKey();
    const groups = new GroupAuthorities([pk(relaySk)]);
    const [ownerSk, memberSk, outsiderSk, removedSk] = [generateSecretKey(), generateSecretKey(), generateSecretKey(), generateSecretKey()];
    let repo: EventRepository;
    let indexer: Indexer;
    let api: ReturnType<typeof createIndexerApi>;
    let base: string;
    const ingest = (e: NostrEvent) => indexer.ingest(e, 'ws://relay');
    const get = (sk: Uint8Array | undefined, path: string) => (sk ? nip98Fetch(sk, `${base}${path}`) : fetch(`${base}${path}`).then(async (r) => ({ status: r.status, json: await r.json() })));
    const contents = async (sk: Uint8Array | undefined, path: string) => ((await get(sk, path)).json.events as NostrEvent[]).map((e) => e.content);

    beforeAll(async () => {
      repo = await makeRepo();
      indexer = new Indexer(new RelayPool({ webSocketFactory: factory }), repo, { relays: [], filters: [], authorities: groups });
      api = createIndexerApi(repo, { name: 'indexer-membership', groups });
      base = await api.listen();
    });
    afterAll(async () => {
      await api.close();
    });

    it('serves channel messages and NIP-29 state only to members and admins of the relay-signed lists', async () => {
      for (const e of [
        sign(relaySk, 39000, '', [['d', 'dev'], ['name', 'Desarrollo'], ['private']]),
        admins(relaySk, 'dev', [ownerSk]),
        members(relaySk, 'dev', [ownerSk, memberSk, removedSk]),
        members(relaySk, 'ops', [ownerSk]),
        // A list for the outsider signed by some other key grants nothing.
        members(forgerSk, 'dev', [outsiderSk]),
        admins(forgerSk, 'ops', [outsiderSk]),
        sign(memberSk, 9, 'plan del sprint', [['h', 'dev']]),
        sign(ownerSk, 9, 'guardia de ops', [['h', 'ops']]),
        sign(outsiderSk, 1, 'nota pública', []),
      ])
        await ingest(e);

      expect(await contents(memberSk, '/v1/events?kinds=9')).toEqual(['plan del sprint']);
      expect((await contents(ownerSk, '/v1/events?kinds=9')).sort()).toEqual(['guardia de ops', 'plan del sprint']);
      expect(await contents(outsiderSk, '/v1/events?kinds=9')).toEqual([]);
      expect(await contents(undefined, '/v1/events?kinds=9')).toEqual([]);
      // Outside channels nothing changes.
      expect(await contents(undefined, '/v1/events?kinds=1')).toEqual(['nota pública']);
      // The channel's own state (metadata, lists) is channel content too.
      expect((await get(memberSk, '/v1/events?kinds=39000,39001,39002')).json.events.filter((e: NostrEvent) => e.pubkey === pk(relaySk)).map((e: NostrEvent) => e.kind).sort()).toEqual([39000, 39001, 39002]);
      expect((await get(outsiderSk, '/v1/events?kinds=39000,39002')).json.events.filter((e: NostrEvent) => e.pubkey === pk(relaySk))).toEqual([]);

      const msg = (await get(memberSk, '/v1/events?kinds=9')).json.events[0] as NostrEvent;
      expect((await get(memberSk, `/v1/events/${msg.id}`)).status).toBe(200);
      expect((await get(outsiderSk, `/v1/events/${msg.id}`)).status).toBe(404);
      expect((await get(memberSk, '/v1/channels/dev/summary')).json.messages).toBe(1);
      expect((await get(outsiderSk, '/v1/channels/dev/summary')).status).toBe(403);
      expect((await get(memberSk, '/v1/channels/ops/summary')).status).toBe(403);
      expect((await nip98Fetch(outsiderSk, `${base}/v1/read-cursor`, 'PUT', { h: 'dev', until: now() })).status).toBe(403);
      expect((await nip98Fetch(memberSk, `${base}/v1/read-cursor`, 'PUT', { h: 'dev', until: now() })).status).toBe(200);
      expect((await get(memberSk, '/v1/unread?h=dev,ops')).json.unread).toEqual({ dev: 0 });
      expect((await get(outsiderSk, '/v1/unread?h=dev,ops')).json.unread).toEqual({});

      // Removed from the channel: the relay publishes a new list, and the access goes with it.
      expect(await contents(removedSk, '/v1/events?kinds=9')).toEqual(['plan del sprint']);
      await ingest(members(relaySk, 'dev', [ownerSk, memberSk]));
      expect(await contents(removedSk, '/v1/events?kinds=9')).toEqual([]);
    });

    it('searches only the channels the reader is a member of, also without naming one', async () => {
      await ingest(sign(ownerSk, 9, 'la clave del incidente está en ops', [['h', 'ops']]));
      await ingest(sign(memberSk, 9, 'la clave del sprint está en dev', [['h', 'dev']]));
      expect(await contents(memberSk, '/v1/search?q=clave')).toEqual(['la clave del sprint está en dev']);
      expect(await contents(memberSk, '/v1/search?q=clave&h=ops')).toEqual([]);
      expect((await contents(ownerSk, '/v1/search?q=clave')).sort()).toEqual(['la clave del incidente está en ops', 'la clave del sprint está en dev']);
      expect(await contents(outsiderSk, '/v1/search?q=clave')).toEqual([]);
    });

    it('applies 9005 deletions from the author or a channel admin, whatever arrives first', async () => {
      const [a, b, c, d, e] = ['uno', 'dos', 'tres', 'cuatro', 'cinco'].map((t) => sign(memberSk, 9, `borrable ${t}`, [['h', 'dev']]));
      for (const m of [a, b, c, d]) await ingest(m!);
      const visible = async () => (await contents(ownerSk, '/v1/search?q=borrable&h=dev')).sort();
      const del = (by: Uint8Array, target: NostrEvent, h = 'dev') => sign(by, 9005, '', [['h', h], ['e', target.id]]);

      await ingest(del(memberSk, a!)); // its author
      await ingest(del(ownerSk, b!)); // a channel admin
      await ingest(del(removedSk, c!)); // neither
      await ingest(del(ownerSk, d!, 'ops')); // admin of another channel, target not in it
      expect(await visible()).toEqual(['borrable cuatro', 'borrable tres']);

      // A deletion that arrives before its target hides it as soon as it is mirrored.
      await ingest(del(ownerSk, e!));
      await ingest(e!);
      expect(await visible()).toEqual(['borrable cuatro', 'borrable tres']);

      // An admin named only by a later list: the waiting deletion applies when that list arrives, not a forged one.
      const lateAdmin = generateSecretKey();
      await ingest(del(lateAdmin, c!));
      await ingest(admins(forgerSk, 'dev', [lateAdmin]));
      expect(await visible()).toEqual(['borrable cuatro', 'borrable tres']);
      await ingest(admins(relaySk, 'dev', [ownerSk, lateAdmin]));
      expect(await visible()).toEqual(['borrable cuatro']);
    });
  });
}

suite('FR014-05 membership and moderation (memory)', async () => new MemoryEventRepository());
suite('FR014-05 membership and moderation (memory, sealed)', async () => new MemoryEventRepository(sealedCodec(new Uint8Array(32).fill(6))));
const PG = process.env.TEST_DATABASE_URL;
if (PG) {
  // Its own schema: indexer.test.ts resets the same tables in the default one, in parallel.
  const schemaPool = async (schema: string) => {
    const admin = createPgPool(PG);
    await admin.query(`CREATE SCHEMA IF NOT EXISTS ${schema}`);
    await admin.end();
    const pool = createPgPool(`${PG}${PG.includes('?') ? '&' : '?'}options=${encodeURIComponent(`-c search_path=${schema}`)}`);
    await resetScope(pool, 'indexer', INDEXER_TABLES);
    await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'indexer');
    return pool;
  };
  suite('FR014-05 membership and moderation (postgres, sealed)', async () => new PgEventRepository(await schemaPool('fr014_sealed'), sealedCodec(new Uint8Array(32).fill(5))));
  suite('FR014-05 membership and moderation (postgres, plain)', async () => new PgEventRepository(await schemaPool('fr014_plain')));
}

describe('FR014-05 against a Buzz-like relay (NIP-11 self, lists by REQ, 9005 live on #h)', () => {
  const relaySk = generateSecretKey();
  const relay = new TestRelay({ self: pk(relaySk), channelScopedFanout: true });
  const [adminSk, memberSk, outsiderSk] = [generateSecretKey(), generateSecretKey(), generateSecretKey()];
  let pool: RelayPool;
  let indexer: Indexer;
  let api: ReturnType<typeof createIndexerApi>;
  let base: string;
  beforeAll(async () => {
    await relay.start();
    // Group state as Buzz stores it: signed by the relay key, read by REQ (it is not fanned out live).
    for (const e of [sign(relaySk, 39000, '', [['d', 'room'], ['name', 'Sala'], ['public'], ['closed']]), admins(relaySk, 'room', [adminSk]), members(relaySk, 'room', [adminSk, memberSk])]) relay.inject(e);
  });
  afterAll(async () => {
    await api?.close();
    await indexer?.stop();
    pool?.close();
    await relay.stop();
  });

  it('learns the relay key from NIP-11, serves the channel to its members and hides what an admin deletes', async () => {
    const groups = new GroupAuthorities();
    pool = new RelayPool({ webSocketFactory: factory });
    const repo = new MemoryEventRepository();
    indexer = new Indexer(pool, repo, { relays: [relay.url], filters: [{ kinds: [1] }], authorities: groups, channelRefreshMs: 60_000 });
    await indexer.start();
    expect(groups.list()).toEqual([pk(relaySk)]);
    api = createIndexerApi(repo, { name: 'indexer-buzz-like', groups });
    base = await api.listen();

    const msg = sign(memberSk, 9, 'hola sala', [['h', 'room']]);
    expect((await rawPublish(relay.url, msg))[2]).toBe(true);
    await until(async () => !!(await repo.get(msg.id)));
    const read = async (sk: Uint8Array) => ((await nip98Fetch(sk, `${base}/v1/events?kinds=9&h=room`)).json.events as NostrEvent[]).map((e) => e.id);
    expect(await read(memberSk)).toEqual([msg.id]);
    expect(await read(outsiderSk)).toEqual([]);

    expect((await rawPublish(relay.url, sign(adminSk, 9005, '', [['h', 'room'], ['e', msg.id]])))[2]).toBe(true);
    await until(async () => (await repo.get(msg.id))!.deleted);
    expect(await read(memberSk)).toEqual([]);
  });
});
