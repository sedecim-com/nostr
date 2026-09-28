import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';
import * as nt from 'nostr-tools';
import { generateSecretKey, getPublicKey, finalizeEvent, toUnsigned, type NostrEvent } from '@sedecim/nostr-core';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { LocalSigner } from '@sedecim/signer';
import { createDirectMessage } from '@sedecim/messaging';
import { createPgPool, migrate, nip98Fetch, resetScope } from '@sedecim/service-kit';
import { createIndexerApi, enforceRetention, GroupAuthorities, Indexer, MemoryEventRepository, PgEventRepository, sealedCodec, type EventRepository } from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
const INDEXER_TABLES = ['read_cursors', 'event_sources', 'events', 'indexer_checkpoints', 'indexer_jobs', 'indexer_replicas', 'moderation_deletions'];

// FR014-05: the relay key that signs NIP-29 group state, and a member list (kind 39002) signed with it.
const relaySk = generateSecretKey();
const groups = new GroupAuthorities([getPublicKey(relaySk)]);
const memberList = (h: string, members: Uint8Array[]) =>
  finalizeEvent(toUnsigned({ kind: 39002, content: '', tags: [['d', h], ...members.map((sk) => ['p', getPublicKey(sk), '', 'member'])], created_at: Math.floor(Date.now() / 1000) }, getPublicKey(relaySk)), relaySk);

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

async function until(fn: () => Promise<boolean>, ms = 3000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error('timeout');
}

function suite(name: string, makeRepo: () => Promise<EventRepository>) {
  describe(name, () => {
    const relay = new TestRelay();
    let pool: RelayPool;
    let repo: EventRepository;
    let indexer: Indexer;

    beforeAll(async () => {
      await relay.start();
      repo = await makeRepo();
      pool = new RelayPool({ webSocketFactory: factory });
      indexer = new Indexer(pool, repo, { relays: [relay.url], filters: [{}] });
      await indexer.start();
    });
    afterAll(async () => {
      indexer.stop();
      pool.close();
      await relay.stop();
    });

    it('mirrors events sent by any compatible client without proprietary APIs (FR-014)', async () => {
      const sk = generateSecretKey();
      const evt = nt.finalizeEvent({ kind: 9, content: 'desde otro cliente', tags: [['h', 'general']], created_at: Math.floor(Date.now() / 1000) }, sk) as NostrEvent;
      expect((await rawPublish(relay.url, evt))[2]).toBe(true);
      await until(async () => !!(await repo.get(evt.id)));
      const row = (await repo.get(evt.id))!;
      expect(row.event).toEqual(JSON.parse(JSON.stringify(evt)));
      expect(row.sensitivity).toBe('channel');
    });

    it('stores gift wraps as ciphertext and applies deletions as tombstones', async () => {
      const alice = new LocalSigner(generateSecretKey());
      const bobPk = getPublicKey(generateSecretKey());
      const dm = await createDirectMessage(alice, { recipients: [bobPk], content: 'secreto' });
      const wrap = dm.wraps.find((w) => w.recipient === bobPk)!.event;
      await rawPublish(relay.url, wrap);
      const note = await alice.signEvent({ kind: 1, content: 'borrame' });
      await rawPublish(relay.url, note);
      await until(async () => !!(await repo.get(wrap.id)) && !!(await repo.get(note.id)));
      expect(JSON.stringify((await repo.get(wrap.id))!.event)).not.toContain('secreto');
      expect((await repo.get(wrap.id))!.sensitivity).toBe('ciphertext');
      await rawPublish(relay.url, await alice.signEvent({ kind: 5, content: '', tags: [['e', note.id]] }));
      await until(async () => (await repo.get(note.id))!.deleted);
      expect(await repo.query({ ids: [note.id] })).toHaveLength(0);
    });

    it('keeps only the newest replaceable event', async () => {
      const sk = generateSecretKey();
      const pk = getPublicKey(sk);
      const now = Math.floor(Date.now() / 1000);
      const newer = finalizeEvent(toUnsigned({ kind: 0, content: '{"name":"new"}', created_at: now }, pk), sk);
      const older = finalizeEvent(toUnsigned({ kind: 0, content: '{"name":"old"}', created_at: now - 100 }, pk), sk);
      await indexer.ingest(newer, relay.url);
      expect(await indexer.ingest(older, relay.url)).toBe(false);
    });

    it('serves derived views and restricts gift wraps to their recipient', async () => {
      const readerSk = generateSecretKey();
      await indexer.ingest(memberList('general', [readerSk]), relay.url);
      const api = createIndexerApi(repo, { name: 'indexer-test', groups });
      const base = await api.listen();
      try {
        const res = await nip98Fetch(readerSk, `${base}/v1/events?kinds=9&h=general`);
        expect(res.json.events.map((e: NostrEvent) => e.content)).toContain('desde otro cliente');
        // FR014-05: channel content only for its members.
        expect((await (await fetch(`${base}/v1/events?kinds=9&h=general`)).json()).events).toEqual([]);
        expect((await fetch(`${base}/v1/events?kinds=1059`)).status).toBe(401);
        const bobSk = generateSecretKey();
        const bobPk = getPublicKey(bobSk);
        const dm = await createDirectMessage(new LocalSigner(generateSecretKey()), { recipients: [bobPk], content: 'x' });
        await indexer.ingest(dm.wraps.find((w) => w.recipient === bobPk)!.event, relay.url);
        const mine = await nip98Fetch(bobSk, `${base}/v1/events?kinds=1059&p=${bobPk}`);
        expect(mine.status).toBe(200);
        expect(mine.json.events).toHaveLength(1);
        const other = await nip98Fetch(generateSecretKey(), `${base}/v1/events?kinds=1059&p=${bobPk}`);
        expect(other.status).toBe(403);
        const summary = await nip98Fetch(readerSk, `${base}/v1/channels/general/summary`);
        expect(summary.json.messages).toBeGreaterThanOrEqual(1);
        expect((await fetch(`${base}/v1/channels/general/summary`)).status).toBe(403);
        // Malformed numeric parameters are a 400, never a database error (500).
        for (const q of ['kinds=abc', 'kinds=9&limit=-1', 'kinds=9&since=x', 'kinds=9&until=1.5', 'kinds=-3', 'kinds=9&limit='])
          expect((await fetch(`${base}/v1/events?${q}`)).status, q).toBe(400);
      } finally {
        await api.close();
      }
    });

    it('derived views: unread counts per reader and search over allowed plaintext only (FR014-03)', async () => {
      const channel = `c-${Math.random().toString(36).slice(2)}`;
      const other = `o-${Math.random().toString(36).slice(2)}`;
      const aliceSk = generateSecretKey();
      const bobSk = generateSecretKey();
      const t = Math.floor(Date.now() / 1000);
      const sign = (sk: Uint8Array, kind: number, content: string, created_at: number, tags: string[][] = [['h', channel]]) =>
        finalizeEvent(toUnsigned({ kind, content, tags, created_at }, getPublicKey(sk)), sk);
      const msgs = [sign(aliceSk, 9, 'Una AGUJA en el pajar', t - 30), sign(aliceSk, 11, 'hilo sobre agujas', t - 20), sign(aliceSk, 9, 'tercero', t - 10)];
      const deleted = sign(aliceSk, 9, 'aguja borrada', t - 9);
      for (const e of [...msgs, deleted, sign(bobSk, 9, 'mi propia aguja', t - 5), sign(aliceSk, 7, '+', t - 4), sign(aliceSk, 1, 'nota pública con aguja', t - 3, []), sign(aliceSk, 9, 'aguja en otro canal', t - 2, [['h', other]])]) {
        await indexer.ingest(e, relay.url);
      }
      await indexer.ingest(sign(aliceSk, 5, '', t - 1, [['h', channel], ['e', deleted.id]]), relay.url);
      const dm = await createDirectMessage(new LocalSigner(aliceSk), { recipients: [getPublicKey(bobSk)], content: 'aguja cifrada' });
      const wrap = dm.wraps[0]!.event;
      await indexer.ingest(wrap, relay.url);
      // Both read the two channels (FR014-05).
      for (const h of [channel, other]) await indexer.ingest(memberList(h, [aliceSk, bobSk]), relay.url);

      const api = createIndexerApi(repo, { name: 'indexer-test', groups });
      const base = await api.listen();
      try {
        expect((await fetch(`${base}/v1/unread?h=${channel}`)).status).toBe(401);
        const unread = await nip98Fetch(bobSk, `${base}/v1/unread?h=${channel},${other}`);
        expect(unread.status).toBe(200);
        // bob's own message, the reaction and the deleted message do not count
        expect(unread.json).toEqual({ unread: { [channel]: 3, [other]: 1 }, cursors: { [channel]: 0, [other]: 0 } });
        const put = await nip98Fetch(bobSk, `${base}/v1/read-cursor`, 'PUT', { h: channel, until: t - 20 });
        expect(put).toMatchObject({ status: 200, json: { h: channel, until: t - 20 } });
        // cursors never move backwards
        expect((await nip98Fetch(bobSk, `${base}/v1/read-cursor`, 'PUT', { h: channel, until: t - 100 })).json.until).toBe(t - 20);
        expect((await nip98Fetch(bobSk, `${base}/v1/unread?h=${channel}`)).json.unread).toEqual({ [channel]: 1 });
        // cursors are per reader
        expect((await nip98Fetch(aliceSk, `${base}/v1/unread?h=${channel}`)).json.unread).toEqual({ [channel]: 1 });
        expect((await nip98Fetch(bobSk, `${base}/v1/read-cursor`, 'PUT', { h: channel, until: 'ayer' })).status).toBe(400);

        const search = (await nip98Fetch(bobSk, `${base}/v1/search?q=aguja&h=${channel}`)).json;
        expect(search.events.map((e: NostrEvent) => e.content)).toEqual(['mi propia aguja', 'hilo sobre agujas', 'Una AGUJA en el pajar']);
        const everywhere = (await nip98Fetch(bobSk, `${base}/v1/search?q=aguja`)).json;
        expect(everywhere.events.map((e: NostrEvent) => e.content)).toContain('aguja en otro canal');
        expect(everywhere.events.map((e: NostrEvent) => e.content)).not.toContain('nota pública con aguja');
        // never over gift wraps, even when the query matches their (ciphertext) content
        const cipher = (await nip98Fetch(bobSk, `${base}/v1/search?q=${encodeURIComponent(wrap.content.slice(10, 40))}`)).json;
        expect(cipher.events).toEqual([]);
        expect((await repo.search({ text: 'aguja', kinds: [1059, 1] })).length).toBe(0);
        expect((await fetch(`${base}/v1/search?q=a`)).status).toBe(400);
        // LIKE wildcards are literal
        expect((await nip98Fetch(bobSk, `${base}/v1/search?q=${encodeURIComponent('%_')}&h=${channel}`)).json.events).toEqual([]);
        // FR014-05: nothing for someone outside both channels, also without naming one.
        expect((await (await fetch(`${base}/v1/search?q=aguja`)).json()).events).toEqual([]);
        expect((await nip98Fetch(generateSecretKey(), `${base}/v1/search?q=aguja&h=${channel}`)).json.events).toEqual([]);
      } finally {
        await api.close();
      }
    });
  });
}

suite('Indexer (memory repository)', async () => new MemoryEventRepository());
suite('Indexer (memory repository, sealed at rest)', async () => new MemoryEventRepository(sealedCodec(new Uint8Array(32).fill(9))));

const PG = process.env.TEST_DATABASE_URL;
if (PG) {
  suite('Indexer (postgres repository)', async () => {
    const pool = createPgPool(PG);
    await resetScope(pool, 'indexer', INDEXER_TABLES);
    await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'indexer');
    return new PgEventRepository(pool, sealedCodec(new Uint8Array(32).fill(4)));
  });
  // Plain rows are searched in SQL (ILIKE) instead of being decrypted and scanned.
  suite('Indexer (postgres repository, plain)', async () => {
    const pool = createPgPool(PG);
    await resetScope(pool, 'indexer', INDEXER_TABLES);
    await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'indexer');
    return new PgEventRepository(pool);
  });
} else {
  describe.skip('Indexer (postgres repository) — set TEST_DATABASE_URL', () => {
    it('skipped', () => undefined);
  });
}

describe('Indexer against a p-gated relay (Buzz behaviour)', () => {
  it('uses default mirror kinds that p-gated relays accept', async () => {
    const { DEFAULT_MIRROR_KINDS } = await import('../src/index');
    const relay = new TestRelay({ pGatedKinds: [1059, 44100, 44101] });
    await relay.start();
    const signer = new LocalSigner(generateSecretKey());
    relay.inject(await signer.signEvent({ kind: 9, content: 'canal', tags: [['h', 'g']] }));
    const pool = new RelayPool({ webSocketFactory: factory });
    const repo = new MemoryEventRepository();
    const closed: string[] = [];
    const idx = new Indexer(pool, repo, { relays: [relay.url], filters: [{ kinds: DEFAULT_MIRROR_KINDS }], logger: { warn: (_m: string, f?: Record<string, unknown>) => closed.push(String(f?.reason)) } as never });
    await idx.start();
    expect(closed).toEqual([]);
    expect((await repo.stats()).events).toBe(1);
    expect(DEFAULT_MIRROR_KINDS).not.toContain(1059);
    idx.stop();
    pool.close();
    await relay.stop();
  });
});

describe('Indexer against a Buzz-like relay (auth required, channel-scoped fan-out)', () => {
  it('authenticates with its service identity and mirrors live channel messages via #h', async () => {
    const relay = new TestRelay({ requireAuth: true, authNoticeOnReq: true, channelScopedFanout: true, pGatedKinds: [1059] });
    await relay.start();
    const author = new LocalSigner(generateSecretKey());
    relay.inject(await author.signEvent({ kind: 39000, content: '', tags: [['d', 'canal-1'], ['name', 'General']] }));
    const pool = new RelayPool({ webSocketFactory: factory, signer: new LocalSigner(generateSecretKey()), authMode: 'auto' });
    const repo = new MemoryEventRepository();
    const idx = new Indexer(pool, repo, { relays: [relay.url], filters: [{ kinds: [0, 1] }], channelRefreshMs: 100 });
    await idx.start();
    expect([...idx.channels]).toEqual(['canal-1']);
    const live = await author.signEvent({ kind: 9, content: 'en vivo', tags: [['h', 'canal-1']] });
    relay.inject(live);
    await until(async () => !!(await repo.get(live.id)));
    // a channel created after start is discovered by the periodic refresh
    relay.inject(await author.signEvent({ kind: 39000, content: '', tags: [['d', 'canal-2'], ['name', 'Nuevo']] }));
    await until(async () => idx.channels.has('canal-2'));
    await new Promise((r) => setTimeout(r, 50));
    const later = await author.signEvent({ kind: 9, content: 'canal nuevo', tags: [['h', 'canal-2']] });
    relay.inject(later);
    await until(async () => !!(await repo.get(later.id)));
    idx.stop();
    pool.close();
    await relay.stop();
  });
});

/** FR023-08: retention and legal hold over the mirror, identical on every repository. */
function retentionSuite(name: string, makeRepo: () => Promise<EventRepository>) {
  describe(name, () => {
    const now = Date.UTC(2027, 0, 15);
    const day = 86_400;
    const sk = generateSecretKey();
    const at = (daysAgo: number, tags: string[][], kind = 9) =>
      nt.finalizeEvent({ kind, content: `hace ${daysAgo} días`, tags, created_at: Math.floor(now / 1000) - daysAgo * day }, sk) as NostrEvent;

    it('deletes expired mirror data per channel/workspace unless on legal hold', async () => {
      const repo = await makeRepo();
      const ev = {
        oldGeneral: at(40, [['h', 'general']]),
        newGeneral: at(5, [['h', 'general']]),
        oldLegal: at(400, [['h', 'legal']]),
        oldOtherWs: at(400, [['h', 'ops']]),
        oldWsNote: at(100, [], 1),
        oldArchive: at(100, [['h', 'archive']]),
        oldHeldWs: at(100, [['h', 'kept']]),
      };
      for (const [k, e] of Object.entries(ev)) await repo.upsert(e, 'ws://r', k === 'oldHeldWs' ? 'held-ws' : 'acme');
      const res = await enforceRetention(
        repo,
        [
          { resourceId: 'general', days: 30, legalHold: false },
          { resourceId: 'legal', days: 30, legalHold: true },
          { resourceId: 'archive', days: null, legalHold: false },
          { resourceId: 'acme', days: 60, legalHold: false },
          { resourceId: 'held-ws', days: 1, legalHold: true },
        ],
        now,
      );
      // general: its own 30-day policy; acme workspace (60 days) covers ops and non-channel events but
      // not channels with their own policy (legal on hold, archive kept forever).
      expect(res).toEqual([
        { resourceId: 'general', deleted: 1 },
        { resourceId: 'acme', deleted: 2 },
      ]);
      const left = async (e: NostrEvent) => !!(await repo.get(e.id));
      expect(await left(ev.oldGeneral)).toBe(false);
      expect(await left(ev.newGeneral)).toBe(true);
      expect(await left(ev.oldLegal)).toBe(true);
      expect(await left(ev.oldOtherWs)).toBe(false);
      expect(await left(ev.oldWsNote)).toBe(false);
      expect(await left(ev.oldArchive)).toBe(true);
      expect(await left(ev.oldHeldWs)).toBe(true);
      // A channel under a held workspace is kept even past its own retention.
      expect(await enforceRetention(repo, [{ resourceId: 'kept', days: 1, legalHold: false }, { resourceId: 'held-ws', days: null, legalHold: true }], now)).toEqual([{ resourceId: 'kept', deleted: 0 }]);
    });
  });
}

retentionSuite('Retention (memory repository)', async () => new MemoryEventRepository());
if (PG) {
  retentionSuite('Retention (postgres repository)', async () => {
    const pool = createPgPool(PG);
    await resetScope(pool, 'indexer', INDEXER_TABLES);
    await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'indexer');
    return new PgEventRepository(pool, sealedCodec(new Uint8Array(32).fill(4)));
  });
}
