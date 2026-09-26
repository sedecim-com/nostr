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
import { createIndexerApi, Indexer, MemoryEventRepository, PgEventRepository, sealedCodec, type EventRepository } from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;

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
      const api = createIndexerApi(repo, { name: 'indexer-test' });
      const base = await api.listen();
      try {
        const res = await fetch(`${base}/v1/events?kinds=9&h=general`);
        const body = await res.json();
        expect(body.events.map((e: NostrEvent) => e.content)).toContain('desde otro cliente');
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
        const summary = await (await fetch(`${base}/v1/channels/general/summary`)).json();
        expect(summary.messages).toBeGreaterThanOrEqual(1);
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
    await resetScope(pool, 'indexer', ['event_sources', 'events']);
    await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'indexer');
    return new PgEventRepository(pool, sealedCodec(new Uint8Array(32).fill(4)));
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
