import { afterEach, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { EncryptedStore, FileBackend, MemoryBackend } from '@sedecim/encrypted-store';
import { TestRelay } from '@sedecim/test-relay';
import { NetworkGuard } from '@sedecim/tor-network';
import { DeliveryEngine, type OutboxRecord, type Publisher } from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
const signer = new LocalSigner(generateSecretKey());
const fast = { baseMs: 20, maxMs: 80 };

async function until(fn: () => Promise<boolean>, ms = 4000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('condition not met in time');
}

function memStore() {
  return EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(1)).collection<OutboxRecord>('outbox');
}

describe('DeliveryEngine', () => {
  const relays: TestRelay[] = [];
  const cleanups: Array<() => void> = [];
  afterEach(async () => {
    cleanups.splice(0).forEach((c) => c());
    await Promise.all(relays.splice(0).map((r) => r.stop()));
  });
  async function relay(opts?: ConstructorParameters<typeof TestRelay>[0]) {
    const r = new TestRelay(opts);
    await r.start();
    relays.push(r);
    return r;
  }
  function pool() {
    const p = new RelayPool({ webSocketFactory: factory, signer, autoReconnect: false, publishTimeoutMs: 500, connectTimeoutMs: 500 });
    cleanups.push(() => p.close());
    return p;
  }

  it('reports outbox stats and per-relay attempt outcomes with a failure class (FR011-03)', async () => {
    let now = 10_000;
    const publisher: Publisher = {
      async publishTo(_evt, relayUrl) {
        if (relayUrl.includes('down')) return { relay: relayUrl, ok: false, message: 'error: connection failed: x', latencyMs: 5 };
        if (relayUrl.includes('strict')) return { relay: relayUrl, ok: false, message: 'invalid: nope', latencyMs: 5 };
        return { relay: relayUrl, ok: true, message: '', latencyMs: 7 };
      },
    };
    const engine = new DeliveryEngine({ store: memStore(), publisher, signer, retry: { baseMs: 60_000, maxMs: 60_000 }, now: () => now });
    cleanups.push(() => engine.stop());
    const attempts: Array<{ relay: string; ok: boolean; failure?: string; permanent: boolean }> = [];
    engine.onAttempt((a) => attempts.push(a));
    await engine.submit({ template: { kind: 1, content: 'ok' } }, { relays: ['wss://up.example'], wait: true });
    await engine.submit({ template: { kind: 1, content: 'pending' } }, { relays: ['wss://down.example'], wait: true });
    now += 5_000;
    await engine.submit({ template: { kind: 1, content: 'failed' } }, { relays: ['wss://strict.example'], wait: true });
    now += 1_000;
    expect(await engine.stats()).toEqual({ depth: 1, oldestPendingAgeMs: 6_000, failed: 1, byState: { REPLICATED: 1, QUEUED: 1, FAILED: 1 }, continuityPending: 0 });
    expect(attempts).toEqual([
      { relay: 'wss://up.example', ok: true, latencyMs: 7, permanent: false },
      { relay: 'wss://down.example', ok: false, latencyMs: 5, failure: 'connection', permanent: false },
      { relay: 'wss://strict.example', ok: false, latencyMs: 5, failure: 'rejected', permanent: true },
    ]);
  });

  it('persists locally (signed) before transmitting (FR-008)', async () => {
    const store = memStore();
    const seenStates: string[] = [];
    const publisher: Publisher = {
      async publishTo(evt, relayUrl) {
        const rec = (await store.all())[0]!.value;
        seenStates.push(rec.state);
        expect(rec.event?.id).toBe(evt.id);
        return { relay: relayUrl, ok: true, message: '', latencyMs: 1 };
      },
    };
    const engine = new DeliveryEngine({ store, publisher, signer });
    cleanups.push(() => engine.stop());
    const rec = await engine.submit({ template: { kind: 1, content: 'hola' } }, { relays: ['wss://a.example'], wait: true });
    expect(rec.state).toBe('REPLICATED');
    expect(seenStates).toEqual(['PUBLISHING']);
    expect(rec.history.map((h) => h.state)).toEqual(['DRAFT', 'LOCAL_PERSISTED', 'SIGNED', 'QUEUED', 'PUBLISHING', 'REPLICATED']);
  });

  it('applies a configurable quorum and records per-relay results (FR-009, FR-010)', async () => {
    const [a, b, c] = [await relay(), await relay(), await relay()];
    c.faults.rejectReason = 'blocked: not allowed here';
    const engine = new DeliveryEngine({ store: memStore(), publisher: pool(), signer, retry: fast });
    cleanups.push(() => engine.stop());
    const rec = await engine.submit({ template: { kind: 1, content: 'q' } }, { relays: [a.url, b.url, c.url], quorum: 2, wait: true });
    expect(rec.state).toBe('REPLICATED');
    expect(rec.relayStatus[c.url]).toMatchObject({ permanent: true, lastError: 'blocked: not allowed here' });
    expect(rec.relayStatus[a.url]!.acceptedAt).toBeTypeOf('number');
  });

  it('never caps the quorum in silence: the record keeps the quorum asked for (FR010-04)', async () => {
    const [a, b] = [await relay(), await relay()];
    const engine = new DeliveryEngine({ store: memStore(), publisher: pool(), signer, retry: fast });
    cleanups.push(() => engine.stop());
    const capped = await engine.submit({ template: { kind: 1, content: 'q3' } }, { relays: [a.url, b.url], quorum: 3, wait: true });
    expect(capped).toMatchObject({ state: 'REPLICATED', quorum: 2, requestedQuorum: 3 });
    expect((await engine.get(capped.opId))!.requestedQuorum).toBe(3); // persisted, so the outbox can show it
    const met = await engine.submit({ template: { kind: 1, content: 'q2' } }, { relays: [a.url, b.url], quorum: 2, wait: true });
    expect(met.quorum).toBe(2);
    expect(met).not.toHaveProperty('requestedQuorum');
  });

  it('retries go where the router points now, until a relay accepts (FR010-03)', async () => {
    const [fallback, inbox] = [await relay(), await relay()];
    fallback.faults.offline = true;
    const asked: string[][] = [];
    let found = false;
    const engine = new DeliveryEngine({
      store: memStore(),
      publisher: pool(),
      signer,
      retry: fast,
      router: async (rec) => {
        asked.push(rec.relays);
        return found ? { relays: [inbox.url], meta: { dmRelaySource: 'dm-relays' } } : { relays: [fallback.url], meta: { dmRelaySource: 'fallback' } };
      },
    });
    cleanups.push(() => engine.stop());
    const rec = await engine.submit({ template: { kind: 1, content: 'ruta' } }, { relays: [fallback.url], quorum: 2, meta: { recipient: 'x', dmRelaySource: 'fallback' }, wait: true });
    expect(rec.state).toBe('QUEUED');
    expect(asked).toEqual([]); // the first round keeps the route the record was written with
    await until(async () => asked.length > 0);
    found = true;
    await until(async () => (await engine.get(rec.opId))!.state === 'REPLICATED');
    const done = (await engine.get(rec.opId))!;
    expect(done).toMatchObject({ relays: [inbox.url], quorum: 1, requestedQuorum: 2, meta: { recipient: 'x', dmRelaySource: 'dm-relays' } });
    expect(Object.keys(done.relayStatus)).toEqual([inbox.url]);
    expect(inbox.events.has(done.event!.id)).toBe(true);
    expect(done.event!.id).toBe(rec.event!.id); // same signed event, only the relays change
    const calls = asked.length;
    await engine.resume();
    expect(asked.length).toBe(calls); // accepted: never rerouted again
  });

  it('keeps an offline message in the outbox and publishes the same event when connectivity returns (FR-011)', async () => {
    const r = await relay();
    r.faults.offline = true;
    const engine = new DeliveryEngine({ store: memStore(), publisher: pool(), signer, retry: fast });
    cleanups.push(() => engine.stop());
    const first = await engine.submit({ template: { kind: 1, content: 'offline' } }, { relays: [r.url], wait: true });
    expect(first.state).toBe('QUEUED');
    expect(first.relayStatus[r.url]!.lastError).toBeDefined();
    r.faults.offline = false;
    await until(async () => (await engine.get(first.opId))!.state === 'REPLICATED');
    const done = (await engine.get(first.opId))!;
    expect(done.event!.id).toBe(first.event!.id);
    expect(r.events.has(first.event!.id)).toBe(true);
    expect(done.relayStatus[r.url]!.attemptCount).toBeGreaterThan(1);
  });

  it('treats a lost OK + duplicate on retry as accepted without creating a new event', async () => {
    const r = await relay();
    r.faults.dropOks = 1;
    const engine = new DeliveryEngine({ store: memStore(), publisher: pool(), signer, retry: fast });
    cleanups.push(() => engine.stop());
    const rec = await engine.submit({ template: { kind: 1, content: 'lost ack' } }, { relays: [r.url] });
    await until(async () => (await engine.get(rec.opId))!.state === 'REPLICATED');
    expect((await engine.get(rec.opId))!.relayStatus[r.url]!.ackMessage).toMatch(/^duplicate:/);
    expect(r.received.filter((e) => e.content === 'lost ack').every((e) => e.id === rec.event!.id)).toBe(true);
    expect([...r.events.values()].filter((e) => e.content === 'lost ack')).toHaveLength(1);
  });

  it('is idempotent on client_operation_id', async () => {
    const r = await relay();
    const engine = new DeliveryEngine({ store: memStore(), publisher: pool(), signer, retry: fast });
    cleanups.push(() => engine.stop());
    const a = await engine.submit({ template: { kind: 1, content: 'once' } }, { relays: [r.url], opId: 'op-1', wait: true });
    const b = await engine.submit({ template: { kind: 1, content: 'once' } }, { relays: [r.url], opId: 'op-1', wait: true });
    expect(b.event!.id).toBe(a.event!.id);
    expect(await engine.list()).toHaveLength(1);
  });

  // FR011-05 (scope §11.2): the UI keeps one operation id while the user retries the same send.
  it('retries an operation under its id without building another event, and re-drives it at once', async () => {
    let up = false;
    const sent: string[] = [];
    const publisher: Publisher = {
      async publishTo(evt, relayUrl) {
        sent.push(evt.id);
        return up ? { relay: relayUrl, ok: true, message: '', latencyMs: 1 } : { relay: relayUrl, ok: false, message: 'error: connection failed: x', latencyMs: 1 };
      },
    };
    // No automatic retry within the test: only the UI's retry sends again.
    const engine = new DeliveryEngine({ store: memStore(), publisher, signer, retry: { baseMs: 60_000, maxMs: 60_000 } });
    cleanups.push(() => engine.stop());
    let builds = 0;
    const build = async () => (builds++, { template: { kind: 1, content: 'retry me' } });
    const first = await engine.submitOnce('ui-op', build, { relays: ['wss://relay.example'], wait: true });
    expect(first.state).toBe('QUEUED');
    expect(first.relayStatus['wss://relay.example']!.lastError).toMatch(/connection failed/);
    up = true;
    const retried = await engine.submitOnce('ui-op', build, { relays: ['wss://relay.example'], wait: true });
    expect(retried.state).toBe('REPLICATED');
    expect(builds).toBe(1);
    expect(retried.event!.id).toBe(first.event!.id);
    expect(new Set(sent)).toEqual(new Set([first.event!.id]));
    expect(await engine.list()).toHaveLength(1);
  });

  it('stores one operation and one event when the same id is submitted twice at once (a double click)', async () => {
    const r = await relay();
    const engine = new DeliveryEngine({ store: memStore(), publisher: pool(), signer, retry: fast });
    cleanups.push(() => engine.stop());
    // Two builds of the same send differ (here in created_at): only the first may become an event.
    const now = Math.floor(Date.now() / 1000);
    const [a, b] = await Promise.all([
      engine.submit({ template: { kind: 1, content: 'double click', created_at: now } }, { relays: [r.url], opId: 'op-2' }),
      engine.submit({ template: { kind: 1, content: 'double click', created_at: now + 1 } }, { relays: [r.url], opId: 'op-2' }),
    ]);
    expect([a.opId, b.opId]).toEqual(['op-2', 'op-2']);
    await until(async () => (await engine.get('op-2'))!.state === 'REPLICATED');
    const stored = (await engine.get('op-2'))!;
    expect(await engine.list()).toHaveLength(1);
    // The operation is the one the first submit stored and returned; the second only re-drove it.
    expect(stored.event!.created_at).toBe(now);
    expect(stored.event!.id).toBe(a.event!.id);
    expect(r.received.filter((e) => e.content === 'double click').every((e) => e.id === stored.event!.id)).toBe(true);
    expect([...r.events.values()].filter((e) => e.content === 'double click')).toHaveLength(1);
  });

  it('fails the operation when quorum becomes unreachable', async () => {
    const r = await relay();
    r.faults.rejectReason = 'invalid: rejected';
    const engine = new DeliveryEngine({ store: memStore(), publisher: pool(), signer, retry: fast });
    cleanups.push(() => engine.stop());
    const rec = await engine.submit({ template: { kind: 1, content: 'x' } }, { relays: [r.url], wait: true });
    expect(rec.state).toBe('FAILED');
    expect(rec.failureReason).toContain('invalid: rejected');
  });

  it('holds messages with an explicit reason when the Tor route is unavailable (FR-020)', async () => {
    const guard = new NetworkGuard({ mode: 'tor-only', socksPort: 1, probeTimeoutMs: 200 });
    const p = new RelayPool({ webSocketFactory: guard.webSocketFactory(), autoReconnect: false });
    cleanups.push(() => p.close());
    const engine = new DeliveryEngine({ store: memStore(), publisher: p, signer, retry: fast });
    cleanups.push(() => engine.stop());
    const rec = await engine.submit({ template: { kind: 1, content: 'tor' } }, { relays: ['wss://relay.example'], wait: true });
    expect(rec.state).toBe('QUEUED');
    expect(rec.blockedReason).toBe('No enviado: red de privacidad no disponible');
    expect(guard.egress.filter((e) => e.allowed)).toHaveLength(0);
  });

  it('survives a restart: a new engine resumes persisted operations (NFR-002)', async () => {
    const r = await relay();
    r.faults.offline = true;
    const dir = await mkdtemp(join(tmpdir(), 'outbox-'));
    const store1 = (await EncryptedStore.open(new FileBackend(dir), 'pw', { logN: 4 })).collection<OutboxRecord>('outbox');
    const e1 = new DeliveryEngine({ store: store1, publisher: pool(), signer, retry: { baseMs: 10_000, maxMs: 10_000 } });
    const rec = await e1.submit({ template: { kind: 1, content: 'crash' } }, { relays: [r.url], wait: true });
    e1.stop(); // simulated crash: timers gone, only disk state remains
    r.faults.offline = false;
    const store2 = (await EncryptedStore.open(new FileBackend(dir), 'pw', { logN: 4 })).collection<OutboxRecord>('outbox');
    const e2 = new DeliveryEngine({ store: store2, publisher: pool(), signer, retry: fast });
    cleanups.push(() => e2.stop());
    const [resumed] = await e2.resume();
    expect(resumed!.state).toBe('REPLICATED');
    expect(resumed!.event!.id).toBe(rec.event!.id);
  });

  it('separates relay ack, recipient ack and read', async () => {
    const r = await relay();
    const engine = new DeliveryEngine({ store: memStore(), publisher: pool(), signer });
    cleanups.push(() => engine.stop());
    const rec = await engine.submit({ template: { kind: 1, content: 'r' } }, { relays: [r.url], wait: true });
    expect(rec.state).toBe('REPLICATED');
    expect((await engine.markRecipientAcked(rec.opId)).state).toBe('RECIPIENT_ACKED');
    expect((await engine.markRead(rec.opId)).state).toBe('READ');
    expect((await engine.markRecipientAcked(rec.opId)).state).toBe('READ');
  });

  it('reconciles lost acks by looking the event up on the relay', async () => {
    const r = await relay();
    r.faults.dropOks = 100;
    const p = pool();
    const engine = new DeliveryEngine({
      store: memStore(),
      publisher: p,
      signer,
      retry: { baseMs: 10_000, maxMs: 10_000 },
      lookup: { has: async (url, id) => (await p.query([url], [{ ids: [id] }], 1000)).length > 0 },
    });
    cleanups.push(() => engine.stop());
    const rec = await engine.submit({ template: { kind: 1, content: 'recon' } }, { relays: [r.url], wait: true });
    expect(rec.state).toBe('QUEUED');
    await engine.reconcile();
    expect((await engine.get(rec.opId))!.state).toBe('REPLICATED');
  });

  it('resumes pending work when the pool reconnects (FR-011)', async () => {
    const r = await relay();
    const port = r.port;
    const url = r.url;
    const p = new RelayPool({ webSocketFactory: factory, signer, reconnectBaseMs: 20, reconnectMaxMs: 50, connectTimeoutMs: 500, publishTimeoutMs: 500 });
    cleanups.push(() => p.close());
    // an open subscription (e.g. the inbox) keeps the pool reconnecting in the background
    await new Promise<void>((resolve) => p.subscribe([url], [{ kinds: [1] }], { onevent: () => undefined, oneose: resolve }));
    const engine = new DeliveryEngine({ store: memStore(), publisher: p, signer, retry: { baseMs: 30_000, maxMs: 30_000 } });
    cleanups.push(() => engine.stop());
    const off = p.onReconnect(() => void engine.resume());
    cleanups.push(off);
    await r.stop();
    const rec = await engine.submit({ template: { kind: 1, content: 'vuelve la red' } }, { relays: [url], wait: true });
    expect(rec.state).toBe('QUEUED');
    const back = new TestRelay({ port });
    await back.start();
    relays.push(back);
    // well before the 15-30 s backoff: the reconnect event drove the retry
    await until(async () => (await engine.get(rec.opId))!.state === 'REPLICATED', 3000);
    expect(back.events.has(rec.event!.id)).toBe(true);
  });

  it('resume() is idempotent while in flight', async () => {
    const r = await relay();
    r.faults.okDelayMs = 100;
    let publishes = 0;
    const p = pool();
    const publisher: Publisher = { publishTo: (evt, url) => (publishes++, p.publishTo(evt, url)) };
    const engine = new DeliveryEngine({ store: memStore(), publisher, signer, retry: { baseMs: 10_000, maxMs: 10_000 } });
    cleanups.push(() => engine.stop());
    r.faults.offline = true;
    await engine.submit({ template: { kind: 1, content: 'una vez' } }, { relays: [r.url], wait: true });
    r.faults.offline = false;
    publishes = 0;
    const [a, b] = [engine.resume(), engine.resume()];
    expect(a).toBe(b);
    const [rec] = await a;
    expect(rec!.state).toBe('REPLICATED');
    expect(publishes).toBe(1);
  });
});
