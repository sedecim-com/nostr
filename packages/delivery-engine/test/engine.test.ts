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
});
