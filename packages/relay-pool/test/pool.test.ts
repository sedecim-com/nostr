import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { TestRelay } from '@sedecim/test-relay';
import { RelayPool, type WebSocketLike } from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;

describe('RelayPool', () => {
  let relays: TestRelay[] = [];
  let pool: RelayPool;
  const signer = new LocalSigner(generateSecretKey());

  beforeEach(() => {
    relays = [];
  });
  afterEach(async () => {
    pool?.close();
    await Promise.all(relays.map((r) => r.stop()));
  });

  async function startRelay(opts: ConstructorParameters<typeof TestRelay>[0] = {}) {
    const r = new TestRelay(opts);
    await r.start();
    relays.push(r);
    return r;
  }

  it('publishes to several relays and records OK per relay (FR-009, FR-010)', async () => {
    const a = await startRelay();
    const b = await startRelay();
    b.faults.rejectReason = 'blocked: policy';
    pool = new RelayPool({ webSocketFactory: factory, signer });
    const evt = await signer.signEvent({ kind: 1, content: 'hola' });
    const res = await pool.publish(evt, [a.url, b.url]);
    expect(res.find((r) => r.relay === a.url)?.ok).toBe(true);
    expect(res.find((r) => r.relay === b.url)).toMatchObject({ ok: false, message: 'blocked: policy' });
    const again = await pool.publishTo(evt, a.url);
    expect(again).toMatchObject({ ok: true, duplicate: true });
  });

  it('answers NIP-42 challenges on auth-required and retries (FR-016)', async () => {
    const r = await startRelay({ requireAuth: true });
    pool = new RelayPool({ webSocketFactory: factory, signer });
    const evt = await signer.signEvent({ kind: 1, content: 'auth me' });
    const res = await pool.publishTo(evt, r.url);
    expect(res.ok).toBe(true);
    expect(pool.health()[0]!.authenticatedAs).toEqual([await signer.getPublicKey()]);
    const got = await pool.query([r.url], [{ ids: [evt.id] }], 3000);
    expect(got.map((e) => e.id)).toEqual([evt.id]);
  });

  it('reports auth failure as recoverable when not allowlisted', async () => {
    const r = await startRelay({ requireAuth: true, allowlist: ['00'.repeat(32)] });
    pool = new RelayPool({ webSocketFactory: factory, signer });
    const evt = await signer.signEvent({ kind: 1, content: 'x' });
    const res = await pool.publishTo(evt, r.url);
    expect(res.ok).toBe(false);
    expect(res.message).toMatch(/^auth-required:/);
  });

  it('deduplicates the same event id across relays (FR-012)', async () => {
    const a = await startRelay();
    const b = await startRelay();
    const evt = await signer.signEvent({ kind: 1, content: 'dup' });
    a.inject(evt);
    b.inject(evt);
    pool = new RelayPool({ webSocketFactory: factory });
    const seen: NostrEvent[] = [];
    await new Promise<void>((resolve) => {
      const sub = pool.subscribe([a.url, b.url], [{ kinds: [1] }], {
        onevent: (e) => seen.push(e),
        oneose: () => {
          expect(sub.seenOn(evt.id).sort()).toEqual([a.url, b.url].sort());
          resolve();
        },
      });
    });
    expect(seen).toHaveLength(1);
  });

  it('drops events with invalid signatures', async () => {
    const r = await startRelay();
    const evt = await signer.signEvent({ kind: 1, content: 'ok' });
    r.inject(evt);
    r.events.set('f'.repeat(64), { ...evt, id: 'f'.repeat(64) });
    pool = new RelayPool({ webSocketFactory: factory });
    const got = await pool.query([r.url], [{ kinds: [1] }], 3000);
    expect(got.map((e) => e.id)).toEqual([evt.id]);
  });

  it('resubscribes after the relay drops the connection', async () => {
    const r = await startRelay();
    pool = new RelayPool({ webSocketFactory: factory, reconnectBaseMs: 20, reconnectMaxMs: 50 });
    const seen: string[] = [];
    await new Promise<void>((resolve) => pool.subscribe([r.url], [{ kinds: [1] }], { onevent: (e) => seen.push(e.content), oneose: resolve }));
    r.disconnectAll();
    await new Promise((res) => setTimeout(res, 300));
    r.inject(await signer.signEvent({ kind: 1, content: 'after reconnect' }));
    await new Promise((res) => setTimeout(res, 200));
    expect(seen).toContain('after reconnect');
  });
});
