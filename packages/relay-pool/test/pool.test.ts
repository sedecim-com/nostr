import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { TestRelay } from '@sedecim/test-relay';
import { RelayPool, percentile, relayDegradation, type WebSocketLike } from '../src/index';

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

  it('authenticates and retries when a p-gated relay answers restricted: to an unauthenticated REQ', async () => {
    const r = await startRelay({ pGatedKinds: [1059] });
    const me = await signer.getPublicKey();
    const wrap = await new LocalSigner(generateSecretKey()).signEvent({ kind: 1059, content: 'x', tags: [['p', me]] });
    r.inject(wrap);
    pool = new RelayPool({ webSocketFactory: factory, signer });
    const got = await pool.query([r.url], [{ kinds: [1059], '#p': [me] }], 3000);
    expect(got.map((e) => e.id)).toEqual([wrap.id]);
  });

  it('proceeds when a relay never answers OK to a successful AUTH (nostr-rs-relay behaviour)', async () => {
    const r = await startRelay({ requireAuth: true, silentAuthOk: true, pGatedKinds: [1059] });
    pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'auto', authTimeoutMs: 200 });
    const started = Date.now();
    const evt = await signer.signEvent({ kind: 1, content: 'silent auth' });
    expect((await pool.publishTo(evt, r.url)).ok).toBe(true);
    const got = await pool.query([r.url], [{ kinds: [1059], '#p': [await signer.getPublicKey()] }], 3000);
    expect(got).toEqual([]);
    expect(Date.now() - started).toBeLessThan(2500);
  });

  it('authenticates and replays REQs when the relay answers with a NOTICE auth-required (Buzz behaviour)', async () => {
    const r = await startRelay({ requireAuth: true, authNoticeOnReq: true });
    const evt = await signer.signEvent({ kind: 1, content: 'needs auth to read' });
    r.inject(evt);
    pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'on-demand' });
    const got = await pool.query([r.url], [{ kinds: [1] }], 3000);
    expect(got.map((e) => e.id)).toEqual([evt.id]);
  });

  it('signs AUTH with the public relay URL when dialling an internal address (Buzz checks the tag against the tenant host)', async () => {
    const r = await startRelay({ requireAuth: true, authNoticeOnReq: true, publicUrl: 'wss://relay.example.org' });
    const internal = `ws://127.0.0.1:${r.port}`;
    const evt = await signer.signEvent({ kind: 1, content: 'behind a proxy' });
    r.inject(evt);
    const naive = new RelayPool({ webSocketFactory: factory, signer, authMode: 'auto' });
    expect(await naive.query([internal], [{ kinds: [1] }], 1500)).toEqual([]);
    naive.close();
    pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'auto', authRelayUrl: () => 'wss://relay.example.org' });
    const got = await pool.query([internal], [{ kinds: [1] }], 3000);
    expect(got.map((e) => e.id)).toEqual([evt.id]);
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

  it('emits onReconnect when a dropped relay comes back, not on the first connect (FR-011)', async () => {
    const r = await startRelay();
    const port = r.port;
    pool = new RelayPool({ webSocketFactory: factory, reconnectBaseMs: 20, reconnectMaxMs: 50 });
    const reconnects: string[] = [];
    const off = pool.onReconnect((url) => reconnects.push(url));
    await new Promise<void>((resolve) => pool.subscribe([r.url], [{ kinds: [1] }], { onevent: () => undefined, oneose: resolve }));
    expect(reconnects).toEqual([]);
    await r.stop();
    await new Promise((res) => setTimeout(res, 150)); // a few failed attempts while it is down
    const back = new TestRelay({ port });
    await back.start();
    relays.push(back);
    const end = Date.now() + 3000;
    while (reconnects.length === 0 && Date.now() < end) await new Promise((res) => setTimeout(res, 20));
    expect(reconnects).toEqual([r.url]);
    off();
    back.disconnectAll();
    await new Promise((res) => setTimeout(res, 300));
    expect(reconnects).toHaveLength(1);
  });

  it('treats the first success after a failed attempt as a reconnect (offline start)', async () => {
    const r = await startRelay();
    const port = r.port;
    await r.stop();
    pool = new RelayPool({ webSocketFactory: factory, autoReconnect: false, connectTimeoutMs: 500 });
    const reconnects: string[] = [];
    pool.onReconnect((url) => reconnects.push(url));
    const evt = await signer.signEvent({ kind: 1, content: 'offline' });
    expect((await pool.publishTo(evt, r.url)).ok).toBe(false);
    const back = new TestRelay({ port });
    await back.start();
    relays.push(back);
    expect((await pool.publishTo(evt, r.url)).ok).toBe(true);
    await new Promise((res) => setTimeout(res, 0));
    expect(reconnects).toEqual([r.url]);
  });

  it('exposes publish results to observers and a P95 of ACK latency; slow relays are reported degraded (NFR004-01/02)', async () => {
    const r = await startRelay();
    r.faults.okDelayMs = 120;
    const seen: Array<{ relay: string; ok: boolean; latencyMs: number }> = [];
    pool = new RelayPool({ webSocketFactory: factory, signer });
    const off = pool.onPublishResult((res) => seen.push(res));
    pool.onPublishResult(() => {
      throw new Error('observer bug');
    });
    for (let i = 0; i < 3; i++) expect((await pool.publishTo(await signer.signEvent({ kind: 1, content: `p${i}` }), r.url)).ok).toBe(true);
    off();
    await pool.publishTo(await signer.signEvent({ kind: 1, content: 'unobserved' }), r.url);
    expect(seen).toHaveLength(3);
    expect(seen.every((x) => x.relay === r.url && x.ok && x.latencyMs >= 100)).toBe(true);
    const h = pool.health()[0]!;
    expect(h.ackSamples).toBe(4);
    expect(h.p95AckLatencyMs).toBeGreaterThanOrEqual(100);
    expect(relayDegradation(h, { p95Ms: 50 })).toMatchObject({ degraded: true, reasons: [expect.stringMatching(/^P95 de confirmación \d+ ms \(> 50 ms\)$/)] });
    expect(relayDegradation(h, { p95Ms: 10_000 }).degraded).toBe(false);
    expect(relayDegradation({ ...h, status: 'blocked' }).reasons).toContain('bloqueado por la política de red');
    expect(percentile([5, 1, 3, 2, 4], 0.95)).toBe(5);
    expect(percentile([], 0.95)).toBeUndefined();
  });
});
