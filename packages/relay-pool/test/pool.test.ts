import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { TestRelay } from '@sedecim/test-relay';
import { asksForAuth, RelayPool, percentile, relayDegradation, type WebSocketLike } from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
/** Delivers what the relay sends `ms` late and in order, as a slow circuit (e.g. Tor) does. */
const slowFactory = (ms: number) => (url: string): WebSocketLike => {
  const ws = new WebSocket(url);
  return {
    get readyState() {
      return ws.readyState;
    },
    send: (data) => ws.send(data),
    close: (code, reason) => ws.close(code, reason),
    set onopen(f: WebSocketLike['onopen']) {
      ws.onopen = f;
    },
    set onclose(f: WebSocketLike['onclose']) {
      ws.onclose = f;
    },
    set onerror(f: WebSocketLike['onerror']) {
      ws.onerror = f;
    },
    set onmessage(f: WebSocketLike['onmessage']) {
      ws.onmessage = (ev) => setTimeout(() => f?.({ data: ev.data }), ms);
    },
  } as WebSocketLike;
};

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

  // FR023-13: nostr-rs-relay behind its nauthz admission server (the institutional secure relay) wraps the
  // answer to an event sent before AUTH in its own `blocked:` prefix. It still asks for NIP-42.
  it('authenticates and retries when the relay answers blocked: auth-required: (nostr-rs-relay with nauthz)', async () => {
    const r = await startRelay({ requireAuth: true, eventAuthRequiredMessage: 'blocked: auth-required: NIP-42 authentication required to publish' });
    pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'on-demand' });
    const evt = await signer.signEvent({ kind: 1, content: 'institutional' });
    const res = await pool.publishTo(evt, r.url);
    expect(res.ok, res.message).toBe(true);
    expect(pool.health()[0]!.authenticatedAs).toEqual([await signer.getPublicKey()]);
    expect(asksForAuth('blocked: auth-required: x')).toBe(true);
    expect(asksForAuth('auth-required: x')).toBe(true);
    expect(asksForAuth('blocked: restricted: pubkey not in the institutional allowlist')).toBe(false);
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

  it('authenticates before asking for gift wraps, which nostr-rs-relay with nip42_dms drops silently otherwise (FR025-11)', async () => {
    const r = await startRelay({ silentDmKinds: [4, 44, 1059], silentAuthOk: true });
    const me = await signer.getPublicKey();
    const wrap = await new LocalSigner(generateSecretKey()).signEvent({ kind: 1059, content: 'sealed', tags: [['p', me]] });
    r.inject(wrap);
    const anonymous = new RelayPool({ webSocketFactory: factory });
    expect(await anonymous.query([r.url], [{ kinds: [1059], '#p': [me] }], 1500)).toEqual([]);
    anonymous.close();
    pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'on-demand' });
    const started = Date.now();
    expect((await pool.query([r.url], [{ kinds: [1059], '#p': [me] }], 3000)).map((e) => e.id)).toEqual([wrap.id]);
    // The REQ follows the AUTH at once, without waiting for the OK nostr-rs-relay never sends (authTimeoutMs: 2 s).
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it('asks for gift wraps again with AUTH when the challenge comes after the REQ, over a slow link such as Tor (OPS-21)', async () => {
    const r = await startRelay({ silentDmKinds: [1059], silentAuthOk: true });
    const me = await signer.getPublicKey();
    const wrap = await new LocalSigner(generateSecretKey()).signEvent({ kind: 1059, content: 'sealed', tags: [['p', me]] });
    r.inject(wrap);
    // Everything the relay sends arrives 300 ms late, in order: the challenge comes after the 50 ms wait, so the
    // first REQ goes out unauthenticated and the relay answers it with an empty EOSE, which arrives after the challenge.
    pool = new RelayPool({ webSocketFactory: slowFactory(300), signer, authMode: 'on-demand', challengeWaitMs: 50 });
    expect((await pool.query([r.url], [{ kinds: [1059], '#p': [me] }], 5000)).map((e) => e.id)).toEqual([wrap.id]);
  });

  it('does not authenticate for public reads in on-demand mode', async () => {
    const r = await startRelay({ silentDmKinds: [1059] });
    r.inject(await signer.signEvent({ kind: 1, content: 'public' }));
    pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'on-demand' });
    expect(await pool.query([r.url], [{ kinds: [1] }], 2000)).toHaveLength(1);
    await new Promise((res) => setTimeout(res, 100));
    expect(pool.health()[0]!.authenticatedAs).toEqual([]);
  });

  it('authenticates again before resubscribing to gift wraps after a reconnect', async () => {
    const r = await startRelay({ silentDmKinds: [1059], silentAuthOk: true });
    const me = await signer.getPublicKey();
    pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'on-demand', reconnectBaseMs: 20, reconnectMaxMs: 50 });
    const seen: string[] = [];
    await new Promise<void>((resolve) => pool.subscribe([r.url], [{ kinds: [1059], '#p': [me] }], { onevent: (e) => seen.push(e.content), oneose: resolve }));
    r.disconnectAll();
    await new Promise((res) => setTimeout(res, 300));
    r.inject(await new LocalSigner(generateSecretKey()).signEvent({ kind: 1059, content: 'after reconnect', tags: [['p', me]] }));
    await new Promise((res) => setTimeout(res, 300));
    expect(seen).toContain('after reconnect');
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
