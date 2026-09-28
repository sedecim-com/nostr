import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, getPublicKey, type Filter, type NostrEvent } from '@sedecim/nostr-core';
import { RelayPool, type PoolSubscribeOptions, type WebSocketLike } from '@sedecim/relay-pool';
import { NOTIFICATION_MODES, OPAQUE_PUSH_PAYLOAD } from '@sedecim/profiles';
import { nip98Fetch } from '@sedecim/service-kit';
import { LocalSigner } from '@sedecim/signer';
import { createDirectMessage } from '@sedecim/messaging';
import { TestRelay } from '@sedecim/test-relay';
import { createLogger, type LogRecord } from '@sedecim/telemetry-policy';
import { createNotificationApi, createWebPushSender, generateVapidKeys, NotificationGateway, type PushSubscriptionJSON, type WebPushMessage } from '../src/index';
import { fakeSubscription } from './ua';

const RELAY = 'wss://relay.example.org';

/** Pool double: records REQs and lets the test deliver events to them. */
class FakePool {
  subs: Array<{ urls: string[]; filters: Filter[]; opts: PoolSubscribeOptions; closed: boolean }> = [];
  subscribe(urls: string[], filters: Filter[], opts: PoolSubscribeOptions) {
    const s = { urls, filters, opts, closed: false };
    this.subs.push(s);
    queueMicrotask(() => opts.oneose?.());
    return { close: () => void (s.closed = true), seenOn: () => [] };
  }
  get open() {
    return this.subs.filter((s) => !s.closed);
  }
  deliver(evt: Partial<NostrEvent>) {
    for (const s of this.open) s.opts.onevent({ id: Math.random().toString(16).slice(2), kind: 1059, tags: [], content: 'x', pubkey: 'f'.repeat(64), created_at: 0, sig: '', ...evt } as NostrEvent, s.urls[0]!);
  }
}

class FakeSender {
  sent: Array<{ sub: PushSubscriptionJSON; msg: WebPushMessage }> = [];
  status = 201;
  async send(sub: PushSubscriptionJSON, msg: WebPushMessage) {
    this.sent.push({ sub, msg });
    return this.status;
  }
}

const sub = (n = 1) => fakeSubscription(`https://fcm.googleapis.com/fcm/send/device-${n}`).subscription;
const pk = () => getPublicKey(generateSecretKey());

function setup(extra: Partial<ConstructorParameters<typeof NotificationGateway>[0]> = {}) {
  const pool = new FakePool();
  const sender = new FakeSender();
  const logs: LogRecord[] = [];
  // The push logic on a pool double: which relays can be observed is tested against real relays below (OPS-06).
  const gw = new NotificationGateway({ pool, sender, relays: [{ public: RELAY, dial: 'ws://relay:3000' }], random: () => 0.5, requireObservation: false, logger: createLogger({ level: 'debug', write: (r) => logs.push(r) }), ...extra });
  return { pool, sender, gw, logs };
}

describe('profile refusal (ADR 0010)', () => {
  it('refuses sovereign, Tor-only and .onion registrations and custom "none"', () => {
    const { gw } = setup();
    const status = (fn: () => unknown) => {
      try {
        fn();
        return 0;
      } catch (e) {
        return (e as { status: number }).status;
      }
    };
    expect(status(() => gw.register(pk(), { subscription: sub(), profile: 'sovereign' }))).toBe(403);
    expect(status(() => gw.register(pk(), { subscription: sub(), profile: 'sovereign-tor' }))).toBe(403);
    expect(status(() => gw.register(pk(), { subscription: sub(), profile: 'custom', mode: 'push', network: 'tor-only' }))).toBe(403);
    expect(status(() => gw.register(pk(), { subscription: sub(), profile: 'custom', mode: 'none' }))).toBe(403);
    expect(status(() => gw.register(pk(), { subscription: sub(), profile: 'convenience', relays: ['ws://abcdefghijklmnop.onion'] }))).toBe(403);
    expect(status(() => gw.register(pk(), { subscription: sub(), profile: 'convenience', mode: 'none' }))).toBe(403);
    expect(gw.size).toBe(0);
  });

  it('assigns the mode of the profile; a client may only ask for a stricter one', () => {
    const { gw } = setup();
    expect(gw.register(pk(), { subscription: sub(), profile: 'convenience' }).policy.mode).toBe('push');
    expect(gw.register(pk(), { subscription: sub(), profile: 'institutional' }).policy.mode).toBe('push');
    expect(gw.register(pk(), { subscription: sub(), profile: 'private-resilient', mode: 'push' }).policy.mode).toBe('privacy-push');
    expect(gw.register(pk(), { subscription: sub(), profile: 'convenience', mode: 'privacy-push' }).policy.mode).toBe('privacy-push');
  });

  it('validates endpoints (known push services, https) and keys', () => {
    const { gw } = setup();
    expect(() => gw.register(pk(), { subscription: { ...sub(), endpoint: 'https://169.254.169.254/latest' }, profile: 'convenience' })).toThrow(/push service/);
    expect(() => gw.register(pk(), { subscription: { ...sub(), endpoint: 'http://fcm.googleapis.com/x' }, profile: 'convenience' })).toThrow(/https/);
    expect(() => gw.register(pk(), { subscription: { ...sub(), keys: { p256dh: 'AAAA', auth: 'AAAA' } }, profile: 'convenience' })).toThrow(/keys/);
    expect(() => gw.register(pk(), { subscription: sub(), profile: 'convenience', relays: ['wss://other.example'] })).toThrow(/served/);
  });

  it('rate limits registrations and caps devices per pubkey', () => {
    const { gw } = setup({ registrationsPerMinute: 3, maxDevicesPerPubkey: 2 });
    const p = pk();
    gw.register(p, { subscription: sub(1), profile: 'convenience' });
    gw.register(p, { subscription: sub(2), profile: 'convenience' });
    expect(() => gw.register(p, { subscription: sub(3), profile: 'convenience' })).toThrow(/too many devices/);
    expect(() => gw.register(p, { subscription: sub(1), profile: 'convenience' })).toThrow(/too many registrations/);
  });
});

describe('batching and random delay (fake timers)', () => {
  afterEach(() => vi.useRealTimers());

  it('watches kind 1059 #p on the configured dial URL with one REQ for all pubkeys, live only', async () => {
    const { gw, pool } = setup();
    const [a, b] = [pk(), pk()];
    gw.register(a, { subscription: sub(1), profile: 'convenience' });
    gw.register(b, { subscription: sub(2), profile: 'convenience' });
    expect(pool.open).toHaveLength(1);
    expect(pool.open[0]!.urls).toEqual(['ws://relay:3000']);
    expect(pool.open[0]!.filters).toEqual([{ kinds: [1059], '#p': [a, b].sort(), limit: 1 }]);
    gw.unregister(a);
    gw.unregister(b);
    expect(pool.open).toHaveLength(0);
  });

  it('coalesces a burst into one opaque push after the profile delay and respects the minimum interval', async () => {
    vi.useFakeTimers({ now: 0 });
    const { gw, pool, sender } = setup();
    const p = pk();
    gw.register(p, { subscription: sub(), profile: 'convenience' });
    await vi.advanceTimersByTimeAsync(0); // EOSE
    const policy = NOTIFICATION_MODES.push;
    for (let i = 0; i < 5; i++) pool.deliver({ tags: [['p', p]] });
    await vi.advanceTimersByTimeAsync(policy.minDelayMs - 1);
    expect(sender.sent).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(policy.maxDelayMs + policy.batchTickMs);
    expect(sender.sent).toHaveLength(1);
    const { msg } = sender.sent[0]!;
    expect(new TextDecoder().decode(msg.payload!)).toBe(OPAQUE_PUSH_PAYLOAD);
    expect(msg).toMatchObject({ ttlSeconds: policy.ttlSeconds, urgency: 'normal', topic: 'activity' });
    // new activity right after a push waits for the minimum interval
    const sentAt = gw.registrations()[0]!.lastSentAt!;
    pool.deliver({ tags: [['p', p]] });
    await vi.advanceTimersByTimeAsync(sentAt + policy.minIntervalMs - Date.now() - 1);
    expect(sender.sent).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(policy.batchTickMs + 1);
    expect(sender.sent).toHaveLength(2);
    gw.stop();
  });

  it('privacy-push sends an empty wake-up push with the longer delay', async () => {
    vi.useFakeTimers({ now: 0 });
    const { gw, pool, sender } = setup();
    const p = pk();
    gw.register(p, { subscription: sub(), profile: 'private-resilient' });
    await vi.advanceTimersByTimeAsync(0);
    pool.deliver({ tags: [['p', p]] });
    await vi.advanceTimersByTimeAsync(NOTIFICATION_MODES.push.maxDelayMs + NOTIFICATION_MODES.push.batchTickMs);
    expect(sender.sent).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(NOTIFICATION_MODES['privacy-push'].maxDelayMs + NOTIFICATION_MODES['privacy-push'].batchTickMs);
    expect(sender.sent).toHaveLength(1);
    expect(sender.sent[0]!.msg).toMatchObject({ payload: null, urgency: 'low' });
    gw.stop();
  });

  it('ignores events before EOSE, other kinds, unwatched pubkeys and duplicates', async () => {
    vi.useFakeTimers({ now: 0 });
    const { gw, pool, sender } = setup({ delayFor: () => 10 });
    const p = pk();
    gw.register(p, { subscription: sub(), profile: 'convenience' });
    pool.deliver({ tags: [['p', p]] }); // before EOSE (stored replay)
    await vi.advanceTimersByTimeAsync(100);
    pool.deliver({ kind: 1, tags: [['p', p]] });
    pool.deliver({ tags: [['p', pk()]] });
    await vi.advanceTimersByTimeAsync(100);
    expect(sender.sent).toHaveLength(0);
    pool.deliver({ id: 'dup', tags: [['p', p]] });
    await vi.advanceTimersByTimeAsync(100);
    pool.deliver({ id: 'dup', tags: [['p', p]] });
    await vi.advanceTimersByTimeAsync(100);
    expect(sender.sent).toHaveLength(1);
    gw.stop();
  });

  it('drops the subscription when the push service answers 404/410', async () => {
    vi.useFakeTimers({ now: 0 });
    const { gw, pool, sender, logs } = setup({ delayFor: () => 10 });
    const p = pk();
    const s = sub();
    gw.register(p, { subscription: s, profile: 'convenience' });
    await vi.advanceTimersByTimeAsync(0);
    sender.status = 410;
    pool.deliver({ tags: [['p', p]] });
    await vi.advanceTimersByTimeAsync(20);
    expect(gw.size).toBe(0);
    expect(gw.stats.dropped).toBe(1);
    expect(pool.open).toHaveLength(0);
    // logs never carry the pubkey or the endpoint
    const text = JSON.stringify(logs);
    expect(text).not.toContain(p);
    expect(text).not.toContain(s.endpoint);
    expect(text).not.toContain('device-1');
  });
});

describe('end to end: test relay + NIP-98 API + fake push service', () => {
  const relay = new TestRelay();
  const received: Array<{ headers: IncomingMessage['headers']; body: Buffer; path: string }> = [];
  let pushServer: Server;
  let pushUrl: string;
  let pool: RelayPool;
  let gw: NotificationGateway;
  let api: ReturnType<typeof createNotificationApi>;
  let base: string;

  beforeAll(async () => {
    await relay.start();
    pushServer = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        received.push({ headers: req.headers, body: Buffer.concat(chunks), path: req.url ?? '' });
        res.writeHead(req.url?.includes('gone') ? 410 : 201).end();
      });
    });
    await new Promise<void>((r) => pushServer.listen(0, '127.0.0.1', r));
    pushUrl = `http://127.0.0.1:${(pushServer.address() as AddressInfo).port}`;
    pool = new RelayPool({ webSocketFactory: (u) => new WebSocket(u) as unknown as WebSocketLike });
    const vapid = generateVapidKeys();
    gw = new NotificationGateway({
      pool,
      sender: createWebPushSender({ vapid, subject: 'mailto:ops@example.org' }),
      relays: [{ public: relay.url }],
      pushHosts: ['127.0.0.1'],
      allowInsecureEndpoints: true,
      delayFor: () => 800,
    });
    api = createNotificationApi(gw, { name: 'notification-gateway', vapid });
    base = await api.listen();
    // OPS-06: this relay serves gift wraps by #p to anyone, so the canary shows the gateway can watch it.
    expect((await gw.probeRelays()).map((o) => o.observable)).toEqual([true]);
  });

  afterAll(async () => {
    gw.stop();
    pool.close();
    await api.close();
    await new Promise((r) => pushServer.close(r));
    await relay.stop();
  });

  async function until(fn: () => boolean, ms = 5000) {
    const end = Date.now() + ms;
    while (!fn()) {
      if (Date.now() > end) throw new Error('timeout');
      await new Promise((r) => setTimeout(r, 20));
    }
  }

  it('serves the VAPID key and refuses unauthenticated or Tor registrations', async () => {
    const v = await (await fetch(`${base}/v1/vapid`)).json();
    expect(Buffer.from(v.publicKey, 'base64url')).toHaveLength(65);
    const anon = await fetch(`${base}/v1/subscriptions`, { method: 'POST', body: '{}' });
    expect(anon.status).toBe(401);
    const res = await nip98Fetch(generateSecretKey(), `${base}/v1/subscriptions`, 'POST', { subscription: fakeSubscription(`${pushUrl}/x`).subscription, profile: 'sovereign-tor' });
    expect(res.status).toBe(403);
  });

  it('a NIP-17 DM to the registered pubkey yields one opaque push with no sender, content or count', async () => {
    const bobSk = generateSecretKey();
    const bob = getPublicKey(bobSk);
    const device = fakeSubscription(`${pushUrl}/push/bob`);
    const reg = await nip98Fetch(bobSk, `${base}/v1/subscriptions`, 'POST', { subscription: device.subscription, profile: 'convenience', relays: [relay.url] });
    expect(reg.status).toBe(201);
    expect(reg.json).toMatchObject({ mode: 'push', relays: [relay.url] });
    await new Promise((r) => setTimeout(r, 200)); // REQ + EOSE

    const aliceSk = generateSecretKey();
    const alice = new LocalSigner(aliceSk);
    const pool2 = new RelayPool({ webSocketFactory: (u) => new WebSocket(u) as unknown as WebSocketLike });
    const wraps: NostrEvent[] = [];
    for (let i = 0; i < 3; i++) wraps.push((await createDirectMessage(alice, { recipients: [bob], content: `mensaje secreto ${i}` })).wraps.find((w) => w.recipient === bob)!.event);
    for (const r of await Promise.all(wraps.map((w) => pool2.publish(w, [relay.url])))) expect(r[0]!.ok).toBe(true);
    pool2.close();

    await until(() => received.some((r) => r.path === '/push/bob'));
    await new Promise((r) => setTimeout(r, 300));
    const pushes = received.filter((r) => r.path === '/push/bob');
    expect(pushes).toHaveLength(1); // three DMs, one batched push: no count leaks
    const push = pushes[0]!;
    expect(push.headers['content-encoding']).toBe('aes128gcm');
    expect(push.headers.authorization).toMatch(/^vapid t=.+, k=.+$/);
    expect(push.headers.topic).toBe('activity');
    expect(device.decrypt(new Uint8Array(push.body))).toBe(OPAQUE_PUSH_PAYLOAD);
    const everything = JSON.stringify(push.headers) + push.body.toString('latin1') + push.body.toString('hex');
    for (const leak of [getPublicKey(aliceSk), bob, 'mensaje', 'secreto']) expect(everything).not.toContain(leak);

    const del = await nip98Fetch(bobSk, `${base}/v1/subscriptions`, 'DELETE', { endpoint: device.subscription.endpoint });
    expect(del.json).toEqual({ removed: 1 });
    expect(gw.size).toBe(0);
  });

  it('drops a subscription the push service reports as gone (410)', async () => {
    const sk = generateSecretKey();
    const p = getPublicKey(sk);
    expect((await nip98Fetch(sk, `${base}/v1/subscriptions`, 'POST', { subscription: fakeSubscription(`${pushUrl}/gone/1`).subscription, profile: 'institutional' })).status).toBe(201);
    await new Promise((r) => setTimeout(r, 200));
    const dm = await createDirectMessage(new LocalSigner(generateSecretKey()), { recipients: [p], content: 'x' });
    const pool2 = new RelayPool({ webSocketFactory: (u) => new WebSocket(u) as unknown as WebSocketLike });
    await pool2.publish(dm.wraps.find((w) => w.recipient === p)!.event, [relay.url]);
    pool2.close();
    await until(() => !gw.registrations().some((r) => r.pubkey === p));
    expect(received.some((r) => r.path === '/gone/1')).toBe(true);
  });
});

describe('OPS-06: push only where the gateway can observe activity without reading DMs', () => {
  // Like Buzz and the secure relay: NIP-42, and gift wraps only for their authenticated recipient.
  const gated = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  const open = new TestRelay();
  const identity = generateSecretKey();
  let pool: RelayPool;
  let gw: NotificationGateway;
  let api: ReturnType<typeof createNotificationApi>;
  let base: string;
  const device = (n: number) => fakeSubscription(`https://fcm.googleapis.com/fcm/send/ops06-${n}`).subscription;

  beforeAll(async () => {
    await gated.start();
    await open.start();
    // The gateway authenticates with its own service identity, as NOTIFY_NSEC in production.
    pool = new RelayPool({ webSocketFactory: (u) => new WebSocket(u) as unknown as WebSocketLike, signer: new LocalSigner(identity), authMode: 'auto' });
    gw = new NotificationGateway({ pool, sender: new FakeSender(), relays: [{ public: gated.url }, { public: open.url }] });
    api = createNotificationApi(gw, { name: 'notification-gateway', vapid: generateVapidKeys() });
    base = await api.listen();
  });
  afterAll(async () => {
    gw.stop();
    pool.close();
    await api.close();
    await gated.stop();
    await open.stop().catch(() => undefined); // the last test stops it
  });

  it('refuses to register before it has checked its relays', async () => {
    const res = await nip98Fetch(generateSecretKey(), `${base}/v1/subscriptions`, 'POST', { subscription: device(1), profile: 'convenience', relays: [open.url] });
    expect(res.status).toBe(503);
    expect((await (await fetch(`${base}/v1/relays`)).json()).relays.every((r: { observable: boolean }) => !r.observable)).toBe(true);
  });

  it('a canary tells the relay that only serves gift wraps to their recipient from one that serves them to anyone', async () => {
    const found = await gw.probeRelays(3000);
    expect(found.find((o) => o.relay === open.url)).toMatchObject({ observable: true });
    expect(found.find((o) => o.relay === gated.url)).toMatchObject({ observable: false, reason: expect.stringMatching(/closed|not delivered/) });
    const listed = (await (await fetch(`${base}/v1/relays`)).json()).relays as Array<{ relay: string; observable: boolean }>;
    expect(Object.fromEntries(listed.map((r) => [r.relay, r.observable]))).toEqual({ [gated.url]: false, [open.url]: true });
    // A relay that closes the REQ gets no canary. The canary: from a throwaway key to another throwaway key,
    // expiring soon; never from the gateway itself.
    expect(gated.received.filter((e: NostrEvent) => e.kind === 1059)).toHaveLength(0);
    const canaries = open.received.filter((e: NostrEvent) => e.kind === 1059);
    expect(canaries.length).toBeGreaterThan(0);
    for (const c of canaries) {
      expect(c.pubkey).not.toBe(getPublicKey(identity));
      expect(Number(c.tags.find((t) => t[0] === 'expiration')![1]) - c.created_at).toBeLessThanOrEqual(600);
    }
  });

  it('registers only on observable relays, and says which relays it cannot watch', async () => {
    const onlyGated = await nip98Fetch(generateSecretKey(), `${base}/v1/subscriptions`, 'POST', { subscription: device(2), profile: 'convenience', relays: [gated.url] });
    expect(onlyGated.status).toBe(409);
    expect(onlyGated.json.error).toMatch(/without read access to your DMs/);
    const both = await nip98Fetch(generateSecretKey(), `${base}/v1/subscriptions`, 'POST', { subscription: device(3), profile: 'convenience', relays: [gated.url, open.url] });
    expect(both.status).toBe(201);
    expect(both.json).toMatchObject({ relays: [open.url], unwatched: [gated.url] });
  });

  it('a relay that stops being observable stops counting, and a registration left without relays goes', async () => {
    expect(gw.size).toBeGreaterThan(0);
    await open.stop();
    const found = await gw.probeRelays(1000);
    expect(found.find((o) => o.relay === open.url)!.observable).toBe(false);
    expect(gw.size).toBe(0);
  });
});
