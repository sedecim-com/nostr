/**
 * OPS-16: webhooks. Deliveries to real HTTP servers on 127.0.0.1 (ephemeral ports) with an injected clock, on both
 * repositories: the HMAC signature and its window, the idempotency key, retries with backoff and jitter, the attempts
 * limit, disabling after failures in a row, destinations that fail or hang, a dispatcher that dies holding a claim, and
 * the destination checks (SSRF) that run before every connection.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { createServer, type IncomingHttpHeaders } from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { fileURLToPath } from 'node:url';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { createPgPool, migrate, nip98Fetch, resetScope, type Pool } from '@sedecim/service-kit';
import {
  absoluteName,
  canonicalJson,
  checkWebhookUrl,
  ConflictError,
  createPolicyApi,
  DestinationError,
  isPublicAddress,
  LEASE_MARGIN_MS,
  MemoryPolicyRepository,
  parseSigningKey,
  PgPolicyRepository,
  PolicyEngine,
  POLICY_TABLES,
  postWebhook,
  resolveDestination,
  retryDelay,
  verifyPolicyEvent,
  verifyWebhookSignature,
  WEBHOOK_DISABLED_REASON,
  WEBHOOK_MAX_BODY_BYTES,
  WebhookDispatcher,
  webhookSecret,
  type DeliveryResult,
  type DeliveryRow,
  type DestinationPolicy,
  type PolicyEvent,
  type PolicyRepository,
  type WebhookDispatcherOptions,
  type WebhookView,
} from '../src/index';

const MIGRATIONS = fileURLToPath(new URL('../migrations', import.meta.url));
const WEBAUTHN = { rpId: 'localhost', rpName: 'Test', origins: ['http://localhost:8080'] };
const ISSUER = 'https://policy.example.org';
const pubkey = () => getPublicKey(generateSecretKey());
const waitFor = async (check: () => Promise<boolean>, ms = 5_000) => {
  const end = Date.now() + ms;
  while (!(await check())) {
    if (Date.now() > end) throw new Error('timed out waiting');
    await new Promise((r) => setTimeout(r, 5));
  }
};

interface Hit {
  url: string;
  path: string;
  headers: IncomingHttpHeaders;
  body: string;
}

/** HTTP destinations on 127.0.0.1: each path behaves as its name says. */
async function destinations() {
  const hits: Hit[] = [];
  const sockets = new Set<Socket>();
  let flaky = 0;
  let base = '';
  const server = createServer((req, res) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (c: string) => (body += c));
    req.on('end', () => {
      const url = req.url ?? '/';
      const path = url.split('?')[0]!;
      hits.push({ url, path, headers: req.headers, body });
      if (path === '/ok') res.writeHead(204).end();
      else if (path === '/500') res.writeHead(500, { 'x-internal': 'stack-trace' }).end('internal error: db password is hunter2');
      else if (path === '/flaky') res.writeHead(++flaky === 1 ? 500 : 200).end('ok');
      else if (path === '/close') req.socket.destroy();
      else if (path === '/redirect') res.writeHead(302, { location: `${base}/ok?via=redirect` }).end();
      else if (path !== '/slow') res.writeHead(404).end();
      // '/slow' never answers.
    });
  });
  server.on('connection', (s) => {
    sockets.add(s);
    s.on('close', () => sockets.delete(s));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  base = `http://127.0.0.1:${port}`;
  return {
    base,
    port,
    hits,
    url: (path: string) => `${base}${path}`,
    count: (path: string) => hits.filter((h) => h.path === path).length,
    close: async () => {
      for (const s of sockets) s.destroy();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}

/** Same behaviour on both repositories. */
function suite(name: string, makeRepo: () => Promise<PolicyRepository>) {
  describe(name, () => {
    let now = 1_700_000_000_000;
    const clock = () => now;
    const adminSk = generateSecretKey();
    const admin = getPublicKey(adminSk);
    const key = parseSigningKey(randomBytes(32).toString('hex'));
    const secretsKey = randomBytes(32);
    // Local destinations: http and 127.0.0.1, as POLICY_WEBHOOKS_ALLOW_PRIVATE allows in tests. No name resolves.
    const policy: DestinationPolicy = { allowPrivate: true, resolve: async () => Promise.reject(new Error('no DNS in these tests')) };
    let repo: PolicyRepository;
    let engine: PolicyEngine;
    let api: ReturnType<typeof createPolicyApi>;
    let base: string;
    let dest: Awaited<ReturnType<typeof destinations>>;
    const asAdmin = (path: string, method = 'GET', body?: unknown) => nip98Fetch(adminSk, `${base}${path}`, method, body);
    const dispatcher = (o: Partial<WebhookDispatcherOptions> = {}) =>
      new WebhookDispatcher({ repo, secretsKey, policy, now: clock, random: () => 0.5, maxAttempts: 4, disableAfter: 100, timeoutMs: 2_000, onDisabled: (id, f) => engine.webhookDisabled(id, f), ...o });
    /** Only device.register by default: a subscription to every type would also get the webhook.* events of the tests. */
    const subscribe = async (path: string, types: string[] = ['device.register']) => {
      const r = await asAdmin('/v1/webhooks', 'POST', { url: dest.url(path), types });
      expect(r.status, JSON.stringify(r.json)).toBe(201);
      return r.json as { webhook: WebhookView; secret: string };
    };
    const deliveries = (id: string) => engine.listWebhookDeliveries(id);
    const webhookOf = async (id: string) => (await engine.listWebhooks()).find((w) => w.id === id)!;
    /** One device.register event. */
    const emit = () => engine.registerDevice(admin, pubkey());
    const run = async (d: WebhookDispatcher) => {
      const n = await d.tick();
      await d.drain();
      return n;
    };

    beforeAll(async () => {
      repo = await makeRepo();
      engine = new PolicyEngine(repo, clock, WEBAUTHN, { issuer: ISSUER, key, webhooks: { secretsKey, policy, max: 20 } });
      await engine.initEvents();
      api = createPolicyApi(engine, { name: 'policy-webhooks', adminPubkeys: [admin] });
      base = await api.listen();
      dest = await destinations();
    });
    afterEach(async () => {
      for (const w of await engine.listWebhooks()) await engine.deleteWebhook(admin, w.id);
    });
    afterAll(async () => {
      await api.close();
      await dest.close();
    });

    it('delivers each event signed: HMAC of timestamp.body within the window, the event id as idempotency key, the Ed25519 signature inside (OPS-16)', async () => {
      const { webhook, secret } = await subscribe('/ok', ['device.register']);
      expect(webhook).toEqual({ id: expect.any(String), url: dest.url('/ok'), types: ['device.register'], status: 'active', createdAt: now, createdBy: admin, consecutiveFailures: 0 });
      expect(secret).toMatch(/^whsec_[\w-]{43}$/);
      // Another type: not for this subscription.
      await engine.upsertSubject(admin, { pubkey: pubkey(), roles: [], attributes: {} });
      await emit();
      const before = dest.count('/ok');
      expect(await run(dispatcher())).toBe(1);
      const hits = dest.hits.filter((h) => h.path === '/ok').slice(before);
      expect(hits).toHaveLength(1);
      const [hit] = hits as [Hit];
      expect(hit.headers['content-type']).toBe('application/json');
      expect(hit.headers['user-agent']).toBe('acceso-nostr-policy-webhooks/1');
      const signature = hit.headers['x-sedecim-signature'] as string;
      expect(signature).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
      expect(verifyWebhookSignature(signature, hit.body, secret, { now })).toEqual({ ok: true, timestamp: Math.floor(now / 1000) });
      const event = JSON.parse(hit.body) as PolicyEvent;
      expect(hit.headers['idempotency-key']).toBe(event.id);
      expect(event.type).toBe('device.register');
      // The Ed25519 signature inside verifies with the published keys, and the body is the event as the cursor serves it.
      const jwks = await (await fetch(`${base}/v1/events/keys`)).json();
      expect(verifyPolicyEvent(event, { issuer: ISSUER, keys: jwks })).toEqual({ ok: true, event });
      const served = (await engine.listEvents({ limit: 1000 })).events.find((e) => e.id === event.id)!;
      expect(hit.body).toBe(canonicalJson(served));
      // What a receiver refuses: outside the window (replayed later, or dated ahead), altered, re-dated, another secret.
      expect(verifyWebhookSignature(signature, hit.body, secret, { now: now + 301_000 })).toEqual({ ok: false, reason: 'stale' });
      expect(verifyWebhookSignature(signature, hit.body, secret, { now: now - 301_000 })).toEqual({ ok: false, reason: 'stale' });
      expect(verifyWebhookSignature(signature, hit.body.replace('device.register', 'device.revoke'), secret, { now })).toEqual({ ok: false, reason: 'signature' });
      expect(verifyWebhookSignature(signature.replace(/t=\d+/, (t) => `t=${Number(t.slice(2)) + 1}`), hit.body, secret, { now })).toEqual({ ok: false, reason: 'signature' });
      expect(verifyWebhookSignature(signature, hit.body, `${secret}x`, { now })).toEqual({ ok: false, reason: 'signature' });
      expect(verifyWebhookSignature('v1=abc', hit.body, secret, { now })).toEqual({ ok: false, reason: 'malformed' });
      // The delivery log: status, attempts, HTTP status; nothing the destination sent.
      expect(await deliveries(webhook.id)).toEqual([{ id: expect.any(Number), webhookId: webhook.id, eventSeq: event.seq, eventId: event.id, eventType: 'device.register', status: 'delivered', attempts: 1, lastAttemptAt: now, lastStatus: 204, finishedAt: now, createdAt: now }]);
      expect((await asAdmin(`/v1/webhooks/${webhook.id}/deliveries`)).json.deliveries).toEqual(await deliveries(webhook.id));
    });

    it('retries a failed delivery with the same event and idempotency key until the destination takes it (OPS-16)', async () => {
      const { webhook, secret } = await subscribe('/flaky');
      await emit();
      const d = dispatcher();
      await run(d);
      const first = now;
      expect((await deliveries(webhook.id))[0]).toMatchObject({ status: 'pending', attempts: 1, lastStatus: 500, lastError: 'http_5xx', nextAttemptAt: now + 22_500 });
      expect((await webhookOf(webhook.id)).consecutiveFailures).toBe(1);
      // Not due yet: nothing to claim.
      expect(await d.tick()).toBe(0);
      now += 22_500;
      expect(await run(d)).toBe(1);
      const [delivery] = await deliveries(webhook.id);
      expect(delivery).toMatchObject({ status: 'delivered', attempts: 2, lastStatus: 200 });
      expect(delivery!.lastError).toBeUndefined();
      const tries = dest.hits.filter((h) => h.path === '/flaky');
      expect(tries).toHaveLength(2);
      // The same event under the same idempotency key, each attempt signed at its own time.
      expect(tries[1]!.body).toBe(tries[0]!.body);
      expect(tries[1]!.headers['idempotency-key']).toBe(tries[0]!.headers['idempotency-key']);
      expect(verifyWebhookSignature(tries[0]!.headers['x-sedecim-signature'] as string, tries[0]!.body, secret, { now: first }).ok).toBe(true);
      expect(verifyWebhookSignature(tries[1]!.headers['x-sedecim-signature'] as string, tries[1]!.body, secret, { now }).ok).toBe(true);
      // A success ends the run of failures.
      expect((await webhookOf(webhook.id)).consecutiveFailures).toBe(0);
    });

    it('backs off exponentially with jitter until the attempts run out, then fails for good, keeping nothing of the answers (OPS-16)', async () => {
      const { webhook } = await subscribe('/500');
      await emit();
      const d = dispatcher({ maxAttempts: 4 });
      const before = dest.count('/500');
      const gaps: number[] = [];
      for (let attempt = 1; attempt <= 4; attempt++) {
        expect(await run(d)).toBe(1);
        const [delivery] = (await deliveries(webhook.id)) as [DeliveryRow];
        expect(delivery.attempts).toBe(attempt);
        if (attempt < 4) {
          gaps.push(delivery.nextAttemptAt! - now);
          now = delivery.nextAttemptAt!;
        } else {
          expect(delivery).toMatchObject({ status: 'failed', lastStatus: 500, lastError: 'http_5xx', finishedAt: now });
          expect(delivery.nextAttemptAt).toBeUndefined();
        }
      }
      // 30 s doubling, with random() = 0.5 halfway between half and all of each step.
      expect(gaps).toEqual([22_500, 45_000, 90_000]);
      now += 24 * 3_600_000;
      expect(await d.tick()).toBe(0);
      expect(dest.count('/500') - before).toBe(4);
      expect(JSON.stringify(await deliveries(webhook.id))).not.toMatch(/hunter2|stack-trace|internal error/);
      expect([retryDelay(1, () => 0), retryDelay(1, () => 1), retryDelay(3, () => 0.5)]).toEqual([15_000, 30_000, 90_000]);
      expect([retryDelay(40, () => 0), retryDelay(40, () => 1)]).toEqual([3 * 3_600_000, 6 * 3_600_000]);
    });

    it('disables a subscription after failed attempts in a row, audits it, stops delivering to it, and an admin enables it again (OPS-16)', async () => {
      const { webhook } = await subscribe('/500');
      const watcher = await subscribe('/ok', ['webhook.disable']);
      await emit();
      const d = dispatcher({ disableAfter: 3, maxAttempts: 10 });
      for (let i = 0; i < 3; i++) {
        expect(await run(d)).toBe(1);
        now = (await deliveries(webhook.id))[0]!.nextAttemptAt ?? now;
      }
      expect(await webhookOf(webhook.id)).toMatchObject({ status: 'disabled', disabledReason: WEBHOOK_DISABLED_REASON, disabledAt: expect.any(Number), consecutiveFailures: 3 });
      expect((await deliveries(webhook.id))[0]).toMatchObject({ status: 'failed', attempts: 3, lastError: 'subscription_disabled' });
      const [audited] = await engine.listAudit({ limit: 1 });
      expect(audited).toMatchObject({ action: 'webhook.disable', actor: 'policy-engine', target: webhook.id, details: { failures: 3 } });
      // The other subscription hears of it.
      const before = dest.count('/ok');
      expect(await run(d)).toBe(1);
      const told = JSON.parse(dest.hits.filter((h) => h.path === '/ok')[before]!.body) as PolicyEvent;
      expect([told.type, told.data.target]).toEqual(['webhook.disable', webhook.id]);
      // A disabled subscription gets no new deliveries.
      await emit();
      expect(await deliveries(webhook.id)).toHaveLength(1);
      expect(await d.tick()).toBe(0);
      // Enabled again: from the next event on, with its failures at 0.
      const enabled = await asAdmin(`/v1/webhooks/${webhook.id}/enable`, 'POST', {});
      expect(enabled.status).toBe(200);
      expect(enabled.json.webhook).toEqual({ ...webhook, status: 'active', consecutiveFailures: 0 });
      expect((await engine.listAudit({ limit: 1 }))[0]).toMatchObject({ action: 'webhook.enable', actor: admin, target: webhook.id });
      await emit();
      expect((await deliveries(webhook.id)).map((x) => x.status)).toEqual(['pending', 'failed']);
      expect((await deliveries(watcher.webhook.id)).length).toBe(1);
    });

    it('a destination that answers 500, hangs past the limit or closes the connection fails, and does not hold up the others (OPS-16)', async () => {
      const hooks = { fails: await subscribe('/500'), hangs: await subscribe('/slow'), closes: await subscribe('/close'), takes: await subscribe('/ok') };
      await emit();
      const d = dispatcher({ timeoutMs: 400 });
      expect(await d.tick()).toBe(4);
      await waitFor(async () => (await deliveries(hooks.takes.webhook.id))[0]?.status === 'delivered');
      // Delivered while the one that hangs is still waiting for its limit.
      expect((await deliveries(hooks.hangs.webhook.id))[0]).toMatchObject({ status: 'pending', attempts: 1 });
      expect((await deliveries(hooks.hangs.webhook.id))[0]!.lastError).toBeUndefined();
      expect(d.pending).toBeGreaterThanOrEqual(1);
      await d.drain();
      const last = async (h: { webhook: WebhookView }) => (await deliveries(h.webhook.id))[0];
      expect(await last(hooks.fails)).toMatchObject({ status: 'pending', lastStatus: 500, lastError: 'http_5xx' });
      expect(await last(hooks.hangs)).toMatchObject({ status: 'pending', lastError: 'timeout' });
      expect((await last(hooks.hangs))!.lastStatus).toBeUndefined();
      expect(await last(hooks.closes)).toMatchObject({ status: 'pending', lastError: 'connection_closed' });
      expect(await last(hooks.takes)).toMatchObject({ status: 'delivered', lastStatus: 204 });
    });

    it('never follows a redirect (OPS-16)', async () => {
      const { webhook } = await subscribe('/redirect');
      await emit();
      await run(dispatcher());
      expect((await deliveries(webhook.id))[0]).toMatchObject({ status: 'pending', lastStatus: 302, lastError: 'redirect' });
      expect(dest.hits.some((h) => h.url.includes('via=redirect'))).toBe(false);
    });

    it('shows the secret only in the creation answer; what is stored cannot give it back (OPS-16)', async () => {
      const created = await subscribe('/ok');
      const listed = await asAdmin('/v1/webhooks');
      expect(listed.json.webhooks).toEqual([created.webhook]);
      expect(JSON.stringify(listed.json)).not.toContain(created.secret);
      expect(Object.keys(created.webhook)).not.toContain('salt');
      const stored = (await repo.getWebhook(created.webhook.id))!;
      expect(JSON.stringify(stored)).not.toContain(created.secret);
      // Derived from the secrets key: with the stored row alone, or another key, there is no secret.
      expect(webhookSecret(secretsKey, stored.id, stored.salt)).toBe(created.secret);
      expect(webhookSecret(randomBytes(32), stored.id, stored.salt)).not.toBe(created.secret);
      // The audit and its event keep the host, never the URL (it may carry a token) nor the secret.
      const audit = (await engine.listAudit({ limit: 10 })).find((a) => a.action === 'webhook.create' && a.target === created.webhook.id);
      expect(audit?.details).toEqual({ host: new URL(dest.base).host, types: ['device.register'] });
      const events = JSON.stringify((await engine.listEvents({ limit: 1000 })).events);
      expect(events).not.toContain(created.secret);
      expect(events).not.toContain(dest.url('/ok'));
    });

    it('survives a dispatcher that dies holding a claim: the claim expires and another one delivers (OPS-16)', async () => {
      const { webhook } = await subscribe('/ok');
      await emit();
      let finish!: (r: DeliveryResult) => void;
      const dying = dispatcher({ send: () => new Promise<DeliveryResult>((r) => (finish = r)) });
      expect(await dying.tick()).toBe(1);
      const other = dispatcher();
      expect(await other.tick()).toBe(0);
      now += 2_000 + LEASE_MARGIN_MS;
      expect(await other.tick()).toBe(1);
      await other.drain();
      expect((await deliveries(webhook.id))[0]).toMatchObject({ status: 'delivered', attempts: 2, lastStatus: 204 });
      // The dead one coming back changes nothing: its lease is gone.
      finish({ ok: false, error: 'network' });
      await dying.drain();
      expect((await deliveries(webhook.id))[0]).toMatchObject({ status: 'delivered', attempts: 2, lastStatus: 204 });
      expect((await webhookOf(webhook.id)).consecutiveFailures).toBe(0);
      // When the claim that died was the last attempt allowed, the delivery fails, recorded as such.
      await emit();
      const last = dispatcher({ maxAttempts: 1, send: () => new Promise<DeliveryResult>(() => {}) });
      expect(await last.tick()).toBe(1);
      now += 2_000 + LEASE_MARGIN_MS;
      expect(await dispatcher({ maxAttempts: 1 }).tick()).toBe(0);
      expect((await deliveries(webhook.id))[0]).toMatchObject({ status: 'failed', attempts: 1, lastError: 'lease_expired' });
    });

    it('an event too large for a webhook fails at once, and stays readable from the cursor (OPS-16)', async () => {
      const { webhook } = await subscribe('/ok', ['subject.upsert']);
      await engine.upsertSubject(admin, { pubkey: pubkey(), roles: ['r'.repeat(WEBHOOK_MAX_BODY_BYTES)], attributes: {} });
      const before = dest.count('/ok');
      await run(dispatcher());
      expect((await deliveries(webhook.id))[0]).toMatchObject({ status: 'failed', attempts: 1, lastError: 'payload_too_large' });
      expect(dest.count('/ok')).toBe(before);
      expect((await engine.listEvents({ limit: 1000 })).events.at(-1)?.type).toBe('subject.upsert');
    });

    it('limits the subscriptions of the organisation; only admins manage them and bad input is refused (OPS-16)', async () => {
      const limited = new PolicyEngine(repo, clock, WEBAUTHN, { issuer: ISSUER, key, webhooks: { secretsKey, policy, max: 2 } });
      await limited.createWebhook(admin, { url: dest.url('/ok'), types: ['device.register'] });
      await limited.createWebhook(admin, { url: dest.url('/ok'), types: ['device.revoke'] });
      await expect(limited.createWebhook(admin, { url: dest.url('/ok') })).rejects.toThrow(ConflictError);
      await expect(limited.createWebhook(admin, { url: dest.url('/ok') })).rejects.toThrow(/POLICY_WEBHOOKS_MAX/);
      const stranger = generateSecretKey();
      expect((await nip98Fetch(stranger, `${base}/v1/webhooks`, 'POST', { url: dest.url('/ok') })).status).toBe(403);
      expect((await nip98Fetch(stranger, `${base}/v1/webhooks`)).status).toBe(403);
      const some = (await engine.listWebhooks()).find((w) => w.types.includes('device.register'));
      expect((await nip98Fetch(stranger, `${base}/v1/webhooks/${some!.id}`, 'DELETE')).status).toBe(403);
      expect((await nip98Fetch(stranger, `${base}/v1/webhooks/${some!.id}/deliveries`)).status).toBe(403);
      for (const body of [{}, { url: 'ftp://hooks.example.com/x' }, { url: dest.url('/ok'), types: ['nope'] }, { url: dest.url('/ok'), types: 'device.revoke' }, [dest.url('/ok')]]) {
        expect((await asAdmin('/v1/webhooks', 'POST', body)).status, JSON.stringify(body)).toBe(400);
      }
      for (const [path, method] of [['/v1/webhooks/nope', 'DELETE'], ['/v1/webhooks/nope/enable', 'POST'], ['/v1/webhooks/nope/deliveries', 'GET']] as const) {
        expect((await asAdmin(path, method, method === 'POST' ? {} : undefined)).status).toBe(404);
      }
      // Deleting one takes its deliveries with it, and the audit keeps its host.
      await emit();
      expect(await deliveries(some!.id)).toHaveLength(1);
      expect((await asAdmin(`/v1/webhooks/${some!.id}`, 'DELETE')).status).toBe(200);
      expect((await engine.listAudit({ limit: 1 }))[0]).toMatchObject({ action: 'webhook.delete', target: some!.id, details: { host: new URL(dest.base).host } });
      await expect(engine.listWebhookDeliveries(some!.id)).rejects.toThrow(/unknown webhook/);
    });

    it('a subscription to every type gets its own creation first, then every event after it (OPS-16)', async () => {
      const r = await asAdmin('/v1/webhooks', 'POST', { url: dest.url('/ok') });
      expect(r.json.webhook.types).toEqual([]);
      await emit();
      expect((await deliveries(r.json.webhook.id)).reverse().map((x) => x.eventType)).toEqual(['webhook.create', 'device.register']);
    });

    it('prunes finished deliveries after their retention, never pending ones (OPS-16)', async () => {
      const ok = await subscribe('/ok');
      const failing = await subscribe('/500');
      await emit();
      await run(dispatcher());
      now += 31 * 86_400_000;
      expect(await engine.pruneWebhookDeliveries(30)).toBe(1);
      expect(await deliveries(ok.webhook.id)).toEqual([]);
      expect((await deliveries(failing.webhook.id)).map((x) => x.status)).toEqual(['pending']);
    });
  });
}

suite('webhooks (memory)', async () => new MemoryPolicyRepository());

describe('webhook destinations: what is refused before connecting (OPS-16)', () => {
  const BLOCKED = [
    '127.0.0.1',
    '127.8.9.10',
    '0.0.0.0',
    '10.0.0.1',
    '172.16.5.4',
    '172.31.255.255',
    '192.168.1.1',
    '169.254.169.254',
    '169.254.170.2',
    '100.64.0.1',
    '100.100.100.200',
    '192.0.0.192',
    '192.0.2.1',
    '198.18.0.1',
    '224.0.0.1',
    '255.255.255.255',
    '::',
    '::1',
    '::ffff:127.0.0.1',
    '::ffff:169.254.169.254',
    '::127.0.0.1',
    'fe80::1',
    'fc00::1',
    'fd00:ec2::254',
    '64:ff9b::a9fe:a9fe',
    '2002:7f00:1::',
    '2001:db8::1',
    'ff02::1',
  ];
  const PUBLIC = ['93.184.216.34', '8.8.8.8', '1.1.1.1', '172.32.0.1', '100.128.0.1', '2606:4700:4700::1111', '::ffff:8.8.8.8'];
  const answering = (...addresses: string[]): DestinationPolicy => ({ allowPrivate: false, resolve: async () => addresses.map((address) => ({ address, family: address.includes(':') ? 6 : 4 })) });

  it('refuses loopback, private, link-local, cloud metadata, ULA and every other non-public address, as a literal or as a DNS answer (OPS-16)', async () => {
    for (const ip of BLOCKED) expect(isPublicAddress(ip), ip).toBe(false);
    for (const ip of PUBLIC) expect(isPublicAddress(ip), ip).toBe(true);
    expect(isPublicAddress('fe80::1%eth0')).toBe(false);
    expect(isPublicAddress('not-an-ip')).toBe(false);
    for (const ip of BLOCKED) {
      expect(() => checkWebhookUrl(`https://${ip.includes(':') ? `[${ip}]` : ip}/hook`, false), ip).toThrow(/not a public address/);
      await expect(resolveDestination(new URL('https://hooks.example.com/x'), answering(ip)), ip).rejects.toMatchObject({ kind: 'blocked' });
    }
    // The other spellings of 127.0.0.1 are normalised by the URL parser and refused the same.
    for (const url of ['https://2130706433/', 'https://0x7f.0.0.1/', 'https://127.1/', 'https://[::ffff:7f00:1]/']) expect(() => checkWebhookUrl(url, false), url).toThrow(/not a public address/);
    // One internal answer among public ones refuses it all; public answers pass, the first one is the address used.
    await expect(resolveDestination(new URL('https://hooks.example.com/x'), answering('93.184.216.34', '10.0.0.7'))).rejects.toMatchObject({ kind: 'blocked' });
    await expect(resolveDestination(new URL('https://hooks.example.com/x'), answering('93.184.216.34', '2606:4700:4700::1111'))).resolves.toEqual({ address: '93.184.216.34', family: 4 });
    await expect(resolveDestination(new URL('https://hooks.example.com/x'), answering())).rejects.toMatchObject({ kind: 'dns' });
    expect(checkWebhookUrl('https://8.8.8.8/hook', false).hostname).toBe('8.8.8.8');
  });

  it('refuses internal names, plain http, credentials and fragments; accepts a public https URL (OPS-16)', () => {
    const refused = (url: unknown, allowPrivate = false) => {
      try {
        checkWebhookUrl(url, allowPrivate);
        return 'accepted';
      } catch (e) {
        expect(e).toBeInstanceOf(DestinationError);
        return (e as Error).message;
      }
    };
    for (const url of ['https://localhost/x', 'https://api.localhost/x', 'https://metadata.google.internal/computeMetadata/v1/', 'https://printer.local/x', 'https://abcdefghijklmnop.onion/x', 'https://router.home.arpa/x', 'https://intranet/x', 'https://kubernetes/x']) {
      expect(refused(url), url).toMatch(/not a public host name/);
    }
    expect(refused('http://hooks.example.com/x')).toMatch(/must be https/);
    expect(refused('http://127.0.0.1:8080/x', true)).toBe('accepted');
    for (const allowPrivate of [false, true]) expect(refused('https://user:pass@hooks.example.com/x', allowPrivate)).toMatch(/credentials/);
    expect(refused('https://hooks.example.com/x#frag')).toMatch(/fragment/);
    expect(refused('https://hooks.example.com./x')).toMatch(/usable host/);
    expect(refused(`https://hooks.example.com/${'a'.repeat(2048)}`)).toMatch(/2048/);
    expect(refused('not a url')).toMatch(/valid URL/);
    expect(refused(42)).toMatch(/string/);
    expect(refused('javascript:alert(1)')).toMatch(/must be https/);
    expect(checkWebhookUrl('https://Hooks.Example.com:8443/in?token=abc', false).href).toBe('https://hooks.example.com:8443/in?token=abc');
    // The system resolver asks for the absolute name: no search domain turns it into an internal service.
    expect([absoluteName('hooks.example.com'), absoluteName('hooks.example.com.')]).toEqual(['hooks.example.com.', 'hooks.example.com.']);
  });

  describe('against a real server on 127.0.0.1', () => {
    let dest: Awaited<ReturnType<typeof destinations>>;
    beforeAll(async () => (dest = await destinations()));
    afterAll(() => dest.close());

    it('resolves once and connects to the checked address: a rebinding answer is never used (OPS-16)', async () => {
      // Only the test server's address counts as public here; the name answers something else from its second lookup.
      const lookups: string[] = [];
      const rebinding: DestinationPolicy = {
        allowPrivate: true,
        isAllowed: (ip) => ip === '127.0.0.1',
        resolve: async (host) => {
          lookups.push(host);
          return [{ address: lookups.length === 1 ? '127.0.0.1' : '127.0.0.2', family: 4 }];
        },
      };
      const before = dest.count('/ok');
      expect(await postWebhook({ url: `http://rebind.test:${dest.port}/ok`, body: '{}', headers: {} }, { policy: rebinding, timeoutMs: 2_000 })).toEqual({ ok: true, status: 204 });
      expect(lookups).toEqual(['rebind.test']);
      const hit = dest.hits.filter((h) => h.path === '/ok').at(-1)!;
      expect(hit.headers.host).toBe(`rebind.test:${dest.port}`);
      expect(dest.count('/ok')).toBe(before + 1);
      // Answered with the other address from the start, it is refused before any connection.
      const refusing: DestinationPolicy = { ...rebinding, resolve: async () => [{ address: '127.0.0.2', family: 4 }] };
      expect(await postWebhook({ url: `http://rebind.test:${dest.port}/ok`, body: '{}', headers: {} }, { policy: refusing, timeoutMs: 2_000 })).toEqual({ ok: false, error: 'blocked_destination' });
      expect(dest.count('/ok')).toBe(before + 1);
    });

    it('checks the destination again at delivery: a name that now resolves inside, an unusable URL or a body over the limit never connect (OPS-16)', async () => {
      const before = dest.hits.length;
      const post = (url: string, policy: DestinationPolicy, body = '{}') => postWebhook({ url, body, headers: {} }, { policy, timeoutMs: 2_000 });
      expect(await post('https://hooks.example.com/x', answering('10.0.0.1'))).toEqual({ ok: false, error: 'blocked_destination' });
      expect(await post(dest.url('/ok'), answering())).toEqual({ ok: false, error: 'invalid_destination' });
      expect(await post('https://hooks.example.com/x', { allowPrivate: false, resolve: async () => Promise.reject(new Error('ENOTFOUND')) })).toEqual({ ok: false, error: 'dns' });
      expect(await post('https://127.0.0.1/x', answering())).toEqual({ ok: false, error: 'blocked_destination' });
      expect(await post(dest.url('/ok'), { allowPrivate: true, resolve: answering().resolve }, 'x'.repeat(WEBHOOK_MAX_BODY_BYTES + 1))).toEqual({ ok: false, error: 'payload_too_large' });
      expect(await post(`http://127.0.0.1:1/x`, { allowPrivate: true, resolve: answering().resolve })).toEqual({ ok: false, error: 'connect' });
      expect(dest.hits.length).toBe(before);
    });
  });
});

const PG = process.env.TEST_DATABASE_URL;
if (PG) {
  // A schema of this file's own: the other suites reset the policy tables of the default one.
  const SCHEMA = 'ops16_webhooks';
  const url = `${PG}${PG.includes('?') ? '&' : '?'}options=${encodeURIComponent(`-c search_path=${SCHEMA}`)}`;
  let pool: Pool;
  const fresh = async () => {
    if (!pool) {
      const admin = createPgPool(PG);
      await admin.query(`CREATE SCHEMA IF NOT EXISTS ${SCHEMA}`);
      await admin.end();
      pool = createPgPool(url);
    }
    await resetScope(pool, 'policy-engine', POLICY_TABLES);
    await migrate(pool, MIGRATIONS, 'policy-engine');
    return new PgPolicyRepository(pool);
  };
  suite('webhooks (postgres)', fresh);

  describe('webhooks (postgres) with several replicas', () => {
    const policy: DestinationPolicy = { allowPrivate: true, resolve: async () => [] };
    const key = parseSigningKey(randomBytes(32).toString('hex'));
    afterAll(() => pool?.end());

    it('two replicas never claim the same delivery, and together claim them all (OPS-16)', async () => {
      const repo = await fresh();
      const engine = new PolicyEngine(repo, Date.now, WEBAUTHN, { issuer: ISSUER, key, webhooks: { secretsKey: randomBytes(32), policy, max: 5 } });
      await engine.createWebhook('admin', { url: 'http://127.0.0.1:9/hook', types: ['directory.upsert'] });
      const person = pubkey();
      for (let i = 0; i < 40; i++) await engine.putDirectoryEntry('admin', { pubkey: person, title: `turno ${i}` });
      const pool2 = createPgPool(url);
      try {
        const replica = new PgPolicyRepository(pool2);
        const now = Date.now() + 1_000;
        const claim = (r: PolicyRepository, leaseId: string) => r.claimDeliveries({ now, limit: 25, leaseMs: 60_000, leaseId, maxAttempts: 5 });
        const [a, b] = await Promise.all([claim(repo, 'lease-a'), claim(replica, 'lease-b')]);
        const ids = [...a, ...b].map((c) => c.id);
        expect(new Set(ids).size).toBe(ids.length);
        expect(ids.length).toBe(40);
        // Claimed: nobody else gets them until the lease expires.
        expect(await claim(repo, 'lease-c')).toEqual([]);
        expect((await claim(replica, 'lease-d')).length).toBe(0);
      } finally {
        await pool2.end();
      }
    });

    it('completions of one subscription at once neither deadlock nor disable it twice (OPS-16)', async () => {
      const repo = await fresh();
      const engine = new PolicyEngine(repo, Date.now, WEBAUTHN, { issuer: ISSUER, key, webhooks: { secretsKey: randomBytes(32), policy, max: 5 } });
      const { webhook } = await engine.createWebhook('admin', { url: 'http://127.0.0.1:9/hook', types: ['directory.upsert'] });
      const person = pubkey();
      for (let i = 0; i < 12; i++) await engine.putDirectoryEntry('admin', { pubkey: person, title: `turno ${i}` });
      const now = Date.now() + 1_000;
      const claimed = await repo.claimDeliveries({ now, limit: 50, leaseMs: 60_000, leaseId: 'lease', maxAttempts: 5 });
      expect(claimed).toHaveLength(12);
      const pools = Array.from({ length: 4 }, () => createPgPool(url));
      try {
        const replicas = pools.map((p) => new PgPolicyRepository(p));
        const results = await Promise.all(
          claimed.map((c, i) => replicas[i % replicas.length]!.completeDelivery({ id: c.id, leaseId: 'lease', now, ok: false, status: 500, error: 'http_5xx', retryAt: now + 30_000, disableAfter: 5 })),
        );
        expect(results.filter((r) => r.disabled)).toEqual([{ disabled: true, failures: 5 }]);
      } finally {
        await Promise.all(pools.map((p) => p.end()));
      }
      expect(await repo.getWebhook(webhook.id)).toMatchObject({ status: 'disabled', consecutiveFailures: 5 });
      const rows = await repo.listDeliveries(webhook.id, { limit: 50 });
      expect(rows.map((d) => [d.status, d.lastError])).toEqual(Array.from({ length: 12 }, () => ['failed', 'subscription_disabled']));
    });

    it('an audited action neither waits for a subscription being deleted nor fails when it goes (OPS-16)', async () => {
      const repo = await fresh();
      const engine = new PolicyEngine(repo, Date.now, WEBAUTHN, { issuer: ISSUER, key, webhooks: { secretsKey: randomBytes(32), policy, max: 5 } });
      const { webhook } = await engine.createWebhook('admin', { url: 'http://127.0.0.1:9/hook', types: ['directory.upsert'] });
      const deleting = await pool.connect();
      try {
        await deleting.query('BEGIN');
        await deleting.query('DELETE FROM policy_webhooks WHERE id = $1', [webhook.id]);
        // The deletion holds the subscription's row until it commits: the action goes ahead without it.
        await engine.putDirectoryEntry('admin', { pubkey: pubkey(), title: 'mientras se borra' });
        await deleting.query('COMMIT');
      } finally {
        deleting.release();
      }
      const events = (await engine.listEvents()).events;
      expect(events.at(-1)?.type).toBe('directory.upsert');
      expect((await pool.query('SELECT count(*)::int AS n FROM policy_webhook_deliveries')).rows[0].n).toBe(0);
    });

    it('concurrent creations cannot go past the limit, and the table holds a salt, never a secret (OPS-16)', async () => {
      const repo = await fresh();
      const engine = new PolicyEngine(repo, Date.now, WEBAUTHN, { issuer: ISSUER, key, webhooks: { secretsKey: randomBytes(32), policy, max: 3 } });
      const results = await Promise.allSettled(Array.from({ length: 6 }, () => engine.createWebhook('admin', { url: 'http://127.0.0.1:9/hook' })));
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(3);
      expect(results.filter((r) => r.status === 'rejected').every((r) => (r as PromiseRejectedResult).reason instanceof ConflictError)).toBe(true);
      const secrets = results.flatMap((r) => (r.status === 'fulfilled' ? [r.value.secret] : []));
      const { rows, fields } = await pool.query('SELECT * FROM policy_webhooks');
      expect(fields.map((f) => f.name)).not.toContain('secret');
      for (const s of secrets) expect(JSON.stringify(rows)).not.toContain(s);
    });
  });
}
