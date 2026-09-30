/**
 * OPS-16: signed events. Each audit entry is also emitted as an Ed25519-signed event with a stable envelope; a cursor
 * pages them without holes or repeats while writers race; the public keys are served to anyone, those of a rotated key
 * too; and an event never carries more than the audit entry it copies.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { createPgPool, migrate, nip98Fetch, resetScope, type Pool } from '@sedecim/service-kit';
import {
  canonicalJson,
  createPolicyApi,
  eventData,
  eventsConfigFromEnv,
  FORBIDDEN_EVENT_KEYS,
  MemoryPolicyRepository,
  parseSigningKey,
  PgPolicyRepository,
  PolicyEngine,
  POLICY_TABLES,
  signPolicyEvent,
  verifyPolicyEvent,
  type EventPublicJwk,
  type PolicyEvent,
  type PolicyRepository,
} from '../src/index';
import { TestAuthenticator } from './webauthn-fixture';

const MIGRATIONS = fileURLToPath(new URL('../migrations', import.meta.url));
const WEBAUTHN = { rpId: 'localhost', rpName: 'Test', origins: ['http://localhost:8080'] };
const ORIGIN = WEBAUTHN.origins[0]!;
const ISSUER = 'https://policy.example.org';
const seed = () => randomBytes(32).toString('hex');
const pubkey = () => getPublicKey(generateSecretKey());

describe('signed events: canonical form, keys, signature and verification (OPS-16)', () => {
  const key = parseSigningKey(seed());
  const unsigned = { id: 'e1', type: 'device.revoke', created_at: 1_700_000_000_000, seq: 7, issuer: ISSUER, data: { audit_id: 3, actor: 'a', target: 'd1', details: { reason: 'lost' } } };

  it('canonical JSON sorts members by code unit and writes numbers and strings as ECMAScript does (OPS-16)', () => {
    expect(canonicalJson({ b: 1, a: [true, null, 'x'], c: { z: 0, y: -0 } })).toBe('{"a":[true,null,"x"],"b":1,"c":{"y":0,"z":0}}');
    expect(canonicalJson({ n: [1e21, 0.1, 1.5e-7, 100] })).toBe('{"n":[1e+21,0.1,1.5e-7,100]}');
    // Code-unit order (RFC 8785): "é" (U+00E9) sorts after "z", an astral character after both; escapes as JSON.stringify.
    expect(canonicalJson({ z: 1, é: 2, '😀': 3, 'a\n"': 4 })).toBe('{"a\\n\\"":4,"z":1,"é":2,"😀":3}');
    expect(canonicalJson({ skip: undefined, keep: 1 })).toBe('{"keep":1}');
    expect(() => canonicalJson({ n: Number.NaN })).toThrow(/finite/);
    expect(() => canonicalJson({ n: 1n })).toThrow(/not JSON/);
  });

  it('reads the key from a PKCS#8 PEM or its hex seed, and refuses anything else without quoting it (OPS-16)', () => {
    const pair = generateKeyPairSync('ed25519');
    const pem = pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    const fromPem = parseSigningKey(pem);
    const hex = pair.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(16).toString('hex');
    expect(parseSigningKey(`${hex}\n`).kid).toBe(fromPem.kid);
    expect(fromPem.publicJwk).toEqual({ kty: 'OKP', crv: 'Ed25519', x: pair.publicKey.export({ format: 'jwk' }).x, kid: fromPem.kid, alg: 'EdDSA', use: 'sig' });
    const p256 = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    for (const bad of [p256, 'ab'.repeat(31), 'not a key', '']) {
      let message = '';
      try {
        parseSigningKey(bad);
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toMatch(/not an Ed25519 private key/);
      if (bad.length > 60) expect(message).not.toContain(bad.slice(30, 60));
    }
  });

  it('verifies an event of its issuer, and refuses a tampered one, an unknown kid and one of another organisation (OPS-16)', () => {
    const event = signPolicyEvent(unsigned, key);
    const jwks = { keys: [key.publicJwk] };
    expect(event.kid).toBe(key.kid);
    expect(verifyPolicyEvent(event, { issuer: ISSUER, keys: jwks })).toEqual({ ok: true, event });
    // Survives a JSON round trip and any member order: the signature is over the canonical form.
    const shuffled = JSON.parse(JSON.stringify({ sig: event.sig, data: event.data, kid: event.kid, seq: event.seq, type: event.type, issuer: event.issuer, id: event.id, created_at: event.created_at }));
    expect(verifyPolicyEvent(shuffled, { issuer: ISSUER, keys: jwks }).ok).toBe(true);
    // Tampered: the data, the position, the type, the key id it claims or the signature itself.
    const refused = (e: unknown, keys: readonly EventPublicJwk[] = jwks.keys) => {
      const r = verifyPolicyEvent(e, { issuer: ISSUER, keys });
      return r.ok ? 'ok' : r.reason;
    };
    expect(refused({ ...event, data: { ...event.data, details: { reason: 'stolen' } } })).toBe('signature');
    expect(refused({ ...event, seq: 8 })).toBe('signature');
    expect(refused({ ...event, type: 'device.register' })).toBe('signature');
    expect(refused({ ...event, sig: `${event.sig.slice(0, -4)}AAAA` })).toBe('signature');
    // A key the consumer does not know, or a known key relabelled with the event's kid.
    const other = parseSigningKey(seed());
    expect(refused(signPolicyEvent(unsigned, other))).toBe('unknown_kid');
    expect(refused(signPolicyEvent(unsigned, other), [{ ...key.publicJwk, kid: other.kid }])).toBe('unknown_kid');
    expect(refused({ ...event, kid: other.kid }, [key.publicJwk, other.publicJwk])).toBe('signature');
    // Another organisation's event: its own issuer, or relabelled with ours (the label is signed).
    const theirs = signPolicyEvent({ ...unsigned, issuer: 'https://policy.other.example' }, other);
    expect(refused(theirs, [key.publicJwk, other.publicJwk])).toBe('issuer');
    expect(refused({ ...theirs, issuer: ISSUER }, [key.publicJwk, other.publicJwk])).toBe('signature');
    expect(verifyPolicyEvent(event, { issuer: 'https://policy.other.example', keys: jwks })).toEqual({ ok: false, reason: 'issuer' });
    // Not an event at all.
    for (const junk of [null, 'x', [], { ...event, seq: 0 }, { ...event, data: undefined }, { ...event, sig: undefined }]) expect(refused(junk)).toBe('malformed');
  });

  it('an event copies its audit entry as stored, and drops forbidden names at any depth (OPS-16)', () => {
    const entry = { id: 4, at: 5, actor: 'admin', action: 'x', target: 't', details: { reason: 'ok', nested: [{ challenge: 'c', Token: 't', keep: 1 }], credentialId: 'id', n: Number.POSITIVE_INFINITY } };
    expect(eventData(entry)).toEqual({ audit_id: 4, actor: 'admin', target: 't', details: { reason: 'ok', nested: [{ keep: 1 }], n: null } });
    expect(eventData({ id: 1, at: 1, actor: 'a', action: 'x', target: 't' })).toEqual({ audit_id: 1, actor: 'a', target: 't' });
  });
});

describe('events configuration: off without a key, fail closed with a bad one (OPS-16)', () => {
  const files: Record<string, string> = {};
  const readFile = (path: string) => {
    if (!(path in files)) throw Object.assign(new Error(`ENOENT: ${path}`), { code: 'ENOENT' });
    return files[path]!;
  };
  const config = (env: Record<string, string>) => eventsConfigFromEnv(env, { readFile });

  it('is off without POLICY_EVENTS_SIGNING_KEY_FILE, and says so (OPS-16)', () => {
    const off = config({});
    expect(off.events).toBeUndefined();
    expect(off.warnings.join('\n')).toMatch(/signed events and webhooks are off/);
    expect(off.dispatch).toEqual({ maxAttempts: 10, disableAfter: 15, timeoutMs: 10_000, intervalMs: 2_000, deliveryRetentionDays: 30 });
    expect(() => config({ POLICY_WEBHOOK_SECRETS_KEY_FILE: '/run/secrets/w' })).toThrow(/needs POLICY_EVENTS_SIGNING_KEY_FILE/);
  });

  it('refuses to start with a key file it cannot read, an empty one, or one without an Ed25519 key, and never quotes it (OPS-16)', () => {
    files['/run/secrets/empty'] = '\n';
    const p256 = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    files['/run/secrets/p256'] = p256;
    expect(() => config({ POLICY_EVENTS_SIGNING_KEY_FILE: '/run/secrets/missing', PUBLIC_BASE_URL: ISSUER })).toThrow(/POLICY_EVENTS_SIGNING_KEY_FILE: cannot read \/run\/secrets\/missing \(ENOENT\)/);
    expect(() => config({ POLICY_EVENTS_SIGNING_KEY_FILE: '/run/secrets/empty', PUBLIC_BASE_URL: ISSUER })).toThrow(/is empty/);
    let message = '';
    try {
      config({ POLICY_EVENTS_SIGNING_KEY_FILE: '/run/secrets/p256', PUBLIC_BASE_URL: ISSUER });
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/^POLICY_EVENTS_SIGNING_KEY_FILE: not an Ed25519 private key/);
    expect(message).not.toContain(p256.split('\n')[1]!);
  });

  it('needs an issuer; webhooks need their own key, and POLICY_WEBHOOKS_ALLOW_PRIVATE is only true or false (OPS-16)', () => {
    const hex = seed();
    files['/run/secrets/events'] = hex;
    files['/run/secrets/webhooks'] = seed();
    files['/run/secrets/short'] = 'abcd';
    const base = { POLICY_EVENTS_SIGNING_KEY_FILE: '/run/secrets/events' };
    expect(() => config(base)).toThrow(/POLICY_EVENTS_ISSUER \(or PUBLIC_BASE_URL\) is required/);
    const on = config({ ...base, PUBLIC_BASE_URL: 'https://policy.example.org', POLICY_EVENTS_REVOKED_KIDS: 'k1, k2' });
    expect(on.events).toMatchObject({ issuer: 'https://policy.example.org', key: { kid: parseSigningKey(hex).kid }, revokedKids: ['k1', 'k2'] });
    expect(on.events?.webhooks).toBeUndefined();
    expect(on.warnings.join('\n')).toMatch(/webhooks are off/);
    expect(config({ ...base, PUBLIC_BASE_URL: 'x', POLICY_EVENTS_ISSUER: ISSUER }).events?.issuer).toBe(ISSUER);
    const hooks = config({ ...base, POLICY_EVENTS_ISSUER: ISSUER, POLICY_WEBHOOK_SECRETS_KEY_FILE: '/run/secrets/webhooks', POLICY_WEBHOOKS_MAX: '3' });
    expect(hooks.events?.webhooks).toMatchObject({ max: 3, policy: { allowPrivate: false } });
    expect(hooks.events?.webhooks?.secretsKey).toHaveLength(32);
    expect(() => config({ ...base, POLICY_EVENTS_ISSUER: ISSUER, POLICY_WEBHOOK_SECRETS_KEY_FILE: '/run/secrets/short' })).toThrow(/POLICY_WEBHOOK_SECRETS_KEY_FILE: the webhook secrets key must be 32 bytes in hex/);
    expect(() => config({ ...base, POLICY_EVENTS_ISSUER: ISSUER, POLICY_WEBHOOKS_ALLOW_PRIVATE: 'yes' })).toThrow(/true or false/);
    const open = config({ ...base, POLICY_EVENTS_ISSUER: ISSUER, POLICY_WEBHOOK_SECRETS_KEY_FILE: '/run/secrets/webhooks', POLICY_WEBHOOKS_ALLOW_PRIVATE: 'true' });
    expect(open.events?.webhooks?.policy.allowPrivate).toBe(true);
    expect(open.warnings.join('\n')).toMatch(/tests and development only/);
    expect(() => config({ POLICY_WEBHOOK_TIMEOUT_MS: '0' })).toThrow(/POLICY_WEBHOOK_TIMEOUT_MS must be a positive whole number/);
  });
});

describe('events off (OPS-16)', () => {
  const adminSk = generateSecretKey();
  const engine = new PolicyEngine(new MemoryPolicyRepository(), Date.now, WEBAUTHN);
  const api = createPolicyApi(engine, { name: 'policy-events-off', adminPubkeys: [getPublicKey(adminSk)] });
  let base: string;
  beforeAll(async () => (base = await api.listen()));
  afterAll(() => api.close());

  it('emits nothing, and its routes answer 404 (OPS-16)', async () => {
    await engine.registerDevice('admin', pubkey());
    expect(await engine.repo.listEvents({ after: 0, limit: 10 })).toEqual([]);
    expect((await engine.listAudit()).length).toBe(1);
    expect((await fetch(`${base}/v1/events/keys`)).status).toBe(404);
    for (const path of ['/v1/events', '/v1/webhooks']) {
      const r = await nip98Fetch(adminSk, `${base}${path}`);
      expect([r.status, r.json.error]).toEqual([404, expect.stringMatching(/disabled on this policy-engine/)]);
    }
  });
});

/** Same behaviour on both repositories. */
function suite(name: string, makeRepo: () => Promise<PolicyRepository>) {
  describe(name, () => {
    const adminSk = generateSecretKey();
    const admin = getPublicKey(adminSk);
    const key = parseSigningKey(seed());
    let repo: PolicyRepository;
    let engine: PolicyEngine;
    let api: ReturnType<typeof createPolicyApi>;
    let base: string;
    const asAdmin = (path: string, method = 'GET', body?: unknown) => nip98Fetch(adminSk, `${base}${path}`, method, body);
    const withToken = (token: string, path: string) => fetch(`${base}${path}`, { headers: { authorization: `Bearer ${token}` } });
    const allEvents = async (e = engine) => (await e.listEvents({ limit: 1000 })).events;

    beforeAll(async () => {
      repo = await makeRepo();
      engine = new PolicyEngine(repo, Date.now, WEBAUTHN, { issuer: ISSUER, key });
      await engine.initEvents();
      api = createPolicyApi(engine, {
        name: 'policy-events',
        adminPubkeys: [admin],
        bearerTokens: { 'siem-token-1234': 'siem', 'indexer-token-1234': 'indexer' },
        serviceScopes: { siem: ['events'], indexer: ['evaluate', 'retention'] },
      });
      base = await api.listen();
    });
    afterAll(() => api.close());

    it('every audit entry becomes one signed event, in order, whose data is the entry as stored (OPS-16)', async () => {
      const owner = pubkey();
      await engine.upsertSubject(admin, { pubkey: owner, roles: ['analyst'], attributes: { unit: 'legal' } });
      const device = await engine.registerDevice(admin, owner);
      await engine.revokeDevice(admin, device.id, 'lost phone');
      const audit = (await engine.listAudit({ limit: 1000 })).reverse();
      const events = await allEvents();
      expect(events.map((e) => e.type)).toEqual(audit.map((a) => a.action));
      expect(events.map((e) => e.type)).toEqual(['subject.upsert', 'device.register', 'device.revoke']);
      const seqs = events.map((e) => e.seq);
      expect(seqs).toEqual([...seqs].sort((a, b) => a - b));
      expect(new Set(events.map((e) => e.id)).size).toBe(events.length);
      events.forEach((e, i) => {
        const a = audit[i]!;
        expect(e).toEqual({ id: expect.any(String), type: a.action, created_at: a.at, seq: seqs[i], issuer: ISSUER, data: { audit_id: a.id, actor: a.actor, target: a.target, ...(a.details ? { details: a.details } : {}) }, kid: key.kid, sig: expect.any(String) });
        expect(verifyPolicyEvent(e, { issuer: ISSUER, keys: [key.publicJwk] }).ok).toBe(true);
      });
      // What is stored is the envelope as signed.
      const stored = await repo.listEvents({ after: 0, limit: 1000 });
      expect(stored.map((s) => s.envelope)).toEqual(events.map((e) => canonicalJson(e)));
    });

    it('serves the events from a cursor, oldest first, to an admin or a token with the events scope (OPS-16)', async () => {
      for (let i = 0; i < 5; i++) await engine.putDirectoryEntry(admin, { pubkey: pubkey(), title: `puesto ${i}` });
      const all = await allEvents();
      const pages: PolicyEvent[] = [];
      let after = 0;
      for (;;) {
        const r = await asAdmin(`/v1/events?after=${after}&limit=3`);
        expect(r.status).toBe(200);
        pages.push(...r.json.events);
        if (!r.json.events.length) {
          expect(r.json.next).toBe(after);
          break;
        }
        expect(r.json.next).toBe(r.json.events.at(-1).seq);
        after = r.json.next;
      }
      expect(pages).toEqual(all);
      // An integration reads it with its own token, which reaches nothing else.
      const siem = await withToken('siem-token-1234', `/v1/events?after=${all[1]!.seq}&limit=2`);
      expect(siem.status).toBe(200);
      expect(((await siem.json()) as { events: PolicyEvent[] }).events).toEqual(all.slice(2, 4));
      expect((await withToken('siem-token-1234', '/v1/audit')).status).toBe(401);
      expect((await withToken('siem-token-1234', '/v1/rotations')).status).toBe(403);
      expect((await withToken('indexer-token-1234', '/v1/events')).status).toBe(403);
      expect((await withToken('wrong-token-0000', '/v1/events')).status).toBe(401);
      expect((await nip98Fetch(generateSecretKey(), `${base}/v1/events`)).status).toBe(403);
      expect((await asAdmin('/v1/events?after=-1')).status).toBe(400);
      expect((await asAdmin('/v1/events?limit=0')).status).toBe(400);
    });

    it('publishes the public keys without authentication; a rotated key keeps verifying its events, a revoked one does not (OPS-16)', async () => {
      const res = await fetch(`${base}/v1/events/keys`);
      expect(res.status).toBe(200);
      const jwks = (await res.json()) as { issuer: string; current: string; keys: EventPublicJwk[] };
      expect(jwks).toEqual({ issuer: ISSUER, current: key.kid, keys: [key.publicJwk] });
      // Rotation: a restart with a new key. The old public key stays served, so both generations verify.
      const next = parseSigningKey(seed());
      const rotated = new PolicyEngine(repo, Date.now, WEBAUTHN, { issuer: ISSUER, key: next });
      await rotated.initEvents();
      await rotated.putDirectoryEntry(admin, { pubkey: pubkey(), unit: 'tras la rotación' });
      const keys = await rotated.eventKeys();
      expect(keys.current).toBe(next.kid);
      expect(keys.keys.map((k) => k.kid).sort()).toEqual([key.kid, next.kid].sort());
      const events = await allEvents(rotated);
      expect(new Set(events.map((e) => e.kid))).toEqual(new Set([key.kid, next.kid]));
      for (const e of events) expect(verifyPolicyEvent(e, { issuer: ISSUER, keys })).toMatchObject({ ok: true });
      // A compromised key is withdrawn: its events stop verifying, the others do not.
      const withdrawn = new PolicyEngine(repo, Date.now, WEBAUTHN, { issuer: ISSUER, key: next, revokedKids: [key.kid] });
      const served = await withdrawn.eventKeys();
      expect(served.keys.map((k) => k.kid)).toEqual([next.kid]);
      for (const e of events) expect(verifyPolicyEvent(e, { issuer: ISSUER, keys: served })).toEqual(e.kid === key.kid ? { ok: false, reason: 'unknown_kid' } : { ok: true, event: e });
      expect(() => new PolicyEngine(repo, Date.now, WEBAUTHN, { issuer: ISSUER, key: next, revokedKids: [next.kid] })).toThrow(/revoked/);
    });

    it('never carries WebAuthn material, credentials, tokens, access decisions or session openings: never more than the audit (OPS-16)', async () => {
      const ownerSk = generateSecretKey();
      const owner = getPublicKey(ownerSk);
      const before = (await allEvents()).length;
      const auditBefore = (await engine.listAudit({ limit: 1000 })).length;
      await engine.upsertSubject(admin, { pubkey: owner, roles: ['analyst'], attributes: {} });
      await engine.upsertResource(admin, { id: 'sala-ops16', kind: 'group', sensitivity: 'internal', members: [owner], rules: [{ actions: ['read'], anyRole: ['analyst'] }] });
      await engine.upsertResource(admin, { id: 'canal-ops16', kind: 'channel', sensitivity: 'internal', rules: [] });
      const device = await engine.registerDevice(admin, owner);
      // A passkey registered, a session opened with it (not audited), two assertions refused (audited, without material).
      const auth = new TestAuthenticator();
      const creation = await engine.webauthnOptions(device.id);
      await engine.webauthnRegister(owner, device.id, auth.create({ challenge: creation.challenge, origin: ORIGIN, rpId: 'localhost' }));
      const first = await engine.webauthnAssertionOptions(owner, device.id);
      const assertion = auth.get({ challenge: first.challenge, origin: ORIGIN, rpId: 'localhost', counter: 1, userHandle: Buffer.from(owner, 'hex') });
      const token = await engine.openSession(owner, device.id, assertion);
      await expect(engine.openSession(owner, device.id, assertion)).rejects.toThrow();
      const second = await engine.webauthnAssertionOptions(owner, device.id);
      const tampered = auth.get({ challenge: second.challenge, origin: ORIGIN, rpId: 'localhost', counter: 2, tamperSig: true });
      await expect(engine.openSession(owner, device.id, tampered)).rejects.toThrow();
      // An access decision goes to the access log, never to the audit nor to an event.
      await engine.evaluate({ pubkey: owner, deviceId: device.id, resourceId: 'sala-ops16', action: 'read' });
      await engine.revokeDevice(admin, device.id, 'robado');
      for (const r of await engine.listRotations('pending')) await engine.markRotationDone('rotation-worker', r.id);
      await engine.putDirectoryEntry(admin, { pubkey: owner, title: 'Analista' });
      await engine.deleteDirectoryEntry(admin, owner);
      await engine.putRetention(admin, { resourceId: 'canal-ops16', days: 30, legalHold: true });
      await engine.revokeSubject(admin, owner);
      await engine.reactivateSubject(admin, owner);

      const audit = (await engine.listAudit({ limit: 1000 })).slice(0, -auditBefore || undefined).reverse();
      const events = (await allEvents()).slice(before);
      expect(events.length).toBe(audit.length);
      expect(new Set(events.map((e) => e.type))).toEqual(
        new Set(['subject.upsert', 'resource.upsert', 'device.register', 'device.attest', 'session.assert', 'device.revoke', 'rotation.done', 'directory.upsert', 'directory.delete', 'retention.set', 'subject.revoke', 'subject.reactivate']),
      );
      // Each event is its audit entry, field for field.
      events.forEach((e, i) => expect([e.type, e.created_at, e.data]).toEqual([audit[i]!.action, audit[i]!.at, { audit_id: audit[i]!.id, actor: audit[i]!.actor, target: audit[i]!.target, ...(audit[i]!.details ? { details: audit[i]!.details } : {}) }]));
      // Only the two refused assertions: opening a session leaves no trace, and neither do access decisions.
      expect(events.filter((e) => e.type === 'session.assert').map((e) => e.data.details?.ok)).toEqual([false, false]);
      expect(events.some((e) => /evaluate|session\.open|access/.test(e.type))).toBe(false);
      const text = JSON.stringify(events);
      for (const secret of [creation.challenge, first.challenge, second.challenge, auth.id, assertion.response.signature, assertion.response.clientDataJSON, token]) expect(text).not.toContain(secret);
      const names = new Set<string>();
      const walk = (v: unknown): void => {
        if (Array.isArray(v)) v.forEach(walk);
        else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) (names.add(k.toLowerCase()), walk(x));
      };
      walk(events.map((e) => e.data));
      for (const forbidden of FORBIDDEN_EVENT_KEYS) expect(names.has(forbidden.toLowerCase()), forbidden).toBe(false);
    });
  });
}

suite('events (memory)', async () => new MemoryPolicyRepository());

const PG = process.env.TEST_DATABASE_URL;
if (PG) {
  let pool: Pool;
  const fresh = async () => {
    pool ??= createPgPool(PG);
    await resetScope(pool, 'policy-engine', POLICY_TABLES);
    await migrate(pool, MIGRATIONS, 'policy-engine');
    return new PgPolicyRepository(pool);
  };
  suite('events (postgres)', fresh);

  /** A pool whose clients pause at random before each statement: a writer's seq and its commit drift apart. */
  const jittery = (target: Pool): Pool =>
    new Proxy(target, {
      get(t, prop) {
        if (prop === 'connect') {
          return async () => {
            const client = await t.connect();
            return {
              query: async (...args: unknown[]) => {
                await new Promise((r) => setTimeout(r, Math.floor(Math.random() * 3)));
                return (client.query as (...a: unknown[]) => unknown).apply(client, args);
              },
              release: (e?: Error | boolean) => client.release(e),
            };
          };
        }
        const v = Reflect.get(t, prop);
        return typeof v === 'function' ? v.bind(t) : v;
      },
    }) as Pool;

  describe('events (postgres) under concurrency', () => {
    afterAll(() => pool?.end());

    it('pages the stream without holes or repeats while writers race, as each write commits (OPS-16)', async () => {
      const reader = await fresh();
      const key = parseSigningKey(seed());
      const writers = Array.from({ length: 6 }, () => jittery(createPgPool(PG)));
      const person = pubkey();
      try {
        let done = false;
        const seen: number[] = [];
        const read = async () => {
          let cursor = 0;
          for (;;) {
            const page = await reader.listEvents({ after: cursor, limit: 7 });
            for (const e of page) seen.push(e.seq);
            if (page.length) cursor = page.at(-1)!.seq;
            else if (done) return;
            else await new Promise((r) => setImmediate(r));
          }
        };
        const reading = read();
        await Promise.all(
          writers.map(async (p, w) => {
            const engine = new PolicyEngine(new PgPolicyRepository(p), Date.now, WEBAUTHN, { issuer: ISSUER, key });
            for (let i = 0; i < 30; i++) await engine.putDirectoryEntry('admin', { pubkey: person, title: `w${w}-${i}` });
          }),
        );
        done = true;
        await reading;
        const all = (await pool.query('SELECT seq FROM policy_events ORDER BY seq')).rows.map((r) => Number(r.seq));
        expect(all).toHaveLength(6 * 30);
        // Every event once, in order: the reader never jumped past one that committed later.
        expect(seen).toEqual(all);
      } finally {
        await Promise.all(writers.map((p) => p.end()));
      }
    }, 60_000);

    it('the events are append-only and keep verifying after the key changes (OPS-16)', async () => {
      const repo = await fresh();
      const [a, b] = [parseSigningKey(seed()), parseSigningKey(seed())];
      const first = new PolicyEngine(repo, Date.now, WEBAUTHN, { issuer: ISSUER, key: a });
      await first.initEvents();
      await first.registerDevice('admin', pubkey());
      // "Restart" with a rotated key: a new pool, repository and engine.
      const pool2 = createPgPool(PG);
      try {
        const second = new PolicyEngine(new PgPolicyRepository(pool2), Date.now, WEBAUTHN, { issuer: ISSUER, key: b });
        await second.initEvents();
        await second.registerDevice('admin', pubkey());
        const keys = await second.eventKeys();
        const events = (await second.listEvents()).events;
        expect(events.map((e) => e.kid)).toEqual([a.kid, b.kid]);
        for (const e of events) expect(verifyPolicyEvent(e, { issuer: ISSUER, keys }).ok).toBe(true);
      } finally {
        await pool2.end();
      }
      await expect(pool.query("UPDATE policy_events SET type = 'x'")).rejects.toThrow(/append-only/);
      await expect(pool.query('DELETE FROM policy_events')).rejects.toThrow(/append-only/);
      await expect(pool.query('TRUNCATE policy_events')).rejects.toThrow(/append-only|foreign key/);
      expect((await repo.listEvents({ after: 0, limit: 10 })).length).toBe(2);
    });
  });
}
