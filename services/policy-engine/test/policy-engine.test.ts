import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { createPgPool, migrate, nip98Fetch, resetScope, type Pool } from '@sedecim/service-kit';
import {
  ASSERTION_REJECTED,
  createPolicyApi,
  GROUP_RETENTION_REFUSED,
  MemoryPolicyRepository,
  PgPolicyRepository,
  PolicyEngine,
  POLICY_TABLES,
  RETENTION_NOTICE,
  type PolicyRepository,
  type WebAuthnConfig,
} from '../src/index';
import { TestAuthenticator, type AssertionInput } from './webauthn-fixture';

const MIGRATIONS = fileURLToPath(new URL('../migrations', import.meta.url));
const WEBAUTHN = { rpId: 'localhost', rpName: 'Test', origins: ['http://localhost:8080'] };

/** Same behaviour on both repositories (FR023-03). */
function suite(name: string, makeRepo: () => Promise<PolicyRepository>) {
  describe(name, () => {
    const adminSk = generateSecretKey();
    const aliceSk = generateSecretKey();
    const alice = getPublicKey(aliceSk);
    const bob = getPublicKey(generateSecretKey());
    let engine: PolicyEngine;
    let api: ReturnType<typeof createPolicyApi>;
    let base: string;
    /** Moves the engine's clock (NIP-98 keeps the real one). */
    let skew = 0;
    const bearerFetch = (path: string, init: RequestInit = {}) => fetch(`${base}${path}`, { ...init, headers: { authorization: 'Bearer relay-token-1234' } });
    const evaluate = (body: unknown) => bearerFetch('/v1/evaluate', { method: 'POST', body: JSON.stringify(body) }).then((r) => r.json());
    const asAdmin = (path: string, method = 'GET', body?: unknown) => nip98Fetch(adminSk, `${base}${path}`, method, body);

    beforeAll(async () => {
      engine = new PolicyEngine(await makeRepo(), () => Date.now() + skew, WEBAUTHN);
      // One service principal with every scope, so each route can be exercised with it (scopes themselves: below).
      api = createPolicyApi(engine, {
        name: 'policy-test',
        adminPubkeys: [getPublicKey(adminSk)],
        bearerTokens: { 'relay-token-1234': 'relay' },
        serviceScopes: { relay: ['evaluate', 'retention', 'relay', 'rotations'] },
      });
      base = await api.listen();
    });
    afterAll(() => api.close());

    it('enforces RBAC/ABAC for protected resources', async () => {
      expect((await nip98Fetch(aliceSk, `${base}/v1/subjects/${alice}`, 'PUT', { roles: ['admin'] })).status).toBe(403);
      await asAdmin(`/v1/subjects/${alice}`, 'PUT', { roles: ['analyst'], attributes: { department: 'legal', clearance: 'confidential' } });
      await asAdmin(`/v1/subjects/${bob}`, 'PUT', { roles: ['guest'], attributes: {} });
      await asAdmin('/v1/resources/legal-room', 'PUT', {
        kind: 'group',
        sensitivity: 'confidential',
        members: [alice, bob],
        rules: [{ actions: ['read', 'publish'], anyRole: ['analyst'], attributes: { department: 'legal' } }],
      });
      const dev = (await asAdmin('/v1/devices', 'POST', { owner: alice })).json;
      expect((await evaluate({ pubkey: alice, deviceId: dev.id, resourceId: 'legal-room', action: 'publish' })).allow).toBe(true);
      expect((await evaluate({ pubkey: bob, resourceId: 'legal-room', action: 'read' })).allow).toBe(false);
      expect((await bearerFetch('/v1/relay/allowlist').then((r) => r.json())).pubkeys).toEqual([alice]);
    });

    it('lists subjects, resources and devices for admins only', async () => {
      expect((await nip98Fetch(aliceSk, `${base}/v1/subjects`)).status).toBe(403);
      expect((await asAdmin('/v1/subjects')).json.subjects.map((s: { pubkey: string }) => s.pubkey).sort()).toEqual([alice, bob].sort());
      expect((await asAdmin('/v1/resources')).json.resources).toEqual([expect.objectContaining({ id: 'legal-room', kind: 'group', members: [alice, bob] })]);
      const devices = (await asAdmin(`/v1/devices?owner=${alice}`)).json.devices;
      expect(devices).toHaveLength(1);
      expect(devices[0]).toMatchObject({ ownerPubkey: alice, trust: 'registered' });
      expect((await asAdmin(`/v1/devices?owner=${bob}`)).json.devices).toEqual([]);
      expect((await asAdmin('/v1/devices', 'POST', { owner: bob, trust: 'attested' })).status).toBe(400);
    });

    it('revoking a device blocks sessions, access and triggers group rotation', async () => {
      const dev = (await asAdmin('/v1/devices', 'POST', { owner: alice })).json;
      const session = await nip98Fetch(aliceSk, `${base}/v1/sessions`, 'POST', { device_id: dev.id });
      expect(session.status).toBe(201);
      expect(await engine.sessionValid(session.json.token)).toBe(true);
      const rev = await asAdmin(`/v1/devices/${dev.id}/revoke`, 'POST', { reason: 'lost phone' });
      expect(rev.json.rotations).toEqual([expect.objectContaining({ resourceId: 'legal-room', removedPubkey: alice, status: 'pending', id: expect.any(String) })]);
      expect(await engine.sessionValid(session.json.token)).toBe(false);
      expect((await nip98Fetch(aliceSk, `${base}/v1/sessions`, 'POST', { device_id: dev.id })).status).toBe(403);
      expect((await evaluate({ pubkey: alice, deviceId: dev.id, resourceId: 'legal-room', action: 'read' })).reasons).toEqual(['device revoked']);
      expect((await asAdmin('/v1/devices/nope/revoke', 'POST', {})).status).toBe(404);
      const audit = (await asAdmin('/v1/audit')).json.audit;
      expect(audit.some((a: { action: string }) => a.action === 'device.revoke')).toBe(true);
      expect(JSON.stringify(audit)).not.toMatch(/content|plaintext/);
    });

    it('rotations have ids, services read them, and an admin or a service marks them done', async () => {
      const pending = (await asAdmin('/v1/rotations?status=pending')).json.rotations;
      // FR024-05: the rotation worker reads them with its service token; a non-admin key cannot.
      expect((await bearerFetch('/v1/rotations?status=pending').then((r) => r.json())).rotations).toEqual(pending);
      expect((await nip98Fetch(aliceSk, `${base}/v1/rotations?status=pending`)).status).toBe(403);
      expect((await fetch(`${base}/v1/rotations?status=pending`, { headers: { authorization: 'Bearer wrong-token-0000' } })).status).toBe(401);
      expect(pending).toHaveLength(1);
      expect((await fetch(`${base}/v1/rotations/${pending[0].id}/done`, { method: 'POST', headers: { authorization: 'Bearer wrong-token-0000' } })).status).toBe(401);
      expect((await nip98Fetch(aliceSk, `${base}/v1/rotations/${pending[0].id}/done`, 'POST', {})).status).toBe(403);
      const done = await bearerFetch(`/v1/rotations/${pending[0].id}/done`, { method: 'POST' });
      expect(done.status).toBe(200);
      expect(await done.json()).toMatchObject({ id: pending[0].id, status: 'done', doneAt: expect.any(Number) });
      expect((await asAdmin('/v1/rotations?status=pending')).json.rotations).toEqual([]);
      expect((await asAdmin('/v1/rotations?status=done')).json.rotations).toHaveLength(1);
      expect((await asAdmin('/v1/rotations')).json.rotations).toHaveLength(1);
      expect((await asAdmin('/v1/rotations/nope/done', 'POST', {})).status).toBe(404);
      expect((await asAdmin('/v1/rotations?status=bogus')).status).toBe(400);
    });

    it('pages the audit newest first', async () => {
      const all = (await asAdmin('/v1/audit?limit=1000')).json.audit as Array<{ id: number; action: string }>;
      expect(all.length).toBeGreaterThan(5);
      expect(all.map((a) => a.id)).toEqual([...all.map((a) => a.id)].sort((x, y) => y - x));
      const page1 = (await asAdmin('/v1/audit?limit=3')).json.audit as Array<{ id: number }>;
      const page2 = (await asAdmin(`/v1/audit?limit=3&before=${page1.at(-1)!.id}`)).json.audit as Array<{ id: number }>;
      expect([...page1, ...page2]).toEqual(all.slice(0, 6));
      expect(all.at(-1)!.action).toBe('subject.upsert');
      expect((await asAdmin('/v1/audit?limit=0')).status).toBe(400);
    });

    it('keeps an admin-only organisational directory (FR023-06)', async () => {
      expect((await nip98Fetch(aliceSk, `${base}/v1/directory`)).status).toBe(403);
      expect((await bearerFetch('/v1/directory')).status).toBe(401);
      expect((await asAdmin(`/v1/directory/${alice}`, 'PUT', { title: 'Jefa de área', unit: 'Legal' })).json).toEqual({ pubkey: alice, title: 'Jefa de área', unit: 'Legal' });
      await asAdmin(`/v1/directory/${bob}`, 'PUT', { unit: 'Invitados' });
      expect((await asAdmin(`/v1/directory/${bob}`, 'PUT', { title: 'x'.repeat(201) })).status).toBe(400);
      expect((await asAdmin('/v1/directory/not-a-key', 'PUT', {})).status).toBe(400);
      expect((await asAdmin('/v1/directory')).json.entries).toEqual(
        [{ pubkey: alice, title: 'Jefa de área', unit: 'Legal' }, { pubkey: bob, unit: 'Invitados' }].sort((a, b) => (a.pubkey < b.pubkey ? -1 : 1)),
      );
      expect((await asAdmin(`/v1/directory/${bob}`, 'DELETE')).status).toBe(200);
      expect((await asAdmin(`/v1/directory/${bob}`, 'DELETE')).status).toBe(404);
      expect((await asAdmin('/v1/directory')).json.entries).toEqual([{ pubkey: alice, title: 'Jefa de área', unit: 'Legal' }]);
    });

    it('stores retention policies with legal hold and the replication notice (FR023-08)', async () => {
      await asAdmin('/v1/resources/general', 'PUT', { kind: 'channel', sensitivity: 'internal', rules: [] });
      expect((await nip98Fetch(aliceSk, `${base}/v1/retention/general`, 'PUT', { days: 30, legalHold: false })).status).toBe(403);
      expect((await asAdmin('/v1/retention/general', 'PUT', { days: 0, legalHold: false })).status).toBe(400);
      expect((await asAdmin('/v1/retention/general', 'PUT', { days: 30 })).status).toBe(400);
      expect((await asAdmin('/v1/retention/unknown', 'PUT', { days: 30, legalHold: false })).status).toBe(404);
      expect((await asAdmin('/v1/retention/general', 'PUT', { days: 30, legalHold: false })).status).toBe(200);
      // FR023-12: an MLS group has no mirror copy for a retention or a legal hold to act on.
      const refused = await asAdmin('/v1/retention/legal-room', 'PUT', { days: null, legalHold: true });
      expect([refused.status, refused.json.error]).toEqual([409, GROUP_RETENTION_REFUSED]);
      await asAdmin('/v1/resources/legal-channel', 'PUT', { kind: 'channel', sensitivity: 'confidential', rules: [] });
      expect((await asAdmin('/v1/retention/legal-channel', 'PUT', { days: null, legalHold: true })).status).toBe(200);
      const expected = { policies: [{ resourceId: 'general', days: 30, legalHold: false }, { resourceId: 'legal-channel', days: null, legalHold: true }], notice: RETENTION_NOTICE };
      expect((await asAdmin('/v1/retention')).json).toEqual(expected);
      // The indexer's retention job reads them with its service token.
      expect(await (await bearerFetch('/v1/retention')).json()).toEqual(expected);
      expect(RETENTION_NOTICE).toMatch(/otros relays/);
    });

    it('logs access decisions apart from the audit, and prunes them after their retention unless held (FR023-12)', async () => {
      await asAdmin('/v1/resources/pruned-channel', 'PUT', { kind: 'channel', sensitivity: 'internal', rules: [{ actions: ['read'], anyRole: ['analyst'] }] });
      await evaluate({ pubkey: alice, resourceId: 'pruned-channel', action: 'read' });
      await evaluate({ pubkey: bob, resourceId: 'legal-channel', action: 'publish' });
      expect((await nip98Fetch(aliceSk, `${base}/v1/access-log`)).status).toBe(403);
      const access = (await asAdmin('/v1/access-log?limit=2')).json.access as Array<{ id: number; pubkey: string; resourceId: string; action: string; allow: boolean }>;
      expect(access.map((a) => [a.pubkey, a.resourceId, a.action, a.allow])).toEqual([
        [bob, 'legal-channel', 'publish', false],
        [alice, 'pruned-channel', 'read', true],
      ]);
      expect(access[0]!.id).toBeGreaterThan(access[1]!.id);
      expect(((await asAdmin('/v1/access-log?resource=pruned-channel')).json.access as unknown[]).length).toBe(1);
      // The audit records what admins do; decisions are no longer there.
      expect(((await asAdmin('/v1/audit?limit=1000')).json.audit as Array<{ action: string }>).some((a) => a.action === 'policy.evaluate')).toBe(false);
      await new Promise((r) => setTimeout(r, 5));
      // Everything is past a zero-day retention but the decisions on legal-channel, under legal hold.
      expect(await engine.pruneAccessLog(0)).toBeGreaterThan(0);
      expect(((await asAdmin('/v1/access-log?limit=1000')).json.access as Array<{ resourceId: string }>).map((a) => a.resourceId)).toEqual(['legal-channel']);
    });

    it('a policy left on a group applies to nothing, and a workspace hold keeps the whole access log (FR023-12)', async () => {
      const logged = async () => ((await asAdmin('/v1/access-log?limit=1000')).json.access as Array<{ resourceId: string }>).map((a) => a.resourceId);
      // A channel on hold that becomes an MLS group: its policy stays stored, and applies to nothing.
      await asAdmin('/v1/resources/was-channel', 'PUT', { kind: 'channel', sensitivity: 'internal', rules: [] });
      expect((await asAdmin('/v1/retention/was-channel', 'PUT', { days: null, legalHold: true })).status).toBe(200);
      await asAdmin('/v1/resources/was-channel', 'PUT', { kind: 'group', sensitivity: 'internal', rules: [] });
      expect(((await asAdmin('/v1/retention')).json.policies as Array<{ resourceId: string }>).map((p) => p.resourceId)).toEqual(['general', 'legal-channel']);
      await evaluate({ pubkey: alice, resourceId: 'was-channel', action: 'read' });
      // A workspace hold covers its channels, which the engine cannot tell apart: nothing is pruned while it lasts.
      await asAdmin('/v1/resources/acme', 'PUT', { kind: 'workspace', sensitivity: 'internal', rules: [] });
      expect((await asAdmin('/v1/retention/acme', 'PUT', { days: null, legalHold: true })).status).toBe(200);
      await evaluate({ pubkey: alice, resourceId: 'pruned-channel', action: 'read' });
      await new Promise((r) => setTimeout(r, 5));
      expect(await engine.pruneAccessLog(0)).toBe(0);
      expect(await logged()).toEqual(['pruned-channel', 'was-channel', 'legal-channel']);
      // Lifted: the decisions on the group go as well.
      expect((await asAdmin('/v1/retention/acme', 'PUT', { days: null, legalHold: false })).status).toBe(200);
      expect(await engine.pruneAccessLog(0)).toBe(2);
      expect(await logged()).toEqual(['legal-channel']);
    });

    it('attests a device through WebAuthn registration (FR023-07)', async () => {
      const dev = (await asAdmin('/v1/devices', 'POST', { owner: alice })).json;
      const auth = new TestAuthenticator();
      // Only the owner or an admin: to anyone else the device does not exist.
      expect((await nip98Fetch(generateSecretKey(), `${base}/v1/devices/${dev.id}/webauthn/options`, 'POST', {})).status).toBe(404);
      const opts = (await nip98Fetch(aliceSk, `${base}/v1/devices/${dev.id}/webauthn/options`, 'POST', {})).json;
      expect(opts).toMatchObject({ rp: { id: 'localhost' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], attestation: 'direct' });
      expect(Buffer.from(opts.user.id, 'base64url').toString('hex')).toBe(alice);
      // Wrong origin: rejected and the challenge is consumed.
      const bad = await nip98Fetch(aliceSk, `${base}/v1/devices/${dev.id}/webauthn/register`, 'POST', auth.create({ challenge: opts.challenge, origin: 'https://evil.example', rpId: 'localhost' }));
      expect(bad.status).toBe(400);
      expect(bad.json.error).toMatch(/origin/);
      const replay = await nip98Fetch(aliceSk, `${base}/v1/devices/${dev.id}/webauthn/register`, 'POST', auth.create({ challenge: opts.challenge, origin: 'http://localhost:8080', rpId: 'localhost' }));
      expect(replay.json.error).toMatch(/no pending challenge/);

      const opts2 = (await nip98Fetch(aliceSk, `${base}/v1/devices/${dev.id}/webauthn/options`, 'POST', {})).json;
      const ok = await nip98Fetch(aliceSk, `${base}/v1/devices/${dev.id}/webauthn/register`, 'POST', auth.create({ challenge: opts2.challenge, origin: 'http://localhost:8080', rpId: 'localhost' }));
      expect(ok.status).toBe(200);
      expect(ok.json).toEqual({ id: dev.id, ownerPubkey: alice, trust: 'attested', registeredAt: dev.registeredAt, credentialId: auth.create({ challenge: 'x', origin: 'x', rpId: 'x' }).id, attestationFormat: 'packed' });
      // The stored public key never leaves the service.
      expect(JSON.stringify((await asAdmin(`/v1/devices?owner=${alice}`)).json)).not.toMatch(/credentialPublicKey|signCount/);
      const listed = (await asAdmin(`/v1/devices?owner=${alice}`)).json.devices.find((d: { id: string }) => d.id === dev.id);
      expect(listed.trust).toBe('attested');

      // The same credential cannot attest a second device; the options exclude it.
      const dev2 = (await asAdmin('/v1/devices', 'POST', { owner: alice })).json;
      const opts3 = (await asAdmin(`/v1/devices/${dev2.id}/webauthn/options`, 'POST', {})).json;
      expect(opts3.excludeCredentials).toEqual([{ type: 'public-key', id: ok.json.credentialId }]);
      const dup = await asAdmin(`/v1/devices/${dev2.id}/webauthn/register`, 'POST', { credential: auth.create({ challenge: opts3.challenge, origin: 'http://localhost:8080', rpId: 'localhost' }) });
      expect(dup.status).toBe(409);
      // Revoked devices cannot be attested.
      await asAdmin(`/v1/devices/${dev2.id}/revoke`, 'POST', {});
      expect((await asAdmin(`/v1/devices/${dev2.id}/webauthn/options`, 'POST', {})).status).toBe(409);
      expect((await asAdmin('/v1/audit')).json.audit.some((a: { action: string }) => a.action === 'device.attest')).toBe(true);
    });

    it('editing a revoked subject keeps it revoked; reactivating is explicit and audited (FR023-09)', async () => {
      const carolSk = generateSecretKey();
      const carol = getPublicKey(carolSk);
      await asAdmin(`/v1/subjects/${carol}`, 'PUT', { roles: ['analyst'], attributes: {} });
      await asAdmin('/v1/devices', 'POST', { owner: carol });
      const allowlist = async () => (await bearerFetch('/v1/relay/allowlist').then((r) => r.json())).pubkeys as string[];
      const subject = async () => (await asAdmin('/v1/subjects')).json.subjects.find((s: { pubkey: string }) => s.pubkey === carol);
      expect(await allowlist()).toContain(carol);
      expect((await asAdmin(`/v1/subjects/${carol}/reactivate`, 'POST', {})).status).toBe(409);

      await asAdmin(`/v1/subjects/${carol}/revoke`, 'POST', {});
      // The console's "Editar" sends a PUT without `suspended`; so does a PUT that tries to lift it.
      expect((await asAdmin(`/v1/subjects/${carol}`, 'PUT', { roles: ['analyst', 'legal'], attributes: { unit: 'ops' } })).status).toBe(200);
      expect((await asAdmin(`/v1/subjects/${carol}`, 'PUT', { roles: ['analyst'], attributes: {}, suspended: false })).status).toBe(200);
      expect(await subject()).toMatchObject({ roles: ['analyst'], suspended: true });
      expect(await allowlist()).not.toContain(carol);
      expect((await evaluate({ pubkey: carol, resourceId: 'general', action: 'read' })).reasons).toEqual(['subject suspended']);

      expect((await nip98Fetch(carolSk, `${base}/v1/subjects/${carol}/reactivate`, 'POST', {})).status).toBe(403);
      expect((await asAdmin(`/v1/subjects/${getPublicKey(generateSecretKey())}/reactivate`, 'POST', {})).status).toBe(404);
      expect((await asAdmin(`/v1/subjects/${carol}/reactivate`, 'POST', {})).status).toBe(200);
      expect((await subject()).suspended).toBeUndefined();
      const audit = (await asAdmin('/v1/audit?limit=20')).json.audit as Array<{ action: string; target: string }>;
      expect(audit.find((a) => a.target === carol)?.action).toBe('subject.reactivate');
      // Its devices stay revoked: no relay access until a new device is registered.
      expect(await allowlist()).not.toContain(carol);
      await asAdmin('/v1/devices', 'POST', { owner: carol });
      expect(await allowlist()).toContain(carol);
    });

    it('serves device revocations from a cursor, whatever else the audit holds (FR024-04)', async () => {
      type Revocation = { cursor: number; at: number; deviceId: string; reason?: string };
      const before = (await asAdmin('/v1/revocations')).json.latest as number;
      const dave = getPublicKey(generateSecretKey());
      const devices: string[] = [];
      for (let i = 0; i < 3; i++) devices.push((await asAdmin('/v1/devices', 'POST', { owner: dave })).json.id);
      await asAdmin(`/v1/devices/${devices[0]}/revoke`, 'POST', { reason: 'lost phone' });
      // More than a page of other audit entries after the first revocation (B2). Access decisions no longer go to the
      // audit (FR023-12): admin actions fill it here.
      for (let i = 0; i < 150; i++) await engine.putDirectoryEntry('admin', { pubkey: dave, title: `turno ${i}` });
      await asAdmin(`/v1/devices/${devices[1]}/revoke`, 'POST', {});
      await asAdmin(`/v1/devices/${devices[2]}/revoke`, 'POST', {});
      expect((await asAdmin('/v1/audit')).json.audit.some((a: { target: string }) => a.target === devices[0])).toBe(false);

      const page = (await asAdmin(`/v1/revocations?after=${before}`)).json as { revocations: Revocation[]; latest: number; now: number };
      expect(page.revocations.map((r) => r.deviceId)).toEqual(devices);
      expect(page.revocations[0]).toMatchObject({ reason: 'lost phone', at: expect.any(Number) });
      expect(page.revocations[1]!.reason).toBe('revoked');
      expect(page.latest).toBe(page.revocations[2]!.cursor);
      expect(page.now).toBeGreaterThanOrEqual(page.revocations[2]!.at);
      // Pages by `after` and `limit`. A service token may read it; no other identity may.
      const first = (await bearerFetch(`/v1/revocations?after=${before}&limit=2`).then((r) => r.json())).revocations as Revocation[];
      expect(first.map((r) => r.deviceId)).toEqual(devices.slice(0, 2));
      const rest = (await bearerFetch(`/v1/revocations?after=${first[1]!.cursor}&limit=2`).then((r) => r.json())).revocations as Revocation[];
      expect(rest.map((r) => r.deviceId)).toEqual([devices[2]]);
      expect((await nip98Fetch(aliceSk, `${base}/v1/revocations`)).status).toBe(403);
      expect((await asAdmin('/v1/revocations?after=-1')).status).toBe(400);
      expect((await asAdmin('/v1/revocations?limit=0')).status).toBe(400);
    });

    it('publish grants for the relays: who may publish in each channel and group, never an access decision (FR023-10)', async () => {
      const key = () => getPublicKey(generateSecretKey());
      const [ana, beto, carla, dani, eva] = [key(), key(), key(), key(), key()];
      const people: Array<[string, string[], Record<string, string>]> = [
        [ana, ['staff'], {}],
        [beto, ['staff'], {}],
        [carla, ['guest'], {}],
        [dani, ['staff'], { clearance: 'confidential' }],
        [eva, ['staff'], { clearance: 'confidential' }],
      ];
      for (const [p, roles, attributes] of people) await asAdmin(`/v1/subjects/${p}`, 'PUT', { roles, attributes });
      for (const p of [ana, carla]) await asAdmin('/v1/devices', 'POST', { owner: p });
      // beto's only device is revoked; dani has an unverified device and a registered one; eva only an unverified one.
      const betoDevice = (await asAdmin('/v1/devices', 'POST', { owner: beto })).json as { id: string };
      await asAdmin(`/v1/devices/${betoDevice.id}/revoke`, 'POST', { reason: 'lost' });
      await asAdmin('/v1/devices', 'POST', { owner: dani, trust: 'unverified' });
      await asAdmin('/v1/devices', 'POST', { owner: dani });
      await asAdmin('/v1/devices', 'POST', { owner: eva, trust: 'unverified' });
      await asAdmin('/v1/resources/fr023-10-canal', 'PUT', { kind: 'channel', sensitivity: 'internal', rules: [{ actions: ['publish'], anyRole: ['staff'] }] });
      await asAdmin('/v1/resources/fr023-10-sala', 'PUT', { kind: 'group', sensitivity: 'confidential', members: [ana, dani, eva], rules: [{ actions: ['read', 'publish'], anyRole: ['staff'] }] });
      await asAdmin('/v1/resources/fr023-10-lectura', 'PUT', { kind: 'channel', sensitivity: 'internal', rules: [{ actions: ['read'], anyRole: ['staff'] }] });
      await asAdmin('/v1/resources/fr023-10-ws', 'PUT', { kind: 'workspace', sensitivity: 'internal', rules: [{ actions: ['publish'], anyRole: ['staff'] }] });
      const decisions = async () => ((await asAdmin('/v1/access-log?limit=1000')).json as { access: unknown[] }).access.length;
      const before = await decisions();

      const res = await bearerFetch('/v1/relay/grants');
      expect(res.status).toBe(200);
      const grants = ((await res.json()) as { grants: Array<{ resourceId: string; kind: string; pubkeys: string[] }> }).grants;
      const of = (id: string) => grants.find((g) => g.resourceId === id);
      // beto: no device left; carla: no rule for guests; dani: allowed by one of her devices.
      expect(of('fr023-10-canal')).toEqual({ resourceId: 'fr023-10-canal', kind: 'channel', pubkeys: [ana, dani, eva].sort() });
      // Confidential: ana has no clearance and eva no registered device.
      expect(of('fr023-10-sala')).toEqual({ resourceId: 'fr023-10-sala', kind: 'group', pubkeys: [dani] });
      expect(of('fr023-10-lectura')).toEqual({ resourceId: 'fr023-10-lectura', kind: 'channel', pubkeys: [] });
      // A workspace is no channel of a relay.
      expect(of('fr023-10-ws')).toBeUndefined();
      expect(await decisions()).toBe(before);
      expect((await fetch(`${base}/v1/relay/grants`)).status).toBe(401);
      expect((await nip98Fetch(aliceSk, `${base}/v1/relay/grants`)).status).toBe(401);
    });

    describe('passkey in every session (FR023-11)', () => {
      const ORIGIN = WEBAUTHN.origins[0]!;
      type Audit = { action: string; actor: string; target: string; details?: Record<string, unknown> };
      const person = () => {
        const sk = generateSecretKey();
        return { sk, pk: getPublicKey(sk) };
      };
      const newDevice = async (owner: string) => (await asAdmin('/v1/devices', 'POST', { owner })).json as { id: string };
      /** webauthn/options → the authenticator creates the credential → webauthn/register, as the owner (sk) or an admin. */
      const enroll = async (who: Uint8Array, deviceId: string, auth: TestAuthenticator) => {
        const opts = (await nip98Fetch(who, `${base}/v1/devices/${deviceId}/webauthn/options`, 'POST', {})).json;
        return nip98Fetch(who, `${base}/v1/devices/${deviceId}/webauthn/register`, 'POST', auth.create({ challenge: opts.challenge, origin: ORIGIN, rpId: 'localhost' }));
      };
      const assertOptions = (sk: Uint8Array, deviceId: string) => nip98Fetch(sk, `${base}/v1/devices/${deviceId}/webauthn/assert/options`, 'POST', {});
      const openSession = (sk: Uint8Array, body: unknown) => nip98Fetch(sk, `${base}/v1/sessions`, 'POST', body);
      /** assert/options → the authenticator signs the challenge → POST /v1/sessions. */
      const passkeySession = async (sk: Uint8Array, deviceId: string, auth: TestAuthenticator, o: Partial<AssertionInput> = {}) => {
        const { challenge } = (await assertOptions(sk, deviceId)).json;
        return openSession(sk, { deviceId, assertion: auth.get({ challenge, origin: ORIGIN, rpId: 'localhost', ...o }) });
      };
      const assertAudit = async (deviceId: string) => ((await asAdmin('/v1/audit?limit=1000')).json.audit as Audit[]).filter((a) => a.action === 'session.assert' && a.target === deviceId);
      const hashOf = (token: string) => createHash('sha256').update(token).digest('hex');

      it('the owner registers the passkey on their device, and from then on a session needs its assertion (FR023-11)', async () => {
        const erin = person();
        const dev = await newDevice(erin.pk);
        // Without a passkey a session opens as before (compatibility), and there is nothing to assert with.
        const before = await openSession(erin.sk, { device_id: dev.id });
        expect([before.status, before.json.asserted]).toEqual([201, false]);
        expect(await engine.sessionValid(before.json.token)).toBe(true);
        expect((await assertOptions(erin.sk, dev.id)).status).toBe(409);
        // The owner reads their own devices, and nobody else's.
        expect((await nip98Fetch(erin.sk, `${base}/v1/devices?owner=${erin.pk}`)).json.devices.map((d: { id: string }) => d.id)).toEqual([dev.id]);
        expect((await nip98Fetch(erin.sk, `${base}/v1/devices?owner=${alice}`)).status).toBe(403);
        expect((await nip98Fetch(erin.sk, `${base}/v1/devices`)).status).toBe(403);

        const auth = new TestAuthenticator();
        const enrolled = await enroll(erin.sk, dev.id, auth);
        expect([enrolled.status, enrolled.json.trust, enrolled.json.credentialId]).toEqual([200, 'attested', auth.id]);
        // The session opened without a passkey is over, and a new one needs the assertion.
        expect(await engine.sessionValid(before.json.token)).toBe(false);
        expect(await engine.repo.getSession(hashOf(before.json.token))).toBeUndefined();
        const bare = await openSession(erin.sk, { deviceId: dev.id });
        expect(bare.status).toBe(403);
        expect(bare.json.error).toMatch(/assertion/);

        // Assertion options: only for the owner, with the one credential of the device.
        expect((await assertOptions(generateSecretKey(), dev.id)).status).toBe(404);
        expect((await asAdmin(`/v1/devices/${dev.id}/webauthn/assert/options`, 'POST', {})).status).toBe(404);
        const opts = (await assertOptions(erin.sk, dev.id)).json;
        expect(opts).toEqual({ challenge: expect.any(String), rpId: 'localhost', allowCredentials: [{ type: 'public-key', id: auth.id }], timeout: 300_000, userVerification: 'preferred' });
        const assertion = auth.get({ challenge: opts.challenge, origin: ORIGIN, rpId: 'localhost', counter: 1, userHandle: Buffer.from(erin.pk, 'hex') });
        const ok = await openSession(erin.sk, { deviceId: dev.id, assertion });
        expect(ok.status).toBe(201);
        expect(ok.json).toEqual({ token: expect.stringMatching(/^[0-9a-f]{48}$/), deviceId: dev.id, asserted: true });
        expect(await engine.sessionValid(ok.json.token)).toBe(true);
        expect((await engine.repo.getSession(hashOf(ok.json.token)))?.credentialId).toBe(auth.id);
        // Every session asks again: the same assertion, its challenge spent, opens nothing.
        const replay = await openSession(erin.sk, { deviceId: dev.id, assertion });
        expect([replay.status, replay.json.error]).toEqual([403, ASSERTION_REJECTED]);

        // Only the failure is audited: when someone opens sessions is usage metadata, not an admin action.
        const audit = await assertAudit(dev.id);
        expect(audit.map((a) => [a.actor, a.details?.ok, a.details?.reason])).toEqual([[erin.pk, false, 'no pending challenge']]);
        // Neither the challenge, nor the credential, nor the signature or the token reach the audit.
        const text = JSON.stringify((await asAdmin('/v1/audit?limit=1000')).json.audit);
        for (const secret of [opts.challenge, auth.id, assertion.response.signature, ok.json.token]) expect(text).not.toContain(secret);
      });

      it('rejects assertions of another origin, RP id, challenge, device or owner, without presence or with a bad signature, and consumes the challenge (FR023-11)', async () => {
        const erin = person();
        const dev = await newDevice(erin.pk);
        const auth = new TestAuthenticator();
        await enroll(erin.sk, dev.id, auth);
        const refused = async (r: { status: number; json: { error?: string } }) => expect([r.status, r.json.error]).toEqual([403, ASSERTION_REJECTED]);
        await refused(await passkeySession(erin.sk, dev.id, auth, { origin: 'https://evil.example' }));
        await refused(await passkeySession(erin.sk, dev.id, auth, { rpId: 'evil.example' }));
        await refused(await passkeySession(erin.sk, dev.id, auth, { challenge: 'b3RoZXItY2hhbGxlbmdl' }));
        await refused(await passkeySession(erin.sk, dev.id, auth, { flags: 0x04 }));
        await refused(await passkeySession(erin.sk, dev.id, auth, { tamperSig: true }));
        await refused(await passkeySession(erin.sk, dev.id, auth, { type: 'webauthn.create' }));
        await refused(await passkeySession(erin.sk, dev.id, auth, { userHandle: Buffer.from(alice, 'hex') }));
        // Another authenticator claiming this credential: the stored public key does not verify it.
        await refused(await passkeySession(erin.sk, dev.id, new TestAuthenticator(), { id: auth.id }));
        expect((await assertAudit(dev.id)).map((a) => a.details?.reason)).toEqual([
          'assertion signature invalid',
          'user handle mismatch',
          'clientData.type must be webauthn.get',
          'assertion signature invalid',
          'user presence required',
          'challenge mismatch',
          'rpIdHash mismatch',
          'origin not allowed',
        ]);
        // A failed assertion spends the challenge: a good assertion on it opens nothing.
        const { challenge } = (await assertOptions(erin.sk, dev.id)).json;
        await refused(await openSession(erin.sk, { deviceId: dev.id, assertion: auth.get({ challenge, origin: 'https://evil.example', rpId: 'localhost' }) }));
        await refused(await openSession(erin.sk, { deviceId: dev.id, assertion: auth.get({ challenge, origin: ORIGIN, rpId: 'localhost' }) }));
        expect((await assertAudit(dev.id))[0]?.details?.reason).toBe('no pending challenge');

        // A second device of the same owner (an admin registers its passkey): the challenge of one device does not open
        // the other, nor does the credential of one sign for the other.
        const dev2 = await newDevice(erin.pk);
        const auth2 = new TestAuthenticator();
        expect((await enroll(adminSk, dev2.id, auth2)).status).toBe(200);
        const c1 = (await assertOptions(erin.sk, dev.id)).json.challenge;
        await assertOptions(erin.sk, dev2.id);
        await refused(await openSession(erin.sk, { deviceId: dev2.id, assertion: auth2.get({ challenge: c1, origin: ORIGIN, rpId: 'localhost' }) }));
        expect((await assertAudit(dev2.id))[0]?.details?.reason).toBe('challenge mismatch');
        await refused(await passkeySession(erin.sk, dev2.id, auth));
        expect((await assertAudit(dev2.id))[0]?.details?.reason).toBe('credential not allowed');
        const onDev2 = await passkeySession(erin.sk, dev2.id, auth2);
        expect(onDev2.status).toBe(201);
        // A device without a passkey opens no session once its owner has one.
        const dev3 = await newDevice(erin.pk);
        expect((await openSession(erin.sk, { deviceId: dev3.id })).status).toBe(403);
        expect((await assertOptions(erin.sk, dev3.id)).status).toBe(409);

        // Another person's key opens nothing on these devices, and leaves no trace on them. What it gets back is what an
        // id nobody uses gets: it cannot tell whose devices exist.
        const mallory = person();
        const before = (await assertAudit(dev.id)).length;
        for (const deviceId of [dev.id, 'no-such-device']) {
          expect((await openSession(mallory.sk, { deviceId, assertion: auth.get({ challenge: c1, origin: ORIGIN, rpId: 'localhost' }) })).json).toEqual({ error: 'device not usable for a new session' });
          expect((await assertOptions(mallory.sk, deviceId)).json).toEqual({ error: 'unknown device' });
        }
        expect((await assertAudit(dev.id)).length).toBe(before);

        // Revoking a device invalidates the sessions opened with its passkey and refuses new ones.
        expect(await engine.sessionValid(onDev2.json.token)).toBe(true);
        await asAdmin(`/v1/devices/${dev2.id}/revoke`, 'POST', { reason: 'robado' });
        expect(await engine.sessionValid(onDev2.json.token)).toBe(false);
        expect((await assertOptions(erin.sk, dev2.id)).status).toBe(409);
        expect((await passkeySession(erin.sk, dev2.id, auth2)).status).toBe(403);
        // Its passkey is still required on the other device.
        expect((await openSession(erin.sk, { deviceId: dev.id })).status).toBe(403);
      });

      it('revoking the device that holds the passkey neither brings back sessions without one nor lets the owner enroll another (FR023-11)', async () => {
        const lee = person();
        const [phone, laptop] = [await newDevice(lee.pk), await newDevice(lee.pk)];
        await enroll(lee.sk, phone.id, new TestAuthenticator());
        await asAdmin(`/v1/devices/${phone.id}/revoke`, 'POST', { reason: 'perdido' });
        // Whoever holds only the Nostr key (say, the thief who took the phone) opens nothing on the laptop, which has no
        // passkey, and cannot enroll an authenticator of their own on it.
        const bare = await openSession(lee.sk, { deviceId: laptop.id });
        expect([bare.status, bare.json.error]).toEqual([403, expect.stringMatching(/registered a passkey/)]);
        const selfEnroll = await nip98Fetch(lee.sk, `${base}/v1/devices/${laptop.id}/webauthn/options`, 'POST', {});
        expect([selfEnroll.status, selfEnroll.json.error]).toEqual([403, expect.stringMatching(/an admin registers/)]);
        // An admin registers the laptop's passkey, and sessions open with it.
        const laptopKey = new TestAuthenticator();
        expect((await enroll(adminSk, laptop.id, laptopKey)).status).toBe(200);
        expect((await passkeySession(lee.sk, laptop.id, laptopKey)).status).toBe(201);
        // The enrollment routes tell a stranger nothing either: the same 404 as an id nobody uses.
        const stranger = generateSecretKey();
        for (const id of [laptop.id, phone.id, 'no-such-device']) {
          for (const route of ['options', 'register']) expect((await nip98Fetch(stranger, `${base}/v1/devices/${id}/webauthn/${route}`, 'POST', {})).json).toEqual({ error: 'unknown device' });
        }
      });

      it('an expired challenge opens nothing (FR023-11)', async () => {
        const erin = person();
        const dev = await newDevice(erin.pk);
        const auth = new TestAuthenticator();
        await enroll(erin.sk, dev.id, auth);
        const { challenge } = (await assertOptions(erin.sk, dev.id)).json;
        skew = 300_001;
        try {
          const late = await openSession(erin.sk, { deviceId: dev.id, assertion: auth.get({ challenge, origin: ORIGIN, rpId: 'localhost' }) });
          expect([late.status, late.json.error]).toEqual([403, ASSERTION_REJECTED]);
        } finally {
          skew = 0;
        }
        expect((await assertAudit(dev.id))[0]?.details?.reason).toBe('challenge expired');
      });

      it('the signature counter must go up: a cloned authenticator is refused and audited (FR023-11)', async () => {
        const gina = person();
        const dev = await newDevice(gina.pk);
        const auth = new TestAuthenticator();
        await enroll(gina.sk, dev.id, auth);
        expect((await passkeySession(gina.sk, dev.id, auth, { counter: 5 })).status).toBe(201);
        // A clone holds the same key and credential id, and its counter lags behind (or repeats).
        const clone = new TestAuthenticator(auth);
        for (const counter of [5, 4, 0]) expect((await passkeySession(gina.sk, dev.id, clone, { counter })).json.error).toBe(ASSERTION_REJECTED);
        expect((await passkeySession(gina.sk, dev.id, auth, { counter: 6 })).status).toBe(201);
        // Newest first: the three attempts of the clone, each with the counter it claimed.
        const audit = await assertAudit(dev.id);
        expect(audit.map((a) => [a.details?.ok, a.details?.signCount])).toEqual([
          [false, 0],
          [false, 4],
          [false, 5],
        ]);
        for (const a of audit) expect(a.details?.reason).toBe('signature counter did not increase: possible cloned authenticator');
        // An authenticator without a counter (most synced passkeys) always reports 0: nothing to compare.
        const hank = person();
        const dev2 = await newDevice(hank.pk);
        const noCounter = new TestAuthenticator();
        await enroll(hank.sk, dev2.id, noCounter);
        for (let i = 0; i < 2; i++) expect((await passkeySession(hank.sk, dev2.id, noCounter)).status).toBe(201);
      });

      it('of two uses of one assertion, or two assertions with the same counter, at once, only one gets through (FR023-11)', async () => {
        const ivy = person();
        const dev = await newDevice(ivy.pk);
        const auth = new TestAuthenticator();
        await enroll(ivy.sk, dev.id, auth);
        const { challenge } = (await assertOptions(ivy.sk, dev.id)).json;
        const body = { deviceId: dev.id, assertion: auth.get({ challenge, origin: ORIGIN, rpId: 'localhost', counter: 3 }) };
        const both = await Promise.all([openSession(ivy.sk, body), openSession(ivy.sk, body)]);
        expect(both.map((r) => r.status).sort()).toEqual([201, 403]);
        // The counter check and its write are one step in the repository.
        for (const counter of [7, 8, 9]) {
          const results = await Promise.all([engine.repo.advanceSignCount(dev.id, auth.id, counter), engine.repo.advanceSignCount(dev.id, auth.id, counter)]);
          expect(results.filter(Boolean)).toHaveLength(1);
        }
        expect((await engine.repo.getDevice(dev.id))?.signCount).toBe(9);
        expect(await engine.repo.advanceSignCount(dev.id, 'another-credential', 10)).toBe(false);
      });

      it('once the owner has a passkey, an admin registers any other one, which ends the sessions of the passkey it replaces (FR023-11)', async () => {
        const jo = person();
        const dev = await newDevice(jo.pk);
        const auth = new TestAuthenticator();
        await enroll(jo.sk, dev.id, auth);
        const s1 = (await passkeySession(jo.sk, dev.id, auth, { counter: 1 })).json.token as string;
        // Whoever holds only the owner's Nostr key cannot enroll an authenticator of their own, on a new device or this one.
        const dev2 = await newDevice(jo.pk);
        for (const id of [dev2.id, dev.id]) {
          const r = await nip98Fetch(jo.sk, `${base}/v1/devices/${id}/webauthn/options`, 'POST', {});
          expect([r.status, r.json.error]).toEqual([403, expect.stringMatching(/an admin registers/)]);
          expect((await nip98Fetch(jo.sk, `${base}/v1/devices/${id}/webauthn/register`, 'POST', new TestAuthenticator().create({ challenge: 'x', origin: ORIGIN, rpId: 'localhost' }))).status).toBe(403);
        }
        // An admin replaces the passkey of the device: the sessions of the old one end, and the old one opens no other.
        const replacement = new TestAuthenticator();
        expect((await enroll(adminSk, dev.id, replacement)).json.credentialId).toBe(replacement.id);
        expect(await engine.sessionValid(s1)).toBe(false);
        expect((await passkeySession(jo.sk, dev.id, auth, { counter: 2 })).status).toBe(403);
        expect((await assertAudit(dev.id))[0]?.details?.reason).toBe('credential not allowed');
        expect((await passkeySession(jo.sk, dev.id, replacement)).status).toBe(201);
      });

      it('registering a passkey ends the sessions its owner opened without one, on every device (FR023-11)', async () => {
        const kim = person();
        const [d1, d2] = [await newDevice(kim.pk), await newDevice(kim.pk)];
        const tokens = [(await openSession(kim.sk, { deviceId: d1.id })).json.token as string, (await openSession(kim.sk, { deviceId: d2.id })).json.token as string];
        for (const t of tokens) expect(await engine.sessionValid(t)).toBe(true);
        await enroll(kim.sk, d1.id, new TestAuthenticator());
        for (const t of tokens) {
          expect(await engine.sessionValid(t)).toBe(false);
          expect(await engine.repo.getSession(hashOf(t))).toBeUndefined();
        }
        // A session opened without one while the passkey was being registered does not count either.
        await engine.repo.putSession(hashOf('late-session'), { pubkey: kim.pk, deviceId: d2.id, createdAt: Date.now() });
        expect(await engine.sessionValid('late-session')).toBe(false);
      });
    });
  });
}

suite('policy-engine (memory)', async () => new MemoryPolicyRepository());

describe('SESSION_REQUIRE_ASSERTION and WEBAUTHN_REQUIRE_UV (FR023-11)', () => {
  const adminSk = generateSecretKey();
  const ownerSk = generateSecretKey();
  const owner = getPublicKey(ownerSk);
  const repo = new MemoryPolicyRepository();
  const ORIGIN = WEBAUTHN.origins[0]!;
  const apis: Array<ReturnType<typeof createPolicyApi>> = [];
  const serve = async (config: Partial<WebAuthnConfig>) => {
    const engine = new PolicyEngine(repo, Date.now, { ...WEBAUTHN, ...config });
    const api = createPolicyApi(engine, { name: 'policy-strict', adminPubkeys: [getPublicKey(adminSk)] });
    apis.push(api);
    return { engine, base: await api.listen() };
  };
  afterAll(async () => {
    for (const a of apis) await a.close();
  });

  it('with SESSION_REQUIRE_ASSERTION every session needs a passkey, and sessions opened without one stop counting (FR023-11)', async () => {
    const lax = await serve({});
    const device = await lax.engine.registerDevice('admin', owner);
    const old = (await nip98Fetch(ownerSk, `${lax.base}/v1/sessions`, 'POST', { deviceId: device.id })).json.token as string;
    expect(await lax.engine.sessionValid(old)).toBe(true);

    const strict = await serve({ sessionRequireAssertion: true });
    expect(await strict.engine.sessionValid(old)).toBe(false);
    const refused = await nip98Fetch(ownerSk, `${strict.base}/v1/sessions`, 'POST', { deviceId: device.id });
    expect([refused.status, refused.json.error]).toEqual([403, expect.stringMatching(/\(SESSION_REQUIRE_ASSERTION\): register a passkey/)]);
    // The owner registers their passkey and opens the session with it.
    const auth = new TestAuthenticator();
    const opts = (await nip98Fetch(ownerSk, `${strict.base}/v1/devices/${device.id}/webauthn/options`, 'POST', {})).json;
    expect((await nip98Fetch(ownerSk, `${strict.base}/v1/devices/${device.id}/webauthn/register`, 'POST', auth.create({ challenge: opts.challenge, origin: ORIGIN, rpId: 'localhost' }))).status).toBe(200);
    const { challenge } = (await nip98Fetch(ownerSk, `${strict.base}/v1/devices/${device.id}/webauthn/assert/options`, 'POST', {})).json;
    const ok = await nip98Fetch(ownerSk, `${strict.base}/v1/sessions`, 'POST', { deviceId: device.id, assertion: auth.get({ challenge, origin: ORIGIN, rpId: 'localhost' }) });
    expect(ok.status).toBe(201);
    expect(await strict.engine.sessionValid(ok.json.token)).toBe(true);
  });

  it('with WEBAUTHN_REQUIRE_UV registrations and assertions need user verification, not only presence (FR023-11)', async () => {
    const uv = await serve({ requireUserVerification: true });
    const sk = generateSecretKey();
    const device = await uv.engine.registerDevice('admin', getPublicKey(sk));
    const auth = new TestAuthenticator();
    const call = (path: string, body: unknown = {}) => nip98Fetch(sk, `${uv.base}/v1/devices/${device.id}${path}`, 'POST', body);
    let opts = (await call('/webauthn/options')).json;
    expect(opts.authenticatorSelection.userVerification).toBe('required');
    // UP | AT, no UV.
    const noUv = await call('/webauthn/register', auth.create({ challenge: opts.challenge, origin: ORIGIN, rpId: 'localhost', flags: 0x41 }));
    expect([noUv.status, noUv.json.error]).toEqual([400, 'webauthn: user verification required']);
    opts = (await call('/webauthn/options')).json;
    expect((await call('/webauthn/register', auth.create({ challenge: opts.challenge, origin: ORIGIN, rpId: 'localhost' }))).status).toBe(200);
    const assertOpts = (await call('/webauthn/assert/options')).json;
    expect(assertOpts.userVerification).toBe('required');
    const presenceOnly = await nip98Fetch(sk, `${uv.base}/v1/sessions`, 'POST', { deviceId: device.id, assertion: auth.get({ challenge: assertOpts.challenge, origin: ORIGIN, rpId: 'localhost', flags: 0x01 }) });
    expect(presenceOnly.status).toBe(403);
    const audit = await uv.engine.listAudit({ limit: 5 });
    expect(audit[0]).toMatchObject({ action: 'session.assert', target: device.id, details: { ok: false, reason: 'user verification required' } });
  });
});

describe('a device revoked while its assertion is checked (FR023-11)', () => {
  it('opens no session, and the audit says so instead of blaming a cloned authenticator', async () => {
    let engine: PolicyEngine | undefined;
    // The revocation lands between reading the device and recording the signature counter.
    class RevokedMeanwhile extends MemoryPolicyRepository {
      override async advanceSignCount(deviceId: string, credentialId: string, signCount: number) {
        await engine!.revokeDevice('admin', deviceId, 'robado');
        return super.advanceSignCount(deviceId, credentialId, signCount);
      }
    }
    engine = new PolicyEngine(new RevokedMeanwhile(), Date.now, WEBAUTHN);
    const owner = getPublicKey(generateSecretKey());
    const device = await engine.registerDevice('admin', owner);
    const auth = new TestAuthenticator();
    const creation = await engine.webauthnOptions(device.id);
    await engine.webauthnRegister(owner, device.id, auth.create({ challenge: creation.challenge, origin: WEBAUTHN.origins[0]!, rpId: 'localhost' }));
    const { challenge } = await engine.webauthnAssertionOptions(owner, device.id);
    await expect(engine.openSession(owner, device.id, auth.get({ challenge, origin: WEBAUTHN.origins[0]!, rpId: 'localhost', counter: 1 }))).rejects.toThrow(ASSERTION_REJECTED);
    const [last] = await engine.listAudit({ limit: 1 });
    expect(last).toMatchObject({ action: 'session.assert', actor: owner, target: device.id, details: { ok: false, reason: 'device revoked or given another passkey meanwhile' } });
  });
});

const PG = process.env.TEST_DATABASE_URL;
if (PG) {
  let pool: Pool;
  const fresh = async () => {
    pool ??= createPgPool(PG);
    await resetScope(pool, 'policy-engine', POLICY_TABLES);
    await migrate(pool, MIGRATIONS, 'policy-engine');
    return new PgPolicyRepository(pool);
  };
  suite('policy-engine (postgres)', fresh);

  describe('policy-engine (postgres) persistence', () => {
    afterAll(() => pool?.end());

    it('a new engine on the same database keeps every piece of state (restart)', async () => {
      const repo = await fresh();
      const admin = getPublicKey(generateSecretKey());
      const alice = getPublicKey(generateSecretKey());
      const first = new PolicyEngine(repo, Date.now, WEBAUTHN);
      await first.upsertSubject(admin, { pubkey: alice, roles: ['analyst'], attributes: { clearance: 'secret' } });
      await first.upsertResource(admin, { id: 'room', kind: 'group', sensitivity: 'internal', rules: [{ actions: ['read'], anyRole: ['analyst'] }], members: [alice] });
      const d1 = await first.registerDevice(admin, alice);
      const d2 = await first.registerDevice(admin, alice);
      const token = await first.openSession(alice, d2.id);
      await first.revokeDevice(admin, d1.id, 'lost');
      await first.putDirectoryEntry(admin, { pubkey: alice, title: 'Analista', unit: 'Riesgo' });
      await first.upsertResource(admin, { id: 'canal', kind: 'channel', sensitivity: 'internal', rules: [] });
      await first.putRetention(admin, { resourceId: 'canal', days: 90, legalHold: true });

      // "Restart": a brand new pool, repository and engine.
      const pool2 = createPgPool(PG);
      try {
        await migrate(pool2, MIGRATIONS, 'policy-engine');
        const second = new PolicyEngine(new PgPolicyRepository(pool2), Date.now, WEBAUTHN);
        expect(await second.listSubjects()).toEqual([{ pubkey: alice, roles: ['analyst'], attributes: { clearance: 'secret' } }]);
        expect(await second.listResources()).toEqual([expect.objectContaining({ id: 'canal', kind: 'channel' }), expect.objectContaining({ id: 'room', members: [alice] })]);
        expect((await second.listDevices(alice)).map((d) => [d.id, d.revokedAt !== undefined])).toEqual([
          [d1.id, true],
          [d2.id, false],
        ]);
        expect(await second.sessionValid(token)).toBe(true);
        expect(await second.relayAllowlist()).toEqual([alice]);
        expect(await second.listRotations('pending')).toEqual([expect.objectContaining({ resourceId: 'room', removedPubkey: alice })]);
        expect((await second.evaluate({ pubkey: alice, deviceId: d2.id, resourceId: 'room', action: 'read' })).allow).toBe(true);
        expect(await second.listDirectory()).toEqual([{ pubkey: alice, title: 'Analista', unit: 'Riesgo' }]);
        expect(await second.listRetention()).toEqual([{ resourceId: 'canal', days: 90, legalHold: true }]);
        const audit = await second.listAudit({ limit: 100 });
        expect(audit.map((a) => a.action)).toEqual(['retention.set', 'resource.upsert', 'directory.upsert', 'device.revoke', 'device.register', 'device.register', 'resource.upsert', 'subject.upsert']);
        expect((await second.listAccessLog()).map((a) => [a.pubkey, a.deviceId, a.resourceId, a.action, a.allow])).toEqual([[alice, d2.id, 'room', 'read', true]]);
        // Session tokens are stored hashed.
        const { rows } = await pool2.query('SELECT token_hash FROM policy_sessions');
        expect(rows.map((r) => r.token_hash)).not.toContain(token);
      } finally {
        await pool2.end();
      }
    });

    it('an existing engine upgrades: the decisions in the audit are copied to the access log and stay in the audit (FR023-12)', async () => {
      pool ??= createPgPool(PG);
      await resetScope(pool, 'policy-engine', POLICY_TABLES);
      const before = mkdtempSync(join(tmpdir(), 'policy-migrations-'));
      for (const f of ['001_policy.sql', '002_audit_action_idx.sql']) copyFileSync(join(MIGRATIONS, f), join(before, f));
      await migrate(pool, before, 'policy-engine');
      const alice = getPublicKey(generateSecretKey());
      await pool.query(
        `INSERT INTO policy_audit (at, actor, action, target, details) VALUES
           (1000, $1, 'policy.evaluate', 'room', '{"action":"read","allow":true}'),
           (2000, 'admin', 'subject.upsert', $1, NULL),
           (3000, $1, 'policy.evaluate', 'room', '{"action":"publish","allow":false}')`,
        [alice],
      );
      expect((await migrate(pool, MIGRATIONS, 'policy-engine'))[0]).toBe('003_access_log.sql');
      const engine = new PolicyEngine(new PgPolicyRepository(pool), Date.now, WEBAUTHN);
      expect((await engine.listAccessLog()).map((a) => [a.at, a.pubkey, a.resourceId, a.action, a.allow])).toEqual([
        [3000, alice, 'room', 'publish', false],
        [1000, alice, 'room', 'read', true],
      ]);
      expect((await engine.listAudit({ limit: 10 })).map((a) => a.action)).toEqual(['policy.evaluate', 'subject.upsert', 'policy.evaluate']);
    });

    it('an existing engine upgrades: its sessions count until the owner has a passkey, its pending challenges are registration ones (FR023-11)', async () => {
      pool ??= createPgPool(PG);
      await resetScope(pool, 'policy-engine', POLICY_TABLES);
      const before = mkdtempSync(join(tmpdir(), 'policy-migrations-'));
      for (const f of ['001_policy.sql', '002_audit_action_idx.sql', '003_access_log.sql']) copyFileSync(join(MIGRATIONS, f), join(before, f));
      await migrate(pool, before, 'policy-engine');
      // What the previous version left: a device, a session opened on it and a pending registration challenge.
      const owner = getPublicKey(generateSecretKey());
      const token = 'ab'.repeat(24);
      await pool.query("INSERT INTO policy_devices (id, owner_pubkey, trust, registered_at) VALUES ('d1', $1, 'registered', 1000)", [owner]);
      await pool.query("INSERT INTO policy_sessions (token_hash, pubkey, device_id, created_at) VALUES ($1, $2, 'd1', 2000)", [createHash('sha256').update(token).digest('hex'), owner]);
      await pool.query("INSERT INTO policy_webauthn_challenges (device_id, challenge, expires_at) VALUES ('d1', 'pending-before-004', $1)", [Date.now() + 60_000]);
      expect(await migrate(pool, MIGRATIONS, 'policy-engine')).toEqual(['004_session_assertions.sql']);

      const engine = new PolicyEngine(new PgPolicyRepository(pool), Date.now, WEBAUTHN);
      expect(await engine.sessionValid(token)).toBe(true);
      // The pending challenge registers the passkey; from then on the old session neither counts nor exists.
      const auth = new TestAuthenticator();
      await engine.webauthnRegister(owner, 'd1', auth.create({ challenge: 'pending-before-004', origin: WEBAUTHN.origins[0]!, rpId: 'localhost' }));
      expect(await engine.sessionValid(token)).toBe(false);
      expect((await pool.query('SELECT count(*)::int AS n FROM policy_sessions')).rows[0].n).toBe(0);
      // An assertion challenge and a registration challenge of the same device wait side by side.
      const { challenge } = await engine.webauthnAssertionOptions(owner, 'd1');
      await engine.webauthnOptions('d1');
      const asserted = await engine.openSession(owner, 'd1', auth.get({ challenge, origin: WEBAUTHN.origins[0]!, rpId: 'localhost', counter: 1 }));
      expect(await engine.sessionValid(asserted)).toBe(true);
      expect((await pool.query('SELECT credential_id FROM policy_sessions')).rows).toEqual([{ credential_id: auth.id }]);
      expect((await pool.query('SELECT purpose FROM policy_webauthn_challenges')).rows).toEqual([{ purpose: 'register' }]);
      expect((await engine.repo.getDevice('d1'))?.signCount).toBe(1);
    });

    it('the audit is append-only', async () => {
      const repo = await fresh();
      await repo.appendAudit({ at: 1, actor: 'a', action: 'x', target: 't' });
      await expect(pool.query("UPDATE policy_audit SET action = 'y'")).rejects.toThrow(/append-only/);
      await expect(pool.query('DELETE FROM policy_audit')).rejects.toThrow(/append-only/);
      await expect(pool.query('TRUNCATE policy_audit')).rejects.toThrow(/append-only/);
      expect((await repo.listAudit({ limit: 10 })).map((a) => a.action)).toEqual(['x']);
    });
  });
}
