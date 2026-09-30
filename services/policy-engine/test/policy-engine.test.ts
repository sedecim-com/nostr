import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { copyFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { createPgPool, migrate, nip98Fetch, resetScope, type Pool } from '@sedecim/service-kit';
import { createPolicyApi, GROUP_RETENTION_REFUSED, MemoryPolicyRepository, PgPolicyRepository, PolicyEngine, POLICY_TABLES, RETENTION_NOTICE, type PolicyRepository } from '../src/index';
import { TestAuthenticator } from './webauthn-fixture';

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
    const bearerFetch = (path: string, init: RequestInit = {}) => fetch(`${base}${path}`, { ...init, headers: { authorization: 'Bearer relay-token-1234' } });
    const evaluate = (body: unknown) => bearerFetch('/v1/evaluate', { method: 'POST', body: JSON.stringify(body) }).then((r) => r.json());
    const asAdmin = (path: string, method = 'GET', body?: unknown) => nip98Fetch(adminSk, `${base}${path}`, method, body);

    beforeAll(async () => {
      engine = new PolicyEngine(await makeRepo(), Date.now, WEBAUTHN);
      api = createPolicyApi(engine, { name: 'policy-test', adminPubkeys: [getPublicKey(adminSk)], bearerTokens: { 'relay-token-1234': 'relay' } });
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
      // Only the owner or an admin.
      expect((await nip98Fetch(generateSecretKey(), `${base}/v1/devices/${dev.id}/webauthn/options`, 'POST', {})).status).toBe(403);
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
  });
}

suite('policy-engine (memory)', async () => new MemoryPolicyRepository());

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
      expect(await migrate(pool, MIGRATIONS, 'policy-engine')).toEqual(['003_access_log.sql']);
      const engine = new PolicyEngine(new PgPolicyRepository(pool), Date.now, WEBAUTHN);
      expect((await engine.listAccessLog()).map((a) => [a.at, a.pubkey, a.resourceId, a.action, a.allow])).toEqual([
        [3000, alice, 'room', 'publish', false],
        [1000, alice, 'room', 'read', true],
      ]);
      expect((await engine.listAudit({ limit: 10 })).map((a) => a.action)).toEqual(['policy.evaluate', 'subject.upsert', 'policy.evaluate']);
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
