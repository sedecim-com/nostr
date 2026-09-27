/**
 * In-memory policy-engine for the admin-console E2E: implements the admin API contract the console
 * codes against (apps/admin-console/src/api.ts), with real NIP-98 verification (service-kit) and the
 * admin allowlist. WebAuthn registration checks type, challenge and origin of clientDataJSON only;
 * attestation verification belongs to the real service.
 */
import { randomBytes } from 'node:crypto';
import { HttpError, isHex64, requireFields, Service } from '@sedecim/service-kit';
import type { Device, Resource, Subject } from '@sedecim/policy-client';

export interface StubRotation {
  id: string;
  at: number;
  resourceId: string;
  reason: string;
  removedPubkey: string;
  status: 'pending' | 'done';
}
export interface StubAudit {
  id: number;
  at: number;
  actor: string;
  action: string;
  target: string;
  details?: Record<string, unknown>;
}
export type StubDevice = Device & { credentialId?: string };

export const RETENTION_NOTICE =
  'La retención solo borra copias en los servidores de la organización (relays y blobs propios). No puede borrar lo que ya está en los dispositivos de los miembros ni en relays de terceros.';

export function createPolicyStub(opts: { adminPubkeys: string[]; corsOrigins: string[]; seedAudit?: number }) {
  const subjects = new Map<string, Subject>();
  const resources = new Map<string, Resource>();
  const devices = new Map<string, StubDevice>();
  const rotations: StubRotation[] = [];
  const directory = new Map<string, { pubkey: string; title?: string; unit?: string }>();
  const retention = new Map<string, { resourceId: string; days: number | null; legalHold: boolean }>();
  const challenges = new Map<string, { challenge: string; origin: string }>();
  const audit: StubAudit[] = [];
  /** Every authenticated admin call (method, path with query, pubkey). */
  const calls: Array<{ method: string; path: string; pubkey: string }> = [];
  let clock = Date.now() - 10_000_000;
  const now = () => (clock = Math.max(clock + 1, Date.now()));

  // Older entries so the audit table has several pages.
  for (let i = 0; i < (opts.seedAudit ?? 0); i++) audit.push({ id: audit.length + 1, at: now() - 5_000_000 + i, actor: 'seed', action: i % 2 ? 'seed.even' : 'seed.odd', target: `seed-${i}` });
  audit.sort((a, b) => a.at - b.at);

  const log = (actor: string, action: string, target: string, details?: Record<string, unknown>) => audit.push({ id: audit.length + 1, at: now(), actor, action, target, ...(details ? { details } : {}) });

  const svc = new Service({ name: 'policy-stub', corsOrigins: opts.corsOrigins });
  const admin = (req: { pubkey?: string; method: string; path: string; query: URLSearchParams }) => {
    if (!req.pubkey || !opts.adminPubkeys.includes(req.pubkey)) throw new HttpError(403, 'admin only');
    const qs = req.query.toString();
    calls.push({ method: req.method, path: req.path + (qs ? `?${qs}` : ''), pubkey: req.pubkey });
    return req.pubkey;
  };

  const revokeDevice = (actor: string, d: StubDevice, reason: string) => {
    d.revokedAt = now();
    log(actor, 'device.revoke', d.id, { reason });
    const out: StubRotation[] = [];
    for (const r of resources.values())
      if (r.kind === 'group' && r.members?.includes(d.ownerPubkey)) {
        const rot: StubRotation = { id: randomBytes(6).toString('hex'), at: now(), resourceId: r.id, reason: `device ${d.id} ${reason}`, removedPubkey: d.ownerPubkey, status: 'pending' };
        rotations.push(rot);
        out.push(rot);
      }
    return out;
  };

  svc.get('/v1/subjects', (req) => (admin(req), { subjects: [...subjects.values()] }), 'nip98');
  svc.put('/v1/subjects/:pubkey', (req) => {
    const actor = admin(req);
    if (!isHex64(req.params.pubkey)) throw new HttpError(400, 'invalid pubkey');
    const b = req.json<Partial<Subject>>();
    const prev = subjects.get(req.params.pubkey!);
    subjects.set(req.params.pubkey!, { pubkey: req.params.pubkey!, roles: b.roles ?? [], attributes: b.attributes ?? {}, ...(prev?.suspended ? { suspended: true } : {}) });
    log(actor, 'subject.upsert', req.params.pubkey!, { roles: b.roles ?? [] });
    return { ok: true };
  }, 'nip98');
  svc.post('/v1/subjects/:pubkey/revoke', (req) => {
    const actor = admin(req);
    const pk = req.params.pubkey!;
    const s = subjects.get(pk);
    if (s) s.suspended = true;
    const rots: StubRotation[] = [];
    for (const d of devices.values()) if (d.ownerPubkey === pk && d.revokedAt === undefined) rots.push(...revokeDevice(actor, d, 'subject revoked'));
    for (const r of resources.values()) if (r.members) r.members = r.members.filter((m) => m !== pk);
    log(actor, 'subject.revoke', pk);
    return { rotations: rots };
  }, 'nip98');

  svc.get('/v1/resources', (req) => (admin(req), { resources: [...resources.values()] }), 'nip98');
  svc.put('/v1/resources/:id', (req) => {
    const actor = admin(req);
    const b = req.json<Omit<Resource, 'id'>>();
    requireFields(b, ['kind', 'sensitivity']);
    resources.set(req.params.id!, { id: req.params.id!, kind: b.kind, sensitivity: b.sensitivity, rules: b.rules ?? [], ...(b.members ? { members: b.members } : {}) });
    log(actor, 'resource.upsert', req.params.id!, { sensitivity: b.sensitivity });
    return { ok: true };
  }, 'nip98');

  svc.get('/v1/devices', (req) => {
    admin(req);
    const owner = req.query.get('owner');
    if (!isHex64(owner)) throw new HttpError(400, 'owner required');
    return { devices: [...devices.values()].filter((d) => d.ownerPubkey === owner) };
  }, 'nip98');
  svc.post('/v1/devices', (req) => {
    const actor = admin(req);
    const b = req.json<{ owner: string; trust?: Device['trust'] }>();
    if (!isHex64(b.owner)) throw new HttpError(400, 'invalid owner');
    const d: StubDevice = { id: randomBytes(8).toString('hex'), ownerPubkey: b.owner, trust: b.trust ?? 'registered', registeredAt: now() };
    devices.set(d.id, d);
    log(actor, 'device.register', d.id, { owner: b.owner, trust: d.trust });
    return { status: 201, body: d };
  }, 'nip98');
  svc.post('/v1/devices/:id/revoke', (req) => {
    const actor = admin(req);
    const d = devices.get(req.params.id!);
    if (!d) throw new HttpError(404, 'unknown device');
    return { rotations: revokeDevice(actor, d, req.json<{ reason?: string }>().reason ?? 'revoked') };
  }, 'nip98');
  svc.post('/v1/devices/:id/webauthn/options', (req) => {
    admin(req);
    const d = devices.get(req.params.id!);
    if (!d || d.revokedAt !== undefined) throw new HttpError(404, 'unknown device');
    const origin = String(req.headers.origin ?? '');
    const challenge = randomBytes(32).toString('base64url');
    challenges.set(d.id, { challenge, origin });
    return {
      challenge,
      rp: { name: 'Acceso Nostr', id: origin ? new URL(origin).hostname : 'localhost' },
      user: { id: Buffer.from(d.id).toString('base64url'), name: d.id, displayName: `Dispositivo ${d.id.slice(0, 6)}` },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      timeout: 60_000,
      attestation: 'none',
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      excludeCredentials: d.credentialId ? [{ type: 'public-key', id: d.credentialId }] : [],
    };
  }, 'nip98');
  svc.post('/v1/devices/:id/webauthn/register', (req) => {
    const actor = admin(req);
    const d = devices.get(req.params.id!);
    const pending = challenges.get(req.params.id!);
    if (!d || !pending) throw new HttpError(400, 'no pending registration');
    const cred = req.json<{ id?: string; rawId?: string; type?: string; response?: { clientDataJSON?: string; attestationObject?: string } }>();
    if (cred.type !== 'public-key' || !cred.id || cred.rawId !== cred.id || !cred.response?.attestationObject) throw new HttpError(400, 'malformed credential');
    const client = JSON.parse(Buffer.from(cred.response.clientDataJSON ?? '', 'base64url').toString('utf8')) as { type?: string; challenge?: string; origin?: string };
    if (client.type !== 'webauthn.create' || client.challenge !== pending.challenge || client.origin !== pending.origin) throw new HttpError(400, 'clientData mismatch');
    challenges.delete(d.id);
    d.trust = 'attested';
    d.credentialId = cred.id;
    log(actor, 'device.webauthn', d.id);
    return d;
  }, 'nip98');

  svc.get('/v1/audit', (req) => {
    admin(req);
    const limit = Math.min(Math.max(Number(req.query.get('limit') ?? 50) || 50, 1), 200);
    const before = req.query.get('before');
    const list = audit.filter((e) => before === null || e.id < Number(before)).sort((a, b) => b.id - a.id);
    return { audit: list.slice(0, limit) };
  }, 'nip98');

  svc.get('/v1/rotations', (req) => {
    admin(req);
    const status = req.query.get('status');
    return { rotations: rotations.filter((r) => !status || r.status === status) };
  }, 'nip98');
  svc.post('/v1/rotations/:id/done', (req) => {
    const actor = admin(req);
    const r = rotations.find((x) => x.id === req.params.id);
    if (!r) throw new HttpError(404, 'unknown rotation');
    r.status = 'done';
    log(actor, 'rotation.done', r.id, { resourceId: r.resourceId });
    return { ok: true };
  }, 'nip98');

  svc.get('/v1/directory', (req) => (admin(req), { entries: [...directory.values()] }), 'nip98');
  svc.put('/v1/directory/:pubkey', (req) => {
    const actor = admin(req);
    if (!isHex64(req.params.pubkey)) throw new HttpError(400, 'invalid pubkey');
    const b = req.json<{ title?: string; unit?: string }>();
    directory.set(req.params.pubkey!, { pubkey: req.params.pubkey!, ...(b.title ? { title: b.title } : {}), ...(b.unit ? { unit: b.unit } : {}) });
    log(actor, 'directory.upsert', req.params.pubkey!);
    return { ok: true };
  }, 'nip98');
  svc.delete('/v1/directory/:pubkey', (req) => {
    const actor = admin(req);
    if (!directory.delete(req.params.pubkey!)) throw new HttpError(404, 'not found');
    log(actor, 'directory.delete', req.params.pubkey!);
    return { ok: true };
  }, 'nip98');

  svc.get('/v1/retention', (req) => (admin(req), { policies: [...retention.values()], notice: RETENTION_NOTICE }), 'nip98');
  svc.put('/v1/retention/:resourceId', (req) => {
    const actor = admin(req);
    const b = req.json<{ days?: number | null; legalHold?: boolean }>();
    if (b.days !== null && (typeof b.days !== 'number' || !Number.isInteger(b.days) || b.days < 1)) throw new HttpError(400, 'invalid days');
    if (typeof b.legalHold !== 'boolean') throw new HttpError(400, 'invalid legalHold');
    retention.set(req.params.resourceId!, { resourceId: req.params.resourceId!, days: b.days, legalHold: b.legalHold });
    log(actor, 'retention.set', req.params.resourceId!, { days: b.days, legalHold: b.legalHold });
    return { ok: true };
  }, 'nip98');

  return { svc, subjects, resources, devices, rotations, directory, retention, audit, calls };
}
