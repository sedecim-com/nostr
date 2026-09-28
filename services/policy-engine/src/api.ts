import { Service, HttpError, isHex64, lookupToken, requireFields, type Req, type ServiceOptions } from '@sedecim/service-kit';
import type { Action, Resource, Subject, Device, Rotation } from '@sedecim/policy-client';
import { ConflictError, NotFoundError, PolicyEngine, RETENTION_NOTICE } from './engine';
import { WebAuthnError, type RegistrationCredentialJSON } from './webauthn';

const TEXT_MAX = 200;
const optText = (v: unknown, field: string): string | undefined => {
  if (v === undefined || v === null || v === '') return undefined;
  if (typeof v !== 'string' || v.length > TEXT_MAX) throw new HttpError(400, `${field} must be a string of up to ${TEXT_MAX} chars`);
  return v;
};

/** Optional integer query parameter of at least `min`. */
const intParam = (req: Req, k: string, min: number): number | undefined => {
  const v = req.query.get(k);
  if (v === null || v === '') return undefined;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < min) throw new HttpError(400, min === 1 ? `${k} must be a positive integer` : `${k} must be an integer of at least ${min}`);
  return n;
};

/** Maps engine errors to HTTP statuses. */
async function run<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof HttpError) throw e;
    if (e instanceof NotFoundError) throw new HttpError(404, e.message);
    if (e instanceof ConflictError) throw new HttpError(409, e.message);
    if (e instanceof WebAuthnError) throw new HttpError(400, `webauthn: ${e.message}`);
    throw e;
  }
}

/**
 * Admin routes are NIP-98 and restricted to configured admin pubkeys; evaluate/allowlist are callable by
 * relays/services (bearer). A few routes accept either (see `adminOrService`). The directory and the
 * audit are never served without admin authentication.
 */
export function createPolicyApi(engine: PolicyEngine, opts: ServiceOptions & { adminPubkeys: string[] }) {
  const svc = new Service(opts);
  const admin = (pubkey?: string) => {
    if (!pubkey || !opts.adminPubkeys.includes(pubkey)) throw new HttpError(403, 'admin only');
    return pubkey;
  };
  /** 'nip98-or-token' routes: an admin (NIP-98) or a configured service bearer token. Returns the actor. */
  const adminOrService = (req: Req): string => {
    if (req.token !== undefined) {
      const principal = lookupToken(opts.bearerTokens, req.token);
      if (!principal) throw new HttpError(401, 'invalid bearer token');
      req.limitPrincipal(`service:${principal}`);
      return `service:${principal}`;
    }
    return admin(req.pubkey);
  };
  const deviceOwnerOrAdmin = async (req: Req) => {
    const d = await engine.getDevice(req.params.id!);
    if (!d) throw new HttpError(404, 'unknown device');
    if (req.pubkey !== d.ownerPubkey) admin(req.pubkey);
    return req.pubkey!;
  };

  svc.get('/health', () => ({ ok: true }), 'none', { rateClass: 'none' });

  svc.get('/v1/subjects', async (req) => (admin(req.pubkey), { subjects: await engine.listSubjects() }), 'nip98');
  svc.put('/v1/subjects/:pubkey', async (req) => {
    const actor = admin(req.pubkey);
    if (!isHex64(req.params.pubkey)) throw new HttpError(400, 'invalid pubkey');
    const body = req.json<Partial<Subject>>();
    await engine.upsertSubject(actor, { pubkey: req.params.pubkey!, roles: body.roles ?? [], attributes: body.attributes ?? {} });
    return { ok: true };
  }, 'nip98');
  svc.post('/v1/subjects/:pubkey/revoke', async (req) => ({ rotations: await engine.revokeSubject(admin(req.pubkey), req.params.pubkey!) }), 'nip98');
  svc.post('/v1/subjects/:pubkey/reactivate', async (req) => {
    const actor = admin(req.pubkey);
    await run(() => engine.reactivateSubject(actor, req.params.pubkey!));
    return { ok: true };
  }, 'nip98');

  svc.get('/v1/resources', async (req) => (admin(req.pubkey), { resources: await engine.listResources() }), 'nip98');
  svc.put('/v1/resources/:id', async (req) => {
    const actor = admin(req.pubkey);
    const body = req.json<Omit<Resource, 'id'>>();
    requireFields(body, ['kind', 'sensitivity']);
    await engine.upsertResource(actor, { id: req.params.id!, kind: body.kind, sensitivity: body.sensitivity, rules: body.rules ?? [], ...(body.members ? { members: body.members } : {}) });
    return { ok: true };
  }, 'nip98');

  svc.get('/v1/devices', async (req) => {
    admin(req.pubkey);
    const owner = req.query.get('owner') ?? undefined;
    if (owner !== undefined && !isHex64(owner)) throw new HttpError(400, 'invalid owner');
    return { devices: await engine.listDevices(owner) };
  }, 'nip98');
  svc.post('/v1/devices', async (req) => {
    const actor = admin(req.pubkey);
    const body = req.json<{ owner: string; trust?: Device['trust'] }>();
    if (!isHex64(body.owner)) throw new HttpError(400, 'invalid owner');
    if (body.trust !== undefined && body.trust !== 'unverified' && body.trust !== 'registered') throw new HttpError(400, "trust must be 'unverified' or 'registered' ('attested' requires WebAuthn)");
    return { status: 201, body: await engine.registerDevice(actor, body.owner, body.trust) };
  }, 'nip98');
  svc.post('/v1/devices/:id/revoke', async (req) => {
    const actor = admin(req.pubkey);
    return run(async () => ({ rotations: await engine.revokeDevice(actor, req.params.id!, req.json<{ reason?: string }>().reason) }));
  }, 'nip98');
  svc.post('/v1/devices/:id/webauthn/options', async (req) => {
    await deviceOwnerOrAdmin(req);
    return run(() => engine.webauthnOptions(req.params.id!));
  }, 'nip98');
  svc.post('/v1/devices/:id/webauthn/register', async (req) => {
    const actor = await deviceOwnerOrAdmin(req);
    const body = req.json<RegistrationCredentialJSON | { credential: RegistrationCredentialJSON } | null>();
    if (!body || typeof body !== 'object') throw new HttpError(400, 'credential JSON required');
    const credential = 'credential' in body ? body.credential : body;
    return run(() => engine.webauthnRegister(actor, req.params.id!, credential));
  }, 'nip98');

  svc.post('/v1/sessions', async (req) => {
    const { device_id } = req.json<{ device_id: string }>();
    try {
      return { status: 201, body: { token: await engine.openSession(req.pubkey!, device_id) } };
    } catch (e) {
      throw new HttpError(403, (e as Error).message);
    }
  }, 'nip98');

  svc.post('/v1/evaluate', async (req) => {
    const body = req.json<{ pubkey: string; deviceId?: string; resourceId: string; action: Action }>();
    requireFields(body, ['pubkey', 'resourceId', 'action']);
    return engine.evaluate(body);
  }, 'bearer');
  svc.get('/v1/relay/allowlist', async () => ({ pubkeys: await engine.relayAllowlist() }), 'bearer');

  svc.get('/v1/rotations', async (req) => {
    admin(req.pubkey);
    const status = req.query.get('status');
    if (status !== null && status !== 'pending' && status !== 'done') throw new HttpError(400, "status must be 'pending' or 'done'");
    return { rotations: await engine.listRotations((status ?? undefined) as Rotation['status'] | undefined) };
  }, 'nip98');
  svc.post('/v1/rotations/:id/done', async (req) => {
    const actor = adminOrService(req);
    // Wrapped: a Rotation has a `status` field, which Service would read as the HTTP status.
    return { body: await run(() => engine.markRotationDone(actor, req.params.id!)) };
  }, 'nip98-or-token');

  svc.get('/v1/audit', async (req) => {
    admin(req.pubkey);
    return { audit: await engine.listAudit({ limit: intParam(req, 'limit', 1), before: intParam(req, 'before', 1) }) };
  }, 'nip98');
  // FR024-04: feed of the revocation propagator (an admin, or the rotation worker's service token).
  svc.get('/v1/revocations', async (req) => {
    adminOrService(req);
    return engine.listRevocations({ after: intParam(req, 'after', 0), limit: intParam(req, 'limit', 1) });
  }, 'nip98-or-token');

  svc.get('/v1/directory', async (req) => (admin(req.pubkey), { entries: await engine.listDirectory() }), 'nip98');
  svc.put('/v1/directory/:pubkey', async (req) => {
    const actor = admin(req.pubkey);
    if (!isHex64(req.params.pubkey)) throw new HttpError(400, 'invalid pubkey');
    const body = req.json<{ title?: unknown; unit?: unknown }>();
    const title = optText(body.title, 'title');
    const unit = optText(body.unit, 'unit');
    const entry = { pubkey: req.params.pubkey!, ...(title ? { title } : {}), ...(unit ? { unit } : {}) };
    await engine.putDirectoryEntry(actor, entry);
    return entry;
  }, 'nip98');
  svc.delete('/v1/directory/:pubkey', async (req) => {
    const actor = admin(req.pubkey);
    await run(() => engine.deleteDirectoryEntry(actor, req.params.pubkey!));
    return { ok: true };
  }, 'nip98');

  // Services (the indexer's retention job) read policies with a bearer token; only admins change them.
  svc.get('/v1/retention', async (req) => (adminOrService(req), { policies: await engine.listRetention(), notice: RETENTION_NOTICE }), 'nip98-or-token');
  svc.put('/v1/retention/:resourceId', async (req) => {
    const actor = admin(req.pubkey);
    const body = req.json<{ days?: unknown; legalHold?: unknown }>();
    if (body.days !== null && (!Number.isSafeInteger(body.days) || (body.days as number) < 1 || (body.days as number) > 36_500)) throw new HttpError(400, 'days must be null or an integer between 1 and 36500');
    if (typeof body.legalHold !== 'boolean') throw new HttpError(400, 'legalHold must be a boolean');
    const policy = { resourceId: req.params.resourceId!, days: body.days as number | null, legalHold: body.legalHold };
    await run(() => engine.putRetention(actor, policy));
    return { policy, notice: RETENTION_NOTICE };
  }, 'nip98');
  return svc;
}
