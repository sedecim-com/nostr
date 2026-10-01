import { Service, HttpError, isHex64, lookupToken, requireFields, type Req, type ServiceOptions } from '@sedecim/service-kit';
import type { Action, Resource, Subject, Device, Rotation } from '@sedecim/policy-client';
import { ConflictError, DEFAULT_ACCESS_LOG_RETENTION_DAYS, FeatureDisabledError, InvalidInputError, NotFoundError, PolicyEngine, RETENTION_NOTICE, SessionDeniedError } from './engine';
import { WebAuthnError, type AssertionCredentialJSON, type RegistrationCredentialJSON } from './webauthn';

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
    if (e instanceof NotFoundError || e instanceof FeatureDisabledError) throw new HttpError(404, e.message);
    if (e instanceof ConflictError) throw new HttpError(409, e.message);
    if (e instanceof InvalidInputError) throw new HttpError(400, e.message);
    if (e instanceof WebAuthnError) throw new HttpError(400, `webauthn: ${e.message}`);
    if (e instanceof SessionDeniedError) throw new HttpError(403, e.message);
    throw e;
  }
}

/**
 * IR-2026-10-01: what a service token may call, by the principal it names in POLICY_SERVICE_TOKENS (`token:principal`).
 * OPS-16: `events` reads the signed event stream (an integration's token; no principal has it by default).
 */
export type ServiceScope = 'evaluate' | 'retention' | 'relay' | 'rotations' | 'events';
export const SERVICE_SCOPES: readonly ServiceScope[] = ['evaluate', 'retention', 'relay', 'rotations', 'events'];

/**
 * The principals our own services use and what each one needs: the indexer evaluates reads and reads the retention,
 * the relay-allowlist reads the allowlist and the publish grants, the rotation worker reads rotations and revocations
 * and closes rotations. Any other principal calls nothing until POLICY_SERVICE_SCOPES names what it may call.
 */
export const DEFAULT_SERVICE_SCOPES: Readonly<Record<string, readonly ServiceScope[]>> = {
  indexer: ['evaluate', 'retention'],
  'relay-allowlist': ['relay'],
  'rotation-worker': ['rotations'],
};

/**
 * POLICY_SERVICE_SCOPES: `principal=scope+scope,...` (scopes: evaluate, retention, relay, rotations, events), added to or
 * replacing the defaults; `principal=` leaves a principal without any.
 */
export function parseServiceScopes(v: string | undefined): Record<string, ServiceScope[]> {
  const out: Record<string, ServiceScope[]> = Object.fromEntries(Object.entries(DEFAULT_SERVICE_SCOPES).map(([p, s]) => [p, [...s]]));
  for (const entry of (v ?? '').split(',').map((e) => e.trim()).filter(Boolean)) {
    const [principal, list = '', ...rest] = entry.split('=');
    if (!principal || rest.length > 0) throw new Error(`POLICY_SERVICE_SCOPES: '${entry}' is not principal=scope+scope`);
    const scopes = list.split('+').map((x) => x.trim()).filter(Boolean);
    const unknown = scopes.filter((x) => !SERVICE_SCOPES.includes(x as ServiceScope));
    if (unknown.length) throw new Error(`POLICY_SERVICE_SCOPES: unknown scope ${unknown.join(', ')} for ${principal} (${SERVICE_SCOPES.join(', ')})`);
    out[principal.trim()] = scopes as ServiceScope[];
  }
  return out;
}

/**
 * Admin routes are NIP-98 and restricted to configured admin pubkeys; evaluate/allowlist are callable by
 * relays/services (bearer), each service only for the scopes of its principal (IR-2026-10-01). A few routes accept
 * either (see `adminOrService`). The directory and the audit are never served without admin authentication.
 */
export function createPolicyApi(
  engine: PolicyEngine,
  opts: ServiceOptions & { adminPubkeys: string[]; accessLogRetentionDays?: number; serviceScopes?: Record<string, readonly ServiceScope[]> },
) {
  const svc = new Service(opts);
  const scopes = opts.serviceScopes ?? DEFAULT_SERVICE_SCOPES;
  /** A service principal may call a route only with that route's scope: the indexer's token cannot close rotations. */
  const inScope = (principal: string, scope: ServiceScope) => {
    if (!scopes[principal]?.includes(scope)) throw new HttpError(403, `service '${principal}' may not call this route (scope ${scope}; see POLICY_SERVICE_SCOPES)`);
  };
  /** 'bearer' routes: the authenticated service must hold the scope. */
  const service = (req: Req, scope: ServiceScope) => inScope(req.principal!, scope);
  const admin = (pubkey?: string) => {
    if (!pubkey || !opts.adminPubkeys.includes(pubkey)) throw new HttpError(403, 'admin only');
    return pubkey;
  };
  /** 'nip98-or-token' routes: an admin (NIP-98) or a configured service bearer token with the scope. Returns the actor. */
  const adminOrService = (req: Req, scope: ServiceScope): string => {
    if (req.token !== undefined) {
      const principal = lookupToken(opts.bearerTokens, req.token);
      if (!principal) throw new HttpError(401, 'invalid bearer token');
      req.limitPrincipal(`service:${principal}`);
      inScope(principal, scope);
      return `service:${principal}`;
    }
    return admin(req.pubkey);
  };
  /**
   * FR023-07/FR023-11: who may register a passkey on a device: an admin, or its owner until they register their first
   * one. Any other (for a new device, replacing one, or after revoking the device that held it) goes through an admin:
   * whoever holds only the owner's Nostr key must not enroll an authenticator of their own and open sessions with it.
   * To anyone else the device does not exist, so a 403 cannot confirm that an id is in use.
   */
  const passkeyEnroller = async (req: Req) => {
    const d = await engine.getDevice(req.params.id!);
    const isAdmin = !!req.pubkey && opts.adminPubkeys.includes(req.pubkey);
    if (!d || (!isAdmin && req.pubkey !== d.ownerPubkey)) throw new HttpError(404, 'unknown device');
    if (isAdmin) return req.pubkey!;
    if (await engine.passkeyBound(d.ownerPubkey)) throw new HttpError(403, 'this owner already registered a passkey: an admin registers any other');
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
    const owner = req.query.get('owner') ?? undefined;
    // FR023-11: an owner reads their own devices, to register a passkey and open sessions on them; the rest is for admins.
    if (owner === undefined || owner !== req.pubkey) admin(req.pubkey);
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
    await passkeyEnroller(req);
    return run(() => engine.webauthnOptions(req.params.id!));
  }, 'nip98');
  svc.post('/v1/devices/:id/webauthn/register', async (req) => {
    const actor = await passkeyEnroller(req);
    const body = req.json<RegistrationCredentialJSON | { credential: RegistrationCredentialJSON } | null>();
    if (!body || typeof body !== 'object') throw new HttpError(400, 'credential JSON required');
    const credential = 'credential' in body ? body.credential : body;
    return run(() => engine.webauthnRegister(actor, req.params.id!, credential));
  }, 'nip98');
  // FR023-11: only the owner, who is the only one who can open a session on the device.
  svc.post('/v1/devices/:id/webauthn/assert/options', async (req) => run(() => engine.webauthnAssertionOptions(req.pubkey!, req.params.id!)), 'nip98');

  /**
   * FR023-11: `{deviceId, assertion?}` (`device_id` still accepted). The assertion is the JSON of navigator.credentials.get
   * on the challenge of /webauthn/assert/options; an owner who registered a passkey cannot open a session without one.
   */
  svc.post('/v1/sessions', async (req) => {
    const body = req.json<{ deviceId?: unknown; device_id?: unknown; assertion?: unknown } | null>();
    if (!body || typeof body !== 'object') throw new HttpError(400, 'JSON object required');
    const deviceId = body.deviceId ?? body.device_id;
    if (typeof deviceId !== 'string' || !deviceId) throw new HttpError(400, 'deviceId required');
    const { assertion } = body;
    if (assertion !== undefined && (!assertion || typeof assertion !== 'object')) throw new HttpError(400, 'assertion must be the JSON of navigator.credentials.get()');
    const token = await run(() => engine.openSession(req.pubkey!, deviceId, assertion as AssertionCredentialJSON | undefined));
    return { status: 201, body: { token, deviceId, asserted: assertion !== undefined } };
  }, 'nip98');

  svc.post('/v1/evaluate', async (req) => {
    service(req, 'evaluate');
    const body = req.json<{ pubkey: string; deviceId?: string; resourceId: string; action: Action }>();
    requireFields(body, ['pubkey', 'resourceId', 'action']);
    return engine.evaluate(body);
  }, 'bearer');
  svc.get('/v1/relay/allowlist', async (req) => (service(req, 'relay'), { pubkeys: await engine.relayAllowlist() }), 'bearer');
  // FR023-10: per-resource publish grants for the relays' admission by `h` (relay-allowlist).
  svc.get('/v1/relay/grants', async (req) => (service(req, 'relay'), { grants: await engine.relayPublishGrants() }), 'bearer');

  // FR024-05: the rotation worker reads them with its service token, so its Nostr key need not be a policy admin.
  svc.get('/v1/rotations', async (req) => {
    adminOrService(req, 'rotations');
    const status = req.query.get('status');
    if (status !== null && status !== 'pending' && status !== 'done') throw new HttpError(400, "status must be 'pending' or 'done'");
    return { rotations: await engine.listRotations((status ?? undefined) as Rotation['status'] | undefined) };
  }, 'nip98-or-token');
  svc.post('/v1/rotations/:id/done', async (req) => {
    const actor = adminOrService(req, 'rotations');
    // Wrapped: a Rotation has a `status` field, which Service would read as the HTTP status.
    return { body: await run(() => engine.markRotationDone(actor, req.params.id!)) };
  }, 'nip98-or-token');

  svc.get('/v1/audit', async (req) => {
    admin(req.pubkey);
    return { audit: await engine.listAudit({ limit: intParam(req, 'limit', 1), before: intParam(req, 'before', 1) }) };
  }, 'nip98');
  // FR023-12: access decisions (evaluate) live in their own log, kept ACCESS_LOG_RETENTION_DAYS (legal hold aside).
  svc.get('/v1/access-log', async (req) => {
    admin(req.pubkey);
    const resource = req.query.get('resource') ?? undefined;
    return {
      access: await engine.listAccessLog({ limit: intParam(req, 'limit', 1), before: intParam(req, 'before', 1), ...(resource ? { resourceId: resource } : {}) }),
      retentionDays: opts.accessLogRetentionDays ?? DEFAULT_ACCESS_LOG_RETENTION_DAYS,
    };
  }, 'nip98');
  // FR024-04: feed of the revocation propagator (an admin, or the rotation worker's service token).
  svc.get('/v1/revocations', async (req) => {
    adminOrService(req, 'rotations');
    return engine.listRevocations({ after: intParam(req, 'after', 0), limit: intParam(req, 'limit', 1) });
  }, 'nip98-or-token');

  // OPS-16: the signed events, from a cursor, instead of polling the audit (an admin, or a token with the `events` scope).
  svc.get('/v1/events', async (req) => {
    adminOrService(req, 'events');
    return run(() => engine.listEvents({ after: intParam(req, 'after', 0), limit: intParam(req, 'limit', 1) }));
  }, 'nip98-or-token');
  // OPS-16: the public keys that verify them, for anyone (JWKS).
  svc.get('/v1/events/keys', () => run(() => engine.eventKeys()), 'none');
  svc.get('/v1/webhooks', async (req) => (admin(req.pubkey), { webhooks: await run(() => engine.listWebhooks()) }), 'nip98');
  // The only answer that carries the subscription's secret.
  svc.post('/v1/webhooks', async (req) => {
    const actor = admin(req.pubkey);
    const body = req.json<{ url?: unknown; types?: unknown } | null>();
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError(400, 'JSON object required');
    return { status: 201, body: await run(() => engine.createWebhook(actor, { url: body.url, types: body.types })) };
  }, 'nip98');
  svc.delete('/v1/webhooks/:id', async (req) => {
    const actor = admin(req.pubkey);
    await run(() => engine.deleteWebhook(actor, req.params.id!));
    return { ok: true };
  }, 'nip98');
  svc.post('/v1/webhooks/:id/enable', async (req) => {
    const actor = admin(req.pubkey);
    return { webhook: await run(() => engine.enableWebhook(actor, req.params.id!)) };
  }, 'nip98');
  svc.get('/v1/webhooks/:id/deliveries', async (req) => {
    admin(req.pubkey);
    return { deliveries: await run(() => engine.listWebhookDeliveries(req.params.id!, { limit: intParam(req, 'limit', 1), before: intParam(req, 'before', 1) })) };
  }, 'nip98');

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
  svc.get('/v1/retention', async (req) => (adminOrService(req, 'retention'), { policies: await engine.listRetention(), notice: RETENTION_NOTICE }), 'nip98-or-token');
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
