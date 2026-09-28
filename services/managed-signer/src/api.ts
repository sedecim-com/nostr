import { Service, HttpError, requireFields, isHex64, lookupToken, CognitoTokenError, type CognitoVerifier, type Req, type ServiceOptions } from '@sedecim/service-kit';
import type { EventTemplate } from '@sedecim/nostr-core';
import { DEVICE_SESSION_PREFIX, ManagedSigner, ManagedSignerError, RateLimitedError, type Actor } from './service';

export interface ManagedSignerApiOptions extends Omit<ServiceOptions, 'bearerTokens'> {
  /** End users authorize with their Acceso (Cognito) token; the key owner is `${issuer}#${sub}` (FR005-04). */
  cognito?: CognitoVerifier;
  /**
   * FR024-03: tokens (token -> principal, e.g. the policy side / rotation worker) allowed to call
   * `POST /v1/devices/:id/revoke`. They can do nothing else.
   */
  revocationTokens?: Record<string, string>;
  /** Key operations only through device sessions (`sds_...`): a bare Acceso token only opens sessions. */
  requireDeviceSession?: boolean;
}

interface Caller extends Actor {
  owner: string;
  /** Authenticated with a device session token. */
  viaDeviceSession?: boolean;
}

const DEVICE_ID = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * FR005-08: a managed (custodial) key is only created or imported with its owner's recorded consent: the version
 * of the texts and terms they accepted, as the client showed them (e.g. "textos 1.3.0; términos 2026-10").
 */
function consentVersion(body: { consent_version?: unknown }): string {
  const v = body.consent_version;
  if (typeof v !== 'string' || !/^[\p{L}\p{N} .;:()/_+-]{1,128}$/u.test(v)) {
    throw new HttpError(400, 'consent_version required: the version of the texts and terms the owner accepted (FR005-08)');
  }
  return v;
}

/**
 * Managed signer HTTP API. Every call is custodial and audited. Callers authenticate with
 * `Authorization: Bearer <token>`: the user's Acceso (Cognito) id/access token or a device session opened with
 * it, so they only ever reach their own keys. The legacy mode where a service token acted for the account
 * named in `x-account-id` was removed (FR005-12): that header is refused, never ignored.
 */
export function createManagedSignerApi(core: ManagedSigner, opts: ManagedSignerApiOptions) {
  const { cognito, revocationTokens, requireDeviceSession, ...serviceOpts } = opts;
  const svc = new Service(serviceOpts);
  const log = svc.logger;

  const bearer = (req: Req) => {
    const header = req.headers.authorization;
    const token = header?.startsWith('Bearer ') ? header.slice(7).trim() : '';
    if (!token) throw new HttpError(401, 'bearer token required');
    return token;
  };
  /** Optional `x-device-id` from Acceso/service callers: a revoked device is refused. */
  const claimedDevice = (req: Req) => {
    const d = req.headers['x-device-id'];
    if (d === undefined) return undefined;
    if (typeof d !== 'string' || !DEVICE_ID.test(d)) throw new HttpError(400, 'invalid x-device-id');
    return d;
  };

  const authenticate = async (req: Req): Promise<Caller> => {
    const token = bearer(req);
    // Never let a caller pick the owner: it always comes from the verified token or device session.
    if (req.headers['x-account-id'] !== undefined) throw new HttpError(403, 'x-account-id is not accepted: the owner is the authenticated user');
    if (token.startsWith(DEVICE_SESSION_PREFIX)) {
      const s = await core.resolveDeviceSession(token);
      return { ...s, viaDeviceSession: true };
    }
    const deviceId = claimedDevice(req);
    await core.assertDeviceUsable(deviceId);
    if (!cognito) throw new HttpError(401, 'invalid bearer token');
    let who;
    try {
      who = await cognito.verify(token);
    } catch (err) {
      if (err instanceof CognitoTokenError) throw new HttpError(401, `invalid Acceso token: ${err.message}`);
      throw err;
    }
    const owner = `${who.issuer}#${who.subject}`;
    return { owner, principal: owner, ...(deviceId ? { deviceId } : {}) };
  };

  const mapErrors = async (fn: () => Promise<unknown>) => {
    try {
      return await fn();
    } catch (err) {
      if (err instanceof RateLimitedError) {
        log.warn('managed signer rate limited', { scope: err.scope, retry_after_s: err.retryAfterSeconds });
        return { status: 429, headers: { 'retry-after': String(err.retryAfterSeconds) }, body: { error: err.message } };
      }
      if (err instanceof ManagedSignerError) throw new HttpError(err.status, err.message);
      throw err;
    }
  };
  /** `keyOp`: operations on keys, which `requireDeviceSession` restricts to device sessions. */
  const route = (fn: (req: Req, caller: Caller) => Promise<unknown>, keyOp = true) => (req: Req) =>
    mapErrors(async () => {
      const caller = await authenticate(req);
      if (keyOp && requireDeviceSession && !caller.viaDeviceSession) throw new HttpError(403, 'device session required');
      return fn(req, caller);
    });

  svc.get('/health', () => ({ ok: true, custodial: true }), 'none', { rateClass: 'none' });

  // FR024-03: device-bound sessions. Opened with an Acceso (or service) token, never from another session.
  svc.post('/v1/device-sessions', route(async (req, c) => {
    if (c.viaDeviceSession) throw new HttpError(403, 'a device session cannot open another one');
    const body = req.json<{ device_id?: string; ttl_seconds?: number }>();
    if (typeof body.device_id !== 'string' || !DEVICE_ID.test(body.device_id)) throw new HttpError(400, 'invalid device_id');
    if (body.ttl_seconds !== undefined && !(Number.isInteger(body.ttl_seconds) && body.ttl_seconds > 0)) throw new HttpError(400, 'invalid ttl_seconds');
    const s = await core.openDeviceSession(c.owner, c.principal, body.device_id, body.ttl_seconds === undefined ? undefined : body.ttl_seconds * 1000);
    log.info('device session opened', { device_id: body.device_id });
    return { status: 201, body: { token: s.token, device_id: body.device_id, expires_at: new Date(s.expiresAt).toISOString() } };
  }, false), 'none', { rateClass: 'auth' });
  // Called by the policy side when a device is revoked (idempotent). Revocation tokens only.
  svc.post('/v1/devices/:id/revoke', (req) =>
    mapErrors(async () => {
      const principal = lookupToken(revocationTokens, bearer(req));
      if (!principal) throw new HttpError(401, 'invalid revocation token');
      const deviceId = req.params.id!;
      if (!DEVICE_ID.test(deviceId)) throw new HttpError(400, 'invalid device id');
      const { reason } = req.json<{ reason?: unknown }>();
      const r = await core.revokeDevice(deviceId, principal, typeof reason === 'string' ? reason.slice(0, 200) : undefined);
      log.info('device revoked', { device_id: deviceId, by: principal, sessions_dropped: r.sessionsDropped, repeated: r.alreadyRevoked });
      return { revoked: true, already_revoked: r.alreadyRevoked, sessions_dropped: r.sessionsDropped };
    }),
  );
  svc.get('/v1/keys', route(async (_req, c) => ({ keys: await core.list(c.owner) })));
  svc.post('/v1/keys', route(async (req, c) => {
    const body = req.json<{ allowed_kinds?: number[]; consent_version?: string }>();
    if (body.allowed_kinds !== undefined && (!Array.isArray(body.allowed_kinds) || !body.allowed_kinds.every((k) => Number.isInteger(k) && k >= 0))) {
      throw new HttpError(400, 'invalid allowed_kinds');
    }
    const k = await core.create(c.owner, c.principal, { allowedKinds: body.allowed_kinds, consentVersion: consentVersion(body) });
    log.info('managed key created', { key_id: k.keyId, pubkey: k.pubkey });
    return { status: 201, body: await core.describe(k.keyId, c.owner) };
  }));
  svc.post('/v1/keys/import', route(async (req, c) => {
    const body = req.json<{ ncryptsec: string; password: string; consent_version?: string }>();
    requireFields(body, ['ncryptsec', 'password']);
    const k = await core.importEncrypted(c.owner, c.principal, body.ncryptsec, body.password, { consentVersion: consentVersion(body) });
    return { status: 201, body: await core.describe(k.keyId, c.owner) };
  }));
  svc.get('/v1/keys/:id', route((req, c) => core.describe(req.params.id!, c.owner)));
  svc.post('/v1/keys/:id/sign', route(async (req, c) => {
    const { template } = req.json<{ template: EventTemplate }>();
    if (!template || typeof template.kind !== 'number' || typeof template.content !== 'string') throw new HttpError(400, 'invalid template');
    const event = await core.sign(req.params.id!, c.owner, c, template);
    log.info('managed signature', { key_id: req.params.id, kind: event.kind, event_id: event.id });
    return { event };
  }));
  for (const op of ['encrypt', 'decrypt'] as const) {
    svc.post(`/v1/keys/:id/nip44/${op}`, route(async (req, c) => {
      const body = req.json<{ peer: string; plaintext?: string; ciphertext?: string }>();
      if (!isHex64(body.peer)) throw new HttpError(400, 'invalid peer');
      const data = op === 'encrypt' ? body.plaintext : body.ciphertext;
      if (typeof data !== 'string') throw new HttpError(400, 'missing data');
      const out = await core.nip44(req.params.id!, c.owner, c, op, body.peer, data);
      return op === 'encrypt' ? { ciphertext: out } : { plaintext: out };
    }));
  }
  svc.post('/v1/keys/:id/export', route(async (req, c) => {
    const { password } = req.json<{ password: string }>();
    return core.export(req.params.id!, c.owner, c.principal, password ?? '');
  }));
  svc.post('/v1/keys/:id/confirm-migration', route(async (req, c) => {
    const { proof } = req.json<{ proof: unknown }>();
    return { state: (await core.confirmMigration(req.params.id!, c.owner, c.principal, proof)).state };
  }));
  svc.delete('/v1/keys/:id', route(async (req, c) => {
    const { destroyAfter } = await core.delete(req.params.id!, c.owner, c.principal);
    return { deleted: true, destroy_after: new Date(destroyAfter).toISOString() };
  }));
  svc.get('/v1/keys/:id/usage', route(async (req, c) => ({ usage: await core.usageOf(req.params.id!, c.owner) })));
  return svc;
}
