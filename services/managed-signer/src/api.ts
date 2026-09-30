import { Service, HttpError, requireFields, isHex64, lookupToken, CognitoTokenError, type CognitoVerifier, type Req, type ServiceOptions } from '@sedecim/service-kit';
import type { EventTemplate } from '@sedecim/nostr-core';
import { DEVICE_SESSION_PREFIX, ManagedSigner, ManagedSignerError, RateLimitedError, ReauthRequiredError, type Actor } from './service';

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
  /**
   * IR-2026-10-03: how recent (seconds) the Acceso sign-in must be to export a key, confirm its migration, delete it,
   * cancel its custody or close the other sessions (default 300). Those calls never go through a device session.
   */
  reauthMaxAgeSeconds?: number;
}

/** IR-2026-10-03: default age limit of the Acceso sign-in for the calls that let a key out or destroy it. */
export const DEFAULT_REAUTH_MAX_AGE_S = 300;
/** A sign-in stamped this far ahead of our clock is still believed (clock skew with Cognito). */
const AUTH_TIME_SKEW_S = 60;

interface Caller extends Actor {
  owner: string;
  /** Authenticated with a device session token. */
  viaDeviceSession?: boolean;
  /** That session's public id (FR005-11). */
  sessionId?: string;
  /** Acceso callers: when they last signed in with their password (`auth_time`, seconds) and which sign-in it is. */
  authTime?: number;
  loginId?: string;
}

const SESSION_ID = /^[0-9a-f]{32}$/;

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

/** FR005-10: the client's own nonce for an enclave attestation: base64url (no padding) of 16 to 64 bytes. */
function attestationNonce(v: string | null): Uint8Array {
  const bytes = typeof v === 'string' && /^[A-Za-z0-9_-]+$/.test(v) ? Buffer.from(v, 'base64url') : Buffer.alloc(0);
  if (bytes.length < 16 || bytes.length > 64 || bytes.toString('base64url') !== v) throw new HttpError(400, 'nonce must be base64url of 16 to 64 bytes');
  return new Uint8Array(bytes);
}

/**
 * Managed signer HTTP API. Every call is custodial and audited. Callers authenticate with
 * `Authorization: Bearer <token>`: the user's Acceso (Cognito) id/access token or a device session opened with
 * it, so they only ever reach their own keys. The legacy mode where a service token acted for the account
 * named in `x-account-id` was removed (FR005-12): that header is refused, never ignored.
 */
export function createManagedSignerApi(core: ManagedSigner, opts: ManagedSignerApiOptions) {
  const { cognito, revocationTokens, requireDeviceSession, reauthMaxAgeSeconds = DEFAULT_REAUTH_MAX_AGE_S, ...serviceOpts } = opts;
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
    // IR-2026-10-11: a login from before its owner closed their other sessions (a lost device's) is turned away.
    await core.assertLoginCurrent(owner, who.authTime, who.loginId);
    return { owner, principal: owner, ...(deviceId ? { deviceId } : {}), ...(who.authTime !== undefined ? { authTime: who.authTime } : {}), ...(who.loginId ? { loginId: who.loginId } : {}) };
  };

  /**
   * IR-2026-10-03: letting the key out (export, confirming the migration) or destroying it (delete, cancel), and cutting
   * off the other logins (closing the other sessions, IR-2026-10-11), take the owner's password again: an Acceso token
   * whose sign-in is at most `reauthMaxAgeSeconds` old, never a device session or an older login that a stolen browser
   * keeps refreshing.
   */
  const assertRecentSignIn = (c: Caller) => {
    if (c.viaDeviceSession) throw new ReauthRequiredError('this needs the Acceso login, not a device session: sign in again with your password', reauthMaxAgeSeconds);
    const age = Math.floor(Date.now() / 1000) - (c.authTime ?? -Infinity);
    if (!(age <= reauthMaxAgeSeconds && age >= -AUTH_TIME_SKEW_S)) {
      throw new ReauthRequiredError(`this needs a sign-in with your Acceso password from the last ${reauthMaxAgeSeconds} seconds: sign in again`, reauthMaxAgeSeconds);
    }
  };

  const mapErrors = async (fn: () => Promise<unknown>) => {
    try {
      return await fn();
    } catch (err) {
      if (err instanceof RateLimitedError) {
        log.warn('managed signer rate limited', { scope: err.scope, retry_after_s: err.retryAfterSeconds });
        return { status: 429, headers: { 'retry-after': String(err.retryAfterSeconds) }, body: { error: err.message } };
      }
      if (err instanceof ReauthRequiredError) {
        // RFC 9470 step-up; the body says the same for clients that cannot read the header.
        const maxAge = err.maxAgeSeconds === undefined ? '' : `, max_age=${err.maxAgeSeconds}`;
        log.info('managed signer asked for a recent sign-in', { max_age_s: err.maxAgeSeconds ?? null });
        return {
          status: 401,
          headers: { 'www-authenticate': `Bearer error="insufficient_user_authentication", error_description="${err.message}"${maxAge}` },
          body: { error: err.message, error_code: 'insufficient_user_authentication', ...(err.maxAgeSeconds === undefined ? {} : { max_age: err.maxAgeSeconds }) },
        };
      }
      if (err instanceof ManagedSignerError) throw new HttpError(err.status, err.message);
      throw err;
    }
  };
  /**
   * `kind`: 'key' operations, which `requireDeviceSession` restricts to device sessions; 'account' calls (the owner's
   * own sessions), open to both; 'sensitive' ones, only with a recent Acceso sign-in (assertRecentSignIn).
   */
  const route = (fn: (req: Req, caller: Caller) => Promise<unknown>, kind: 'key' | 'account' | 'sensitive' = 'key') => (req: Req) =>
    mapErrors(async () => {
      const caller = await authenticate(req);
      if (kind === 'key' && requireDeviceSession && !caller.viaDeviceSession) throw new HttpError(403, 'device session required');
      if (kind === 'sensitive') assertRecentSignIn(caller);
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
  }, 'account'), 'none', { rateClass: 'auth' });
  // FR005-11: the user's own sessions. Listed with the Acceso login or any of them; closed with the Acceso login, or
  // one by itself (sign out). Closing one never revokes its device (that is the organisation's call, below).
  svc.get('/v1/device-sessions', route(async (_req, c) => ({ sessions: await core.listDeviceSessions(c.owner, c.sessionId) }), 'account'));
  svc.delete('/v1/device-sessions/:id', route(async (req, c) => {
    const id = req.params.id!;
    if (!SESSION_ID.test(id)) throw new HttpError(400, 'invalid session id');
    if (c.viaDeviceSession && id !== c.sessionId) throw new HttpError(403, 'a device session can only close itself: close the others with the Acceso login');
    const closed = await core.closeDeviceSessions(c.owner, { ids: [id] });
    if (closed === 0) throw new HttpError(404, 'no such session');
    log.info('device session closed', { by: c.viaDeviceSession ? 'itself' : 'owner' });
    return { closed };
  }, 'account'));
  // IR-2026-10-11: it also cuts off the owner's other logins signed in before now (this one keeps working), so it takes a
  // recent sign-in: a thief with a stolen browser cannot lock its owner out.
  svc.delete('/v1/device-sessions', route(async (req, c) => {
    const except = req.query.get('except') ?? undefined;
    if (except !== undefined && !SESSION_ID.test(except)) throw new HttpError(400, 'invalid except');
    const closed = await core.closeDeviceSessions(c.owner, except === undefined ? {} : { except }, c.loginId);
    log.info('device sessions closed', { closed, kept: except ? 1 : 0, login_kept: !!c.loginId });
    return { closed };
  }, 'sensitive'));
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
  // FR026-04: before /v1/keys/:id, which would take "closed" for a key id.
  svc.get('/v1/keys/closed', route(async (_req, c) => ({ keys: await core.closed(c.owner) })));
  svc.post('/v1/keys', route(async (req, c) => {
    const body = req.json<{ allowed_kinds?: number[]; consent_version?: string }>();
    if (body.allowed_kinds !== undefined && (!Array.isArray(body.allowed_kinds) || !body.allowed_kinds.every((k) => Number.isInteger(k) && k >= 0))) {
      throw new HttpError(400, 'invalid allowed_kinds');
    }
    const k = await core.create(c.owner, c.principal, { allowedKinds: body.allowed_kinds, consentVersion: consentVersion(body) });
    log.info('managed key created', { key_id: k.keyId, pubkey: k.pubkey });
    return { status: 201, body: await core.describe(k.keyId, c.owner) };
  }));
  // FR005-10: the enclave's attestation for the caller's own nonce: the client verifies it before sealing an import or an
  // export password to the key in it. With the Acceso login or a device session (an import may come through one). It
  // makes the enclave sign a document, so it is limited like a write, not like a read.
  svc.get('/v1/enclave/attestation', route(async (req) => ({ document: Buffer.from(await core.enclaveAttestation(attestationNonce(req.query.get('nonce')))).toString('base64') }), 'account'), 'none', { rateClass: 'mutating' });
  svc.post('/v1/keys/import', route(async (req, c) => {
    const body = req.json<{ ncryptsec?: string; password?: string; sealed_secrets?: unknown; consent_version?: string }>();
    if (body.sealed_secrets !== undefined) {
      // FR005-10: sealed by the client to the enclave. Relayed as it is, never logged: this process cannot read it.
      if (body.ncryptsec !== undefined || body.password !== undefined) throw new HttpError(400, 'send ncryptsec and password, or sealed_secrets, not both');
      const k = await core.importSealed(c.owner, c.principal, body.sealed_secrets, { consentVersion: consentVersion(body) });
      return { status: 201, body: await core.describe(k.keyId, c.owner) };
    }
    requireFields(body, ['ncryptsec', 'password']);
    const k = await core.importEncrypted(c.owner, c.principal, body.ncryptsec!, body.password!, { consentVersion: consentVersion(body) });
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
  // IR-2026-10-03: the calls that let the key out or destroy it take a recent sign-in with the Acceso password.
  svc.post('/v1/keys/:id/export', route(async (req, c) => {
    const { password, sealed_password: sealedPassword } = req.json<{ password?: string; sealed_password?: unknown }>();
    // FR005-09: the same Acceso token that just authenticated this call is the enclave's proof of the owner.
    if (sealedPassword !== undefined) {
      // FR005-10: the password sealed by the client to the enclave; this process relays it and never holds it.
      if (password !== undefined) throw new HttpError(400, 'send password or sealed_password, not both');
      return core.exportSealed(req.params.id!, c.owner, c.principal, sealedPassword, undefined, bearer(req));
    }
    return core.export(req.params.id!, c.owner, c.principal, password ?? '', undefined, bearer(req));
  }, 'sensitive'));
  svc.post('/v1/keys/:id/confirm-migration', route(async (req, c) => {
    const { proof } = req.json<{ proof: unknown }>();
    return { state: (await core.confirmMigration(req.params.id!, c.owner, c.principal, proof)).state };
  }, 'sensitive'));
  svc.delete('/v1/keys/:id', route(async (req, c) => {
    const { destroyAfter } = await core.delete(req.params.id!, c.owner, c.principal);
    return { deleted: true, destroy_after: new Date(destroyAfter).toISOString() };
  }, 'sensitive'));
  svc.post('/v1/keys/:id/cancel', route(async (req, c) => {
    const { confirm } = req.json<{ confirm?: unknown }>();
    const { destroyAfter } = await core.cancel(req.params.id!, c.owner, c.principal, confirm);
    log.info('managed key cancelled', { key_id: req.params.id });
    return { cancelled: true, destroy_after: new Date(destroyAfter).toISOString() };
  }, 'sensitive'));
  svc.get('/v1/keys/:id/usage', route(async (req, c) => ({ usage: await core.usageOf(req.params.id!, c.owner) })));
  return svc;
}
