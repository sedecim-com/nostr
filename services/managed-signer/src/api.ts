import { timingSafeEqual } from 'node:crypto';
import { Service, HttpError, requireFields, isHex64, CognitoTokenError, type CognitoVerifier, type Req, type ServiceOptions } from '@sedecim/service-kit';
import type { EventTemplate } from '@sedecim/nostr-core';
import { ManagedSigner, ManagedSignerError } from './service';

export interface ManagedSignerApiOptions extends Omit<ServiceOptions, 'bearerTokens'> {
  /** End users authorize with their Acceso (Cognito) token; the key owner is `${issuer}#${sub}` (FR005-04). */
  cognito?: CognitoVerifier;
  /**
   * Legacy service-to-service mode (token -> principal), off unless configured: these principals act for
   * the account named in `x-account-id`. End users can never use that header.
   */
  serviceTokens?: Record<string, string>;
}

interface Caller {
  owner: string;
  principal: string;
}

/**
 * Managed signer HTTP API. Every call is custodial and audited. Callers authenticate with
 * `Authorization: Bearer <token>`: an Acceso (Cognito) id/access token for end users, who can only reach
 * their own keys, or (if enabled) a service token plus `x-account-id`.
 */
export function createManagedSignerApi(core: ManagedSigner, opts: ManagedSignerApiOptions) {
  const { cognito, serviceTokens, ...serviceOpts } = opts;
  const svc = new Service(serviceOpts);
  const log = svc.logger;

  const servicePrincipal = (token: string) =>
    Object.entries(serviceTokens ?? {}).find(([t]) => t.length === token.length && timingSafeEqual(Buffer.from(t), Buffer.from(token)))?.[1];

  const authenticate = async (req: Req): Promise<Caller> => {
    const header = req.headers.authorization;
    const token = header?.startsWith('Bearer ') ? header.slice(7).trim() : '';
    if (!token) throw new HttpError(401, 'bearer token required');
    const account = req.headers['x-account-id'];
    const principal = servicePrincipal(token);
    if (principal) {
      if (typeof account !== 'string' || !account) throw new HttpError(400, 'x-account-id header required');
      return { owner: account, principal };
    }
    if (!cognito) throw new HttpError(401, 'invalid bearer token');
    let who;
    try {
      who = await cognito.verify(token);
    } catch (err) {
      if (err instanceof CognitoTokenError) throw new HttpError(401, `invalid Acceso token: ${err.message}`);
      throw err;
    }
    // Never let an end user pick the owner: it always comes from the verified token.
    if (account !== undefined) throw new HttpError(403, 'x-account-id is only accepted from service principals');
    const owner = `${who.issuer}#${who.subject}`;
    return { owner, principal: owner };
  };

  const route = (fn: (req: Req, caller: Caller) => Promise<unknown>) => async (req: Req) => {
    try {
      return await fn(req, await authenticate(req));
    } catch (err) {
      if (err instanceof ManagedSignerError) throw new HttpError(err.status, err.message);
      throw err;
    }
  };

  svc.get('/health', () => ({ ok: true, custodial: true }));
  svc.get('/v1/keys', route(async (_req, c) => ({ keys: await core.list(c.owner) })));
  svc.post('/v1/keys', route(async (req, c) => {
    const body = req.json<{ allowed_kinds?: number[] }>();
    if (body.allowed_kinds !== undefined && (!Array.isArray(body.allowed_kinds) || !body.allowed_kinds.every((k) => Number.isInteger(k) && k >= 0))) {
      throw new HttpError(400, 'invalid allowed_kinds');
    }
    const k = await core.create(c.owner, c.principal, { allowedKinds: body.allowed_kinds });
    log.info('managed key created', { key_id: k.keyId, pubkey: k.pubkey });
    return { status: 201, body: await core.describe(k.keyId, c.owner) };
  }));
  svc.post('/v1/keys/import', route(async (req, c) => {
    const body = req.json<{ ncryptsec: string; password: string }>();
    requireFields(body, ['ncryptsec', 'password']);
    const k = await core.importEncrypted(c.owner, c.principal, body.ncryptsec, body.password);
    return { status: 201, body: await core.describe(k.keyId, c.owner) };
  }));
  svc.get('/v1/keys/:id', route((req, c) => core.describe(req.params.id!, c.owner)));
  svc.post('/v1/keys/:id/sign', route(async (req, c) => {
    const { template } = req.json<{ template: EventTemplate }>();
    if (!template || typeof template.kind !== 'number' || typeof template.content !== 'string') throw new HttpError(400, 'invalid template');
    const event = await core.sign(req.params.id!, c.owner, c.principal, template);
    log.info('managed signature', { key_id: req.params.id, kind: event.kind, event_id: event.id });
    return { event };
  }));
  for (const op of ['encrypt', 'decrypt'] as const) {
    svc.post(`/v1/keys/:id/nip44/${op}`, route(async (req, c) => {
      const body = req.json<{ peer: string; plaintext?: string; ciphertext?: string }>();
      if (!isHex64(body.peer)) throw new HttpError(400, 'invalid peer');
      const data = op === 'encrypt' ? body.plaintext : body.ciphertext;
      if (typeof data !== 'string') throw new HttpError(400, 'missing data');
      const out = await core.nip44(req.params.id!, c.owner, c.principal, op, body.peer, data);
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
