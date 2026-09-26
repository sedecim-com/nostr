import { Service, HttpError, requireFields, isHex64, type Req, type ServiceOptions } from '@sedecim/service-kit';
import type { EventTemplate } from '@sedecim/nostr-core';
import { ManagedSigner, ManagedSignerError } from './service';

/**
 * Managed signer HTTP API. Service-to-service only (bearer): the SaaS backend authenticates end users
 * and passes the account id in `x-account-id`. Every call is custodial and audited.
 */
export function createManagedSignerApi(core: ManagedSigner, opts: ServiceOptions) {
  const svc = new Service(opts);
  const owner = (req: Req) => {
    const o = req.headers['x-account-id'];
    if (typeof o !== 'string' || !o) throw new HttpError(400, 'x-account-id header required');
    return o;
  };
  const wrap = (fn: (req: Req) => Promise<unknown> | unknown) => async (req: Req) => {
    try {
      return await fn(req);
    } catch (err) {
      if (err instanceof ManagedSignerError) throw new HttpError(err.status, err.message);
      throw err;
    }
  };
  const log = svc.logger;

  svc.get('/health', () => ({ ok: true, custodial: true }));
  svc.post('/v1/keys', wrap(async (req) => {
    const body = req.json<{ allowed_kinds?: number[] }>();
    const k = await core.create(owner(req), req.principal!, { allowedKinds: body.allowed_kinds });
    log.info('managed key created', { key_id: k.keyId, pubkey: k.pubkey });
    return { status: 201, body: core.describe(k.keyId, owner(req)) };
  }), 'bearer');
  svc.post('/v1/keys/import', wrap(async (req) => {
    const body = req.json<{ ncryptsec: string; password: string }>();
    requireFields(body, ['ncryptsec', 'password']);
    const k = await core.importEncrypted(owner(req), req.principal!, body.ncryptsec, body.password);
    return { status: 201, body: core.describe(k.keyId, owner(req)) };
  }), 'bearer');
  svc.get('/v1/keys/:id', wrap((req) => core.describe(req.params.id!, owner(req))), 'bearer');
  svc.post('/v1/keys/:id/sign', wrap(async (req) => {
    const { template } = req.json<{ template: EventTemplate }>();
    if (!template || typeof template.kind !== 'number' || typeof template.content !== 'string') throw new HttpError(400, 'invalid template');
    const event = await core.sign(req.params.id!, owner(req), req.principal!, template);
    log.info('managed signature', { key_id: req.params.id, kind: event.kind, event_id: event.id });
    return { event };
  }), 'bearer');
  for (const op of ['encrypt', 'decrypt'] as const) {
    svc.post(`/v1/keys/:id/nip44/${op}`, wrap(async (req) => {
      const body = req.json<{ peer: string; plaintext?: string; ciphertext?: string }>();
      if (!isHex64(body.peer)) throw new HttpError(400, 'invalid peer');
      const data = op === 'encrypt' ? body.plaintext : body.ciphertext;
      if (typeof data !== 'string') throw new HttpError(400, 'missing data');
      const out = await core.nip44(req.params.id!, owner(req), req.principal!, op, body.peer, data);
      return op === 'encrypt' ? { ciphertext: out } : { plaintext: out };
    }), 'bearer');
  }
  svc.post('/v1/keys/:id/export', wrap(async (req) => {
    const { password } = req.json<{ password: string }>();
    return core.export(req.params.id!, owner(req), req.principal!, password ?? '');
  }), 'bearer');
  svc.post('/v1/keys/:id/confirm-migration', wrap((req) => {
    const { proof } = req.json<{ proof: unknown }>();
    return { state: core.confirmMigration(req.params.id!, owner(req), req.principal!, proof).state };
  }), 'bearer');
  svc.delete('/v1/keys/:id', wrap(async (req) => {
    await core.delete(req.params.id!, owner(req), req.principal!);
    return { deleted: true };
  }), 'bearer');
  svc.get('/v1/keys/:id/usage', wrap((req) => ({ usage: core.usageOf(req.params.id!, owner(req)) })), 'bearer');
  return svc;
}
