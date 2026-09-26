import { Service, HttpError, isHex64, requireFields, type ServiceOptions } from '@sedecim/service-kit';
import type { Action, Resource, Subject, Device } from '@sedecim/policy-client';
import { PolicyEngine } from './engine';

/** Admin routes are NIP-98 and restricted to configured admin pubkeys; evaluate is callable by relays/services (bearer). */
export function createPolicyApi(engine: PolicyEngine, opts: ServiceOptions & { adminPubkeys: string[] }) {
  const svc = new Service(opts);
  const admin = (pubkey?: string) => {
    if (!pubkey || !opts.adminPubkeys.includes(pubkey)) throw new HttpError(403, 'admin only');
    return pubkey;
  };
  svc.get('/health', () => ({ ok: true }));
  svc.put('/v1/subjects/:pubkey', (req) => {
    const actor = admin(req.pubkey);
    if (!isHex64(req.params.pubkey)) throw new HttpError(400, 'invalid pubkey');
    const body = req.json<Partial<Subject>>();
    engine.upsertSubject(actor, { pubkey: req.params.pubkey!, roles: body.roles ?? [], attributes: body.attributes ?? {} });
    return { ok: true };
  }, 'nip98');
  svc.put('/v1/resources/:id', (req) => {
    const actor = admin(req.pubkey);
    const body = req.json<Omit<Resource, 'id'>>();
    requireFields(body, ['kind', 'sensitivity']);
    engine.upsertResource(actor, { id: req.params.id!, kind: body.kind, sensitivity: body.sensitivity, rules: body.rules ?? [], ...(body.members ? { members: body.members } : {}) });
    return { ok: true };
  }, 'nip98');
  svc.post('/v1/devices', (req) => {
    const actor = admin(req.pubkey);
    const body = req.json<{ owner: string; trust?: Device['trust'] }>();
    if (!isHex64(body.owner)) throw new HttpError(400, 'invalid owner');
    return { status: 201, body: engine.registerDevice(actor, body.owner, body.trust) };
  }, 'nip98');
  svc.post('/v1/devices/:id/revoke', (req) => {
    const actor = admin(req.pubkey);
    try {
      return { rotations: engine.revokeDevice(actor, req.params.id!, req.json<{ reason?: string }>().reason) };
    } catch (e) {
      throw new HttpError(404, (e as Error).message);
    }
  }, 'nip98');
  svc.post('/v1/subjects/:pubkey/revoke', (req) => ({ rotations: engine.revokeSubject(admin(req.pubkey), req.params.pubkey!) }), 'nip98');
  svc.post('/v1/sessions', (req) => {
    const { device_id } = req.json<{ device_id: string }>();
    try {
      return { status: 201, body: { token: engine.openSession(req.pubkey!, device_id) } };
    } catch (e) {
      throw new HttpError(403, (e as Error).message);
    }
  }, 'nip98');
  svc.post('/v1/evaluate', (req) => {
    const body = req.json<{ pubkey: string; deviceId?: string; resourceId: string; action: Action }>();
    requireFields(body, ['pubkey', 'resourceId', 'action']);
    return engine.evaluate(body);
  }, 'bearer');
  svc.get('/v1/relay/allowlist', () => ({ pubkeys: engine.relayAllowlist() }), 'bearer');
  svc.get('/v1/rotations', (req) => (admin(req.pubkey), { rotations: engine.rotations }), 'nip98');
  svc.get('/v1/audit', (req) => (admin(req.pubkey), { audit: engine.audit }), 'nip98');
  return svc;
}
