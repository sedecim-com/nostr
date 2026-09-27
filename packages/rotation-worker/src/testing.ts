import { HttpError, Service } from '@sedecim/service-kit';
import { createLogger } from '@sedecim/telemetry-policy';
import type { PolicyAuditEntry, Rotation } from './policy';

export interface RotationFeedItem {
  at: number;
  resourceId: string;
  reason: string;
  removedPubkey: string;
}

/**
 * Test double of the policy-engine rotation contract (tests only): `GET /v1/rotations?status=` (admin
 * NIP-98), `POST /v1/rotations/:id/done` (admin NIP-98 or bearer) and `GET /v1/audit`. Rotations come from
 * `feed` (e.g. an in-memory PolicyEngine's `rotations`) and get ids by position.
 */
export class StubPolicyApi {
  readonly done = new Set<string>();
  readonly service: Service;
  /** Make the next N `done` calls fail with 503 (to test that the worker retries). */
  failDone = 0;

  constructor(opts: { adminPubkeys: string[]; bearerTokens?: Record<string, string>; feed: () => RotationFeedItem[]; audit?: () => PolicyAuditEntry[] }) {
    const svc = new Service({ name: 'policy-stub', bearerTokens: opts.bearerTokens ?? {}, logger: createLogger({ write: () => {} }) });
    const admin = (pubkey?: string) => {
      if (!pubkey || !opts.adminPubkeys.includes(pubkey)) throw new HttpError(403, 'admin only');
    };
    this.rotations = () => opts.feed().map((r, i) => ({ ...r, id: `rot-${i + 1}`, status: this.done.has(`rot-${i + 1}`) ? 'done' : 'pending' }));
    svc.get('/v1/rotations', (req) => {
      admin(req.pubkey);
      const status = req.query.get('status');
      return { rotations: this.rotations().filter((r) => !status || r.status === status) };
    }, 'nip98');
    svc.post('/v1/rotations/:id/done', (req) => {
      const bearer = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : undefined;
      if (bearer === undefined) admin(req.pubkey);
      else if (!Object.keys(opts.bearerTokens ?? {}).includes(bearer)) throw new HttpError(401, 'invalid bearer token');
      if (this.failDone > 0) {
        this.failDone--;
        throw new HttpError(503, 'unavailable');
      }
      if (!this.rotations().some((r) => r.id === req.params.id)) throw new HttpError(404, 'unknown rotation');
      this.done.add(req.params.id!);
      return { ok: true };
    }, 'nip98-or-token');
    svc.get('/v1/audit', (req) => (admin(req.pubkey), { audit: opts.audit?.() ?? [] }), 'nip98');
    this.service = svc;
  }

  readonly rotations: () => Rotation[];

  listen(): Promise<string> {
    return this.service.listen();
  }

  close(): Promise<void> {
    return this.service.close();
  }
}
