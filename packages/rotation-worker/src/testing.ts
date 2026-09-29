import { HttpError, Service, type Req } from '@sedecim/service-kit';
import { createLogger } from '@sedecim/telemetry-policy';
import type { DeviceRevocation, Rotation } from './policy';

export interface RotationFeedItem {
  at: number;
  resourceId: string;
  reason: string;
  removedPubkey: string;
}

/**
 * Test double of the policy-engine rotation contract (tests only): `GET /v1/rotations?status=`,
 * `POST /v1/rotations/:id/done` and `GET /v1/revocations` (admin NIP-98 or bearer). Rotations
 * come from `feed` (e.g. an in-memory PolicyEngine's `rotations`) and get ids by position; revocations from
 * `revocations`, oldest first.
 */
export class StubPolicyApi {
  readonly done = new Set<string>();
  readonly service: Service;
  /** Make the next N `done` calls fail with 503 (to test that the worker retries). */
  failDone = 0;

  /** Number of `GET /v1/revocations` requests served. */
  revocationReads = 0;

  constructor(opts: { adminPubkeys: string[]; bearerTokens?: Record<string, string>; feed: () => RotationFeedItem[]; revocations?: () => DeviceRevocation[]; now?: () => number }) {
    const svc = new Service({ name: 'policy-stub', bearerTokens: opts.bearerTokens ?? {}, logger: createLogger({ write: () => {} }) });
    const admin = (pubkey?: string) => {
      if (!pubkey || !opts.adminPubkeys.includes(pubkey)) throw new HttpError(403, 'admin only');
    };
    this.rotations = () => opts.feed().map((r, i) => ({ ...r, id: `rot-${i + 1}`, status: this.done.has(`rot-${i + 1}`) ? 'done' : 'pending' }));
    const adminOrService = (req: Req) => {
      const bearer = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : undefined;
      if (bearer === undefined) admin(req.pubkey);
      else if (!Object.keys(opts.bearerTokens ?? {}).includes(bearer)) throw new HttpError(401, 'invalid bearer token');
    };
    svc.get('/v1/rotations', (req) => {
      adminOrService(req);
      const status = req.query.get('status');
      return { rotations: this.rotations().filter((r) => !status || r.status === status) };
    }, 'nip98-or-token');
    svc.post('/v1/rotations/:id/done', (req) => {
      adminOrService(req);
      if (this.failDone > 0) {
        this.failDone--;
        throw new HttpError(503, 'unavailable');
      }
      if (!this.rotations().some((r) => r.id === req.params.id)) throw new HttpError(404, 'unknown rotation');
      this.done.add(req.params.id!);
      return { ok: true };
    }, 'nip98-or-token');
    svc.get('/v1/revocations', (req) => {
      adminOrService(req);
      this.revocationReads++;
      const all = opts.revocations?.() ?? [];
      const after = Number(req.query.get('after') ?? 0);
      const limit = Math.min(Number(req.query.get('limit') ?? 100), 1000);
      return { revocations: all.filter((r) => r.cursor > after).slice(0, limit), latest: all.at(-1)?.cursor ?? 0, now: (opts.now ?? Date.now)() };
    }, 'nip98-or-token');
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
