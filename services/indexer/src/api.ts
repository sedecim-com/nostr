import { Service, HttpError, type ServiceOptions } from '@sedecim/service-kit';
import type { EventQuery, EventRepository } from './repository';

const P_GATED = [1059, 44100, 44101];

function parseList(v: string | null): string[] | undefined {
  return v ? v.split(',').filter(Boolean) : undefined;
}

/**
 * Read API for SaaS derived views. Messaging itself stays on Nostr (WebSocket); this API only serves
 * mirror queries. p-gated kinds (gift wraps) are only returned to their authenticated recipient.
 */
export function createIndexerApi(repo: EventRepository, opts: ServiceOptions & { requireAuth?: boolean }) {
  const svc = new Service(opts);
  const auth = opts.requireAuth ? 'nip98' : 'nip98-optional';
  svc.get('/health', async () => ({ ok: true, ...(await repo.stats()) }));
  svc.get(
    '/v1/events',
    async (req) => {
      const q: EventQuery = {
        ids: parseList(req.query.get('ids')),
        kinds: parseList(req.query.get('kinds'))?.map(Number),
        authors: parseList(req.query.get('authors')),
        h: req.query.get('h') ?? undefined,
        p: req.query.get('p') ?? undefined,
        since: req.query.has('since') ? Number(req.query.get('since')) : undefined,
        until: req.query.has('until') ? Number(req.query.get('until')) : undefined,
        limit: req.query.has('limit') ? Math.min(Number(req.query.get('limit')), 1000) : 100,
      };
      const touchesGated = !q.kinds || q.kinds.some((k) => P_GATED.includes(k));
      if (touchesGated) {
        if (!req.pubkey) {
          q.kinds = (q.kinds ?? []).filter((k) => !P_GATED.includes(k));
          if (q.kinds.length === 0) throw new HttpError(401, 'p-gated kinds require NIP-98 authentication');
        } else if (q.p !== req.pubkey) {
          throw new HttpError(403, 'p-gated kinds require p= your authenticated pubkey');
        }
      }
      const rows = await repo.query(q);
      return { events: rows.map((r) => r.event), meta: rows.map((r) => ({ id: r.event.id, relays: r.relays, sensitivity: r.sensitivity, firstSeenAt: r.firstSeenAt })) };
    },
    auth,
  );
  svc.get(
    '/v1/events/:id',
    async (req) => {
      const row = await repo.get(req.params.id!);
      if (!row || row.deleted) throw new HttpError(404, 'not found');
      if (P_GATED.includes(row.event.kind) && !row.event.tags.some((t) => t[0] === 'p' && t[1] === req.pubkey)) throw new HttpError(404, 'not found');
      return { event: row.event, relays: row.relays };
    },
    auth,
  );
  svc.get('/v1/channels/:h/summary', async (req) => {
    const rows = await repo.query({ h: req.params.h, kinds: [9], limit: 1000 });
    return { channel: req.params.h, messages: rows.length, lastMessageAt: rows[0]?.event.created_at ?? null, authors: [...new Set(rows.map((r) => r.event.pubkey))].length };
  }, auth);
  return svc;
}
