import { Service, HttpError, type Req, type ServiceOptions } from '@sedecim/service-kit';
import type { NostrEvent } from '@sedecim/nostr-core';
import type { Action, Decision } from '@sedecim/policy-client';
import { channelOf, GroupAuthorities } from './groups';
import type { EventQuery, EventRepository, MirroredEvent } from './repository';

const P_GATED = [1059, 44100, 44101];

function parseList(v: string | null): string[] | undefined {
  return v ? v.split(',').filter(Boolean) : undefined;
}

const MAX_CHANNELS = 100;

/** Non-negative integer query parameter; NaN or negative values would otherwise reach SQL (500). */
function intParam(req: Req, name: string): number | undefined {
  const v = req.query.get(name);
  if (v === null) return undefined;
  const n = Number(v);
  if (v === '' || !Number.isSafeInteger(n) || n < 0) throw new HttpError(400, `${name} must be a non-negative integer`);
  return n;
}

function kindList(v: string | null): number[] | undefined {
  const kinds = parseList(v)?.map(Number);
  if (kinds?.some((k) => !Number.isSafeInteger(k) || k < 0)) throw new HttpError(400, 'kinds must be non-negative integers');
  return kinds;
}

function channelList(v: string | null, required: boolean): string[] | undefined {
  const hs = parseList(v);
  if (!hs?.length) {
    if (required) throw new HttpError(400, 'h is required (comma separated channel ids)');
    return undefined;
  }
  if (hs.length > MAX_CHANNELS || hs.some((h) => h.length > 256)) throw new HttpError(400, `at most ${MAX_CHANNELS} channel ids of up to 256 chars`);
  return [...new Set(hs)];
}

const eventsBody = (rows: MirroredEvent[]) => ({
  events: rows.map((r) => r.event),
  meta: rows.map((r) => ({ id: r.event.id, relays: r.relays, sensitivity: r.sensitivity, firstSeenAt: r.firstSeenAt })),
});

/**
 * FR023-05: institutional mode. Every read is evaluated by the policy-engine for the authenticated reader:
 * an event's resource is its channel (`h`) or, without one, the workspace. Default deny (engine errors too).
 */
export interface IndexerPolicy {
  evaluate(input: { pubkey: string; deviceId?: string; resourceId: string; action: Action }): Promise<Decision>;
  /** Resource of events outside any channel (usually COMMUNITY_ID). Unset: those events are denied. */
  workspaceId?: string;
}

/** Header a client may send to evaluate with its registered device (sensitive resources require one). */
export const POLICY_DEVICE_HEADER = 'x-policy-device-id';

/**
 * Per-request memoized read checks. FR014-05: a channel's events (its `h` messages and its NIP-29 state, 39000-39003)
 * are only read by its members: the reader must be in the channel's admin (39001) or member (39002) list signed by a
 * trusted relay key, as on the relay. In institutional mode the policy-engine must allow it as well (FR023-05);
 * without a policy, events outside channels are public.
 */
function readGuard(repo: EventRepository, groups: GroupAuthorities, policy: IndexerPolicy | undefined, req: Req) {
  const memo = new Map<string, Promise<boolean>>();
  const device = req.headers[POLICY_DEVICE_HEADER];
  const deviceId = typeof device === 'string' && device ? device : undefined;
  const allowedByPolicy = (resourceId: string | undefined): Promise<boolean> => {
    if (!policy) return Promise.resolve(true);
    if (!resourceId || !req.pubkey) return Promise.resolve(false);
    let p = memo.get(resourceId);
    if (!p) {
      p = policy.evaluate({ pubkey: req.pubkey, ...(deviceId ? { deviceId } : {}), resourceId, action: 'read' }).then((d) => d.allow, () => false);
      memo.set(resourceId, p);
    }
    return p;
  };
  let member: Promise<Set<string>> | undefined;
  const memberOf = () => (member ??= req.pubkey ? repo.memberChannels(req.pubkey, groups.list()).then((hs) => new Set(hs), () => new Set<string>()) : Promise.resolve(new Set<string>()));
  const canChannel = async (h: string) => (await memberOf()).has(h) && (await allowedByPolicy(h));
  const canEvent = (e: NostrEvent) => {
    const h = channelOf(e);
    return h !== undefined ? canChannel(h) : allowedByPolicy(policy?.workspaceId);
  };
  const channels = async (hs: string[]) => {
    const ok = await Promise.all(hs.map(canChannel));
    return hs.filter((_, i) => ok[i]);
  };
  return {
    canChannel,
    canEvent,
    channels,
    async filter(rows: MirroredEvent[]) {
      const ok = await Promise.all(rows.map((r) => canEvent(r.event)));
      return rows.filter((_, i) => ok[i]);
    },
    /** Every channel the reader may read. */
    async readable() {
      return channels([...(await memberOf())]);
    },
  };
}

/**
 * Read API for SaaS derived views. Messaging itself stays on Nostr (WebSocket); this API only serves
 * mirror queries. p-gated kinds (gift wraps) are only returned to their authenticated recipient, and channel
 * content to the channel's members (FR014-05; `groups`: the relay keys whose NIP-29 lists count, none by default).
 */
export function createIndexerApi(repo: EventRepository, opts: ServiceOptions & { requireAuth?: boolean; policy?: IndexerPolicy; groups?: GroupAuthorities }) {
  const svc = new Service(opts);
  // Institutional mode always needs the reader's identity.
  const auth = opts.requireAuth || opts.policy ? 'nip98' : 'nip98-optional';
  const groups = opts.groups ?? new GroupAuthorities();
  const guard = (req: Req) => readGuard(repo, groups, opts.policy, req);
  svc.get('/health', async () => ({ ok: true, ...(await repo.stats()) }));
  svc.get(
    '/v1/events',
    async (req) => {
      const q: EventQuery = {
        ids: parseList(req.query.get('ids')),
        kinds: kindList(req.query.get('kinds')),
        authors: parseList(req.query.get('authors')),
        h: req.query.get('h') ?? undefined,
        p: req.query.get('p') ?? undefined,
        since: intParam(req, 'since'),
        until: intParam(req, 'until'),
        limit: Math.min(intParam(req, 'limit') ?? 100, 1000),
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
      return eventsBody(await guard(req).filter(await repo.query(q)));
    },
    auth,
  );
  svc.get(
    '/v1/events/:id',
    async (req) => {
      const row = await repo.get(req.params.id!);
      if (!row || row.deleted) throw new HttpError(404, 'not found');
      if (P_GATED.includes(row.event.kind) && !row.event.tags.some((t) => t[0] === 'p' && t[1] === req.pubkey)) throw new HttpError(404, 'not found');
      if (!(await guard(req).canEvent(row.event))) throw new HttpError(404, 'not found');
      return { event: row.event, relays: row.relays };
    },
    auth,
  );
  svc.get('/v1/channels/:h/summary', async (req) => {
    if (!(await guard(req).canChannel(req.params.h!))) throw new HttpError(403, 'not a member of this channel, or denied by policy');
    const rows = await repo.query({ h: req.params.h, kinds: [9], limit: 1000 });
    return { channel: req.params.h, messages: rows.length, lastMessageAt: rows[0]?.event.created_at ?? null, authors: [...new Set(rows.map((r) => r.event.pubkey))].length };
  }, auth);

  // Derived views (FR014-03). Unread counts are per authenticated reader, so NIP-98 is always required.
  svc.get(
    '/v1/unread',
    async (req) => {
      // Channels the reader may not read (not a member, or denied by policy) are left out of the answer.
      const hs = await guard(req).channels(channelList(req.query.get('h'), true)!);
      return { unread: await repo.unreadCounts(req.pubkey!, hs), cursors: await repo.readCursors(req.pubkey!, hs) };
    },
    'nip98',
  );
  svc.put(
    '/v1/read-cursor',
    async (req) => {
      const body = req.json<{ h?: unknown; until?: unknown }>();
      if (typeof body.h !== 'string' || !body.h || body.h.length > 256) throw new HttpError(400, 'h must be a channel id');
      if (!Number.isSafeInteger(body.until) || (body.until as number) < 0) throw new HttpError(400, 'until must be a unix timestamp');
      if (!(await guard(req).canChannel(body.h))) throw new HttpError(403, 'not a member of this channel, or denied by policy');
      return { h: body.h, until: await repo.setReadCursor(req.pubkey!, body.h, body.until as number) };
    },
    'nip98',
  );
  // Search only covers plaintext channel messages (never gift wraps or other ciphertext) of channels the reader
  // may read; a sealed mirror decrypts candidates through its codec exactly as reads do.
  svc.get(
    '/v1/search',
    async (req) => {
      const text = (req.query.get('q') ?? '').trim();
      if (text.length < 2 || text.length > 200) throw new HttpError(400, 'q must be 2-200 characters');
      const limit = req.query.has('limit') ? Math.max(1, Math.min(Number(req.query.get('limit')) || 50, 200)) : 50;
      const g = guard(req);
      // FR014-05: only channels the reader may read, also when none is named.
      const asked = channelList(req.query.get('h'), false);
      const h = asked ? await g.channels(asked) : await g.readable();
      if (!h.length) return eventsBody([]);
      return eventsBody(await g.filter(await repo.search({ text, h, kinds: kindList(req.query.get('kinds')), limit })));
    },
    auth,
  );
  return svc;
}
