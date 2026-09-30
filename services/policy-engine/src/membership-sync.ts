import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { EventTemplate, Filter, NostrEvent } from '@sedecim/nostr-core';
import type { RelayGrant } from '@sedecim/policy-client';

/**
 * FR023-10: the NIP-29 membership of the channels registered in the policy-engine follows its publish grants.
 *
 * Buzz admits a message with `h` in a private channel only from a channel member (`restricted: not a channel member`),
 * so its members are made equal to the people the policy lets publish there: a kind 9000 (put-user) for each one
 * missing, a kind 9001 (remove-user) for each member without the grant. What each channel holds is read from the group
 * state the relay signs (39000 metadata, 39001 owners and admins, 39002 members), and only lists signed by the relay's
 * key count.
 *
 * - The sync identity must be an owner or admin of each registered channel: Buzz lets only them remove others, and
 *   only members add people to a private channel. A channel where it is not (`withoutAuthority`), or whose state it
 *   cannot read (`unreachable`: no such channel, or private and it is not in it), is reported and left alone.
 * - An open (`public`) channel admits anybody's messages whatever its membership: it is synced but reported as
 *   `notEnforced`.
 * - Owners and admins of the channel keep their membership: the organisation manages those roles in Buzz.
 */

export const NIP29_KINDS = { PutUser: 9000, RemoveUser: 9001, Metadata: 39000, Admins: 39001, Members: 39002 } as const;

/** What the sync needs from the relay: read events, publish an event signed by the sync identity. */
export interface Nip29Relay {
  query(filters: Filter[]): Promise<NostrEvent[]>;
  publish(template: EventTemplate): Promise<{ ok: boolean; message: string }>;
}

export interface MembershipReport {
  channels: number;
  added: number;
  removed: number;
  notEnforced: string[];
  withoutAuthority: string[];
  unreachable: string[];
  errors: string[];
}

export interface MembershipSyncOptions {
  relay: Nip29Relay;
  /** Pubkey (hex) of the sync identity, the one `relay` signs with. */
  self: string;
  /** Key (hex) the relay signs group state with: configured, or NIP-11 `self` (see `nip11Self`). */
  relayKey: () => Promise<string | undefined>;
  log?: (msg: string, fields?: Record<string, unknown>) => void;
}

const ELEVATED = new Set(['owner', 'admin']);

export class BuzzMembershipSync {
  last?: MembershipReport;

  constructor(private readonly opts: MembershipSyncOptions) {}

  async apply(grants: RelayGrant[]): Promise<MembershipReport> {
    const channels = grants.filter((g) => g.kind === 'channel');
    const report: MembershipReport = { channels: channels.length, added: 0, removed: 0, notEnforced: [], withoutAuthority: [], unreachable: [], errors: [] };
    this.last = report;
    if (!channels.length) return report;
    const relayKey = await this.opts.relayKey();
    if (!relayKey) {
      report.errors.push('relay signing key unknown: set BUZZ_MEMBERSHIP_RELAY_KEY or publish NIP-11 self');
      return report;
    }
    const state = await this.opts.relay.query([{ kinds: [NIP29_KINDS.Metadata, NIP29_KINDS.Admins, NIP29_KINDS.Members], '#d': channels.map((c) => c.resourceId), authors: [relayKey] }]);
    const latest = new Map<string, NostrEvent>();
    for (const e of state) {
      if (e.pubkey !== relayKey) continue;
      const d = e.tags.find((t) => t[0] === 'd')?.[1];
      if (d === undefined) continue;
      const key = `${e.kind}:${d}`;
      const prev = latest.get(key);
      if (!prev || e.created_at > prev.created_at) latest.set(key, e);
    }
    for (const ch of channels) {
      const id = ch.resourceId;
      const meta = latest.get(`${NIP29_KINDS.Metadata}:${id}`);
      const members = latest.get(`${NIP29_KINDS.Members}:${id}`);
      if (!meta || !members) {
        report.unreachable.push(id);
        continue;
      }
      const roles = new Map<string, string>();
      for (const t of members.tags) if (t[0] === 'p' && t[1]) roles.set(t[1], t[3] ?? 'member');
      const elevated = new Set([...roles].filter(([, role]) => ELEVATED.has(role)).map(([pk]) => pk));
      for (const t of latest.get(`${NIP29_KINDS.Admins}:${id}`)?.tags ?? []) if (t[0] === 'p' && t[1] && ELEVATED.has(t[2] ?? '')) elevated.add(t[1]);
      if (!elevated.has(this.opts.self)) {
        report.withoutAuthority.push(id);
        continue;
      }
      if (!meta.tags.some((t) => t[0] === 'private')) report.notEnforced.push(id);
      const granted = new Set(ch.pubkeys);
      for (const pk of ch.pubkeys) {
        if (roles.has(pk)) continue;
        const r = await this.opts.relay.publish({ kind: NIP29_KINDS.PutUser, content: '', tags: [['h', id], ['p', pk]] });
        if (r.ok) report.added++;
        else report.errors.push(`${id}: put-user ${pk.slice(0, 8)}: ${r.message}`);
      }
      for (const pk of roles.keys()) {
        if (granted.has(pk) || elevated.has(pk) || pk === this.opts.self || pk === relayKey) continue;
        const r = await this.opts.relay.publish({ kind: NIP29_KINDS.RemoveUser, content: '', tags: [['h', id], ['p', pk]] });
        if (r.ok) report.removed++;
        else report.errors.push(`${id}: remove-user ${pk.slice(0, 8)}: ${r.message}`);
      }
    }
    if (report.added || report.removed) this.opts.log?.('channel membership synced', { added: report.added, removed: report.removed, channels: report.channels });
    return report;
  }
}

/** `public=dial` (or just `public`): clients name the relay by its public URL; this service dials the other one. */
export function parseRelayEntry(entry: string): { public: string; dial: string } {
  const [pub, dial] = entry.split('=').map((s) => s.trim());
  if (!pub || !/^wss?:\/\//.test(pub) || (dial && !/^wss?:\/\//.test(dial))) throw new Error(`invalid relay entry: ${entry} (expected ws(s)://public[=ws(s)://dial])`);
  return { public: pub, dial: dial || pub };
}

/**
 * The relay's signing key from its NIP-11 document (`self`), asked at the dial address with the public host: Buzz
 * serves each community by its `Host` header.
 */
export function nip11Self(entry: { public: string; dial: string }, timeoutMs = 5000): Promise<string | undefined> {
  const url = new URL(entry.dial.replace(/^ws/, 'http'));
  const host = new URL(entry.public.replace(/^ws/, 'http')).host;
  const req = url.protocol === 'https:' ? httpsRequest : httpRequest;
  return new Promise((resolve) => {
    const r = req(url, { headers: { host, accept: 'application/nostr+json' }, timeout: timeoutMs }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        try {
          const self = (JSON.parse(Buffer.concat(chunks).toString('utf8')) as { self?: unknown }).self;
          resolve(typeof self === 'string' && /^[0-9a-f]{64}$/.test(self) ? self : undefined);
        } catch {
          resolve(undefined);
        }
      });
      res.on('error', () => resolve(undefined));
    });
    r.on('timeout', () => r.destroy());
    r.on('error', () => resolve(undefined));
    r.end();
  });
}
