/**
 * FR014-05: NIP-29 access in the mirror. The state of a channel (39000 metadata, 39001 admins, 39002 members) is
 * signed by the relay that hosts it, and only lists signed by a trusted relay key count. The keys come from
 * INDEXER_GROUP_AUTHORITIES or, when that is not set, from each followed relay's NIP-11 `self` field (Buzz
 * publishes its signing key there when it has a stable one, BUZZ_RELAY_PRIVATE_KEY).
 */
import { getTagValue, normalizePubkey, type NostrEvent } from '@sedecim/nostr-core';

/** NIP-29 group state, addressed by the channel id in its `d` tag. */
export const GROUP_STATE_KINDS = [39000, 39001, 39002, 39003];
/** Lists whose `p` tags grant reading a channel: admins (owner/admin) and members. */
export const GROUP_ACCESS_KINDS = [39001, 39002];
/** NIP-29 moderation: delete an event of the group. */
export const GROUP_DELETE_EVENT_KIND = 9005;

/** The channel an event belongs to: its `h` tag, or the `d` tag of NIP-29 group state (39000-39003). */
export function channelOf(e: NostrEvent): string | undefined {
  return getTagValue(e, 'h') ?? (GROUP_STATE_KINDS.includes(e.kind) ? getTagValue(e, 'd') : undefined);
}

/** NIP-11 document URL for a relay websocket URL. */
function relayInfoUrl(relay: string): string {
  const u = new URL(relay);
  u.protocol = u.protocol === 'wss:' ? 'https:' : 'http:';
  return u.toString();
}

/** The relay keys whose NIP-29 lists the mirror trusts. Without any, nobody is a member of anything. */
export class GroupAuthorities {
  private readonly keys = new Set<string>();
  private readonly resolved = new Set<string>();
  /** Keys set by the operator: then NIP-11 is never consulted. */
  readonly configured: boolean;

  constructor(keys: string[] = []) {
    for (const k of keys) this.keys.add(normalizePubkey(k));
    this.configured = this.keys.size > 0;
  }

  list(): string[] {
    return [...this.keys];
  }

  /**
   * Learns the signing key (`self`) of each relay not read yet; a relay that cannot be reached is asked again next
   * time. Returns true when a new key was learned.
   */
  async discover(relays: string[], fetchImpl: typeof fetch = fetch, timeoutMs = 5000): Promise<boolean> {
    if (this.configured) return false;
    const before = this.keys.size;
    await Promise.all(
      relays
        .filter((r) => !this.resolved.has(r))
        .map(async (r) => {
          try {
            const res = await fetchImpl(relayInfoUrl(r), { headers: { accept: 'application/nostr+json' }, signal: AbortSignal.timeout(timeoutMs) });
            if (!res.ok) return;
            const self = ((await res.json()) as { self?: unknown }).self;
            if (typeof self === 'string' && /^[0-9a-f]{64}$/.test(self)) this.keys.add(self);
            this.resolved.add(r);
          } catch {
            /* unreachable now: the next channel refresh asks again */
          }
        }),
    );
    return this.keys.size > before;
  }
}
