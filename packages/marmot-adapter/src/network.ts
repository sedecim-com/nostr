import type { Filter, NostrEvent } from '@sedecim/nostr-core';
import type { RelayPool } from '@sedecim/relay-pool';
import { MARMOT_KINDS, type GroupNetwork } from './types';

/**
 * GroupNetwork over our RelayPool, so Marmot traffic inherits the persona's network policy
 * (Tor-only fail-closed, host allowlist, NIP-42).
 */
export class PoolGroupNetwork implements GroupNetwork {
  constructor(private readonly pool: RelayPool, private readonly discoveryRelays: string[], private readonly timeoutMs = 8000) {}

  async publish(relays: string[], event: NostrEvent) {
    const res = await this.pool.publish(event, relays.length ? relays : this.discoveryRelays);
    return res.map((r) => ({ relay: r.relay, ok: r.ok, message: r.message }));
  }

  query(relays: string[], filters: Filter[], timeoutMs = this.timeoutMs) {
    return this.pool.query(relays.length ? relays : this.discoveryRelays, filters, timeoutMs);
  }

  subscribe(relays: string[], filters: Filter[], onEvent: (e: NostrEvent) => void) {
    return this.pool.subscribe(relays.length ? relays : this.discoveryRelays, filters, { onevent: (e) => onEvent(e) });
  }

  /** kind 10051 (Marmot key package relays) → kind 10050 (NIP-17 DM relays) → discovery relays. */
  async inboxRelays(pubkey: string): Promise<string[]> {
    const lists = await this.query(this.discoveryRelays, [{ kinds: [MARMOT_KINDS.KeyPackageRelays, 10050], authors: [pubkey] }]);
    for (const kind of [MARMOT_KINDS.KeyPackageRelays, 10050]) {
      const newest = lists.filter((e) => e.kind === kind).sort((a, b) => b.created_at - a.created_at)[0];
      const relays = newest?.tags.filter((t) => t[0] === 'relay' && t[1]).map((t) => t[1]!) ?? [];
      if (relays.length) return relays;
    }
    return this.discoveryRelays;
  }
}
