import type { GroupNetwork } from '@sedecim/marmot-adapter';
import { normalizeRelayUrl } from '@sedecim/relay-pool';
import type { RelayEntry } from './config';

/** Public ↔ dial translation of the configured relays. Any other relay is reached as named. */
export function relayMapping(entries: RelayEntry[]) {
  const dial = new Map(entries.map((e) => [e.public, e.dial]));
  const pub = new Map(entries.map((e) => [e.dial, e.public]));
  const norm = (url: string) => {
    try {
      return normalizeRelayUrl(url);
    } catch {
      return url;
    }
  };
  return {
    dialOf: (url: string) => dial.get(norm(url)) ?? url,
    publicOf: (url: string) => pub.get(norm(url)) ?? url,
  };
}

/**
 * Groups, key packages and relay lists name relays by their public URL (what clients use); inside the deployment the
 * worker reaches them at another address (the secure relay's service). This translates every relay list the Marmot
 * session hands to the network.
 */
export function mappedNetwork(inner: GroupNetwork, dialOf: (url: string) => string): GroupNetwork {
  const map = (relays: string[]) => [...new Set(relays.map(dialOf))];
  return {
    publish: (relays, event) => inner.publish(map(relays), event),
    query: (relays, filters, timeoutMs) => inner.query(map(relays), filters, timeoutMs),
    subscribe: (relays, filters, onEvent) => inner.subscribe(map(relays), filters, onEvent),
    inboxRelays: (pubkey) => inner.inboxRelays(pubkey),
  };
}
