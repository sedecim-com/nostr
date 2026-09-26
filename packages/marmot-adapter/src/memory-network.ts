import { matchFilters, type Filter, type NostrEvent } from '@sedecim/nostr-core';
import type { GroupNetwork } from './types';

/** In-process event bus implementing GroupNetwork (self-tests and unit tests; never for production). */
export class MemoryGroupNetwork implements GroupNetwork {
  private readonly events = new Map<string, NostrEvent>();
  private readonly subs = new Set<{ filters: Filter[]; fn: (e: NostrEvent) => void }>();

  async publish(relays: string[], event: NostrEvent) {
    if (!this.events.has(event.id)) {
      this.events.set(event.id, event);
      for (const s of this.subs) if (matchFilters(s.filters, event)) s.fn(event);
    }
    return (relays.length ? relays : ['wss://selftest.invalid']).map((relay) => ({ relay, ok: true, message: '' }));
  }
  async query(_relays: string[], filters: Filter[]) {
    return [...this.events.values()].filter((e) => matchFilters(filters, e));
  }
  subscribe(_relays: string[], filters: Filter[], fn: (e: NostrEvent) => void) {
    const s = { filters, fn };
    this.subs.add(s);
    return { close: () => this.subs.delete(s) };
  }
  async inboxRelays() {
    return ['wss://selftest.invalid'];
  }
}

/** Plain in-memory GroupStorage (self-tests only: NOT encrypted at rest). */
export class VolatileGroupStorage {
  private readonly data = new Map<string, unknown>();
  async get(ns: string, key: string) {
    return this.data.get(`${ns}\u0000${key}`);
  }
  async put(ns: string, key: string, value: unknown) {
    this.data.set(`${ns}\u0000${key}`, value);
  }
  async delete(ns: string, key: string) {
    this.data.delete(`${ns}\u0000${key}`);
  }
  async keys(ns: string) {
    return [...this.data.keys()].filter((k) => k.startsWith(`${ns}\u0000`)).map((k) => k.slice(ns.length + 1));
  }
}
