import type { Filter, NostrEvent, Signer } from '@sedecim/nostr-core';
import { RelayConnection, type RelayConnectionOptions } from './connection';
import type { PublishResult, RelayHealth } from './types';

export interface PoolSubscribeOptions {
  onevent: (evt: NostrEvent, relay: string) => void;
  /** Fires once every relay has sent EOSE (or closed / failed). */
  oneose?: () => void;
  onclosed?: (relay: string, reason: string) => void;
  /** Suppress duplicates of the same event id arriving from several relays (default true). */
  dedupe?: boolean;
}

export interface PoolSubscription {
  close(): void;
  /** relays on which a given event id has been seen */
  seenOn(id: string): string[];
}

export function normalizeRelayUrl(url: string): string {
  const u = new URL(url.trim());
  if (u.protocol !== 'ws:' && u.protocol !== 'wss:') throw new Error(`relay url must be ws:// or wss://: ${url}`);
  u.hash = '';
  let s = u.toString();
  if (s.endsWith('/') && u.pathname === '/') s = s.slice(0, -1);
  return s;
}

export class RelayPool {
  private readonly relays = new Map<string, RelayConnection>();

  constructor(private readonly opts: RelayConnectionOptions = {}) {}

  get signer(): Signer | undefined {
    return this.opts.signer;
  }

  ensureRelay(url: string): RelayConnection {
    const key = normalizeRelayUrl(url);
    let r = this.relays.get(key);
    if (!r) {
      r = new RelayConnection(key, this.opts);
      this.relays.set(key, r);
    }
    return r;
  }

  async publish(evt: NostrEvent, urls: string[]): Promise<PublishResult[]> {
    return Promise.all(urls.map((u) => this.ensureRelay(u).publish(evt)));
  }

  publishTo(evt: NostrEvent, url: string): Promise<PublishResult> {
    return this.ensureRelay(url).publish(evt);
  }

  subscribe(urls: string[], filters: Filter[], opts: PoolSubscribeOptions): PoolSubscription {
    const seen = new Map<string, Set<string>>();
    const pendingEose = new Set(urls.map(normalizeRelayUrl));
    let eoseFired = false;
    const checkEose = () => {
      if (!eoseFired && pendingEose.size === 0) {
        eoseFired = true;
        opts.oneose?.();
      }
    };
    const subs = [...pendingEose].map((url) =>
      this.ensureRelay(url).subscribe(filters, {
        onevent: (evt) => {
          const s = seen.get(evt.id);
          if (s) {
            s.add(url);
            if (opts.dedupe !== false) return;
          } else seen.set(evt.id, new Set([url]));
          opts.onevent(evt, url);
        },
        oneose: () => {
          pendingEose.delete(url);
          checkEose();
        },
        onclosed: (reason) => {
          pendingEose.delete(url);
          opts.onclosed?.(url, reason);
          checkEose();
        },
      }),
    );
    if (pendingEose.size === 0) queueMicrotask(checkEose);
    return {
      close: () => subs.forEach((s) => s.close()),
      seenOn: (id) => [...(seen.get(id) ?? [])],
    };
  }

  /** One-shot query: resolves with deduplicated events after all relays EOSE or the timeout fires. */
  query(urls: string[], filters: Filter[], timeoutMs = 10_000): Promise<NostrEvent[]> {
    return new Promise((resolve) => {
      const out = new Map<string, NostrEvent>();
      let sub: PoolSubscription | undefined;
      const done = () => {
        clearTimeout(timer);
        sub?.close();
        resolve([...out.values()].sort((a, b) => a.created_at - b.created_at || (a.id < b.id ? -1 : 1)));
      };
      const timer = setTimeout(done, timeoutMs);
      sub = this.subscribe(urls, filters, { onevent: (e) => out.set(e.id, e), oneose: () => queueMicrotask(done) });
    });
  }

  health(): RelayHealth[] {
    return [...this.relays.values()].map((r) => r.health());
  }

  close(): void {
    for (const r of this.relays.values()) r.close();
    this.relays.clear();
  }
}
