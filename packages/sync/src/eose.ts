/**
 * FR013-05: a query that tells a complete answer from a partial one. `RelayPool.query` resolves with whatever arrived
 * when its timeout fires or the relay closes the subscription, which is right for reading but not for a sync cursor:
 * a cursor may only move past what a relay really finished sending (its EOSE).
 */
import type { Filter, NostrEvent } from '@sedecim/nostr-core';
import type { PoolSubscription, RelayPool } from '@sedecim/relay-pool';

/** The relay did not end the subscription with EOSE: it timed out, closed it (CLOSED) or the connection failed. */
export class IncompleteSyncError extends Error {
  constructor(message: string, readonly relay: string) {
    super(message);
    this.name = 'IncompleteSyncError';
  }
}

/**
 * One relay's answer to `filters`, deduplicated and sorted (created_at, then id). Each event also goes to `onEvent` as it
 * arrives, so a caller keeps what came before a cut. Rejects with IncompleteSyncError unless the relay sends EOSE
 * within `timeoutMs`.
 */
export function queryUntilEose(pool: Pick<RelayPool, 'subscribe'>, relay: string, filters: Filter[], timeoutMs: number, onEvent?: (e: NostrEvent) => void): Promise<NostrEvent[]> {
  return new Promise((resolve, reject) => {
    const out = new Map<string, NostrEvent>();
    let closed: string | undefined;
    let sub: PoolSubscription | undefined;
    let settled = false;
    const finish = (err?: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sub?.close();
      if (err) reject(err);
      else resolve([...out.values()].sort((a, b) => a.created_at - b.created_at || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)));
    };
    const timer = setTimeout(() => finish(new IncompleteSyncError(`timeout: no EOSE within ${timeoutMs} ms`, relay)), timeoutMs);
    sub = pool.subscribe([relay], filters, {
      onevent: (e) => {
        if (settled || out.has(e.id)) return;
        out.set(e.id, e);
        onEvent?.(e);
      },
      // The pool reports a CLOSED (or a failed connection) and then counts that relay as done: that is not an EOSE.
      onclosed: (_relay, reason) => (closed = reason || 'closed'),
      oneose: () => queueMicrotask(() => finish(closed === undefined ? undefined : new IncompleteSyncError(`closed: ${closed}`, relay))),
    });
    if (settled) sub.close();
  });
}
