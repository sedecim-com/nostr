/**
 * NIP-40: the `expiration` tag, the unix time (seconds) from which relays and clients SHOULD treat an event as expired.
 * It is a request: a relay MAY keep serving the event, and whoever already read it may keep it (PANEL-06).
 */
import type { UnsignedEvent } from './event';

/** The event's expiration (unix seconds), or undefined without a well-formed tag. Several tags: the soonest counts. */
export function eventExpiration(evt: Pick<UnsignedEvent, 'tags'>): number | undefined {
  let soonest: number | undefined;
  for (const t of evt.tags) {
    if (t[0] !== 'expiration' || !/^\d{1,12}$/.test(t[1] ?? '')) continue;
    const at = Number(t[1]);
    if (soonest === undefined || at < soonest) soonest = at;
  }
  return soonest;
}

/** Whether the event has expired at `nowSeconds` (from its expiration second on). */
export function isExpired(evt: Pick<UnsignedEvent, 'tags'>, nowSeconds: number): boolean {
  const at = eventExpiration(evt);
  return at !== undefined && at <= nowSeconds;
}

/** The `expiration` tag for a unix time (seconds). */
export function expirationTag(at: number): string[] {
  if (!Number.isSafeInteger(at) || at < 0) throw new Error('expiration must be a unix time in seconds');
  return ['expiration', String(at)];
}
