/**
 * NIP-77 (Negentropy) set reconciliation (FR013-02). The client is the initiator: it describes the ids
 * it already holds, the relay answers with fingerprints/id lists, and only the missing ids are then
 * fetched with REQ `ids` batches. Relays without NIP-77 are detected (NIP-11 and/or a probe) so
 * `syncHistory` falls back to the REQ/time-window strategy automatically.
 */
import { nip77 } from 'nostr-tools';
import type { Filter, NostrEvent } from '@sedecim/nostr-core';
import type { RelayConnection, RelayPool } from '@sedecim/relay-pool';
import { queryUntilEose } from './eose';
import type { SyncStrategy } from './index';

export class NegentropyError extends Error {
  /** `negErr`: the relay answered NEG-ERR, i.e. it speaks NIP-77 but refused or aborted this session. */
  constructor(message: string, readonly relay: string, readonly negErr = false) {
    super(message);
    this.name = 'NegentropyError';
  }
}

export interface NegentropyStats {
  /** ids the relay has and we did not (fetched afterwards) */
  need: number;
  /** ids we have that the relay lacks (candidates to republish) */
  have: number;
  /** NEG-MSG round trips */
  rounds: number;
  /** events received through the REQ `ids` batches */
  fetched: number;
  /** needed ids that `known` already held (e.g. from another relay): not fetched again */
  reused: number;
}

export interface NegentropySyncOptions {
  /**
   * Ids already stored locally for this relay/filter; only the difference is transferred. They are described to the
   * relay (fingerprints, and the ids themselves in small ranges): FR013-05 passes only what that same relay served.
   */
  local?: (relay: string, filter: Filter) => Iterable<{ id: string; created_at: number }> | Promise<Iterable<{ id: string; created_at: number }>>;
  /** FR013-05: events already held locally; a needed id found here is reported without being downloaded again. */
  known?: (id: string) => NostrEvent | undefined;
  /**
   * FR013-05: fail unless every REQ that fetches the missing events ends with the relay's EOSE (a timeout or a CLOSED
   * then makes the next strategy run). Off by default: a cut batch counts as done, as before.
   */
  requireEose?: boolean;
  /**
   * How to decide support: 'nip11' trusts `supported_nips`, 'probe' sends a NEG-OPEN that matches nothing,
   * 'auto' (default) accepts a NIP-11 claim and otherwise probes (many relays omit 77 from NIP-11).
   */
  detect?: 'nip11' | 'probe' | 'auto';
  /** Per-message timeout (ms). */
  timeoutMs?: number;
  /** Ids per REQ when fetching missing events. */
  batchSize?: number;
  frameSizeLimit?: number;
  fetch?: typeof fetch;
  /** Called with the relay's ids we have and it lacks (e.g. to republish them). */
  onRelayMissing?: (relay: string, ids: string[]) => void;
}

/** NIP-11 document URL for a relay websocket URL. */
export function relayInfoUrl(relay: string): string {
  const u = new URL(relay);
  u.protocol = u.protocol === 'wss:' ? 'https:' : 'http:';
  return u.toString();
}

/** Fetches `supported_nips` from the relay's NIP-11 document; undefined when unavailable. */
export async function fetchSupportedNips(relay: string, fetchImpl: typeof fetch = fetch, timeoutMs = 5_000): Promise<number[] | undefined> {
  try {
    const res = await fetchImpl(relayInfoUrl(relay), { headers: { accept: 'application/nostr+json' }, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return undefined;
    const doc = (await res.json()) as { supported_nips?: unknown };
    return Array.isArray(doc.supported_nips) ? doc.supported_nips.filter((n): n is number => typeof n === 'number') : undefined;
  } catch {
    return undefined;
  }
}

const NOTHING: Filter = { ids: ['0'.repeat(64)] };
let sessionCounter = 0;

interface SessionResult {
  need: string[];
  have: string[];
  rounds: number;
}

export class NegentropySync implements SyncStrategy {
  readonly name = 'nip77-negentropy';
  /** Stats of the last `run` per relay (for reports and tests). */
  readonly stats = new Map<string, NegentropyStats>();
  private readonly support = new Map<string, Promise<boolean>>();

  constructor(private readonly pool: RelayPool, private readonly opts: NegentropySyncOptions = {}) {}

  supported(relay: string): Promise<boolean> {
    let p = this.support.get(relay);
    if (!p) {
      p = this.detect(relay);
      this.support.set(relay, p);
    }
    return p;
  }

  private async detect(relay: string): Promise<boolean> {
    const mode = this.opts.detect ?? 'auto';
    if (mode !== 'probe') {
      const nips = await fetchSupportedNips(relay, this.opts.fetch, this.opts.timeoutMs);
      if (nips?.includes(77)) return true;
      if (mode === 'nip11') return false;
    }
    try {
      await this.session(relay, NOTHING, new nip77.NegentropyStorageVector());
      return true;
    } catch (err) {
      // A NEG-ERR (e.g. "restricted:" for the probe filter) still proves the relay implements NIP-77.
      return err instanceof NegentropyError && err.negErr;
    }
  }

  async run(relay: string, filter: Filter, onEvent: (e: NostrEvent) => void): Promise<void> {
    const storage = new nip77.NegentropyStorageVector();
    const seen = new Set<string>();
    for (const item of (await this.opts.local?.(relay, filter)) ?? []) {
      if (seen.has(item.id)) continue;
      seen.add(item.id);
      storage.insert(item.created_at, item.id);
    }
    const { limit: _limit, ...negFilter } = filter; // NIP-77 reconciles the whole matching set
    const res = await this.session(relay, negFilter, storage);
    if (res.have.length) this.opts.onRelayMissing?.(relay, res.have);
    const stats: NegentropyStats = { need: res.need.length, have: res.have.length, rounds: res.rounds, fetched: 0, reused: 0 };
    this.stats.set(relay, stats);
    // The relay has these: an event held locally (e.g. from another relay) is reported as seen here, not downloaded again.
    const missing: string[] = [];
    for (const id of res.need) {
      const held = this.opts.known?.(id);
      if (held && held.id === id) {
        stats.reused++;
        onEvent(held);
      } else missing.push(id);
    }
    const batch = this.opts.batchSize ?? 100;
    const timeoutMs = this.opts.timeoutMs ?? 10_000;
    for (let i = 0; i < missing.length; i += batch) {
      const ids = new Set(missing.slice(i, i + batch));
      const take = (e: NostrEvent) => {
        if (!ids.has(e.id)) return;
        ids.delete(e.id);
        stats.fetched++;
        onEvent(e);
      };
      // Keep the original constraints next to `ids`: relays gate some kinds (e.g. 1059 needs #p).
      const f = { ...negFilter, ids: [...ids] };
      // Strict batches hand over each event as it arrives: a batch cut half way still keeps what came.
      if (this.opts.requireEose) await queryUntilEose(this.pool, relay, [f], timeoutMs, take);
      else (await this.pool.query([relay], [f], timeoutMs)).forEach(take);
    }
  }

  /** One NEG-OPEN … NEG-CLOSE exchange; retries once after NIP-42 when the relay asks for it. */
  private async session(relay: string, filter: Filter, storage: InstanceType<typeof nip77.NegentropyStorageVector>): Promise<SessionResult> {
    storage.seal();
    const conn = this.pool.ensureRelay(relay);
    try {
      return await this.exchange(conn, relay, filter, storage);
    } catch (err) {
      const reason = (err as Error).message;
      const authable = reason.startsWith('auth-required:') || (reason.startsWith('restricted:') && conn.health().authenticatedAs.length === 0);
      if (authable && conn.canAuthenticate && (await conn.authenticate())) return this.exchange(conn, relay, filter, storage);
      throw err;
    }
  }

  private exchange(conn: RelayConnection, relay: string, filter: Filter, storage: InstanceType<typeof nip77.NegentropyStorageVector>): Promise<SessionResult> {
    const neg = new nip77.Negentropy(storage, this.opts.frameSizeLimit);
    const subId = `neg${++sessionCounter}`;
    // With a frame size limit (either side) a difference can be reported more than once (Negentropy spec): count it once.
    const need = new Set<string>();
    const have = new Set<string>();
    let rounds = 0;
    const timeoutMs = this.opts.timeoutMs ?? 10_000;
    return new Promise<SessionResult>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const arm = () => {
        clearTimeout(timer);
        timer = setTimeout(() => finish(new NegentropyError('timeout: no NIP-77 answer', relay)), timeoutMs);
      };
      const finish = (err?: Error) => {
        clearTimeout(timer);
        off();
        if (err) {
          void conn.sendMessage(['NEG-CLOSE', subId]).catch(() => undefined);
          reject(err);
        } else resolve({ need: [...need], have: [...have], rounds });
      };
      const off = conn.onRawMessage((msg) => {
        const [type, id, payload] = msg as [string, unknown, unknown];
        if (type === 'NOTICE') {
          // Relays that do not know NIP-77 answer with a NOTICE (no subscription id): only trust it before the first reply.
          if (rounds === 0 && typeof id === 'string' && /NEG-|negentropy|unknown|unsupported|not supported|invalid/i.test(id)) finish(new NegentropyError(`unsupported: ${id}`, relay));
          return;
        }
        if (id !== subId) return;
        if (type === 'NEG-ERR' || type === 'CLOSED') return finish(new NegentropyError(typeof payload === 'string' ? payload : 'error: NEG-ERR', relay, type === 'NEG-ERR'));
        if (type !== 'NEG-MSG' || typeof payload !== 'string') return;
        rounds++;
        try {
          const next = neg.reconcile(payload, (x) => have.add(x), (x) => need.add(x));
          if (next === null) {
            void conn.sendMessage(['NEG-CLOSE', subId]).catch(() => undefined);
            finish();
          } else {
            arm();
            void conn.sendMessage(['NEG-MSG', subId, next]).then((ok) => ok || finish(new NegentropyError('error: connection closed', relay)), (e: Error) => finish(e));
          }
        } catch (e) {
          finish(new NegentropyError(`invalid: ${(e as Error).message}`, relay));
        }
      });
      arm();
      conn.sendMessage(['NEG-OPEN', subId, filter, neg.initiate()]).then(
        (ok) => ok || finish(new NegentropyError('error: not connected', relay)),
        (e: Error) => finish(new NegentropyError(`error: ${e.message}`, relay)),
      );
    });
  }
}
