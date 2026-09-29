import { createLogger, type Logger } from '@sedecim/telemetry-policy';
import type { DeviceRevocation, RevocationPage } from './policy';

/** Somewhere a device revocation must land (managed-signer, a NIP-46 bunker...). Must be idempotent. */
export type RevocationSink = (deviceId: string, reason?: string) => Promise<void>;

/** Sink calling the managed-signer's `POST /v1/devices/:id/revoke` with a revocation token (FR024-03). */
export function managedSignerSink(opts: { baseUrl: string; token: string; fetch?: typeof fetch }): RevocationSink {
  const base = opts.baseUrl.replace(/\/$/, '');
  return async (deviceId, reason) => {
    const res = await (opts.fetch ?? fetch)(`${base}/v1/devices/${encodeURIComponent(deviceId)}/revoke`, {
      method: 'POST',
      headers: { authorization: `Bearer ${opts.token}`, 'content-type': 'application/json' },
      body: JSON.stringify(reason ? { reason } : {}),
    });
    if (!res.ok) throw new Error(`managed-signer revoke: ${res.status}`);
  };
}

/** The policy-engine's revocation feed (`HttpPolicySource`). */
export interface RevocationFeed {
  revocations(after: number, limit: number): Promise<RevocationPage>;
}

/** Where the propagator keeps its cursor between runs. Without one, a restart replays every revocation. */
export interface CursorStore {
  load(): Promise<number | undefined>;
  save(cursor: number): Promise<void>;
}

export interface RevocationPropagatorOptions {
  feed: RevocationFeed;
  sinks: RevocationSink[];
  cursor?: CursorStore;
  /** Revocations per request (default 500; the policy-engine serves up to 1000). */
  pageSize?: number;
  /**
   * Age, on the policy-engine clock, a revocation must reach before the cursor moves past it (default 60 s).
   * An audit id is taken before its row commits, so a lower id can show up after a higher one: until then
   * the cursor stays behind and the next runs read those revocations again (skipping the ones already sent).
   */
  settleMs?: number;
  logger?: Logger;
}

/**
 * FR024-03/04: propagates every device revocation of the policy-engine to the signers (managed-signer,
 * bunkers) so that the device's tokens and NIP-46 sessions stop working. It reads `GET /v1/revocations`
 * page by page from its cursor, so no amount of other audit traffic can hide a revocation. A revocation
 * counts as propagated only when every sink accepted it. One that fails is retried on every run and holds
 * the cursor back, while the ones after it are still propagated. Sinks are idempotent, so whatever is
 * read again (after a restart without a saved cursor, or behind a failure) only repeats calls.
 */
export class RevocationPropagator {
  private cursor: number | undefined;
  private saved: number | undefined;
  /** Propagated revocations above the cursor: still settling, or behind one that failed. */
  private readonly sent = new Set<number>();
  /** Revocations whose propagation failed in the last run (the next run retries them), and the last error. */
  failing = 0;
  lastError?: string;
  private readonly log: Logger;

  constructor(private readonly opts: RevocationPropagatorOptions) {
    this.log = opts.logger ?? createLogger({ base: { component: 'revocation-propagator' } });
  }

  /** Returns the ids of the devices whose revocation was propagated in this run. */
  async runOnce(): Promise<string[]> {
    const size = this.opts.pageSize ?? 500;
    const settleMs = this.opts.settleMs ?? 60_000;
    if (this.cursor === undefined) this.saved = this.cursor = (await this.opts.cursor?.load()) ?? 0;
    let cursor = this.cursor;
    let after = cursor;
    let advancing = true;
    let failing = 0;
    const done: string[] = [];
    for (;;) {
      const page = await this.opts.feed.revocations(after, size);
      if (cursor > page.latest) {
        this.log.warn('revocation cursor ahead of the policy-engine (another or a rebuilt database): starting over', { cursor, latest: page.latest });
        cursor = after = 0;
        this.sent.clear();
        continue;
      }
      for (const r of page.revocations) {
        if (!this.sent.has(r.cursor)) {
          if (await this.propagate(r)) {
            this.sent.add(r.cursor);
            done.push(r.deviceId);
          } else failing++;
        }
        if (advancing && this.sent.has(r.cursor) && page.now - r.at >= settleMs) {
          cursor = r.cursor;
          this.sent.delete(r.cursor);
        } else advancing = false;
      }
      const last = page.revocations.at(-1)?.cursor;
      if (page.revocations.length < size || last === undefined || last <= after) break;
      after = last;
    }
    this.cursor = cursor;
    this.failing = failing;
    if (cursor !== this.saved && this.opts.cursor) {
      try {
        await this.opts.cursor.save(cursor);
        this.saved = cursor;
      } catch (err) {
        // The cursor in memory stays right; a restart would only replay more revocations.
        this.log.warn('revocation cursor not saved', { error: (err as Error).message });
      }
    }
    return done;
  }

  private async propagate(r: DeviceRevocation): Promise<boolean> {
    try {
      for (const sink of this.opts.sinks) await sink(r.deviceId, r.reason);
      this.log.info('device revocation propagated', { device_id: r.deviceId, sinks: this.opts.sinks.length });
      return true;
    } catch (err) {
      this.lastError = (err as Error).message;
      this.log.warn('device revocation propagation failed', { device_id: r.deviceId, error: this.lastError });
      return false;
    }
  }
}
