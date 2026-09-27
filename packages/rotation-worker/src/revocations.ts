import { createLogger, type Logger } from '@sedecim/telemetry-policy';
import type { PolicyAuditEntry } from './policy';

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

export interface RevocationPropagatorOptions {
  /** Reads the policy-engine audit log (source of truth for `device.revoke`). */
  audit: () => Promise<PolicyAuditEntry[]>;
  sinks: RevocationSink[];
  logger?: Logger;
}

/**
 * FR024-03: propagates every `device.revoke` of the policy-engine to the signers (managed-signer, bunkers)
 * so that the device's tokens and NIP-46 sessions stop working. A revocation counts as propagated only
 * when every sink accepted it; otherwise it is retried on the next run. Sinks are idempotent, so a
 * restart (which forgets what was propagated) only repeats calls.
 */
export class RevocationPropagator {
  private readonly propagated = new Set<string>();
  private readonly log: Logger;

  constructor(private readonly opts: RevocationPropagatorOptions) {
    this.log = opts.logger ?? createLogger({ base: { component: 'revocation-propagator' } });
  }

  async runOnce(): Promise<string[]> {
    const done: string[] = [];
    for (const e of await this.opts.audit()) {
      if (e.action !== 'device.revoke' || !e.target || this.propagated.has(e.target)) continue;
      const reason = typeof e.details?.reason === 'string' ? e.details.reason : undefined;
      try {
        for (const sink of this.opts.sinks) await sink(e.target, reason);
        this.propagated.add(e.target);
        done.push(e.target);
        this.log.info('device revocation propagated', { device_id: e.target, sinks: this.opts.sinks.length });
      } catch (err) {
        this.log.warn('device revocation propagation failed', { device_id: e.target, error: (err as Error).message });
      }
    }
    return done;
  }
}
