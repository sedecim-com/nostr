import type { EventTemplate, NostrEvent } from '@sedecim/nostr-core';

/** Default kind of synthetic ACK probes: ephemeral (NIP-01 20000-29999), so relays answer OK without storing it. */
export const ACK_PROBE_KIND = 20001;

export interface AckProbeOptions {
  /** Anything that publishes to one relay and is observed by the exporter (e.g. a RelayPool with attachPool). */
  pool: { publishTo(evt: NostrEvent, relay: string): Promise<unknown> };
  signer: { signEvent(t: EventTemplate): Promise<NostrEvent> };
  relays: string[];
  intervalMs: number;
  kind?: number;
}

/**
 * Service-side synthetic probe (NFR004-01): publishes an empty ephemeral event signed by the service
 * identity to every relay on an interval so ACK latency is measured even when no user traffic flows
 * through the service. It carries no user data. Returns a stop function.
 */
export function startAckProbe(opts: AckProbeOptions): () => void {
  let stopped = false;
  const round = async () => {
    const evt = await opts.signer.signEvent({ kind: opts.kind ?? ACK_PROBE_KIND, content: '', tags: [['alt', 'acceso-nostr ack probe']] });
    await Promise.all(opts.relays.map((r) => opts.pool.publishTo(evt, r).catch(() => undefined)));
  };
  const timer = setInterval(() => {
    if (!stopped) void round().catch(() => undefined);
  }, opts.intervalMs);
  (timer as { unref?: () => void }).unref?.();
  void round().catch(() => undefined);
  return () => {
    stopped = true;
    clearInterval(timer);
  };
}
