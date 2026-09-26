export interface WebSocketLike {
  readonly readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  onopen: ((ev: unknown) => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: ((ev: unknown) => void) | null;
  onerror: ((ev: unknown) => void) | null;
}

/**
 * Creates the socket for a relay URL. Network policy (e.g. Tor-only) is enforced here: a factory
 * may throw `NetworkBlockedError` and the pool will never fall back to another transport.
 */
export type WebSocketFactory = (url: string) => WebSocketLike | Promise<WebSocketLike>;

export class NetworkBlockedError extends Error {
  readonly code = 'NETWORK_BLOCKED';
  constructor(message: string, readonly url?: string) {
    super(message);
    this.name = 'NetworkBlockedError';
  }
}

export const WS_OPEN = 1;

export interface PublishResult {
  relay: string;
  ok: boolean;
  message: string;
  latencyMs: number;
  /** true when the relay reported the event as a duplicate (already stored). */
  duplicate?: boolean;
  /** true when the failure was a local network-policy block (fail-closed), not a relay reply. */
  blocked?: boolean;
}

export type RelayStatus = 'idle' | 'connecting' | 'connected' | 'disconnected' | 'blocked';

export interface RelayHealth {
  url: string;
  status: RelayStatus;
  authenticatedAs: string[];
  lastConnectedAt?: number;
  lastError?: string;
  consecutiveFailures: number;
  avgAckLatencyMs?: number;
  /** P95 of the last (up to 50) publish→OK latencies seen by this client (NFR004-02). */
  p95AckLatencyMs?: number;
  /** How many latency samples back avg/p95 (few samples: treat the figure as indicative). */
  ackSamples?: number;
  notices: string[];
}

export interface DegradationThresholds {
  /** P95 publish→OK latency above which the relay is shown as degraded (default 2000 ms, docs/slo.md). */
  p95Ms?: number;
  /** Consecutive connection failures above which the relay is degraded (default 3). */
  failures?: number;
}

export interface RelayDegradation {
  url: string;
  degraded: boolean;
  /** Human-readable (Spanish) reasons, empty when healthy. */
  reasons: string[];
  p95AckLatencyMs?: number;
}

/**
 * Client-side degradation verdict for one relay (NFR004-02 "sin ocultarla"): the UI must show it instead
 * of silently retrying. Blocked/disconnected relays, repeated failures and a slow P95 all count.
 */
export function relayDegradation(h: RelayHealth, t: DegradationThresholds = {}): RelayDegradation {
  const p95Limit = t.p95Ms ?? 2000;
  const failLimit = t.failures ?? 3;
  const reasons: string[] = [];
  if (h.status === 'blocked') reasons.push('bloqueado por la política de red');
  else if (h.status === 'disconnected') reasons.push('desconectado');
  if (h.consecutiveFailures >= failLimit) reasons.push(`${h.consecutiveFailures} fallos de conexión seguidos`);
  if (h.p95AckLatencyMs !== undefined && h.p95AckLatencyMs > p95Limit) reasons.push(`P95 de confirmación ${Math.round(h.p95AckLatencyMs)} ms (> ${p95Limit} ms)`);
  return { url: h.url, degraded: reasons.length > 0, reasons, ...(h.p95AckLatencyMs !== undefined ? { p95AckLatencyMs: h.p95AckLatencyMs } : {}) };
}
