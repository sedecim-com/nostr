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
  notices: string[];
}
