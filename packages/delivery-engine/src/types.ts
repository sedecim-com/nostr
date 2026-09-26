import type { EventTemplate, NostrEvent } from '@sedecim/nostr-core';
import type { PublishResult } from '@sedecim/relay-pool';

/**
 * Delivery state machine (spec §11). Relay OK=true (NIP-01) only means "accepted by that relay";
 * recipient reception and reading are separate, application-level states.
 */
export const DELIVERY_STATES = ['DRAFT', 'LOCAL_PERSISTED', 'SIGNED', 'QUEUED', 'PUBLISHING', 'REPLICATED', 'RECIPIENT_ACKED', 'READ'] as const;
export type DeliveryState = (typeof DELIVERY_STATES)[number] | 'FAILED';

export function stateRank(s: DeliveryState): number {
  return s === 'FAILED' ? -1 : DELIVERY_STATES.indexOf(s);
}

export interface RelayAttempt {
  relay: string;
  attemptCount: number;
  lastAttemptAt?: number;
  acceptedAt?: number;
  ackMessage?: string;
  lastError?: string;
  latencyMs?: number;
  /** Rejected in a way that retrying the same event cannot fix (invalid:, blocked:, restricted:, ...). */
  permanent?: boolean;
  /** Last attempt was stopped locally by network policy (e.g. Tor-only without Tor). */
  blocked?: boolean;
}

export interface OutboxRecord {
  /** Stable client_operation_id: survives UI retries and app restarts (spec §11.2). */
  opId: string;
  groupId?: string;
  state: DeliveryState;
  template?: EventTemplate;
  /** The signed event. Once set it is never regenerated: retries republish the same event id. */
  event?: NostrEvent;
  relays: string[];
  quorum: number;
  relayStatus: Record<string, RelayAttempt>;
  createdAt: number;
  updatedAt: number;
  nextAttemptAt?: number;
  blockedReason?: string;
  failureReason?: string;
  history: Array<{ state: DeliveryState; at: number }>;
  meta?: Record<string, string>;
}

export interface Publisher {
  publishTo(evt: NostrEvent, relay: string): Promise<PublishResult>;
}

export interface EventLookup {
  /** Returns true if the relay already stores this event id (used for reconciliation). */
  has(relay: string, eventId: string): Promise<boolean>;
}

export interface RecordStore {
  put(id: string, value: OutboxRecord): Promise<void>;
  get(id: string): Promise<OutboxRecord | undefined>;
  all(): Promise<Array<{ id: string; value: OutboxRecord }>>;
}

export interface RetryPolicy {
  baseMs: number;
  maxMs: number;
  /** Per-relay attempts before giving up on that relay. Undefined = keep trying. */
  maxAttempts?: number;
}

/**
 * Coarse failure class of a publish attempt (FR011-03): safe as a metrics label (no relay message text,
 * no event ids). `rejected` = permanent NIP-01 prefixes; `blocked-policy` = local network policy.
 */
export type FailureClass = 'blocked-policy' | 'timeout' | 'connection' | 'auth' | 'rate-limited' | 'rejected' | 'other';

export const FAILURE_CLASSES: readonly FailureClass[] = ['blocked-policy', 'timeout', 'connection', 'auth', 'rate-limited', 'rejected', 'other'];

export function classifyFailure(message: string, blocked = false): FailureClass {
  if (blocked) return 'blocked-policy';
  const m = message.toLowerCase();
  if (m.includes('timeout')) return 'timeout';
  if (m.startsWith('auth-required:') || m.includes('auth failed')) return 'auth';
  if (m.startsWith('rate-limited:')) return 'rate-limited';
  if (['invalid:', 'blocked:', 'restricted:', 'pow:', 'unsupported:'].some((p) => m.startsWith(p))) return 'rejected';
  if (m.startsWith('error:') && /(connect|connection|not connected|websocket|econnrefused|enotfound|closed)/.test(m)) return 'connection';
  return 'other';
}

/** One publish attempt of an outbox operation to one relay, for observers (metrics). */
export interface AttemptEvent {
  relay: string;
  ok: boolean;
  latencyMs: number;
  /** set when !ok */
  failure?: FailureClass;
  /** the relay was given up for this operation */
  permanent: boolean;
}

/** Aggregate outbox figures (FR011-03). Never contains ids, content or pubkeys. */
export interface OutboxStats {
  /** operations not yet REPLICATED and not FAILED */
  depth: number;
  /** age of the oldest such operation (0 when empty) */
  oldestPendingAgeMs: number;
  /** operations in FAILED */
  failed: number;
  /** operations per delivery state */
  byState: Partial<Record<DeliveryState, number>>;
}
