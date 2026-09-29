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

/**
 * VAULT-04 (ADR 0011): the copy of each sent event in the Continuity Vault. `best-effort` backs it up beside the
 * relay publishing and never delays it; `required-for-resilient` publishes to relays only once the copy exists.
 */
export type ContinuityPolicy = 'off' | 'best-effort' | 'required-for-resilient';

/**
 * The Continuity Vault track of an operation, kept apart from the relay ACKs: a message can be REPLICATED without
 * a copy in the vault yet, and CONTINUITY_BACKED_UP before any relay accepted it.
 */
export interface ContinuityStatus {
  /** The policy the operation was sent under. */
  policy: Exclude<ContinuityPolicy, 'off'>;
  /** `FAILED`: a best-effort copy given up after `RetryPolicy.maxAttempts`; a required one is never given up. */
  state: 'PENDING' | 'CONTINUITY_BACKED_UP' | 'FAILED';
  attemptCount: number;
  lastAttemptAt?: number;
  backedUpAt?: number;
  lastError?: string;
}

/** Stores the signed event of an operation in the Continuity Vault; resolves once the vault holds it. */
export interface ContinuitySink {
  backup(event: NostrEvent): Promise<void>;
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
  /** Relay acceptances needed to reach REPLICATED: never more than `relays.length`. */
  quorum: number;
  /** FR010-04: the quorum asked for when there were fewer relays (then `quorum` was capped to them). */
  requestedQuorum?: number;
  relayStatus: Record<string, RelayAttempt>;
  createdAt: number;
  updatedAt: number;
  nextAttemptAt?: number;
  blockedReason?: string;
  failureReason?: string;
  history: Array<{ state: DeliveryState; at: number }>;
  meta?: Record<string, string>;
  /** VAULT-04: absent when the operation was sent with the Continuity Vault off. */
  continuity?: ContinuityStatus;
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
  /** VAULT-04: operations whose copy is not yet in the Continuity Vault (FAILED operations aside) */
  continuityPending: number;
}
