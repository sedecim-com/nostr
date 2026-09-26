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
