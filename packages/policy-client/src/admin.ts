/** Admin-facing records of the policy-engine (spec §16). None of them ever carries message plaintext. */

export interface Rotation {
  id: string;
  at: number;
  resourceId: string;
  reason: string;
  removedPubkey: string;
  status: 'pending' | 'done';
  doneAt?: number;
}

export interface PolicyAuditEntry {
  /** Monotonic sequence number: pass the last one received as `before` to page GET /v1/audit. */
  id: number;
  at: number;
  actor: string;
  action: string;
  target: string;
  details?: Record<string, unknown>;
}

/** FR023-06: organisational directory entry (admin-only, never published to relays). */
export interface DirectoryEntry {
  pubkey: string;
  title?: string;
  unit?: string;
}

/** FR023-08: retention of the mirror copy of a workspace/channel. `days: null` keeps it forever. */
export interface RetentionPolicy {
  resourceId: string;
  days: number | null;
  legalHold: boolean;
}
