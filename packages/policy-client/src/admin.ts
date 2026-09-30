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

/** FR024-04: one device revocation of `GET /v1/revocations`, read from the audit. */
export interface DeviceRevocation {
  /** Audit id of the revocation: monotonic, pass the last one handled as `after`. */
  cursor: number;
  at: number;
  deviceId: string;
  reason?: string;
}

/** FR024-04: a page of `GET /v1/revocations`, oldest first. */
export interface RevocationPage {
  revocations: DeviceRevocation[];
  /** Cursor of the newest revocation (0 if none): a consumer holding a higher one is on another or a rebuilt database. */
  latest: number;
  /** Policy-engine clock (epoch ms), the one that stamped `at`. */
  now: number;
}

/**
 * FR023-10: who may publish in a channel (NIP-29, Buzz) or group (Marmot) resource, for the relays (`GET
 * /v1/relay/grants`). Relays match it against the `h` tag of each event.
 */
export interface RelayGrant {
  resourceId: string;
  kind: 'channel' | 'group';
  pubkeys: string[];
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

/**
 * FR023-12: one access decision of `POST /v1/evaluate` (who asked to do what on which resource, and the answer). Kept
 * apart from the audit, with a retention of its own (ACCESS_LOG_RETENTION_DAYS): the audit records what admins do.
 */
export interface AccessLogEntry {
  /** Monotonic: pass the last one received as `before` to page GET /v1/access-log. */
  id: number;
  at: number;
  pubkey: string;
  deviceId?: string;
  resourceId: string;
  action: string;
  allow: boolean;
}
