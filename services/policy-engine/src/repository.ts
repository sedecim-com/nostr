import type { JsonWebKey } from 'node:crypto';
import type { Pool } from '@sedecim/service-kit';
import type { AccessLogEntry, Device, DirectoryEntry, PolicyAuditEntry, Resource, RetentionPolicy, Rotation, Subject } from '@sedecim/policy-client';

/** Device as stored: the public Device plus the WebAuthn public key and counter (never returned by the API). */
export interface StoredDevice extends Device {
  credentialPublicKey?: JsonWebKey;
  signCount?: number;
}

export interface SessionRow {
  pubkey: string;
  deviceId: string;
  createdAt: number;
  /** FR023-11: the passkey whose assertion opened the session; absent when it was opened without one. */
  credentialId?: string;
}

/** FR023-11: a device has at most one pending challenge of each kind: registering a passkey, and asserting with it. */
export type ChallengePurpose = 'register' | 'assert';

export type NewAuditEntry = Omit<PolicyAuditEntry, 'id'>;

/** OPS-16: an audit entry's event, signed, as the engine hands it to the repository. */
export interface SealedEvent {
  id: string;
  type: string;
  createdAt: number;
  /** The signed envelope, canonical JSON: served and delivered as it was signed. */
  envelope: string;
}

/** OPS-16: builds the signed event of an audit entry (with its id) at stream position `seq`, inside the append. */
export type EventSealer = (entry: PolicyAuditEntry, seq: number) => SealedEvent;

export interface StoredEvent extends SealedEvent {
  seq: number;
}

/** OPS-16: a public key that signed events (its JWK `x`), kept so that events signed before a rotation still verify. */
export interface EventKeyRow {
  kid: string;
  x: string;
  createdAt: number;
}

/** OPS-16: a webhook subscription. Its secret is never stored: it is derived from the secrets key and `salt`. */
export interface WebhookRow {
  id: string;
  url: string;
  /** Event types it receives; empty: all of them. */
  types: string[];
  status: 'active' | 'disabled';
  salt: string;
  createdAt: number;
  createdBy: string;
  consecutiveFailures: number;
  disabledAt?: number;
  disabledReason?: string;
}

/** OPS-16: one delivery of an event to a subscription. Never the destination's response body or headers. */
export interface DeliveryRow {
  id: number;
  webhookId: string;
  eventSeq: number;
  eventId: string;
  eventType: string;
  status: 'pending' | 'delivered' | 'failed';
  attempts: number;
  /** When a pending delivery is due. */
  nextAttemptAt?: number;
  lastAttemptAt?: number;
  /** HTTP status of the last answer, if the destination answered. */
  lastStatus?: number;
  /** Class of the last failure (timeout, http_5xx…). */
  lastError?: string;
  finishedAt?: number;
  createdAt: number;
}

/** OPS-16: what a dispatcher needs to send a delivery it claimed. */
export interface ClaimedDelivery {
  id: number;
  webhookId: string;
  url: string;
  salt: string;
  eventId: string;
  envelope: string;
  /** Attempts so far, this one included. */
  attempts: number;
}

export interface DeliveryOutcome {
  id: number;
  /** The claim's lease: a dispatcher whose lease expired (and was taken over) changes nothing. */
  leaseId: string;
  now: number;
  ok: boolean;
  status?: number;
  error?: string;
  /** When to retry; absent on a failure: it failed for good. */
  retryAt?: number;
  /** Consecutive failed attempts that disable the subscription. */
  disableAfter: number;
}

/** Why a subscription was disabled by its failures. */
export const WEBHOOK_DISABLED_REASON = 'too many consecutive failed deliveries';

/** A delivery as the API shows it: `nextAttemptAt` only while pending, no empty fields. */
export function deliveryView(d: DeliveryRow): DeliveryRow {
  const { nextAttemptAt, ...rest } = d;
  const out = Object.fromEntries(Object.entries(rest).filter(([, v]) => v !== undefined && v !== null)) as unknown as DeliveryRow;
  return d.status === 'pending' && nextAttemptAt !== undefined ? { ...out, nextAttemptAt } : out;
}

/**
 * Persistence of the policy-engine (FR023-03). The audit is append-only: there is no way to change or
 * delete an entry. Session tokens are passed already hashed.
 */
export interface PolicyRepository {
  getSubject(pubkey: string): Promise<Subject | undefined>;
  listSubjects(): Promise<Subject[]>;
  putSubject(s: Subject): Promise<void>;
  getResource(id: string): Promise<Resource | undefined>;
  listResources(): Promise<Resource[]>;
  putResource(r: Resource): Promise<void>;
  getDevice(id: string): Promise<StoredDevice | undefined>;
  listDevices(owner?: string): Promise<StoredDevice[]>;
  putDevice(d: StoredDevice): Promise<void>;
  putSession(tokenHash: string, s: SessionRow): Promise<void>;
  getSession(tokenHash: string): Promise<SessionRow | undefined>;
  deleteSessionsOfDevice(deviceId: string): Promise<void>;
  /** FR023-11: deletes the owner's sessions opened without a passkey assertion. */
  deleteUnassertedSessions(pubkey: string): Promise<void>;
  /**
   * FR023-11: records the signature counter of an assertion by the device's credential. Accepted when the stored and the
   * new counter are both 0 (an authenticator without one) or the new one is greater, checked and written at once: of
   * two assertions with the same counter only one gets through. False when the counter did not go up (a possible
   * clone), or the device is revoked or holds another credential by now.
   */
  advanceSignCount(deviceId: string, credentialId: string, signCount: number): Promise<boolean>;
  addRotation(r: Rotation): Promise<void>;
  /** Oldest first. */
  listRotations(status?: Rotation['status']): Promise<Rotation[]>;
  /** Marks a pending rotation done; undefined if unknown. Idempotent for rotations already done. */
  markRotationDone(id: string, at: number): Promise<Rotation | undefined>;
  /**
   * With `seal` (OPS-16), the entry's signed event goes in with it, at once: the next stream position, and one pending
   * delivery per active subscription that wants its type. Writers of events take turns, so they commit in `seq` order:
   * a reader paging by `seq` never sees a position before a lower one that commits later.
   */
  appendAudit(e: NewAuditEntry, seal?: EventSealer): Promise<void>;
  /** Newest first; `before` is an exclusive audit id. */
  listAudit(q: { limit: number; before?: number }): Promise<PolicyAuditEntry[]>;
  /** OPS-16: events after `after` (a `seq`), oldest first. */
  listEvents(q: { after: number; limit: number }): Promise<StoredEvent[]>;
  /** OPS-16: records a signing key (no-op if it is known). */
  recordEventKey(k: EventKeyRow): Promise<void>;
  /** OPS-16: every signing key recorded, oldest first. */
  listEventKeys(): Promise<EventKeyRow[]>;
  /** OPS-16: adds a subscription unless there are already `max`; false then. */
  createWebhook(w: WebhookRow, max: number): Promise<boolean>;
  /** Oldest first. */
  listWebhooks(): Promise<WebhookRow[]>;
  getWebhook(id: string): Promise<WebhookRow | undefined>;
  /** Deletes the subscription and its deliveries. */
  deleteWebhook(id: string): Promise<boolean>;
  /** Active again, with its failure count at 0; undefined if unknown. */
  enableWebhook(id: string): Promise<WebhookRow | undefined>;
  /**
   * OPS-16: claims up to `limit` due deliveries of active subscriptions for `leaseMs`, counting the attempt: no other
   * claim gets them until the lease expires (a dispatcher that died). A delivery whose last allowed attempt died with
   * its dispatcher fails (`lease_expired`).
   */
  claimDeliveries(q: { now: number; limit: number; leaseMs: number; leaseId: string; maxAttempts: number }): Promise<ClaimedDelivery[]>;
  /**
   * OPS-16: records the attempt of a claim that still holds its lease, and the subscription's run of failures: a success
   * resets it; reaching `disableAfter` disables the subscription and fails its pending deliveries (`disabled: true`).
   */
  completeDelivery(r: DeliveryOutcome): Promise<{ disabled: boolean; failures: number }>;
  /** Newest first; `before` is an exclusive delivery id. */
  listDeliveries(webhookId: string, q: { limit: number; before?: number }): Promise<DeliveryRow[]>;
  /** Deletes the finished deliveries (delivered or failed) that finished before `before` (ms). Returns how many. */
  pruneDeliveries(before: number): Promise<number>;
  /** Oldest first: the entries of one action whose id is greater than `after`. */
  listAuditByAction(q: { action: string; after: number; limit: number }): Promise<PolicyAuditEntry[]>;
  /** Id of the newest entry of one action, 0 if none. */
  lastAuditId(action: string): Promise<number>;
  /** FR023-12: one access decision. The access log, unlike the audit, has a retention: see `purgeAccess`. */
  appendAccess(e: Omit<AccessLogEntry, 'id'>): Promise<void>;
  /** Newest first; `before` is an exclusive id; only one resource's with `resourceId`. */
  listAccess(q: { limit: number; before?: number; resourceId?: string }): Promise<AccessLogEntry[]>;
  /** Deletes the decisions made before `before` (ms), except those on `exceptResources` (legal hold). Returns how many. */
  purgeAccess(q: { before: number; exceptResources: string[] }): Promise<number>;
  listDirectory(): Promise<DirectoryEntry[]>;
  putDirectoryEntry(e: DirectoryEntry): Promise<void>;
  deleteDirectoryEntry(pubkey: string): Promise<boolean>;
  listRetention(): Promise<RetentionPolicy[]>;
  putRetention(p: RetentionPolicy): Promise<void>;
  /** Replaces the device's pending challenge of that purpose. */
  putChallenge(deviceId: string, challenge: string, expiresAt: number, purpose: ChallengePurpose): Promise<void>;
  /** Returns and deletes the device's pending challenge of that purpose (single use, atomically). */
  takeChallenge(deviceId: string, purpose: ChallengePurpose): Promise<{ challenge: string; expiresAt: number } | undefined>;
}

const clone = <T>(v: T): T => structuredClone(v);
const byKey = <T>(key: (v: T) => string) => (a: T, b: T) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0);

/** In-memory repository (no DATABASE_URL): same behaviour, lost on restart. Returns copies. */
export class MemoryPolicyRepository implements PolicyRepository {
  private subjects = new Map<string, Subject>();
  private resources = new Map<string, Resource>();
  private devices = new Map<string, StoredDevice>();
  private sessions = new Map<string, SessionRow>();
  private rotations: Rotation[] = [];
  private audit: PolicyAuditEntry[] = [];
  private directory = new Map<string, DirectoryEntry>();
  private retention = new Map<string, RetentionPolicy>();
  private challenges = new Map<string, { challenge: string; expiresAt: number }>();

  async getSubject(pubkey: string) {
    return clone(this.subjects.get(pubkey));
  }
  async listSubjects() {
    return clone([...this.subjects.values()].sort(byKey((s) => s.pubkey)));
  }
  async putSubject(s: Subject) {
    this.subjects.set(s.pubkey, clone(s));
  }
  async getResource(id: string) {
    return clone(this.resources.get(id));
  }
  async listResources() {
    return clone([...this.resources.values()].sort(byKey((r) => r.id)));
  }
  async putResource(r: Resource) {
    this.resources.set(r.id, clone(r));
  }
  async getDevice(id: string) {
    return clone(this.devices.get(id));
  }
  async listDevices(owner?: string) {
    return clone([...this.devices.values()].filter((d) => !owner || d.ownerPubkey === owner).sort((a, b) => a.registeredAt - b.registeredAt || (a.id < b.id ? -1 : 1)));
  }
  async putDevice(d: StoredDevice) {
    if (d.credentialId && [...this.devices.values()].some((x) => x.id !== d.id && x.credentialId === d.credentialId)) throw new Error('credential already registered');
    this.devices.set(d.id, clone(d));
  }
  async putSession(tokenHash: string, s: SessionRow) {
    this.sessions.set(tokenHash, clone(s));
  }
  async getSession(tokenHash: string) {
    return clone(this.sessions.get(tokenHash));
  }
  async deleteSessionsOfDevice(deviceId: string) {
    for (const [t, s] of this.sessions) if (s.deviceId === deviceId) this.sessions.delete(t);
  }
  async deleteUnassertedSessions(pubkey: string) {
    for (const [t, s] of this.sessions) if (s.pubkey === pubkey && s.credentialId === undefined) this.sessions.delete(t);
  }
  // Check and write with no await in between: atomic in this process.
  async advanceSignCount(deviceId: string, credentialId: string, signCount: number) {
    const d = this.devices.get(deviceId);
    if (!d || d.revokedAt !== undefined || d.credentialId !== credentialId) return false;
    const stored = d.signCount ?? 0;
    if (stored === 0 && signCount === 0) return true;
    if (signCount <= stored) return false;
    d.signCount = signCount;
    return true;
  }
  async addRotation(r: Rotation) {
    this.rotations.push(clone(r));
  }
  async listRotations(status?: Rotation['status']) {
    return clone(this.rotations.filter((r) => !status || r.status === status));
  }
  async markRotationDone(id: string, at: number) {
    const r = this.rotations.find((x) => x.id === id);
    if (r && r.status === 'pending') Object.assign(r, { status: 'done', doneAt: at });
    return clone(r);
  }
  // No await in between: the entry, its event and its deliveries land at once in this process, in seq order.
  async appendAudit(e: NewAuditEntry, seal?: EventSealer) {
    const entry: PolicyAuditEntry = clone({ id: this.audit.length + 1, ...e });
    // Sealed before anything is written: if signing throws, neither the entry nor its event exist.
    const sealed = seal ? seal(clone(entry), this.eventSeq + 1) : undefined;
    this.audit.push(entry);
    if (!sealed) return;
    const seq = ++this.eventSeq;
    this.events.push(clone({ seq, ...sealed }));
    for (const w of this.webhooks.values()) {
      if (w.status !== 'active' || (w.types.length > 0 && !w.types.includes(sealed.type))) continue;
      this.deliveries.push({ id: ++this.deliverySeq, webhookId: w.id, eventSeq: seq, eventId: sealed.id, eventType: sealed.type, status: 'pending', attempts: 0, nextAttemptAt: sealed.createdAt, createdAt: sealed.createdAt });
    }
  }
  private events: StoredEvent[] = [];
  private eventSeq = 0;
  private eventKeys = new Map<string, EventKeyRow>();
  private webhooks = new Map<string, WebhookRow>();
  private deliveries: Array<DeliveryRow & { lockedUntil?: number; leaseId?: string }> = [];
  private deliverySeq = 0;
  async listEvents(q: { after: number; limit: number }) {
    return clone(this.events.filter((e) => e.seq > q.after).slice(0, q.limit));
  }
  async recordEventKey(k: EventKeyRow) {
    if (!this.eventKeys.has(k.kid)) this.eventKeys.set(k.kid, clone(k));
  }
  async listEventKeys() {
    return clone([...this.eventKeys.values()]);
  }
  async createWebhook(w: WebhookRow, max: number) {
    if (this.webhooks.size >= max) return false;
    this.webhooks.set(w.id, clone(w));
    return true;
  }
  async listWebhooks() {
    return clone([...this.webhooks.values()].sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1)));
  }
  async getWebhook(id: string) {
    return clone(this.webhooks.get(id));
  }
  async deleteWebhook(id: string) {
    this.deliveries = this.deliveries.filter((d) => d.webhookId !== id);
    return this.webhooks.delete(id);
  }
  async enableWebhook(id: string) {
    const w = this.webhooks.get(id);
    if (!w) return undefined;
    const { disabledAt: _at, disabledReason: _reason, ...rest } = w;
    const enabled: WebhookRow = { ...rest, status: 'active', consecutiveFailures: 0 };
    this.webhooks.set(id, enabled);
    return clone(enabled);
  }
  async claimDeliveries(q: { now: number; limit: number; leaseMs: number; leaseId: string; maxAttempts: number }) {
    const expired = (d: { lockedUntil?: number }) => d.lockedUntil === undefined || d.lockedUntil <= q.now;
    for (const d of this.deliveries) {
      if (d.status === 'pending' && d.attempts >= q.maxAttempts && d.lockedUntil !== undefined && d.lockedUntil <= q.now) {
        Object.assign(d, { status: 'failed', lastError: 'lease_expired', finishedAt: q.now, lockedUntil: undefined, leaseId: undefined });
      }
    }
    const due = this.deliveries
      .filter((d) => d.status === 'pending' && this.webhooks.get(d.webhookId)?.status === 'active' && (d.nextAttemptAt ?? 0) <= q.now && expired(d) && d.attempts < q.maxAttempts)
      .sort((a, b) => (a.nextAttemptAt ?? 0) - (b.nextAttemptAt ?? 0) || a.id - b.id)
      .slice(0, q.limit);
    return due.map((d) => {
      Object.assign(d, { lockedUntil: q.now + q.leaseMs, leaseId: q.leaseId, attempts: d.attempts + 1, lastAttemptAt: q.now });
      const w = this.webhooks.get(d.webhookId)!;
      const e = this.events.find((x) => x.seq === d.eventSeq)!;
      return { id: d.id, webhookId: d.webhookId, url: w.url, salt: w.salt, eventId: e.id, envelope: e.envelope, attempts: d.attempts };
    });
  }
  async completeDelivery(r: DeliveryOutcome) {
    const d = this.deliveries.find((x) => x.id === r.id);
    if (!d || d.status !== 'pending' || d.leaseId !== r.leaseId) return { disabled: false, failures: 0 };
    const status = r.ok ? 'delivered' : r.retryAt === undefined ? 'failed' : 'pending';
    Object.assign(d, { status, lockedUntil: undefined, leaseId: undefined, lastStatus: r.status, lastError: r.ok ? undefined : (r.error ?? 'network') });
    if (status === 'pending') d.nextAttemptAt = r.retryAt;
    else d.finishedAt = r.now;
    const w = this.webhooks.get(d.webhookId);
    if (!w) return { disabled: false, failures: 0 };
    if (r.ok) {
      w.consecutiveFailures = 0;
      return { disabled: false, failures: 0 };
    }
    w.consecutiveFailures += 1;
    if (w.status !== 'active' || w.consecutiveFailures < r.disableAfter) return { disabled: false, failures: w.consecutiveFailures };
    Object.assign(w, { status: 'disabled', disabledAt: r.now, disabledReason: WEBHOOK_DISABLED_REASON });
    for (const x of this.deliveries) {
      if (x.webhookId === w.id && x.status === 'pending') Object.assign(x, { status: 'failed', lastError: 'subscription_disabled', finishedAt: r.now, lockedUntil: undefined, leaseId: undefined });
    }
    return { disabled: true, failures: w.consecutiveFailures };
  }
  async listDeliveries(webhookId: string, q: { limit: number; before?: number }) {
    return this.deliveries
      .filter((d) => d.webhookId === webhookId && (q.before === undefined || d.id < q.before))
      .slice(-q.limit)
      .reverse()
      .map(({ lockedUntil: _l, leaseId: _lease, ...d }) => deliveryView(clone(d)));
  }
  async pruneDeliveries(before: number) {
    const keep = this.deliveries.filter((d) => d.status === 'pending' || d.finishedAt === undefined || d.finishedAt >= before);
    const n = this.deliveries.length - keep.length;
    this.deliveries = keep;
    return n;
  }
  async listAudit(q: { limit: number; before?: number }) {
    return clone(
      this.audit
        .filter((e) => q.before === undefined || e.id < q.before)
        .slice(-q.limit)
        .reverse(),
    );
  }
  async listAuditByAction(q: { action: string; after: number; limit: number }) {
    return clone(this.audit.filter((e) => e.action === q.action && e.id > q.after).slice(0, q.limit));
  }
  async lastAuditId(action: string) {
    for (let i = this.audit.length - 1; i >= 0; i--) if (this.audit[i]!.action === action) return this.audit[i]!.id;
    return 0;
  }
  private access: AccessLogEntry[] = [];
  private accessSeq = 0;
  async appendAccess(e: Omit<AccessLogEntry, 'id'>) {
    this.access.push(clone({ id: ++this.accessSeq, ...e }));
  }
  async listAccess(q: { limit: number; before?: number; resourceId?: string }) {
    return clone(
      this.access
        .filter((e) => (q.before === undefined || e.id < q.before) && (q.resourceId === undefined || e.resourceId === q.resourceId))
        .slice(-q.limit)
        .reverse(),
    );
  }
  async purgeAccess(q: { before: number; exceptResources: string[] }) {
    const keep = this.access.filter((e) => e.at >= q.before || q.exceptResources.includes(e.resourceId));
    const n = this.access.length - keep.length;
    this.access = keep;
    return n;
  }
  async listDirectory() {
    return clone([...this.directory.values()].sort(byKey((e) => e.pubkey)));
  }
  async putDirectoryEntry(e: DirectoryEntry) {
    this.directory.set(e.pubkey, clone(e));
  }
  async deleteDirectoryEntry(pubkey: string) {
    return this.directory.delete(pubkey);
  }
  async listRetention() {
    return clone([...this.retention.values()].sort(byKey((p) => p.resourceId)));
  }
  async putRetention(p: RetentionPolicy) {
    this.retention.set(p.resourceId, clone(p));
  }
  async putChallenge(deviceId: string, challenge: string, expiresAt: number, purpose: ChallengePurpose) {
    this.challenges.set(`${purpose}:${deviceId}`, { challenge, expiresAt });
  }
  async takeChallenge(deviceId: string, purpose: ChallengePurpose) {
    const c = this.challenges.get(`${purpose}:${deviceId}`);
    this.challenges.delete(`${purpose}:${deviceId}`);
    return c;
  }
}

type Row = Record<string, unknown>;
/** The part of a pooled client a transaction uses. */
interface PgClient {
  query: Pool['query'];
  release(err?: Error | boolean): void;
}
const num = (v: unknown) => (v === null || v === undefined ? undefined : Number(v));
/** OPS-16: advisory locks (per database): writers of events, and creations of subscriptions. */
const EVENTS_LOCK = 'sedecim:policy-engine:events';
const WEBHOOKS_LOCK = 'sedecim:policy-engine:webhooks';

export class PgPolicyRepository implements PolicyRepository {
  constructor(private readonly pool: Pool) {}

  private subject = (r: Row): Subject => ({
    pubkey: r.pubkey as string,
    roles: r.roles as string[],
    attributes: r.attributes as Subject['attributes'],
    ...(r.suspended ? { suspended: true } : {}),
  });
  private resource = (r: Row): Resource => ({
    id: r.id as string,
    kind: r.kind as Resource['kind'],
    sensitivity: r.sensitivity as Resource['sensitivity'],
    rules: r.rules as Resource['rules'],
    ...(r.members ? { members: r.members as string[] } : {}),
  });
  private device = (r: Row): StoredDevice => ({
    id: r.id as string,
    ownerPubkey: r.owner_pubkey as string,
    trust: r.trust as Device['trust'],
    registeredAt: Number(r.registered_at),
    ...(r.revoked_at !== null ? { revokedAt: Number(r.revoked_at) } : {}),
    ...(r.credential_id ? { credentialId: r.credential_id as string } : {}),
    ...(r.attestation_format ? { attestationFormat: r.attestation_format as string } : {}),
    ...(r.credential_public_key ? { credentialPublicKey: r.credential_public_key as JsonWebKey } : {}),
    ...(r.sign_count !== null ? { signCount: Number(r.sign_count) } : {}),
  });
  private rotation = (r: Row): Rotation => ({
    id: r.id as string,
    at: Number(r.at),
    resourceId: r.resource_id as string,
    reason: r.reason as string,
    removedPubkey: r.removed_pubkey as string,
    status: r.status as Rotation['status'],
    ...(r.done_at !== null ? { doneAt: Number(r.done_at) } : {}),
  });
  private auditEntry = (r: Row): PolicyAuditEntry => ({
    id: Number(r.id),
    at: Number(r.at),
    actor: r.actor as string,
    action: r.action as string,
    target: r.target as string,
    ...(r.details ? { details: r.details as Record<string, unknown> } : {}),
  });

  async getSubject(pubkey: string) {
    const { rows } = await this.pool.query('SELECT * FROM policy_subjects WHERE pubkey = $1', [pubkey]);
    return rows[0] ? this.subject(rows[0]) : undefined;
  }
  async listSubjects() {
    return (await this.pool.query('SELECT * FROM policy_subjects ORDER BY pubkey')).rows.map(this.subject);
  }
  async putSubject(s: Subject) {
    await this.pool.query(
      `INSERT INTO policy_subjects (pubkey, roles, attributes, suspended) VALUES ($1,$2,$3,$4)
       ON CONFLICT (pubkey) DO UPDATE SET roles = EXCLUDED.roles, attributes = EXCLUDED.attributes, suspended = EXCLUDED.suspended`,
      [s.pubkey, s.roles, JSON.stringify(s.attributes), !!s.suspended],
    );
  }
  async getResource(id: string) {
    const { rows } = await this.pool.query('SELECT * FROM policy_resources WHERE id = $1', [id]);
    return rows[0] ? this.resource(rows[0]) : undefined;
  }
  async listResources() {
    return (await this.pool.query('SELECT * FROM policy_resources ORDER BY id')).rows.map(this.resource);
  }
  async putResource(r: Resource) {
    await this.pool.query(
      `INSERT INTO policy_resources (id, kind, sensitivity, rules, members) VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, sensitivity = EXCLUDED.sensitivity, rules = EXCLUDED.rules, members = EXCLUDED.members`,
      [r.id, r.kind, r.sensitivity, JSON.stringify(r.rules), r.members ?? null],
    );
  }
  async getDevice(id: string) {
    const { rows } = await this.pool.query('SELECT * FROM policy_devices WHERE id = $1', [id]);
    return rows[0] ? this.device(rows[0]) : undefined;
  }
  async listDevices(owner?: string) {
    const { rows } = owner
      ? await this.pool.query('SELECT * FROM policy_devices WHERE owner_pubkey = $1 ORDER BY registered_at, id', [owner])
      : await this.pool.query('SELECT * FROM policy_devices ORDER BY registered_at, id');
    return rows.map(this.device);
  }
  async putDevice(d: StoredDevice) {
    try {
      await this.pool.query(
        `INSERT INTO policy_devices (id, owner_pubkey, trust, registered_at, revoked_at, credential_id, credential_public_key, sign_count, attestation_format)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
         ON CONFLICT (id) DO UPDATE SET owner_pubkey = EXCLUDED.owner_pubkey, trust = EXCLUDED.trust, revoked_at = EXCLUDED.revoked_at,
           credential_id = EXCLUDED.credential_id, credential_public_key = EXCLUDED.credential_public_key, sign_count = EXCLUDED.sign_count,
           attestation_format = EXCLUDED.attestation_format`,
        [d.id, d.ownerPubkey, d.trust, d.registeredAt, d.revokedAt ?? null, d.credentialId ?? null, d.credentialPublicKey ? JSON.stringify(d.credentialPublicKey) : null, d.signCount ?? null, d.attestationFormat ?? null],
      );
    } catch (e) {
      if ((e as { code?: string }).code === '23505') throw new Error('credential already registered');
      throw e;
    }
  }
  async putSession(tokenHash: string, s: SessionRow) {
    await this.pool.query('INSERT INTO policy_sessions (token_hash, pubkey, device_id, created_at, credential_id) VALUES ($1,$2,$3,$4,$5)', [tokenHash, s.pubkey, s.deviceId, s.createdAt, s.credentialId ?? null]);
  }
  async getSession(tokenHash: string) {
    const { rows } = await this.pool.query('SELECT * FROM policy_sessions WHERE token_hash = $1', [tokenHash]);
    const r = rows[0];
    return r ? { pubkey: r.pubkey as string, deviceId: r.device_id as string, createdAt: Number(r.created_at), ...(r.credential_id ? { credentialId: r.credential_id as string } : {}) } : undefined;
  }
  async deleteSessionsOfDevice(deviceId: string) {
    await this.pool.query('DELETE FROM policy_sessions WHERE device_id = $1', [deviceId]);
  }
  async deleteUnassertedSessions(pubkey: string) {
    await this.pool.query('DELETE FROM policy_sessions WHERE pubkey = $1 AND credential_id IS NULL', [pubkey]);
  }
  // One statement: under READ COMMITTED a second UPDATE with the same counter waits for the first and then no longer
  // matches `sign_count < $3`, so only one of two concurrent assertions gets through.
  async advanceSignCount(deviceId: string, credentialId: string, signCount: number) {
    const { rowCount } =
      signCount === 0
        ? await this.pool.query('SELECT 1 FROM policy_devices WHERE id = $1 AND credential_id = $2 AND revoked_at IS NULL AND coalesce(sign_count, 0) = 0', [deviceId, credentialId])
        : await this.pool.query('UPDATE policy_devices SET sign_count = $3 WHERE id = $1 AND credential_id = $2 AND revoked_at IS NULL AND coalesce(sign_count, 0) < $3', [deviceId, credentialId, signCount]);
    return (rowCount ?? 0) > 0;
  }
  async addRotation(r: Rotation) {
    await this.pool.query('INSERT INTO policy_rotations (id, at, resource_id, reason, removed_pubkey, status, done_at) VALUES ($1,$2,$3,$4,$5,$6,$7)', [r.id, r.at, r.resourceId, r.reason, r.removedPubkey, r.status, r.doneAt ?? null]);
  }
  async listRotations(status?: Rotation['status']) {
    const { rows } = status
      ? await this.pool.query('SELECT * FROM policy_rotations WHERE status = $1 ORDER BY seq', [status])
      : await this.pool.query('SELECT * FROM policy_rotations ORDER BY seq');
    return rows.map(this.rotation);
  }
  async markRotationDone(id: string, at: number) {
    await this.pool.query("UPDATE policy_rotations SET status = 'done', done_at = $2 WHERE id = $1 AND status = 'pending'", [id, at]);
    const { rows } = await this.pool.query('SELECT * FROM policy_rotations WHERE id = $1', [id]);
    return rows[0] ? this.rotation(rows[0]) : undefined;
  }
  private async tx<T>(fn: (c: PgClient) => Promise<T>): Promise<T> {
    const c = await this.pool.connect();
    try {
      await c.query('BEGIN');
      const out = await fn(c);
      await c.query('COMMIT');
      return out;
    } catch (e) {
      await c.query('ROLLBACK').catch(() => {});
      throw e;
    } finally {
      c.release();
    }
  }
  async appendAudit(e: NewAuditEntry, seal?: EventSealer) {
    const values = [e.at, e.actor, e.action, e.target, e.details ? JSON.stringify(e.details) : null];
    if (!seal) {
      await this.pool.query('INSERT INTO policy_audit (at, actor, action, target, details) VALUES ($1,$2,$3,$4,$5)', values);
      return;
    }
    await this.tx(async (c) => {
      // OPS-16: writers of events take turns until they commit. The lock is released after the commit is visible, so the
      // next writer draws a higher seq only once the lower one can be read: pages by seq have no hole that fills later.
      await c.query(`SELECT pg_advisory_xact_lock(hashtext('${EVENTS_LOCK}'))`);
      const { rows } = await c.query('INSERT INTO policy_audit (at, actor, action, target, details) VALUES ($1,$2,$3,$4,$5) RETURNING *', values);
      // The entry as stored (what GET /v1/audit returns) is what the event copies.
      const entry = this.auditEntry(rows[0]);
      const seq = Number((await c.query("SELECT nextval(pg_get_serial_sequence('policy_events', 'seq')) AS seq")).rows[0].seq);
      const sealed = seal(entry, seq);
      await c.query('INSERT INTO policy_events (seq, id, audit_id, type, created_at, envelope) VALUES ($1,$2,$3,$4,$5,$6)', [seq, sealed.id, entry.id, sealed.type, sealed.createdAt, sealed.envelope]);
      await c.query(
        `INSERT INTO policy_webhook_deliveries (webhook_id, event_seq, next_attempt_at, created_at)
         SELECT id, $1, $2, $2 FROM policy_webhooks WHERE status = 'active' AND (cardinality(types) = 0 OR $3 = ANY(types))`,
        [seq, sealed.createdAt, sealed.type],
      );
    });
  }
  async listEvents(q: { after: number; limit: number }) {
    const { rows } = await this.pool.query('SELECT seq, id, type, created_at, envelope FROM policy_events WHERE seq > $1 ORDER BY seq LIMIT $2', [q.after, q.limit]);
    return rows.map((r) => ({ seq: Number(r.seq), id: r.id as string, type: r.type as string, createdAt: Number(r.created_at), envelope: r.envelope as string }));
  }
  async recordEventKey(k: EventKeyRow) {
    await this.pool.query('INSERT INTO policy_event_keys (kid, x, created_at) VALUES ($1,$2,$3) ON CONFLICT (kid) DO NOTHING', [k.kid, k.x, k.createdAt]);
  }
  async listEventKeys() {
    const { rows } = await this.pool.query('SELECT kid, x, created_at FROM policy_event_keys ORDER BY created_at, kid');
    return rows.map((r) => ({ kid: r.kid as string, x: r.x as string, createdAt: Number(r.created_at) }));
  }
  private webhook = (r: Row): WebhookRow => ({
    id: r.id as string,
    url: r.url as string,
    types: r.types as string[],
    status: r.status as WebhookRow['status'],
    salt: r.salt as string,
    createdAt: Number(r.created_at),
    createdBy: r.created_by as string,
    consecutiveFailures: Number(r.consecutive_failures),
    ...(r.disabled_at !== null ? { disabledAt: Number(r.disabled_at) } : {}),
    ...(r.disabled_reason !== null ? { disabledReason: r.disabled_reason as string } : {}),
  });
  async createWebhook(w: WebhookRow, max: number) {
    return this.tx(async (c) => {
      // The limit counts every replica's subscriptions: two concurrent creations cannot both take the last place.
      await c.query(`SELECT pg_advisory_xact_lock(hashtext('${WEBHOOKS_LOCK}'))`);
      if (Number((await c.query('SELECT count(*) AS n FROM policy_webhooks')).rows[0].n) >= max) return false;
      await c.query('INSERT INTO policy_webhooks (id, url, types, status, salt, created_at, created_by, consecutive_failures) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [
        w.id,
        w.url,
        w.types,
        w.status,
        w.salt,
        w.createdAt,
        w.createdBy,
        w.consecutiveFailures,
      ]);
      return true;
    });
  }
  async listWebhooks() {
    return (await this.pool.query('SELECT * FROM policy_webhooks ORDER BY created_at, id')).rows.map(this.webhook);
  }
  async getWebhook(id: string) {
    const { rows } = await this.pool.query('SELECT * FROM policy_webhooks WHERE id = $1', [id]);
    return rows[0] ? this.webhook(rows[0]) : undefined;
  }
  async deleteWebhook(id: string) {
    return ((await this.pool.query('DELETE FROM policy_webhooks WHERE id = $1', [id])).rowCount ?? 0) > 0;
  }
  async enableWebhook(id: string) {
    const { rows } = await this.pool.query("UPDATE policy_webhooks SET status = 'active', consecutive_failures = 0, disabled_at = NULL, disabled_reason = NULL WHERE id = $1 RETURNING *", [id]);
    return rows[0] ? this.webhook(rows[0]) : undefined;
  }
  async claimDeliveries(q: { now: number; limit: number; leaseMs: number; leaseId: string; maxAttempts: number }) {
    await this.pool.query(
      `UPDATE policy_webhook_deliveries SET status = 'failed', last_error = 'lease_expired', finished_at = $1, locked_until = NULL, lease_id = NULL
       WHERE status = 'pending' AND attempts >= $2 AND locked_until IS NOT NULL AND locked_until <= $1`,
      [q.now, q.maxAttempts],
    );
    // SKIP LOCKED: concurrent claims of other replicas take other rows instead of waiting for these.
    const { rows } = await this.pool.query(
      `WITH due AS (
         SELECT d.id FROM policy_webhook_deliveries d JOIN policy_webhooks w ON w.id = d.webhook_id
         WHERE d.status = 'pending' AND w.status = 'active' AND d.next_attempt_at <= $1
           AND (d.locked_until IS NULL OR d.locked_until <= $1) AND d.attempts < $5
         ORDER BY d.next_attempt_at, d.id
         LIMIT $2
         FOR UPDATE OF d SKIP LOCKED
       ), claimed AS (
         UPDATE policy_webhook_deliveries d SET locked_until = $3, lease_id = $4, attempts = d.attempts + 1, last_attempt_at = $1
         FROM due WHERE d.id = due.id
         RETURNING d.id, d.webhook_id, d.event_seq, d.attempts
       )
       SELECT c.id, c.webhook_id, c.attempts, w.url, w.salt, e.id AS event_id, e.envelope
       FROM claimed c JOIN policy_webhooks w ON w.id = c.webhook_id JOIN policy_events e ON e.seq = c.event_seq
       ORDER BY c.id`,
      [q.now, q.limit, q.now + q.leaseMs, q.leaseId, q.maxAttempts],
    );
    return rows.map((r) => ({ id: Number(r.id), webhookId: r.webhook_id as string, url: r.url as string, salt: r.salt as string, eventId: r.event_id as string, envelope: r.envelope as string, attempts: Number(r.attempts) }));
  }
  async completeDelivery(r: DeliveryOutcome) {
    const status = r.ok ? 'delivered' : r.retryAt === undefined ? 'failed' : 'pending';
    return this.tx(async (c) => {
      const { rows } = await c.query(
        `UPDATE policy_webhook_deliveries SET status = $3, next_attempt_at = coalesce($4, next_attempt_at), locked_until = NULL, lease_id = NULL,
           last_status = $5, last_error = $6, finished_at = $7
         WHERE id = $1 AND lease_id = $2 AND status = 'pending' RETURNING webhook_id`,
        [r.id, r.leaseId, status, r.retryAt ?? null, r.status ?? null, r.ok ? null : (r.error ?? 'network'), status === 'pending' ? null : r.now],
      );
      if (!rows[0]) return { disabled: false, failures: 0 };
      const webhookId = rows[0].webhook_id as string;
      if (r.ok) {
        await c.query('UPDATE policy_webhooks SET consecutive_failures = 0 WHERE id = $1', [webhookId]);
        return { disabled: false, failures: 0 };
      }
      const w = (await c.query('UPDATE policy_webhooks SET consecutive_failures = consecutive_failures + 1 WHERE id = $1 RETURNING consecutive_failures, status', [webhookId])).rows[0];
      const failures = Number(w?.consecutive_failures ?? 0);
      if (!w || w.status !== 'active' || failures < r.disableAfter) return { disabled: false, failures };
      await c.query("UPDATE policy_webhooks SET status = 'disabled', disabled_at = $2, disabled_reason = $3 WHERE id = $1", [webhookId, r.now, WEBHOOK_DISABLED_REASON]);
      await c.query(
        `UPDATE policy_webhook_deliveries SET status = 'failed', last_error = 'subscription_disabled', finished_at = $2, locked_until = NULL, lease_id = NULL
         WHERE webhook_id = $1 AND status = 'pending'`,
        [webhookId, r.now],
      );
      return { disabled: true, failures };
    });
  }
  async listDeliveries(webhookId: string, q: { limit: number; before?: number }) {
    const { rows } = await this.pool.query(
      `SELECT d.*, e.id AS event_id, e.type AS event_type FROM policy_webhook_deliveries d JOIN policy_events e ON e.seq = d.event_seq
       WHERE d.webhook_id = $1 AND ($3::bigint IS NULL OR d.id < $3) ORDER BY d.id DESC LIMIT $2`,
      [webhookId, q.limit, q.before ?? null],
    );
    return rows.map((r) =>
      deliveryView({
        id: Number(r.id),
        webhookId: r.webhook_id as string,
        eventSeq: Number(r.event_seq),
        eventId: r.event_id as string,
        eventType: r.event_type as string,
        status: r.status as DeliveryRow['status'],
        attempts: Number(r.attempts),
        nextAttemptAt: Number(r.next_attempt_at),
        ...(r.last_attempt_at !== null ? { lastAttemptAt: Number(r.last_attempt_at) } : {}),
        ...(r.last_status !== null ? { lastStatus: Number(r.last_status) } : {}),
        ...(r.last_error !== null ? { lastError: r.last_error as string } : {}),
        ...(r.finished_at !== null ? { finishedAt: Number(r.finished_at) } : {}),
        createdAt: Number(r.created_at),
      }),
    );
  }
  async pruneDeliveries(before: number) {
    return (await this.pool.query("DELETE FROM policy_webhook_deliveries WHERE status <> 'pending' AND finished_at < $1", [before])).rowCount ?? 0;
  }
  async listAudit(q: { limit: number; before?: number }) {
    const { rows } =
      q.before === undefined
        ? await this.pool.query('SELECT * FROM policy_audit ORDER BY id DESC LIMIT $1', [q.limit])
        : await this.pool.query('SELECT * FROM policy_audit WHERE id < $2 ORDER BY id DESC LIMIT $1', [q.limit, q.before]);
    return rows.map(this.auditEntry);
  }
  async listAuditByAction(q: { action: string; after: number; limit: number }) {
    const { rows } = await this.pool.query('SELECT * FROM policy_audit WHERE action = $1 AND id > $2 ORDER BY id LIMIT $3', [q.action, q.after, q.limit]);
    return rows.map(this.auditEntry);
  }
  async appendAccess(e: Omit<AccessLogEntry, 'id'>) {
    await this.pool.query('INSERT INTO policy_access_log (at, pubkey, device_id, resource_id, action, allow) VALUES ($1,$2,$3,$4,$5,$6)', [e.at, e.pubkey, e.deviceId ?? null, e.resourceId, e.action, e.allow]);
  }
  async listAccess(q: { limit: number; before?: number; resourceId?: string }) {
    const { rows } = await this.pool.query(
      'SELECT * FROM policy_access_log WHERE ($2::bigint IS NULL OR id < $2) AND ($3::text IS NULL OR resource_id = $3) ORDER BY id DESC LIMIT $1',
      [q.limit, q.before ?? null, q.resourceId ?? null],
    );
    return rows.map((r) => ({ id: Number(r.id), at: Number(r.at), pubkey: r.pubkey as string, ...(r.device_id ? { deviceId: r.device_id as string } : {}), resourceId: r.resource_id as string, action: r.action as string, allow: r.allow as boolean }));
  }
  async purgeAccess(q: { before: number; exceptResources: string[] }) {
    const r = await this.pool.query('DELETE FROM policy_access_log WHERE at < $1 AND NOT resource_id = ANY($2)', [q.before, q.exceptResources]);
    return r.rowCount ?? 0;
  }
  async lastAuditId(action: string) {
    const { rows } = await this.pool.query('SELECT coalesce(max(id), 0) AS id FROM policy_audit WHERE action = $1', [action]);
    return Number(rows[0].id);
  }
  async listDirectory() {
    const { rows } = await this.pool.query('SELECT * FROM policy_directory ORDER BY pubkey');
    return rows.map((r) => ({ pubkey: r.pubkey as string, ...(r.title !== null ? { title: r.title as string } : {}), ...(r.unit !== null ? { unit: r.unit as string } : {}) }));
  }
  async putDirectoryEntry(e: DirectoryEntry) {
    await this.pool.query('INSERT INTO policy_directory (pubkey, title, unit) VALUES ($1,$2,$3) ON CONFLICT (pubkey) DO UPDATE SET title = EXCLUDED.title, unit = EXCLUDED.unit', [e.pubkey, e.title ?? null, e.unit ?? null]);
  }
  async deleteDirectoryEntry(pubkey: string) {
    return ((await this.pool.query('DELETE FROM policy_directory WHERE pubkey = $1', [pubkey])).rowCount ?? 0) > 0;
  }
  async listRetention() {
    const { rows } = await this.pool.query('SELECT * FROM policy_retention ORDER BY resource_id');
    return rows.map((r) => ({ resourceId: r.resource_id as string, days: num(r.days) ?? null, legalHold: r.legal_hold as boolean }));
  }
  async putRetention(p: RetentionPolicy) {
    await this.pool.query('INSERT INTO policy_retention (resource_id, days, legal_hold) VALUES ($1,$2,$3) ON CONFLICT (resource_id) DO UPDATE SET days = EXCLUDED.days, legal_hold = EXCLUDED.legal_hold', [p.resourceId, p.days, p.legalHold]);
  }
  async putChallenge(deviceId: string, challenge: string, expiresAt: number, purpose: ChallengePurpose) {
    await this.pool.query(
      'INSERT INTO policy_webauthn_challenges (device_id, purpose, challenge, expires_at) VALUES ($1,$2,$3,$4) ON CONFLICT (device_id, purpose) DO UPDATE SET challenge = EXCLUDED.challenge, expires_at = EXCLUDED.expires_at',
      [deviceId, purpose, challenge, expiresAt],
    );
  }
  async takeChallenge(deviceId: string, purpose: ChallengePurpose) {
    const { rows } = await this.pool.query('DELETE FROM policy_webauthn_challenges WHERE device_id = $1 AND purpose = $2 RETURNING challenge, expires_at', [deviceId, purpose]);
    return rows[0] ? { challenge: rows[0].challenge as string, expiresAt: Number(rows[0].expires_at) } : undefined;
  }
}

/** Tables of the policy-engine migration scope (tests reset them). */
export const POLICY_TABLES = ['policy_webhook_deliveries', 'policy_webhooks', 'policy_event_keys', 'policy_events', 'policy_access_log', 'policy_webauthn_challenges', 'policy_retention', 'policy_directory', 'policy_audit', 'policy_rotations', 'policy_sessions', 'policy_devices', 'policy_resources', 'policy_subjects'];
