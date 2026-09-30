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
  appendAudit(e: NewAuditEntry): Promise<void>;
  /** Newest first; `before` is an exclusive audit id. */
  listAudit(q: { limit: number; before?: number }): Promise<PolicyAuditEntry[]>;
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
  async appendAudit(e: NewAuditEntry) {
    this.audit.push(clone({ id: this.audit.length + 1, ...e }));
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
const num = (v: unknown) => (v === null || v === undefined ? undefined : Number(v));

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
  async appendAudit(e: NewAuditEntry) {
    await this.pool.query('INSERT INTO policy_audit (at, actor, action, target, details) VALUES ($1,$2,$3,$4,$5)', [e.at, e.actor, e.action, e.target, e.details ? JSON.stringify(e.details) : null]);
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
export const POLICY_TABLES = ['policy_access_log', 'policy_webauthn_challenges', 'policy_retention', 'policy_directory', 'policy_audit', 'policy_rotations', 'policy_sessions', 'policy_devices', 'policy_resources', 'policy_subjects'];
