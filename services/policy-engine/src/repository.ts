import type { JsonWebKey } from 'node:crypto';
import type { Pool } from '@sedecim/service-kit';
import type { Device, DirectoryEntry, PolicyAuditEntry, Resource, RetentionPolicy, Rotation, Subject } from '@sedecim/policy-client';

/** Device as stored: the public Device plus the WebAuthn public key and counter (never returned by the API). */
export interface StoredDevice extends Device {
  credentialPublicKey?: JsonWebKey;
  signCount?: number;
}

export interface SessionRow {
  pubkey: string;
  deviceId: string;
  createdAt: number;
}

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
  addRotation(r: Rotation): Promise<void>;
  /** Oldest first. */
  listRotations(status?: Rotation['status']): Promise<Rotation[]>;
  /** Marks a pending rotation done; undefined if unknown. Idempotent for rotations already done. */
  markRotationDone(id: string, at: number): Promise<Rotation | undefined>;
  appendAudit(e: NewAuditEntry): Promise<void>;
  /** Newest first; `before` is an exclusive audit id. */
  listAudit(q: { limit: number; before?: number }): Promise<PolicyAuditEntry[]>;
  listDirectory(): Promise<DirectoryEntry[]>;
  putDirectoryEntry(e: DirectoryEntry): Promise<void>;
  deleteDirectoryEntry(pubkey: string): Promise<boolean>;
  listRetention(): Promise<RetentionPolicy[]>;
  putRetention(p: RetentionPolicy): Promise<void>;
  putChallenge(deviceId: string, challenge: string, expiresAt: number): Promise<void>;
  /** Returns and deletes the device's pending challenge (single use). */
  takeChallenge(deviceId: string): Promise<{ challenge: string; expiresAt: number } | undefined>;
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
  async putChallenge(deviceId: string, challenge: string, expiresAt: number) {
    this.challenges.set(deviceId, { challenge, expiresAt });
  }
  async takeChallenge(deviceId: string) {
    const c = this.challenges.get(deviceId);
    this.challenges.delete(deviceId);
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
    await this.pool.query('INSERT INTO policy_sessions (token_hash, pubkey, device_id, created_at) VALUES ($1,$2,$3,$4)', [tokenHash, s.pubkey, s.deviceId, s.createdAt]);
  }
  async getSession(tokenHash: string) {
    const { rows } = await this.pool.query('SELECT * FROM policy_sessions WHERE token_hash = $1', [tokenHash]);
    return rows[0] ? { pubkey: rows[0].pubkey as string, deviceId: rows[0].device_id as string, createdAt: Number(rows[0].created_at) } : undefined;
  }
  async deleteSessionsOfDevice(deviceId: string) {
    await this.pool.query('DELETE FROM policy_sessions WHERE device_id = $1', [deviceId]);
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
    return rows.map((r) => ({ id: Number(r.id), at: Number(r.at), actor: r.actor, action: r.action, target: r.target, ...(r.details ? { details: r.details } : {}) }));
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
  async putChallenge(deviceId: string, challenge: string, expiresAt: number) {
    await this.pool.query('INSERT INTO policy_webauthn_challenges (device_id, challenge, expires_at) VALUES ($1,$2,$3) ON CONFLICT (device_id) DO UPDATE SET challenge = EXCLUDED.challenge, expires_at = EXCLUDED.expires_at', [deviceId, challenge, expiresAt]);
  }
  async takeChallenge(deviceId: string) {
    const { rows } = await this.pool.query('DELETE FROM policy_webauthn_challenges WHERE device_id = $1 RETURNING challenge, expires_at', [deviceId]);
    return rows[0] ? { challenge: rows[0].challenge as string, expiresAt: Number(rows[0].expires_at) } : undefined;
  }
}

/** Tables of the policy-engine migration scope (tests reset them). */
export const POLICY_TABLES = ['policy_webauthn_challenges', 'policy_retention', 'policy_directory', 'policy_audit', 'policy_rotations', 'policy_sessions', 'policy_devices', 'policy_resources', 'policy_subjects'];
