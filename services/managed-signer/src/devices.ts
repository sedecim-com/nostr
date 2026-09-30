import type { Pool } from '@sedecim/service-kit';

/** A signer session bound to one device (FR024-03). Only the SHA-256 of the token is stored. */
export interface DeviceSession {
  tokenHash: string;
  deviceId: string;
  owner: string;
  principal: string;
  createdAt: number;
  expiresAt: number;
}

export interface DeviceRevocation {
  deviceId: string;
  revokedAt: number;
  /** Who asked for it (revocation principal, e.g. `policy-engine`). */
  revokedBy: string;
  reason?: string;
}

/** Revoked devices and device-bound sessions. Metadata only. */
export interface DeviceStore {
  revocation(deviceId: string): Promise<DeviceRevocation | undefined>;
  /** Idempotent: keeps the first revocation and drops every session of the device. */
  revoke(r: DeviceRevocation): Promise<{ alreadyRevoked: boolean; sessionsDropped: number }>;
  insertSession(s: DeviceSession): Promise<void>;
  session(tokenHash: string): Promise<DeviceSession | undefined>;
  /** FR005-11: the owner's sessions still valid at `now`, oldest first. */
  sessionsOf(owner: string, now: number): Promise<DeviceSession[]>;
  /** FR005-11: closes these sessions of `owner` (by token hash); returns how many. Another owner's are untouched. */
  dropSessions(owner: string, tokenHashes: string[]): Promise<number>;
  /** Deletes sessions expired at `now`; returns how many. */
  purgeExpiredSessions(now: number): Promise<number>;
}

export class MemoryDeviceStore implements DeviceStore {
  readonly revoked = new Map<string, DeviceRevocation>();
  readonly sessions = new Map<string, DeviceSession>();

  async revocation(deviceId: string) {
    const r = this.revoked.get(deviceId);
    return r ? { ...r } : undefined;
  }
  async revoke(r: DeviceRevocation) {
    const alreadyRevoked = this.revoked.has(r.deviceId);
    if (!alreadyRevoked) this.revoked.set(r.deviceId, { ...r });
    let sessionsDropped = 0;
    for (const [h, s] of this.sessions) if (s.deviceId === r.deviceId) (this.sessions.delete(h), sessionsDropped++);
    return { alreadyRevoked, sessionsDropped };
  }
  async insertSession(s: DeviceSession) {
    this.sessions.set(s.tokenHash, { ...s });
  }
  async session(tokenHash: string) {
    const s = this.sessions.get(tokenHash);
    return s ? { ...s } : undefined;
  }
  async sessionsOf(owner: string, now: number) {
    return [...this.sessions.values()].filter((s) => s.owner === owner && s.expiresAt > now).sort((a, b) => a.createdAt - b.createdAt).map((s) => ({ ...s }));
  }
  async dropSessions(owner: string, tokenHashes: string[]) {
    let n = 0;
    for (const h of tokenHashes) if (this.sessions.get(h)?.owner === owner) (this.sessions.delete(h), n++);
    return n;
  }
  async purgeExpiredSessions(now: number) {
    let n = 0;
    for (const [h, s] of this.sessions) if (s.expiresAt <= now) (this.sessions.delete(h), n++);
    return n;
  }
}

/** Postgres store (migrations/002): revocations survive restarts and apply to every replica. */
export class PgDeviceStore implements DeviceStore {
  constructor(private readonly pool: Pool) {}

  async revocation(deviceId: string) {
    const { rows } = await this.pool.query<{ device_id: string; revoked_at: Date; revoked_by: string; reason: string | null }>(
      'SELECT device_id, revoked_at, revoked_by, reason FROM managed_signer_revoked_devices WHERE device_id = $1',
      [deviceId],
    );
    const r = rows[0];
    return r ? { deviceId: r.device_id, revokedAt: r.revoked_at.getTime(), revokedBy: r.revoked_by, ...(r.reason === null ? {} : { reason: r.reason }) } : undefined;
  }
  async revoke(r: DeviceRevocation) {
    const ins = await this.pool.query(
      'INSERT INTO managed_signer_revoked_devices (device_id, revoked_at, revoked_by, reason) VALUES ($1,$2,$3,$4) ON CONFLICT (device_id) DO NOTHING',
      [r.deviceId, new Date(r.revokedAt), r.revokedBy, r.reason ?? null],
    );
    const del = await this.pool.query('DELETE FROM managed_signer_device_sessions WHERE device_id = $1', [r.deviceId]);
    return { alreadyRevoked: (ins.rowCount ?? 0) === 0, sessionsDropped: del.rowCount ?? 0 };
  }
  async insertSession(s: DeviceSession) {
    await this.pool.query(
      'INSERT INTO managed_signer_device_sessions (token_hash, device_id, owner, principal, created_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6)',
      [s.tokenHash, s.deviceId, s.owner, s.principal, new Date(s.createdAt), new Date(s.expiresAt)],
    );
  }
  async session(tokenHash: string) {
    const { rows } = await this.pool.query<{ token_hash: string; device_id: string; owner: string; principal: string; created_at: Date; expires_at: Date }>(
      'SELECT * FROM managed_signer_device_sessions WHERE token_hash = $1',
      [tokenHash],
    );
    const r = rows[0];
    return r ? { tokenHash: r.token_hash, deviceId: r.device_id, owner: r.owner, principal: r.principal, createdAt: r.created_at.getTime(), expiresAt: r.expires_at.getTime() } : undefined;
  }
  async sessionsOf(owner: string, now: number) {
    const { rows } = await this.pool.query<{ token_hash: string; device_id: string; owner: string; principal: string; created_at: Date; expires_at: Date }>(
      'SELECT * FROM managed_signer_device_sessions WHERE owner = $1 AND expires_at > $2 ORDER BY created_at, token_hash',
      [owner, new Date(now)],
    );
    return rows.map((r) => ({ tokenHash: r.token_hash, deviceId: r.device_id, owner: r.owner, principal: r.principal, createdAt: r.created_at.getTime(), expiresAt: r.expires_at.getTime() }));
  }
  async dropSessions(owner: string, tokenHashes: string[]) {
    if (tokenHashes.length === 0) return 0;
    const r = await this.pool.query('DELETE FROM managed_signer_device_sessions WHERE owner = $1 AND token_hash = ANY($2)', [owner, tokenHashes]);
    return r.rowCount ?? 0;
  }
  async purgeExpiredSessions(now: number) {
    const r = await this.pool.query('DELETE FROM managed_signer_device_sessions WHERE expires_at <= $1', [new Date(now)]);
    return r.rowCount ?? 0;
  }
}
