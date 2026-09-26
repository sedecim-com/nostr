import type { Pool } from '@sedecim/service-kit';

export type Visibility = 'private' | 'selective' | 'public';

export interface PersonaRow {
  personaId: string;
  accountId: string;
  pubkey: string;
  custodyMode: string;
  linkageVisibility: Visibility;
  label?: string;
}

export interface LinkRow {
  linkId: string;
  fromPersona: string;
  toPersona: string;
  visibility: Visibility;
  audience: string[];
}

export interface KeyMetadataRow {
  keyId: string;
  personaId: string;
  provider: string;
  version: number;
  lastUsed?: string;
  recoveryState: string;
}

/** An external login (Acceso/Cognito) the user chose to attach to an account. Never a secret. */
export interface ExternalLoginRow {
  accountId: string;
  provider: 'cognito';
  issuer: string;
  subject: string;
  username?: string;
}

/** FR027-03: one stored version of an encrypted backup envelope (opaque to the service). */
export interface BackupRow {
  backupId: string;
  accountId: string;
  format: string;
  formatVersion: number;
  size: number;
  sha256: string;
  npub?: string;
  createdAt: string;
  envelope: string;
}

export type BackupMetaRow = Omit<BackupRow, 'envelope'>;

export interface IdentityRepository {
  createAccount(accountId: string, first: PersonaRow): Promise<void>;
  personaByPubkey(pubkey: string): Promise<PersonaRow | undefined>;
  personasOf(accountId: string): Promise<PersonaRow[]>;
  addPersona(p: PersonaRow): Promise<void>;
  removePersona(accountId: string, pubkey: string): Promise<boolean>;
  addLink(l: LinkRow): Promise<void>;
  linksOf(personaIds: string[]): Promise<LinkRow[]>;
  upsertKeyMetadata(k: KeyMetadataRow): Promise<void>;
  keyMetadataOf(personaId: string): Promise<KeyMetadataRow[]>;
  audit(accountId: string, actor: string, action: string, details: Record<string, unknown>): Promise<void>;
  /** Attach an external login; fails if it already belongs to another account. */
  linkExternalLogin(l: ExternalLoginRow): Promise<void>;
  externalLoginsOf(accountId: string): Promise<ExternalLoginRow[]>;
  unlinkExternalLogin(accountId: string, provider: string): Promise<boolean>;
  auditOf(accountId: string): Promise<Array<{ at: string; actor: string; action: string; details: Record<string, unknown> }>>;
  /** Account an external login (issuer + subject) is attached to, if any. */
  accountByExternalLogin(provider: string, issuer: string, subject: string): Promise<string | undefined>;
  /** Stores a new backup version and prunes the account's older versions beyond `keep`. */
  putBackup(b: BackupRow, keep: number): Promise<void>;
  /** Backups of an account, newest first (metadata only). */
  backupsOf(accountId: string): Promise<BackupMetaRow[]>;
  /** One backup of the account ('latest' for the newest). */
  getBackup(accountId: string, backupId: string): Promise<BackupRow | undefined>;
  /** Deletes one backup, or all of the account's when no id is given; returns how many. */
  deleteBackups(accountId: string, backupId?: string): Promise<number>;
}

export class ExternalLoginTakenError extends Error {
  constructor() {
    super('external login already linked to another account');
  }
}

export class MemoryIdentityRepository implements IdentityRepository {
  private accounts = new Set<string>();
  private personas = new Map<string, PersonaRow>();
  private links = new Map<string, LinkRow>();
  private keys = new Map<string, KeyMetadataRow>();
  private logins: ExternalLoginRow[] = [];
  private log: Array<{ accountId: string; at: string; actor: string; action: string; details: Record<string, unknown> }> = [];
  /** Oldest first. */
  private backups: BackupRow[] = [];

  async createAccount(accountId: string, first: PersonaRow) {
    if (await this.personaByPubkey(first.pubkey)) throw new Error('pubkey already registered');
    this.accounts.add(accountId);
    this.personas.set(first.personaId, first);
  }
  async personaByPubkey(pubkey: string) {
    return [...this.personas.values()].find((p) => p.pubkey === pubkey);
  }
  async personasOf(accountId: string) {
    return [...this.personas.values()].filter((p) => p.accountId === accountId);
  }
  async addPersona(p: PersonaRow) {
    if (await this.personaByPubkey(p.pubkey)) throw new Error('pubkey already registered');
    this.personas.set(p.personaId, p);
  }
  async removePersona(accountId: string, pubkey: string) {
    const p = await this.personaByPubkey(pubkey);
    if (!p || p.accountId !== accountId) return false;
    this.personas.delete(p.personaId);
    for (const [id, l] of this.links) if (l.fromPersona === p.personaId || l.toPersona === p.personaId) this.links.delete(id);
    return true;
  }
  async addLink(l: LinkRow) {
    if ([...this.links.values()].some((x) => x.fromPersona === l.fromPersona && x.toPersona === l.toPersona)) throw new Error('link exists');
    this.links.set(l.linkId, l);
  }
  async linksOf(ids: string[]) {
    return [...this.links.values()].filter((l) => ids.includes(l.fromPersona) || ids.includes(l.toPersona));
  }
  async upsertKeyMetadata(k: KeyMetadataRow) {
    this.keys.set(k.keyId, k);
  }
  async keyMetadataOf(personaId: string) {
    return [...this.keys.values()].filter((k) => k.personaId === personaId);
  }
  async linkExternalLogin(l: ExternalLoginRow) {
    const other = this.logins.find((x) => x.provider === l.provider && x.issuer === l.issuer && x.subject === l.subject);
    if (other && other.accountId !== l.accountId) throw new ExternalLoginTakenError();
    this.logins = this.logins.filter((x) => !(x.accountId === l.accountId && x.provider === l.provider));
    this.logins.push({ ...l });
  }
  async externalLoginsOf(accountId: string) {
    return this.logins.filter((x) => x.accountId === accountId).map((x) => ({ ...x }));
  }
  async unlinkExternalLogin(accountId: string, provider: string) {
    const before = this.logins.length;
    this.logins = this.logins.filter((x) => !(x.accountId === accountId && x.provider === provider));
    return this.logins.length < before;
  }
  async audit(accountId: string, actor: string, action: string, details: Record<string, unknown>) {
    this.log.push({ accountId, at: new Date().toISOString(), actor, action, details });
  }
  async auditOf(accountId: string) {
    return this.log.filter((l) => l.accountId === accountId).map(({ accountId: _a, ...r }) => r);
  }
  async accountByExternalLogin(provider: string, issuer: string, subject: string) {
    return this.logins.find((x) => x.provider === provider && x.issuer === issuer && x.subject === subject)?.accountId;
  }
  async putBackup(b: BackupRow, keep: number) {
    this.backups.push({ ...b });
    const mine = this.backups.filter((x) => x.accountId === b.accountId);
    const drop = new Set(mine.slice(0, Math.max(0, mine.length - keep)));
    this.backups = this.backups.filter((x) => !drop.has(x));
  }
  async backupsOf(accountId: string) {
    return this.backups
      .filter((x) => x.accountId === accountId)
      .reverse()
      .map(({ envelope: _e, ...m }) => m);
  }
  async getBackup(accountId: string, backupId: string) {
    const mine = this.backups.filter((x) => x.accountId === accountId);
    const b = backupId === 'latest' ? mine.at(-1) : mine.find((x) => x.backupId === backupId);
    return b ? { ...b } : undefined;
  }
  async deleteBackups(accountId: string, backupId?: string) {
    const before = this.backups.length;
    this.backups = this.backups.filter((x) => !(x.accountId === accountId && (backupId === undefined || x.backupId === backupId)));
    return before - this.backups.length;
  }
}

export class PgIdentityRepository implements IdentityRepository {
  constructor(private readonly pool: Pool) {}

  private mapPersona = (r: Record<string, unknown>): PersonaRow => ({
    personaId: r.persona_id as string,
    accountId: r.account_id as string,
    pubkey: r.pubkey as string,
    custodyMode: r.custody_mode as string,
    linkageVisibility: r.linkage_visibility as Visibility,
    ...(r.label ? { label: r.label as string } : {}),
  });

  async createAccount(accountId: string, first: PersonaRow) {
    const c = await this.pool.connect();
    try {
      await c.query('BEGIN');
      await c.query('INSERT INTO accounts (account_id) VALUES ($1)', [accountId]);
      await c.query('INSERT INTO identity_personas (persona_id, account_id, pubkey, custody_mode, linkage_visibility, label) VALUES ($1,$2,$3,$4,$5,$6)', [first.personaId, accountId, first.pubkey, first.custodyMode, first.linkageVisibility, first.label ?? null]);
      await c.query('COMMIT');
    } catch (e) {
      await c.query('ROLLBACK');
      throw e;
    } finally {
      c.release();
    }
  }
  async personaByPubkey(pubkey: string) {
    const { rows } = await this.pool.query('SELECT * FROM identity_personas WHERE pubkey = $1', [pubkey]);
    return rows[0] ? this.mapPersona(rows[0]) : undefined;
  }
  async personasOf(accountId: string) {
    const { rows } = await this.pool.query('SELECT * FROM identity_personas WHERE account_id = $1 ORDER BY created_at', [accountId]);
    return rows.map(this.mapPersona);
  }
  async addPersona(p: PersonaRow) {
    await this.pool.query('INSERT INTO identity_personas (persona_id, account_id, pubkey, custody_mode, linkage_visibility, label) VALUES ($1,$2,$3,$4,$5,$6)', [p.personaId, p.accountId, p.pubkey, p.custodyMode, p.linkageVisibility, p.label ?? null]);
  }
  async removePersona(accountId: string, pubkey: string) {
    const r = await this.pool.query('DELETE FROM identity_personas WHERE account_id = $1 AND pubkey = $2', [accountId, pubkey]);
    return (r.rowCount ?? 0) > 0;
  }
  async addLink(l: LinkRow) {
    await this.pool.query('INSERT INTO identity_links (link_id, from_persona, to_persona, visibility, audience) VALUES ($1,$2,$3,$4,$5)', [l.linkId, l.fromPersona, l.toPersona, l.visibility, l.audience]);
  }
  async linksOf(ids: string[]) {
    const { rows } = await this.pool.query('SELECT * FROM identity_links WHERE from_persona = ANY($1) OR to_persona = ANY($1)', [ids]);
    return rows.map((r) => ({ linkId: r.link_id, fromPersona: r.from_persona, toPersona: r.to_persona, visibility: r.visibility, audience: r.audience }));
  }
  async upsertKeyMetadata(k: KeyMetadataRow) {
    await this.pool.query(
      `INSERT INTO key_metadata (key_id, persona_id, provider, version, last_used, recovery_state) VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (key_id) DO UPDATE SET provider = EXCLUDED.provider, version = EXCLUDED.version, last_used = EXCLUDED.last_used, recovery_state = EXCLUDED.recovery_state`,
      [k.keyId, k.personaId, k.provider, k.version, k.lastUsed ?? null, k.recoveryState],
    );
  }
  async keyMetadataOf(personaId: string) {
    const { rows } = await this.pool.query('SELECT * FROM key_metadata WHERE persona_id = $1', [personaId]);
    return rows.map((r) => ({ keyId: r.key_id, personaId: r.persona_id, provider: r.provider, version: r.version, ...(r.last_used ? { lastUsed: new Date(r.last_used).toISOString() } : {}), recoveryState: r.recovery_state }));
  }
  async linkExternalLogin(l: ExternalLoginRow) {
    const { rows } = await this.pool.query('SELECT account_id FROM external_logins WHERE provider = $1 AND issuer = $2 AND subject = $3', [l.provider, l.issuer, l.subject]);
    if (rows[0] && rows[0].account_id !== l.accountId) throw new ExternalLoginTakenError();
    await this.pool.query(
      `INSERT INTO external_logins (account_id, provider, issuer, subject, username) VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (account_id, provider) DO UPDATE SET issuer = EXCLUDED.issuer, subject = EXCLUDED.subject, username = EXCLUDED.username`,
      [l.accountId, l.provider, l.issuer, l.subject, l.username ?? null],
    );
  }
  async externalLoginsOf(accountId: string) {
    const { rows } = await this.pool.query('SELECT * FROM external_logins WHERE account_id = $1', [accountId]);
    return rows.map((r) => ({ accountId: r.account_id, provider: r.provider, issuer: r.issuer, subject: r.subject, ...(r.username ? { username: r.username } : {}) }));
  }
  async unlinkExternalLogin(accountId: string, provider: string) {
    const { rowCount } = await this.pool.query('DELETE FROM external_logins WHERE account_id = $1 AND provider = $2', [accountId, provider]);
    return (rowCount ?? 0) > 0;
  }
  async audit(accountId: string, actor: string, action: string, details: Record<string, unknown>) {
    await this.pool.query('INSERT INTO identity_audit (account_id, actor, action, details) VALUES ($1,$2,$3,$4)', [accountId, actor, action, JSON.stringify(details)]);
  }
  async auditOf(accountId: string) {
    const { rows } = await this.pool.query('SELECT at, actor, action, details FROM identity_audit WHERE account_id = $1 ORDER BY id', [accountId]);
    return rows.map((r) => ({ at: new Date(r.at).toISOString(), actor: r.actor, action: r.action, details: r.details }));
  }
  async accountByExternalLogin(provider: string, issuer: string, subject: string) {
    const { rows } = await this.pool.query('SELECT account_id FROM external_logins WHERE provider = $1 AND issuer = $2 AND subject = $3', [provider, issuer, subject]);
    return rows[0]?.account_id as string | undefined;
  }
  private mapBackup = (r: Record<string, unknown>): BackupRow => ({
    backupId: r.backup_id as string,
    accountId: r.account_id as string,
    format: r.format as string,
    formatVersion: r.format_version as number,
    size: r.size as number,
    sha256: r.sha256 as string,
    ...(r.npub ? { npub: r.npub as string } : {}),
    createdAt: new Date(r.created_at as string).toISOString(),
    envelope: r.envelope as string,
  });
  async putBackup(b: BackupRow, keep: number) {
    const c = await this.pool.connect();
    try {
      await c.query('BEGIN');
      await c.query('INSERT INTO backup_vault (backup_id, account_id, format, format_version, size, sha256, npub, envelope, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [b.backupId, b.accountId, b.format, b.formatVersion, b.size, b.sha256, b.npub ?? null, b.envelope, b.createdAt]);
      await c.query('DELETE FROM backup_vault WHERE account_id = $1 AND seq NOT IN (SELECT seq FROM backup_vault WHERE account_id = $1 ORDER BY seq DESC LIMIT $2)', [b.accountId, keep]);
      await c.query('COMMIT');
    } catch (e) {
      await c.query('ROLLBACK');
      throw e;
    } finally {
      c.release();
    }
  }
  async backupsOf(accountId: string) {
    const { rows } = await this.pool.query("SELECT backup_id, account_id, format, format_version, size, sha256, npub, created_at, '' AS envelope FROM backup_vault WHERE account_id = $1 ORDER BY seq DESC", [accountId]);
    return rows.map((r) => {
      const { envelope: _e, ...m } = this.mapBackup(r);
      return m;
    });
  }
  async getBackup(accountId: string, backupId: string) {
    const { rows } =
      backupId === 'latest'
        ? await this.pool.query('SELECT * FROM backup_vault WHERE account_id = $1 ORDER BY seq DESC LIMIT 1', [accountId])
        : await this.pool.query('SELECT * FROM backup_vault WHERE account_id = $1 AND backup_id = $2', [accountId, backupId]);
    return rows[0] ? this.mapBackup(rows[0]) : undefined;
  }
  async deleteBackups(accountId: string, backupId?: string) {
    const r = backupId === undefined ? await this.pool.query('DELETE FROM backup_vault WHERE account_id = $1', [accountId]) : await this.pool.query('DELETE FROM backup_vault WHERE account_id = $1 AND backup_id = $2', [accountId, backupId]);
    return r.rowCount ?? 0;
  }
}
