import { createHash, randomBytes } from 'node:crypto';
import {
  generateSecretKey,
  getPublicKey,
  getTagValue,
  nip49,
  selfTestKey,
  verifyEvent,
  wipe,
  type EventTemplate,
  type NostrEvent,
  type Signer,
} from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import type { Vault } from './vault';
import type { SealedKeyOps } from './enclave/client';
import { MemoryKeyRegistry, PubkeyAlreadyManagedError, type KeyRecord, type KeyRegistry, type UsageRecord } from './registry';
import { MemoryDeviceStore, type DeviceRevocation, type DeviceStore } from './devices';
import { DEFAULT_RATE_LIMITS, DEFAULT_SCRYPT_LIMITS, ScryptGate, SigningRateLimiter, type RateLimitConfig, type ScryptLimitConfig } from './ratelimit';
import { SignerMetrics, type SignerOp } from './metrics';

export const MANAGED_DISCLOSURE =
  'Managed Key activado: la plataforma tiene capacidad técnica de firmar como el usuario. Este modo es CUSTODIAL y nunca debe presentarse como non-custodial.';

export class ManagedSignerError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

/** FR005-06: too many operations for this key (or this kind of this key). */
export class RateLimitedError extends ManagedSignerError {
  /** `owner`/`busy`: import/export admission (IR-2026-09-20). */
  constructor(readonly scope: 'key' | 'kind' | 'owner' | 'busy', readonly retryAfterSeconds: number) {
    super(429, `rate limit exceeded (${scope}): retry after ${retryAfterSeconds}s`);
  }
}

/** Who performs an operation: the audited principal and, for device sessions, the device (FR024-03). */
export interface Actor {
  principal: string;
  deviceId?: string;
}

const asActor = (a: string | Actor): Actor => (typeof a === 'string' ? { principal: a } : a);
export const DEVICE_SESSION_PREFIX = 'sds_';
const hashToken = (t: string) => createHash('sha256').update(t).digest('hex');

export interface ManagedSignerOptions {
  /** Key registry and usage log; defaults to memory (tests/dev). Production uses PgKeyRegistry. */
  registry?: KeyRegistry;
  /** Days the vault material is kept after a key is deleted (DEC-09: 30). */
  retentionDays?: number;
  /** Months the usage log is kept (DEC-09: 12). */
  usageRetentionMonths?: number;
  /** Revoked devices and device-bound sessions (FR024-03); defaults to memory. Production: PgDeviceStore. */
  devices?: DeviceStore;
  /** Device session lifetime (default 12 h, max 30 days). */
  deviceSessionTtlMs?: number;
  /** Per-key / per-kind limits (FR005-06); `false` disables them. */
  rateLimits?: RateLimitConfig | false;
  /** Per-owner rate/concurrency and global concurrency of scrypt (import/export); `false` disables them. */
  scryptLimits?: ScryptLimitConfig | false;
  metrics?: SignerMetrics;
  /**
   * Enclave tier (FR005-05): keys are generated, unsealed and used only inside the enclave; the vault then
   * stores sealed blobs this process cannot decrypt.
   */
  sealedKeys?: SealedKeyOps;
  now?: () => number;
}

const MAX_SESSION_TTL_MS = 30 * 86_400_000;
/** Highest scrypt cost accepted on import (2^18 x 1 KiB = 256 MiB); what our clients produce (16/18). */
export const MAX_IMPORT_LOG_N = 18;
/** At most one `rate-limited` audit row per key per window, so an abusive client cannot flood the log. */
const RATE_AUDIT_WINDOW_MS = 60_000;

/** Signing core over a key registry. Secrets are loaded from the vault per operation and wiped right after. */
export class ManagedSigner {
  readonly registry: KeyRegistry;
  readonly devices: DeviceStore;
  readonly metrics: SignerMetrics;
  private readonly limiter?: SigningRateLimiter;
  private readonly scryptGate?: ScryptGate;
  private readonly lastRateAudit = new Map<string, number>();
  private readonly revocationListeners = new Set<(r: DeviceRevocation) => void | Promise<void>>();

  constructor(private readonly vault: Vault, private readonly opts: ManagedSignerOptions = {}) {
    this.registry = opts.registry ?? new MemoryKeyRegistry();
    this.devices = opts.devices ?? new MemoryDeviceStore();
    this.metrics = opts.metrics ?? new SignerMetrics();
    if (opts.rateLimits !== false) this.limiter = new SigningRateLimiter(opts.rateLimits ?? DEFAULT_RATE_LIMITS);
    if (opts.scryptLimits !== false) this.scryptGate = new ScryptGate(opts.scryptLimits ?? DEFAULT_SCRYPT_LIMITS, () => this.now());
  }

  /** Runs a scrypt operation through the per-owner/global admission (wrong passwords count too). */
  private async scrypt<T>(op: 'import' | 'export', owner: string, fn: () => Promise<T>): Promise<T> {
    if (!this.scryptGate) return fn();
    const r = await this.scryptGate.run(owner, fn);
    if (r.ok) return r.value;
    this.metrics.rateLimited.inc({ op, scope: r.scope });
    throw new RateLimitedError(r.scope, Math.max(1, Math.ceil(r.retryAfterMs / 1000)));
  }

  private now() {
    return (this.opts.now ?? Date.now)();
  }

  private record(r: Omit<UsageRecord, 'at'>) {
    return this.registry.recordUsage({ at: this.now(), ...r });
  }

  private async rateLimit(k: KeyRecord, op: SignerOp, kind: number | undefined, actor: Actor) {
    if (!this.limiter) return;
    const now = this.now();
    const d = this.limiter.take(k.keyId, kind ?? 'nip44', now);
    if (d.ok) return;
    this.metrics.rateLimited.inc({ op, scope: d.scope });
    this.metrics.operations.inc({ op, result: 'rate_limited' });
    if (now - (this.lastRateAudit.get(k.keyId) ?? -Infinity) >= RATE_AUDIT_WINDOW_MS) {
      if (this.lastRateAudit.size > 10_000) this.lastRateAudit.clear();
      this.lastRateAudit.set(k.keyId, now);
      await this.record({ keyId: k.keyId, action: 'rate-limited', ...(kind !== undefined ? { kind } : {}), principal: actor.principal, ...(actor.deviceId ? { deviceId: actor.deviceId } : {}) });
    }
    throw new RateLimitedError(d.scope, Math.max(1, Math.ceil(d.retryAfterMs / 1000)));
  }

  /** Rejects operations from a revoked device (FR024-03). */
  async assertDeviceUsable(deviceId: string | undefined): Promise<void> {
    if (deviceId === undefined) return;
    if (await this.devices.revocation(deviceId)) {
      this.metrics.deviceRejections.inc();
      throw new ManagedSignerError(403, 'device revoked');
    }
  }

  /**
   * Opens a signer session bound to a device. The returned bearer token (`sds_...`) stops working as soon
   * as the device is revoked or the session expires. Only its hash is stored.
   */
  async openDeviceSession(owner: string, principal: string, deviceId: string, ttlMs?: number): Promise<{ token: string; expiresAt: number }> {
    await this.assertDeviceUsable(deviceId);
    const ttl = Math.min(ttlMs ?? this.opts.deviceSessionTtlMs ?? 12 * 3_600_000, MAX_SESSION_TTL_MS);
    const token = DEVICE_SESSION_PREFIX + randomBytes(32).toString('hex');
    const createdAt = this.now();
    await this.devices.insertSession({ tokenHash: hashToken(token), deviceId, owner, principal, createdAt, expiresAt: createdAt + ttl });
    return { token, expiresAt: createdAt + ttl };
  }

  /** Resolves a device session token; fails if unknown, expired or its device was revoked. */
  async resolveDeviceSession(token: string): Promise<{ owner: string; principal: string; deviceId: string }> {
    const s = await this.devices.session(hashToken(token));
    if (!s || s.expiresAt <= this.now()) throw new ManagedSignerError(401, 'invalid or expired device session');
    // Checked on every use: a revocation that raced with the session's creation still applies.
    if (await this.devices.revocation(s.deviceId)) {
      this.metrics.deviceRejections.inc();
      throw new ManagedSignerError(401, 'device revoked');
    }
    return { owner: s.owner, principal: s.principal, deviceId: s.deviceId };
  }

  /**
   * FR024-03: the organisation revoked a device. Its sessions are dropped, new ones are refused and any
   * call naming it fails. Idempotent. Listeners (e.g. a NIP-46 bunker over this vault) are notified.
   */
  async revokeDevice(deviceId: string, revokedBy: string, reason?: string): Promise<{ alreadyRevoked: boolean; sessionsDropped: number }> {
    const r: DeviceRevocation = { deviceId, revokedAt: this.now(), revokedBy, ...(reason ? { reason } : {}) };
    const out = await this.devices.revoke(r);
    this.metrics.deviceRevocations.inc({ result: out.alreadyRevoked ? 'repeated' : 'new' });
    for (const fn of this.revocationListeners) await fn(r);
    return out;
  }

  /** Called on every device revocation (also repeated ones). Returns an unsubscribe function. */
  onDeviceRevoked(fn: (r: DeviceRevocation) => void | Promise<void>): () => void {
    this.revocationListeners.add(fn);
    return () => this.revocationListeners.delete(fn);
  }

  private async key(keyId: string, owner: string): Promise<KeyRecord> {
    const k = await this.registry.get(keyId);
    if (!k || k.state === 'deleted') throw new ManagedSignerError(404, 'unknown key');
    if (k.owner !== owner) throw new ManagedSignerError(403, 'key belongs to another owner');
    return k;
  }

  private async secretOf(k: KeyRecord): Promise<Uint8Array> {
    if (k.state === 'migrated') throw new ManagedSignerError(409, 'key migrated out of managed custody');
    const secret = await this.vault.get(k.keyId);
    if (!secret) throw new ManagedSignerError(500, 'key material missing from vault');
    return secret;
  }

  private async withSigner<T>(k: KeyRecord, fn: (s: Signer) => Promise<T>): Promise<T> {
    const secret = await this.secretOf(k);
    const signer = this.opts.sealedKeys ? this.opts.sealedKeys.signer(secret, k.pubkey) : new LocalSigner(secret, 'managed');
    wipe(secret);
    try {
      return await fn(signer);
    } finally {
      signer.destroy();
      await this.registry.touch(k.keyId, this.now());
    }
  }

  async create(owner: string, principal: string, opts: { allowedKinds?: number[] } = {}): Promise<KeyRecord> {
    if (this.opts.sealedKeys) return this.persist(await this.opts.sealedKeys.generate(), owner, principal, 'created', opts);
    const sk = generateSecretKey();
    try {
      return await this.store(sk, owner, principal, 'created', opts);
    } finally {
      wipe(sk);
    }
  }

  /** local -> managed migration (explicit, opt-in). */
  async importEncrypted(owner: string, principal: string, ncryptsec: string, password: string): Promise<KeyRecord> {
    if (typeof ncryptsec !== 'string' || typeof password !== 'string') throw new ManagedSignerError(400, 'ncryptsec and password must be strings');
    let logN: number;
    try {
      logN = nip49.ncryptsecLogN(ncryptsec);
    } catch {
      throw new ManagedSignerError(400, 'invalid ncryptsec');
    }
    // logN is attacker-chosen: 2^20 would make scrypt allocate 1 GiB per request.
    if (logN > MAX_IMPORT_LOG_N) throw new ManagedSignerError(400, `ncryptsec logN ${logN} is above ${MAX_IMPORT_LOG_N}: re-encrypt it with a lower cost to import`);
    const sealed = this.opts.sealedKeys;
    if (sealed) return this.persist(await this.scrypt('import', owner, () => sealed.importNcryptsec(ncryptsec, password)), owner, principal, 'imported', {});
    let secretKey: Uint8Array;
    try {
      ({ secretKey } = await this.scrypt('import', owner, () => nip49.decryptKeyAsync(ncryptsec, password, { maxLogN: MAX_IMPORT_LOG_N })));
    } catch (err) {
      if (err instanceof RateLimitedError) throw err;
      throw new ManagedSignerError(400, 'cannot decrypt ncryptsec (wrong password or corrupted payload)');
    }
    try {
      return await this.store(secretKey, owner, principal, 'imported', {});
    } finally {
      wipe(secretKey);
    }
  }

  private async store(sk: Uint8Array, owner: string, principal: string, action: 'created' | 'imported', opts: { allowedKinds?: number[] }): Promise<KeyRecord> {
    if (!selfTestKey(sk).ok) throw new ManagedSignerError(500, 'key self-test failed');
    return this.persist({ pubkey: getPublicKey(sk), sealed: sk }, owner, principal, action, opts);
  }

  /** Stores the vault material (the secret, or a sealed blob in the enclave tier) and the registry record. */
  private async persist(key: { pubkey: string; sealed: Uint8Array }, owner: string, principal: string, action: 'created' | 'imported', opts: { allowedKinds?: number[] }): Promise<KeyRecord> {
    const { pubkey } = key;
    if (await this.registry.liveByPubkey(pubkey)) throw new ManagedSignerError(409, 'key already managed');
    const keyId = randomBytes(16).toString('hex');
    await this.vault.put(keyId, key.sealed);
    const rec: KeyRecord = {
      keyId,
      owner,
      pubkey,
      provider: this.opts.sealedKeys ? `${this.opts.sealedKeys.provider}+${this.vault.provider}` : this.vault.provider,
      version: 1,
      state: 'active',
      createdAt: this.now(),
      retentionDays: this.opts.retentionDays ?? 0,
      ...(opts.allowedKinds ? { allowedKinds: opts.allowedKinds } : {}),
    };
    try {
      await this.registry.insert(rec);
    } catch (err) {
      // Lost a race on the same pubkey: drop the copy just written.
      await this.vault.delete(keyId);
      if (err instanceof PubkeyAlreadyManagedError) throw new ManagedSignerError(409, 'key already managed');
      throw err;
    }
    await this.record({ keyId, action, principal });
    return rec;
  }

  private view(rec: KeyRecord) {
    const { migrationChallenge: _c, ...k } = rec;
    return { ...k, custody: this.opts.sealedKeys ? ('managed-enclave' as const) : ('managed' as const), custodial: true, disclosure: MANAGED_DISCLOSURE };
  }

  async describe(keyId: string, owner: string) {
    return this.view(await this.key(keyId, owner));
  }

  /** Live keys of an owner. */
  async list(owner: string) {
    return (await this.registry.listByOwner(owner)).map((k) => this.view(k));
  }

  /** Counts the operation by result class. */
  private async metered<T>(op: SignerOp, fn: () => Promise<T>): Promise<T> {
    try {
      const out = await fn();
      this.metrics.operations.inc({ op, result: 'ok' });
      return out;
    } catch (err) {
      if (!(err instanceof RateLimitedError)) this.metrics.operations.inc({ op, result: err instanceof ManagedSignerError && err.status < 500 ? 'denied' : 'error' });
      throw err;
    }
  }

  async sign(keyId: string, owner: string, who: string | Actor, template: EventTemplate): Promise<NostrEvent> {
    const actor = asActor(who);
    return this.metered('sign', async () => {
      const k = await this.key(keyId, owner);
      await this.assertDeviceUsable(actor.deviceId);
      if (k.allowedKinds && !k.allowedKinds.includes(template.kind)) throw new ManagedSignerError(403, `kind ${template.kind} not allowed for this key`);
      await this.rateLimit(k, 'sign', template.kind, actor);
      const evt = await this.withSigner(k, (s) => s.signEvent({ kind: template.kind, content: template.content, tags: template.tags ?? [], created_at: template.created_at }));
      await this.record({ keyId, action: 'sign', kind: evt.kind, eventId: evt.id, principal: actor.principal, ...(actor.deviceId ? { deviceId: actor.deviceId } : {}) });
      return evt;
    });
  }

  async nip44(keyId: string, owner: string, who: string | Actor, op: 'encrypt' | 'decrypt', peer: string, data: string): Promise<string> {
    const actor = asActor(who);
    const action = op === 'encrypt' ? 'nip44_encrypt' : 'nip44_decrypt';
    return this.metered(action, async () => {
      const k = await this.key(keyId, owner);
      await this.assertDeviceUsable(actor.deviceId);
      await this.rateLimit(k, action, undefined, actor);
      const out = await this.withSigner(k, (s) => (op === 'encrypt' ? s.nip44Encrypt(peer, data) : s.nip44Decrypt(peer, data)));
      await this.record({ keyId, action, principal: actor.principal, ...(actor.deviceId ? { deviceId: actor.deviceId } : {}) });
      return out;
    });
  }

  /**
   * FR-026 step 1: export for migration to local custody. Returns an ncryptsec and a challenge the
   * user must sign with the exported key to prove the migration worked.
   */
  async export(keyId: string, owner: string, principal: string, password: string, logN = 18): Promise<{ ncryptsec: string; challenge: string }> {
    const k = await this.key(keyId, owner);
    if (password.length < 12) throw new ManagedSignerError(400, 'export password must be at least 12 characters');
    const sealed = this.opts.sealedKeys;
    const ncryptsec = await this.scrypt('export', owner, async () => {
      const secret = await this.secretOf(k);
      try {
        return sealed ? await sealed.exportNcryptsec(secret, k.pubkey, password, logN) : await nip49.encryptKeyAsync(secret, password, logN, 0x00);
      } finally {
        wipe(secret);
      }
    });
    k.state = 'export-pending';
    k.migrationChallenge = randomBytes(16).toString('hex');
    k.lastUsed = this.now();
    await this.registry.save(k);
    await this.record({ keyId, action: 'export', principal });
    return { ncryptsec, challenge: k.migrationChallenge };
  }

  /** FR-026 step 2: the user proves possession of the exported key by signing the challenge. */
  async confirmMigration(keyId: string, owner: string, principal: string, proof: unknown): Promise<KeyRecord> {
    const k = await this.key(keyId, owner);
    if (k.state !== 'export-pending' || !k.migrationChallenge) throw new ManagedSignerError(409, 'no pending export');
    if (!verifyEvent(proof) || proof.pubkey !== k.pubkey || getTagValue(proof, 'challenge') !== k.migrationChallenge) {
      throw new ManagedSignerError(400, 'invalid migration proof');
    }
    k.state = 'migrated';
    k.migratedAt = this.now();
    delete k.migrationChallenge;
    await this.registry.save(k);
    await this.record({ keyId, action: 'migration-confirmed', principal });
    return k;
  }

  /**
   * FR-026 step 3: the managed copy can be deleted only after a verified migration. The key is unusable
   * right away; the encrypted material is destroyed once the retention window is over (DEC-09), either by
   * the vault itself (Secrets Manager recovery window) or by runRetention().
   */
  async delete(keyId: string, owner: string, principal: string): Promise<{ destroyAfter: number }> {
    const k = await this.key(keyId, owner);
    if (k.state !== 'migrated') throw new ManagedSignerError(409, 'delete requires a verified migration first');
    if (this.vault.schedulesDeletion) await this.vault.delete(keyId);
    k.state = 'deleted';
    k.deletedAt = this.now();
    await this.registry.save(k);
    await this.record({ keyId, action: 'deleted', principal });
    return { destroyAfter: k.deletedAt + k.retentionDays * 86_400_000 };
  }

  async usageOf(keyId: string, owner: string): Promise<UsageRecord[]> {
    await this.key(keyId, owner);
    return this.registry.usageOf(keyId);
  }

  /**
   * Retention job (DEC-09): purges usage rows older than the usage retention (12 months) and destroys the
   * material of deleted keys whose retention window is over. Idempotent; run it periodically.
   */
  async runRetention(): Promise<{ usagePurged: number; keysDestroyed: number; sessionsPurged: number }> {
    const now = this.now();
    const sessionsPurged = await this.devices.purgeExpiredSessions(now);
    const cutoff = new Date(now);
    cutoff.setUTCMonth(cutoff.getUTCMonth() - (this.opts.usageRetentionMonths ?? 12));
    const usagePurged = await this.registry.purgeUsageBefore(cutoff.getTime());
    let keysDestroyed = 0;
    for (const k of await this.registry.pendingDestruction(now)) {
      if (!this.vault.schedulesDeletion) await this.vault.delete(k.keyId);
      k.destroyedAt = now;
      await this.registry.save(k);
      await this.record({ keyId: k.keyId, action: 'destroyed', principal: 'retention-job' });
      keysDestroyed++;
    }
    return { usagePurged, keysDestroyed, sessionsPurged };
  }
}
