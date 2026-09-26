import { randomBytes } from 'node:crypto';
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
} from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import type { Vault } from './vault';
import { MemoryKeyRegistry, PubkeyAlreadyManagedError, type KeyRecord, type KeyRegistry, type UsageRecord } from './registry';

export const MANAGED_DISCLOSURE =
  'Managed Key activado: la plataforma tiene capacidad técnica de firmar como el usuario. Este modo es CUSTODIAL y nunca debe presentarse como non-custodial.';

export class ManagedSignerError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

export interface ManagedSignerOptions {
  /** Key registry and usage log; defaults to memory (tests/dev). Production uses PgKeyRegistry. */
  registry?: KeyRegistry;
  /** Days the vault material is kept after a key is deleted (DEC-09: 30). */
  retentionDays?: number;
  /** Months the usage log is kept (DEC-09: 12). */
  usageRetentionMonths?: number;
  now?: () => number;
}

/** Signing core over a key registry. Secrets are loaded from the vault per operation and wiped right after. */
export class ManagedSigner {
  readonly registry: KeyRegistry;

  constructor(private readonly vault: Vault, private readonly opts: ManagedSignerOptions = {}) {
    this.registry = opts.registry ?? new MemoryKeyRegistry();
  }

  private now() {
    return (this.opts.now ?? Date.now)();
  }

  private record(r: Omit<UsageRecord, 'at'>) {
    return this.registry.recordUsage({ at: this.now(), ...r });
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

  private async withSigner<T>(k: KeyRecord, fn: (s: LocalSigner) => Promise<T>): Promise<T> {
    const secret = await this.secretOf(k);
    const signer = new LocalSigner(secret, 'managed');
    wipe(secret);
    try {
      return await fn(signer);
    } finally {
      signer.destroy();
      await this.registry.touch(k.keyId, this.now());
    }
  }

  async create(owner: string, principal: string, opts: { allowedKinds?: number[] } = {}): Promise<KeyRecord> {
    const sk = generateSecretKey();
    try {
      return await this.store(sk, owner, principal, 'created', opts);
    } finally {
      wipe(sk);
    }
  }

  /** local -> managed migration (explicit, opt-in). */
  async importEncrypted(owner: string, principal: string, ncryptsec: string, password: string): Promise<KeyRecord> {
    const { secretKey } = await nip49.decryptKeyAsync(ncryptsec, password);
    try {
      return await this.store(secretKey, owner, principal, 'imported', {});
    } finally {
      wipe(secretKey);
    }
  }

  private async store(sk: Uint8Array, owner: string, principal: string, action: 'created' | 'imported', opts: { allowedKinds?: number[] }): Promise<KeyRecord> {
    if (!selfTestKey(sk).ok) throw new ManagedSignerError(500, 'key self-test failed');
    const pubkey = getPublicKey(sk);
    if (await this.registry.liveByPubkey(pubkey)) throw new ManagedSignerError(409, 'key already managed');
    const keyId = randomBytes(16).toString('hex');
    await this.vault.put(keyId, sk);
    const rec: KeyRecord = {
      keyId,
      owner,
      pubkey,
      provider: this.vault.provider,
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
    return { ...k, custody: 'managed' as const, custodial: true, disclosure: MANAGED_DISCLOSURE };
  }

  async describe(keyId: string, owner: string) {
    return this.view(await this.key(keyId, owner));
  }

  /** Live keys of an owner. */
  async list(owner: string) {
    return (await this.registry.listByOwner(owner)).map((k) => this.view(k));
  }

  async sign(keyId: string, owner: string, principal: string, template: EventTemplate): Promise<NostrEvent> {
    const k = await this.key(keyId, owner);
    if (k.allowedKinds && !k.allowedKinds.includes(template.kind)) throw new ManagedSignerError(403, `kind ${template.kind} not allowed for this key`);
    const evt = await this.withSigner(k, (s) => s.signEvent({ kind: template.kind, content: template.content, tags: template.tags ?? [], created_at: template.created_at }));
    await this.record({ keyId, action: 'sign', kind: evt.kind, eventId: evt.id, principal });
    return evt;
  }

  async nip44(keyId: string, owner: string, principal: string, op: 'encrypt' | 'decrypt', peer: string, data: string): Promise<string> {
    const k = await this.key(keyId, owner);
    const out = await this.withSigner(k, (s) => (op === 'encrypt' ? s.nip44Encrypt(peer, data) : s.nip44Decrypt(peer, data)));
    await this.record({ keyId, action: op === 'encrypt' ? 'nip44_encrypt' : 'nip44_decrypt', principal });
    return out;
  }

  /**
   * FR-026 step 1: export for migration to local custody. Returns an ncryptsec and a challenge the
   * user must sign with the exported key to prove the migration worked.
   */
  async export(keyId: string, owner: string, principal: string, password: string, logN = 18): Promise<{ ncryptsec: string; challenge: string }> {
    const k = await this.key(keyId, owner);
    if (password.length < 12) throw new ManagedSignerError(400, 'export password must be at least 12 characters');
    const secret = await this.secretOf(k);
    let ncryptsec: string;
    try {
      ncryptsec = await nip49.encryptKeyAsync(secret, password, logN, 0x00);
    } finally {
      wipe(secret);
    }
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
  async runRetention(): Promise<{ usagePurged: number; keysDestroyed: number }> {
    const now = this.now();
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
    return { usagePurged, keysDestroyed };
  }
}
