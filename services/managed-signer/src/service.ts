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

export type KeyState = 'active' | 'export-pending' | 'migrated' | 'deleted';

export interface KeyRecord {
  keyId: string;
  owner: string;
  pubkey: string;
  provider: string;
  version: number;
  state: KeyState;
  createdAt: number;
  lastUsed?: number;
  allowedKinds?: number[];
  migrationChallenge?: string;
  migratedAt?: number;
  retentionDays: number;
}

export interface UsageRecord {
  at: number;
  keyId: string;
  action: 'sign' | 'nip44_encrypt' | 'nip44_decrypt' | 'export' | 'migration-confirmed' | 'deleted' | 'created' | 'imported';
  kind?: number;
  eventId?: string;
  principal: string;
}

export const MANAGED_DISCLOSURE =
  'Managed Key activado: la plataforma tiene capacidad técnica de firmar como el usuario. Este modo es CUSTODIAL y nunca debe presentarse como non-custodial.';

export class ManagedSignerError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

/** Registry + signing core. Secrets are loaded from the vault per operation and wiped right after. */
export class ManagedSigner {
  readonly keys = new Map<string, KeyRecord>();
  readonly usage: UsageRecord[] = [];

  constructor(private readonly vault: Vault, private readonly opts: { retentionDays?: number; now?: () => number } = {}) {}

  private now() {
    return (this.opts.now ?? Date.now)();
  }

  private record(r: Omit<UsageRecord, 'at'>) {
    this.usage.push({ at: this.now(), ...r });
  }

  private key(keyId: string, owner: string): KeyRecord {
    const k = this.keys.get(keyId);
    if (!k || k.state === 'deleted') throw new ManagedSignerError(404, 'unknown key');
    if (k.owner !== owner) throw new ManagedSignerError(403, 'key belongs to another owner');
    return k;
  }

  private async withSigner<T>(k: KeyRecord, fn: (s: LocalSigner) => Promise<T>): Promise<T> {
    if (k.state === 'migrated') throw new ManagedSignerError(409, 'key migrated out of managed custody');
    const secret = await this.vault.get(k.keyId);
    if (!secret) throw new ManagedSignerError(500, 'key material missing from vault');
    const signer = new LocalSigner(secret, 'managed');
    wipe(secret);
    try {
      return await fn(signer);
    } finally {
      signer.destroy();
      k.lastUsed = this.now();
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
    if ([...this.keys.values()].some((k) => k.pubkey === pubkey && k.state !== 'deleted')) throw new ManagedSignerError(409, 'key already managed');
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
    this.keys.set(keyId, rec);
    this.record({ keyId, action, principal });
    return rec;
  }

  describe(keyId: string, owner: string) {
    const { migrationChallenge: _c, ...k } = this.key(keyId, owner);
    return { ...k, custody: 'managed' as const, custodial: true, disclosure: MANAGED_DISCLOSURE };
  }

  async sign(keyId: string, owner: string, principal: string, template: EventTemplate): Promise<NostrEvent> {
    const k = this.key(keyId, owner);
    if (k.allowedKinds && !k.allowedKinds.includes(template.kind)) throw new ManagedSignerError(403, `kind ${template.kind} not allowed for this key`);
    const evt = await this.withSigner(k, (s) => s.signEvent({ kind: template.kind, content: template.content, tags: template.tags ?? [], created_at: template.created_at }));
    this.record({ keyId, action: 'sign', kind: evt.kind, eventId: evt.id, principal });
    return evt;
  }

  async nip44(keyId: string, owner: string, principal: string, op: 'encrypt' | 'decrypt', peer: string, data: string): Promise<string> {
    const k = this.key(keyId, owner);
    const out = await this.withSigner(k, (s) => (op === 'encrypt' ? s.nip44Encrypt(peer, data) : s.nip44Decrypt(peer, data)));
    this.record({ keyId, action: op === 'encrypt' ? 'nip44_encrypt' : 'nip44_decrypt', principal });
    return out;
  }

  /**
   * FR-026 step 1: export for migration to local custody. Returns an ncryptsec and a challenge the
   * user must sign with the exported key to prove the migration worked.
   */
  async export(keyId: string, owner: string, principal: string, password: string, logN = 18): Promise<{ ncryptsec: string; challenge: string }> {
    const k = this.key(keyId, owner);
    if (password.length < 12) throw new ManagedSignerError(400, 'export password must be at least 12 characters');
    const ncryptsec = await this.withSigner(k, async () => {
      const secret = (await this.vault.get(keyId))!;
      try {
        return await nip49.encryptKeyAsync(secret, password, logN, 0x00);
      } finally {
        wipe(secret);
      }
    });
    k.state = 'export-pending';
    k.migrationChallenge = randomBytes(16).toString('hex');
    this.record({ keyId, action: 'export', principal });
    return { ncryptsec, challenge: k.migrationChallenge };
  }

  /** FR-026 step 2: the user proves possession of the exported key by signing the challenge. */
  confirmMigration(keyId: string, owner: string, principal: string, proof: unknown): KeyRecord {
    const k = this.key(keyId, owner);
    if (k.state !== 'export-pending' || !k.migrationChallenge) throw new ManagedSignerError(409, 'no pending export');
    if (!verifyEvent(proof) || proof.pubkey !== k.pubkey || getTagValue(proof, 'challenge') !== k.migrationChallenge) {
      throw new ManagedSignerError(400, 'invalid migration proof');
    }
    k.state = 'migrated';
    k.migratedAt = this.now();
    delete k.migrationChallenge;
    this.record({ keyId, action: 'migration-confirmed', principal });
    return k;
  }

  /** FR-026 step 3: managed copies are deleted only after verified migration and retention checks. */
  async delete(keyId: string, owner: string, principal: string): Promise<void> {
    const k = this.key(keyId, owner);
    if (k.state !== 'migrated') throw new ManagedSignerError(409, 'delete requires a verified migration first');
    const retentionEnds = (k.migratedAt ?? 0) + k.retentionDays * 86_400_000;
    if (this.now() < retentionEnds) throw new ManagedSignerError(409, `retention policy: deletion allowed after ${new Date(retentionEnds).toISOString()}`);
    await this.vault.delete(keyId);
    k.state = 'deleted';
    this.record({ keyId, action: 'deleted', principal });
  }

  usageOf(keyId: string, owner: string): UsageRecord[] {
    this.key(keyId, owner);
    return this.usage.filter((u) => u.keyId === keyId);
  }
}
