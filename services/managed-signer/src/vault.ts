import { createCipheriv, createDecipheriv } from 'node:crypto';
import { mkdir, readFile, rm, writeFile, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { bytesToHex, concatBytes, hexToBytes, randomBytes, utf8ToBytes } from '@sedecim/nostr-core';

/**
 * Vault holding managed key material (spec §8.4, §19.4). Application tables only ever hold metadata;
 * secrets live exclusively behind this interface.
 */
export interface Vault {
  readonly provider: string;
  put(keyId: string, secret: Uint8Array): Promise<void>;
  get(keyId: string): Promise<Uint8Array | undefined>;
  delete(keyId: string): Promise<void>;
  /**
   * True when delete() only schedules destruction after the retention window (Secrets Manager recovery
   * window), so the core calls it as soon as a key is deleted. Otherwise the retention job calls delete()
   * once the window is over (DEC-09).
   */
  readonly schedulesDeletion?: boolean;
}

export class MemoryVault implements Vault {
  readonly provider = 'memory';
  private readonly data = new Map<string, Uint8Array>();
  async put(k: string, s: Uint8Array) {
    this.data.set(k, new Uint8Array(s));
  }
  async get(k: string) {
    const v = this.data.get(k);
    return v ? new Uint8Array(v) : undefined;
  }
  async delete(k: string) {
    this.data.get(k)?.fill(0);
    this.data.delete(k);
  }
}

/**
 * Envelope-encrypted file vault for self-hosted deployments: a random DEK per key encrypts the secret,
 * and the DEK is wrapped by a KEK provided out-of-band (env / HSM / KMS-decrypted at boot).
 */
export class LocalEnvelopeVault implements Vault {
  readonly provider = 'local-envelope';
  constructor(private readonly dir: string, private readonly kek: Uint8Array) {
    if (kek.length !== 32) throw new Error('KEK must be 32 bytes');
  }
  private path(k: string) {
    if (!/^[a-f0-9]{16,64}$/.test(k)) throw new Error('invalid key id');
    return join(this.dir, `${k}.json`);
  }
  async put(k: string, secret: Uint8Array) {
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    const dek = randomBytes(32);
    const n1 = randomBytes(24);
    const n2 = randomBytes(24);
    const aad = utf8ToBytes(k);
    const record = {
      v: 1,
      wrappedDek: bytesToHex(concatBytes(n1, xchacha20poly1305(this.kek, n1, aad).encrypt(dek))),
      secret: bytesToHex(concatBytes(n2, xchacha20poly1305(dek, n2, aad).encrypt(secret))),
    };
    dek.fill(0);
    const tmp = this.path(k) + '.tmp';
    await writeFile(tmp, JSON.stringify(record), { mode: 0o600 });
    await rename(tmp, this.path(k));
  }
  async get(k: string) {
    let raw: string;
    try {
      raw = await readFile(this.path(k), 'utf8');
    } catch {
      return undefined;
    }
    const r = JSON.parse(raw) as { wrappedDek: string; secret: string };
    const aad = utf8ToBytes(k);
    const w = hexToBytes(r.wrappedDek);
    const dek = xchacha20poly1305(this.kek, w.subarray(0, 24), aad).decrypt(w.subarray(24));
    const s = hexToBytes(r.secret);
    const secret = xchacha20poly1305(dek, s.subarray(0, 24), aad).decrypt(s.subarray(24));
    dek.fill(0);
    return secret;
  }
  async delete(k: string) {
    await rm(this.path(k), { force: true });
  }
}

/** Minimal surface of AWS Secrets Manager used by the vault (aws.ts adapts the SDK v3 client). */
export interface SecretsManagerLike {
  /** Creates the secret; fails if the name already exists. */
  createSecret(name: string, value: string): Promise<void>;
  /** Undefined when the secret does not exist or is scheduled for deletion. */
  getSecretString(name: string): Promise<string | undefined>;
  /** Schedules deletion after the recovery window; unknown secrets are ignored. */
  deleteSecret(name: string, recoveryWindowDays: number): Promise<void>;
}

/** Minimal surface of AWS KMS used for envelope encryption (aws.ts adapts the SDK v3 client). */
export interface KmsLike {
  generateDataKey(kmsKeyId: string, context: Record<string, string>): Promise<{ plaintext: Uint8Array; ciphertext: Uint8Array }>;
  decrypt(kmsKeyId: string, ciphertext: Uint8Array, context: Record<string, string>): Promise<Uint8Array>;
}

export interface SecretsManagerVaultOptions {
  /** KMS key (id, ARN or alias) that wraps the per-key data keys. */
  kmsKeyId: string;
  /** Secret name prefix (default `acceso-nostr/managed-keys/`). */
  prefix?: string;
  /** Retention after deletion (DEC-09), applied as RecoveryWindowInDays clamped to 7..30. Default 30. */
  retentionDays?: number;
}

interface SealedSecret {
  v: 1;
  alg: 'AES-256-GCM';
  kms_key_id: string;
  /** KMS-encrypted data key. */
  edk: string;
  iv: string;
  ct: string;
  tag: string;
}

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');

/**
 * AWS Secrets Manager + KMS vault with envelope encryption (FR005-02, region us-east-1 per DEC-09): each key
 * gets a fresh KMS data key bound to its key id through the encryption context; the secret is sealed locally
 * with AES-256-GCM and only the ciphertext plus the wrapped data key reach Secrets Manager. Plaintext data
 * keys and intermediate buffers are zeroed after use.
 *
 * NOTE: KMS does not produce Nostr signatures (BIP-340/secp256k1); it only protects the material. Signing
 * happens in this service (or inside a Nitro Enclave with attestation-conditioned KMS policies for the
 * enclave tier).
 */
export class SecretsManagerVault implements Vault {
  readonly provider = 'aws-secrets-manager';
  readonly schedulesDeletion = true;
  readonly recoveryWindowDays: number;

  constructor(private readonly sm: SecretsManagerLike, private readonly kms: KmsLike, private readonly opts: SecretsManagerVaultOptions) {
    if (!opts.kmsKeyId) throw new Error('kmsKeyId is required');
    this.recoveryWindowDays = Math.min(30, Math.max(7, Math.round(opts.retentionDays ?? 30)));
  }

  name(k: string) {
    if (!/^[a-f0-9]{16,64}$/.test(k)) throw new Error('invalid key id');
    return `${this.opts.prefix ?? 'acceso-nostr/managed-keys/'}${k}`;
  }

  private context(k: string) {
    return { app: 'acceso-nostr', purpose: 'managed-key', key_id: k };
  }

  async put(k: string, secret: Uint8Array) {
    const name = this.name(k);
    const dk = await this.kms.generateDataKey(this.opts.kmsKeyId, this.context(k));
    let sealed: SealedSecret;
    try {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', dk.plaintext, iv);
      cipher.setAAD(Buffer.from(name));
      const ct = Buffer.concat([cipher.update(secret), cipher.final()]);
      sealed = { v: 1, alg: 'AES-256-GCM', kms_key_id: this.opts.kmsKeyId, edk: b64(dk.ciphertext), iv: b64(iv), ct: b64(ct), tag: b64(cipher.getAuthTag()) };
    } finally {
      dk.plaintext.fill(0);
    }
    await this.sm.createSecret(name, JSON.stringify(sealed));
  }

  async get(k: string) {
    const name = this.name(k);
    const raw = await this.sm.getSecretString(name);
    if (!raw) return undefined;
    const s = JSON.parse(raw) as SealedSecret;
    if (s.v !== 1 || s.alg !== 'AES-256-GCM') throw new Error('unsupported sealed secret');
    const dek = await this.kms.decrypt(this.opts.kmsKeyId, Buffer.from(s.edk, 'base64'), this.context(k));
    const parts: Buffer[] = [];
    try {
      const decipher = createDecipheriv('aes-256-gcm', dek, Buffer.from(s.iv, 'base64'));
      decipher.setAAD(Buffer.from(name));
      decipher.setAuthTag(Buffer.from(s.tag, 'base64'));
      parts.push(decipher.update(Buffer.from(s.ct, 'base64')), decipher.final());
      const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
      let off = 0;
      for (const p of parts) (out.set(p, off), (off += p.length));
      return out;
    } finally {
      dek.fill(0);
      for (const p of parts) p.fill(0);
    }
  }

  async delete(k: string) {
    await this.sm.deleteSecret(this.name(k), this.recoveryWindowDays);
  }
}
