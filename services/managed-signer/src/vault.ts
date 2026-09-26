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

/** Minimal surface of AWS Secrets Manager used by the adapter (inject the real SDK client in prod). */
export interface SecretsManagerLike {
  getSecretString(name: string): Promise<string | undefined>;
  putSecretString(name: string, value: string, opts: { kmsKeyId?: string }): Promise<void>;
  deleteSecret(name: string, opts: { recoveryWindowDays?: number }): Promise<void>;
}

/**
 * AWS Secrets Manager adapter (encryption at rest with KMS). NOTE: KMS does not produce Nostr
 * signatures (BIP-340/secp256k1); it only protects the material. Signing happens in this service
 * (or inside a Nitro Enclave with attestation-conditioned KMS policies for the enclave tier).
 */
export class SecretsManagerVault implements Vault {
  readonly provider = 'aws-secrets-manager';
  constructor(private readonly sm: SecretsManagerLike, private readonly opts: { prefix?: string; kmsKeyId?: string; recoveryWindowDays?: number } = {}) {}
  private name(k: string) {
    return `${this.opts.prefix ?? 'nostr/managed-keys/'}${k}`;
  }
  async put(k: string, secret: Uint8Array) {
    await this.sm.putSecretString(this.name(k), bytesToHex(secret), { kmsKeyId: this.opts.kmsKeyId });
  }
  async get(k: string) {
    const v = await this.sm.getSecretString(this.name(k));
    return v ? hexToBytes(v) : undefined;
  }
  async delete(k: string) {
    await this.sm.deleteSecret(this.name(k), { recoveryWindowDays: this.opts.recoveryWindowDays ?? 7 });
  }
}
