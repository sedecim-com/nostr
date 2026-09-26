import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { scryptAsync } from '@noble/hashes/scrypt';
import { bytesToHex, concatBytes, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils';
import type { StorageBackend } from './backends';
import { EncryptedStore, WrongPassphraseError } from './store';

const VAULT_KEY = 'meta:vault';

/**
 * Wraps the vault master key with a key the page cannot read (e.g. a non-extractable WebCrypto key
 * kept in IndexedDB). Anyone with access to the browser profile can still unwrap it.
 */
export interface DeviceKeyring {
  wrap(plaintext: Uint8Array): Promise<Uint8Array>;
  unwrap(ciphertext: Uint8Array): Promise<Uint8Array>;
}

export type VaultProtection = { kind: 'passphrase'; passphrase: string; logN?: number } | { kind: 'device'; keyring: DeviceKeyring };

interface VaultMeta {
  version: 1;
  kind: 'passphrase' | 'device';
  /** passphrase: scrypt params; the master key is sealed with XChaCha20-Poly1305 under the derived key */
  salt?: string;
  logN?: number;
  wrapped: string;
}

/**
 * Local vault (DEC-05, ADR 0007): a random master key opens an EncryptedStore; the master key itself is
 * wrapped either by a passphrase (scrypt) or by a device key. Changing protection re-wraps the master
 * key only, so records never need re-encrypting.
 */
export class Vault {
  private constructor(private readonly backend: StorageBackend, private master: Uint8Array, private meta: VaultMeta) {}

  static async inspect(backend: StorageBackend): Promise<{ exists: false } | { exists: true; kind: VaultMeta['kind'] }> {
    const meta = await readMeta(backend);
    return meta ? { exists: true, kind: meta.kind } : { exists: false };
  }

  static async create(backend: StorageBackend, protection: VaultProtection): Promise<Vault> {
    if (await readMeta(backend)) throw new Error('a vault already exists in this storage');
    const master = randomBytes(32);
    const meta = await wrapMaster(master, protection);
    await backend.put(VAULT_KEY, utf8ToBytes(JSON.stringify(meta)));
    return new Vault(backend, master, meta);
  }

  static async unlock(backend: StorageBackend, protection: VaultProtection): Promise<Vault> {
    const meta = await readMeta(backend);
    if (!meta) throw new Error('no vault in this storage');
    if (meta.kind !== protection.kind) throw new Error(`vault is protected by ${meta.kind}`);
    let master: Uint8Array;
    if (protection.kind === 'passphrase') {
      const kek = await deriveKek(protection.passphrase, meta.salt!, meta.logN!);
      try {
        master = unseal(kek, hexToBytes(meta.wrapped));
      } catch {
        throw new WrongPassphraseError();
      }
    } else {
      master = await protection.keyring.unwrap(hexToBytes(meta.wrapped));
    }
    return new Vault(backend, master, meta);
  }

  get kind(): VaultMeta['kind'] {
    return this.meta.kind;
  }

  get store(): EncryptedStore {
    return EncryptedStore.withKey(this.backend, this.master);
  }

  /** Switch protection (e.g. device → passphrase when a stricter profile is chosen). */
  async rewrap(protection: VaultProtection): Promise<void> {
    const meta = await wrapMaster(this.master, protection);
    await this.backend.put(VAULT_KEY, utf8ToBytes(JSON.stringify(meta)));
    this.meta = meta;
  }

  lock(): void {
    this.master.fill(0);
  }
}

async function readMeta(backend: StorageBackend): Promise<VaultMeta | undefined> {
  const raw = await backend.get(VAULT_KEY);
  return raw ? (JSON.parse(new TextDecoder().decode(raw)) as VaultMeta) : undefined;
}

async function wrapMaster(master: Uint8Array, p: VaultProtection): Promise<VaultMeta> {
  if (p.kind === 'device') return { version: 1, kind: 'device', wrapped: bytesToHex(await p.keyring.wrap(master)) };
  const salt = bytesToHex(randomBytes(16));
  const logN = p.logN ?? 17;
  return { version: 1, kind: 'passphrase', salt, logN, wrapped: bytesToHex(seal(await deriveKek(p.passphrase, salt, logN), master)) };
}

function deriveKek(passphrase: string, salt: string, logN: number): Promise<Uint8Array> {
  return scryptAsync(utf8ToBytes(passphrase.normalize('NFKC')), hexToBytes(salt), { N: 2 ** logN, r: 8, p: 1, dkLen: 32 });
}

const AAD = utf8ToBytes('sedecim-vault-master-v1');
function seal(key: Uint8Array, pt: Uint8Array): Uint8Array {
  const nonce = randomBytes(24);
  return concatBytes(nonce, xchacha20poly1305(key, nonce, AAD).encrypt(pt));
}
function unseal(key: Uint8Array, data: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, data.subarray(0, 24), AAD).decrypt(data.subarray(24));
}

/** In-memory keyring for tests and non-browser runtimes (never persisted). */
export class MemoryKeyring implements DeviceKeyring {
  private readonly key = randomBytes(32);
  async wrap(pt: Uint8Array) {
    return seal(this.key, pt);
  }
  async unwrap(ct: Uint8Array) {
    return unseal(this.key, ct);
  }
}
