import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { hkdf } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { scryptAsync } from '@noble/hashes/scrypt';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils';
import type { StorageBackend } from './backends';

const META_KEY = 'meta:kdf';
const VERSION = 1;

export interface KdfParams {
  salt: string;
  logN: number;
  r: number;
  p: number;
  check: string;
}

export class WrongPassphraseError extends Error {
  constructor() {
    super('wrong passphrase for encrypted store');
  }
}

/**
 * Local encrypted store (spec §12). Values are sealed with XChaCha20-Poly1305 under a key derived
 * from the store key; entry names are HMAC'd so the backend never sees event ids, pubkeys, etc.
 */
export class EncryptedStore {
  private readonly encKey: Uint8Array;
  private readonly nameKey: Uint8Array;

  private constructor(private readonly backend: StorageBackend, masterKey: Uint8Array) {
    if (masterKey.length !== 32) throw new Error('master key must be 32 bytes');
    this.encKey = hkdf(sha256, masterKey, undefined, 'sedecim-store-enc-v1', 32);
    this.nameKey = hkdf(sha256, masterKey, undefined, 'sedecim-store-names-v1', 32);
  }

  static withKey(backend: StorageBackend, masterKey: Uint8Array): EncryptedStore {
    return new EncryptedStore(backend, masterKey);
  }

  /** Open (or initialise) a store protected by a passphrase using scrypt. */
  static async open(backend: StorageBackend, passphrase: string, opts: { logN?: number } = {}): Promise<EncryptedStore> {
    const raw = await backend.get(META_KEY);
    let params: KdfParams;
    if (raw) params = JSON.parse(new TextDecoder().decode(raw)) as KdfParams;
    else params = { salt: bytesToHex(randomBytes(16)), logN: opts.logN ?? 17, r: 8, p: 1, check: '' };
    const master = await scryptAsync(utf8ToBytes(passphrase.normalize('NFKC')), utf8ToBytes(params.salt), { N: 2 ** params.logN, r: params.r, p: params.p, dkLen: 32 });
    const check = bytesToHex(hmac(sha256, master, utf8ToBytes('check')));
    if (raw && params.check !== check) throw new WrongPassphraseError();
    if (!raw) await backend.put(META_KEY, utf8ToBytes(JSON.stringify({ ...params, check })));
    return new EncryptedStore(backend, master);
  }

  collection<T>(name: string): Collection<T> {
    if (!/^[a-z0-9-]+$/.test(name)) throw new Error('collection names must be [a-z0-9-]');
    return new Collection<T>(this, name);
  }

  /** @internal */
  entryKey(collection: string, id: string): string {
    return `${collection}:${bytesToHex(hmac(sha256, this.nameKey, utf8ToBytes(`${collection}\u0000${id}`))).slice(0, 40)}`;
  }

  /** @internal */
  seal(collection: string, id: string, value: unknown): Uint8Array {
    const nonce = randomBytes(24);
    const aad = utf8ToBytes(collection);
    const pt = utf8ToBytes(JSON.stringify({ id, value }));
    return concatBytes(new Uint8Array([VERSION]), nonce, xchacha20poly1305(this.encKey, nonce, aad).encrypt(pt));
  }

  /** @internal */
  open<T>(collection: string, data: Uint8Array): { id: string; value: T } {
    if (data[0] !== VERSION) throw new Error('unsupported record version');
    const nonce = data.subarray(1, 25);
    const pt = xchacha20poly1305(this.encKey, nonce, utf8ToBytes(collection)).decrypt(data.subarray(25));
    return JSON.parse(new TextDecoder().decode(pt)) as { id: string; value: T };
  }

  /** @internal */
  get raw(): StorageBackend {
    return this.backend;
  }
}

export class Collection<T> {
  constructor(private readonly store: EncryptedStore, readonly name: string) {}

  async put(id: string, value: T): Promise<void> {
    await this.store.raw.put(this.store.entryKey(this.name, id), this.store.seal(this.name, id, value));
  }

  async get(id: string): Promise<T | undefined> {
    const raw = await this.store.raw.get(this.store.entryKey(this.name, id));
    if (!raw) return undefined;
    return this.store.open<T>(this.name, raw).value;
  }

  async delete(id: string): Promise<void> {
    await this.store.raw.delete(this.store.entryKey(this.name, id));
  }

  async all(): Promise<Array<{ id: string; value: T }>> {
    const keys = await this.store.raw.keys(`${this.name}:`);
    const out: Array<{ id: string; value: T }> = [];
    for (const k of keys) {
      const raw = await this.store.raw.get(k);
      if (raw) out.push(this.store.open<T>(this.name, raw));
    }
    return out;
  }
}
