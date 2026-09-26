import { EncryptedStore, IndexedDBBackend, LocalStorageBackend, Vault, WebCryptoKeyring, type Collection } from '@sedecim/encrypted-store/browser';
import { nip49, type Signer } from '@sedecim/nostr-core';
import { isValid, type PresetName, type SovereigntyConfig } from '@sedecim/profiles';

/**
 * Browser vault (DEC-05, ADR 0007): one IndexedDB database per browser holding every persona, sealed with
 * a master key wrapped by the local password (scrypt) or, only in the convenience profile, by a
 * non-extractable WebCrypto device key.
 */
const DB = 'acceso-nostr';
/** Interactive unlock budget in the browser (same cost the v0.1 web store used). */
const WEB_LOGN = 15;

export type PersonaCustody = 'local' | 'nip07' | 'nip46';

export interface PersonaRecord {
  id: string;
  label: string;
  pubkey: string;
  custody: PersonaCustody;
  /** local custody only: the secret key, stored inside the sealed vault (never in clear at rest). */
  secretHex?: string;
  bunker?: string;
  relays: string[];
  preset: PresetName | 'custom';
  config: SovereigntyConfig;
  createdAt: number;
}

export type Protection = { kind: 'passphrase'; passphrase: string } | { kind: 'device' };

const backend = () => new IndexedDBBackend(DB);
const protection = (p: Protection) => (p.kind === 'device' ? { kind: 'device' as const, keyring: new WebCryptoKeyring(DB) } : { kind: 'passphrase' as const, passphrase: p.passphrase, logN: WEB_LOGN });

export async function vaultState() {
  return Vault.inspect(backend());
}

export async function createVault(p: Protection): Promise<Vault> {
  if (p.kind === 'passphrase' && p.passphrase.length < 8) throw new Error('la contraseña local debe tener al menos 8 caracteres');
  return Vault.create(backend(), protection(p));
}

export async function unlockVault(p: Protection): Promise<Vault> {
  return Vault.unlock(backend(), protection(p));
}

/** Change how this browser unlocks the vault (the records are not re-encrypted). */
export async function setProtection(vault: Vault, p: Protection): Promise<void> {
  if (p.kind === 'passphrase' && p.passphrase.length < 8) throw new Error('la contraseña local debe tener al menos 8 caracteres');
  await vault.rewrap(protection(p));
  if (p.kind === 'passphrase') await new WebCryptoKeyring(DB).forget();
}

/** "Olvidar este navegador": delete every persona, outbox and the device key. */
export async function forgetBrowser(): Promise<void> {
  await new WebCryptoKeyring(DB).forget();
  await IndexedDBBackend.destroy(DB);
}

/**
 * The device key is allowed only when every persona chose it and its profile allows it; otherwise the
 * vault needs the password (ADR 0007).
 */
export function deviceKeyAllowed(personas: PersonaRecord[]): boolean {
  return personas.length > 0 && personas.every((p) => p.config.localProtection === 'device' && isValid(p.config, 'web'));
}

export class PersonaBook {
  private readonly col: Collection<PersonaRecord>;
  constructor(readonly vault: Vault) {
    this.col = vault.store.collection<PersonaRecord>('personas');
  }
  get store(): EncryptedStore {
    return this.vault.store;
  }
  async list(): Promise<PersonaRecord[]> {
    return (await this.col.all()).map((e) => e.value).sort((a, b) => a.createdAt - b.createdAt);
  }
  get(id: string) {
    return this.col.get(id);
  }
  save(p: PersonaRecord) {
    return this.col.put(p.id, p);
  }
  remove(id: string) {
    return this.col.delete(id);
  }
}

/** v0.1 of the web kept one ncryptsec in localStorage under "sedecim-web": offer to import it. */
export function hasLegacyKey(): boolean {
  try {
    return localStorage.getItem('sedecim-web/meta:kdf') !== null;
  } catch {
    return false;
  }
}

export async function readLegacyKey(passphrase: string): Promise<Uint8Array> {
  const store = await EncryptedStore.open(new LocalStorageBackend('sedecim-web'), passphrase, { logN: WEB_LOGN });
  const enc = await store.collection<string>('key').get('ncryptsec');
  if (!enc) throw new Error('no hay llave de la versión anterior');
  return (await nip49.decryptKeyAsync(enc, passphrase)).secretKey;
}

export function clearLegacyKey(): void {
  for (let i = localStorage.length - 1; i >= 0; i--) {
    const k = localStorage.key(i);
    if (k?.startsWith('sedecim-web/')) localStorage.removeItem(k);
  }
}

export type { Signer };
