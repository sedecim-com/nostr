import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import {
  bytesToHex,
  bytesToUtf8,
  concatBytes,
  generateSecretKey,
  getPublicKey,
  isHex,
  nip19,
  nip49,
  npubEncode,
  randomBytes,
  selfTestKey,
  utf8ToBytes,
  wipe,
  type Signer,
} from '@sedecim/nostr-core';
import type { Collection, EncryptedStore } from '@sedecim/encrypted-store';
import type { SovereigntyConfig } from '@sedecim/profiles';
import { LocalSigner } from '@sedecim/signer';
import { openKeyBackup } from './key-backup';
import type { AuditEntry, BackupContents, BackupPackage, BackupPackageV2, Compartment, IdentityLink, LinkVisibility, PersonaConfig } from './types';

const BACKUP_AAD = utf8ToBytes('sedecim-identity-backup-v2');

function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

function fromBase64(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

export class ConsentRequiredError extends Error {
  constructor(what: string) {
    super(`${what} requires an explicit user action (confirm: true)`);
  }
}

export interface CreatePersonaInput {
  label: string;
  relays: string[];
  compartment?: Compartment;
  network?: 'direct' | 'tor-only';
  /** Passphrase protecting the NIP-49 copy of the key inside the persona store. */
  keyPassphrase: string;
  scryptLogN?: number;
}

export interface ImportMeta {
  label: string;
  relays: string[];
  compartment?: Compartment;
  network?: 'direct' | 'tor-only';
  scryptLogN?: number;
}

export type ImportInput =
  | { nsec: string; keyPassphrase: string; expectedPubkey?: string }
  /** Raw secret key (already decrypted, e.g. by openKeyBackup); wiped after import. */
  | { secretKey: Uint8Array; keyPassphrase: string; expectedPubkey?: string }
  | { ncryptsec: string; password: string; keyPassphrase: string; expectedPubkey?: string }
  | { bunker: string; pubkey: string }
  | { managedKeyId: string; pubkey: string };

/**
 * Account-level manager of multiple personas (spec §3.1). Personas are never linked by default;
 * each persona gets its own store (compartment), relays and signer (FR-006).
 */
export class IdentityManager {
  private readonly personas: Collection<PersonaConfig>;
  private readonly links: Collection<IdentityLink>;
  private readonly audit: Collection<AuditEntry>;
  private readonly usage: Collection<{ personaId: string; contacts: string[]; files: string[] }>;

  constructor(
    accountStore: EncryptedStore,
    /** Opens the isolated store of a persona (separate directory/key per compartment). */
    private readonly openPersonaStore: (personaId: string) => Promise<EncryptedStore>,
    private readonly now: () => number = Date.now,
  ) {
    this.personas = accountStore.collection('personas');
    this.links = accountStore.collection('links');
    this.audit = accountStore.collection('audit');
    this.usage = accountStore.collection('usage');
  }

  private async log(entry: Omit<AuditEntry, 'at'>) {
    const at = this.now();
    await this.audit.put(`${at}-${bytesToHex(randomBytes(4))}`, { at, ...entry });
  }

  async auditLog(): Promise<AuditEntry[]> {
    return (await this.audit.all()).map((e) => e.value).sort((a, b) => a.at - b.at);
  }

  async list(): Promise<PersonaConfig[]> {
    return (await this.personas.all()).map((e) => e.value).sort((a, b) => a.createdAt - b.createdAt);
  }

  async get(id: string): Promise<PersonaConfig> {
    const p = await this.personas.get(id);
    if (!p) throw new Error(`unknown persona ${id}`);
    return p;
  }

  private async storeKey(personaId: string, secretKey: Uint8Array, passphrase: string, logN?: number) {
    const store = await this.openPersonaStore(personaId);
    await store.collection<string>('key').put('ncryptsec', await nip49.encryptKeyAsync(secretKey, passphrase, logN ?? 16, 0x01));
  }

  /** FR-001: generate a key locally; the nsec never leaves the device. */
  async createPersona(input: CreatePersonaInput): Promise<PersonaConfig> {
    const sk = generateSecretKey();
    try {
      const test = selfTestKey(sk);
      if (!test.ok) throw new Error('key self-test failed');
      const persona: PersonaConfig = {
        id: bytesToHex(randomBytes(8)),
        label: input.label,
        pubkey: test.pubkey,
        custody: 'local',
        compartment: input.compartment ?? 'standard',
        relays: input.relays,
        network: input.network ?? (input.compartment === 'high-risk' ? 'tor-only' : 'direct'),
        createdAt: this.now(),
      };
      await this.storeKey(persona.id, sk, input.keyPassphrase, input.scryptLogN);
      await this.personas.put(persona.id, persona);
      await this.log({ action: 'persona.created', subject: persona.id, details: { custody: 'local', compartment: persona.compartment } });
      return persona;
    } finally {
      wipe(sk);
    }
  }

  /** FR-002: import and validate pubkey/secret correspondence (or register an external/managed signer). */
  async importPersona(input: ImportInput, meta: ImportMeta): Promise<PersonaConfig> {
    let custody: PersonaConfig['custody'];
    let pubkey: string;
    let sk: Uint8Array | undefined;
    const extra: Partial<PersonaConfig> = {};
    if ('nsec' in input || 'ncryptsec' in input || 'secretKey' in input) {
      if ('nsec' in input) {
        const d = nip19.decode(input.nsec);
        if (d.type !== 'nsec') throw new Error('expected nsec');
        sk = d.data;
      } else if ('secretKey' in input) sk = input.secretKey;
      else sk = (await nip49.decryptKeyAsync(input.ncryptsec, input.password)).secretKey;
      const test = selfTestKey(sk, input.expectedPubkey);
      if (!test.ok) throw new Error('imported key does not match expected pubkey or failed self-test');
      pubkey = test.pubkey;
      custody = 'local';
    } else if ('bunker' in input) {
      custody = 'external';
      pubkey = input.pubkey;
      extra.bunker = input.bunker.replace(/([?&]secret=)[^&]+/, '$1');
    } else {
      custody = 'managed';
      pubkey = input.pubkey;
      extra.managedKeyId = input.managedKeyId;
    }
    if ((await this.list()).some((p) => p.pubkey === pubkey)) throw new Error('persona with this pubkey already exists');
    const persona: PersonaConfig = {
      id: bytesToHex(randomBytes(8)),
      label: meta.label,
      pubkey,
      custody,
      compartment: meta.compartment ?? 'standard',
      relays: meta.relays,
      network: meta.network ?? (meta.compartment === 'high-risk' ? 'tor-only' : 'direct'),
      createdAt: this.now(),
      ...extra,
    };
    try {
      if (sk) await this.storeKey(persona.id, sk, (input as { keyPassphrase: string }).keyPassphrase, meta.scryptLogN);
    } finally {
      if (sk) wipe(sk);
    }
    await this.personas.put(persona.id, persona);
    await this.log({ action: 'persona.imported', subject: persona.id, details: { custody } });
    return persona;
  }

  /**
   * FR002-03: import a key backup file (offline generator `sedecim-offline-key` or web
   * `acceso-nostr-key-backup`). The ncryptsec must decrypt to the declared npub or nothing is created.
   */
  async importKeyBackup(json: unknown, backupPassword: string, keyPassphrase: string, meta: ImportMeta): Promise<PersonaConfig> {
    const { secretKey, pubkey } = await openKeyBackup(json, backupPassword);
    try {
      return await this.importPersona({ secretKey, keyPassphrase, expectedPubkey: pubkey }, meta);
    } finally {
      wipe(secretKey);
    }
  }

  /** Unlocks a local persona's signer from its own compartment store. */
  async unlock(personaId: string, keyPassphrase: string): Promise<Signer> {
    const persona = await this.get(personaId);
    if (persona.custody !== 'local' && persona.custody !== 'offline') throw new Error(`persona custody is ${persona.custody}; use the corresponding signer adapter`);
    const store = await this.openPersonaStore(personaId);
    const enc = await store.collection<string>('key').get('ncryptsec');
    if (!enc) throw new Error('no key material for persona in this device');
    const { secretKey } = await nip49.decryptKeyAsync(enc, keyPassphrase);
    try {
      if (getPublicKey(secretKey) !== persona.pubkey) throw new Error('stored key does not match persona pubkey');
      return new LocalSigner(secretKey, persona.custody);
    } finally {
      wipe(secretKey);
    }
  }

  /** FR-007: links require explicit consent and are audited. Never created by default. */
  async link(from: string, to: string, visibility: LinkVisibility, opts: { confirm: boolean; audience?: string[] }): Promise<IdentityLink> {
    if (opts.confirm !== true) throw new ConsentRequiredError('linking identities');
    const [a, b] = [await this.get(from), await this.get(to)];
    if (visibility === 'selective' && !opts.audience?.length) throw new Error('selective links need an audience');
    const link: IdentityLink = {
      id: bytesToHex(randomBytes(8)),
      from: a.id,
      to: b.id,
      visibility,
      ...(opts.audience ? { audience: opts.audience } : {}),
      createdAt: this.now(),
      consent: 'explicit-user-action',
    };
    await this.links.put(link.id, link);
    await this.log({ action: 'link.created', subject: link.id, details: { from: a.id, to: b.id, visibility } });
    return link;
  }

  async unlink(linkId: string): Promise<void> {
    await this.links.delete(linkId);
    await this.log({ action: 'link.removed', subject: linkId });
  }

  async linksOf(personaId: string): Promise<IdentityLink[]> {
    return (await this.links.all()).map((e) => e.value).filter((l) => l.from === personaId || l.to === personaId);
  }

  /** Composer banner: always show who is sending and how linked that identity is (spec §16.1). */
  async sendingAs(personaId: string): Promise<string> {
    const p = await this.get(personaId);
    const links = await this.linksOf(personaId);
    const level = links.length === 0 ? 'sin vínculo' : links.some((l) => l.visibility === 'public') ? 'vínculo público' : links.some((l) => l.visibility === 'selective') ? 'vínculo selectivo' : 'vínculo privado';
    const npub = npubEncode(p.pubkey);
    return `Enviando como ${p.label} (${npub.slice(0, 12)}…${npub.slice(-4)}) · ${level} · ${p.network === 'tor-only' ? 'Tor-only' : 'red directa'}`;
  }

  /** Record use of a contact/file by a persona so reuse across compartments can be warned about. */
  async recordUsage(personaId: string, use: { contact?: string; fileHash?: string }): Promise<void> {
    const u = (await this.usage.get(personaId)) ?? { personaId, contacts: [], files: [] };
    if (use.contact && !u.contacts.includes(use.contact)) u.contacts.push(use.contact);
    if (use.fileHash && !u.files.includes(use.fileHash)) u.files.push(use.fileHash);
    await this.usage.put(personaId, u);
  }

  /** §14.1: warn before reusing an identity, file or contact across high-risk compartments. */
  async reuseWarnings(personaId: string, use: { contact?: string; fileHash?: string }): Promise<string[]> {
    const me = await this.get(personaId);
    const warnings: string[] = [];
    for (const p of await this.list()) {
      if (p.id === personaId) continue;
      if (me.compartment !== 'high-risk' && p.compartment !== 'high-risk') continue;
      if (use.contact === p.pubkey) warnings.push(`El contacto es otra de tus identidades (${p.label}): usarlo puede correlacionar ambas.`);
      const u = await this.usage.get(p.id);
      if (use.contact && u?.contacts.includes(use.contact)) warnings.push(`Este contacto ya se usó desde la persona "${p.label}" (compartimento ${p.compartment}).`);
      if (use.fileHash && u?.files.includes(use.fileHash)) warnings.push(`Este archivo ya se compartió desde la persona "${p.label}": reutilizarlo puede vincular identidades.`);
    }
    return warnings;
  }

  /** Persist the persona's sovereignty/privacy panel configuration in its own compartment (PANEL-03). */
  async saveConfig(personaId: string, config: SovereigntyConfig): Promise<void> {
    await this.get(personaId);
    await (await this.openPersonaStore(personaId)).collection<SovereigntyConfig>('settings').put('sovereignty', config);
  }

  async getConfig(personaId: string): Promise<SovereigntyConfig | undefined> {
    return (await this.openPersonaStore(personaId)).collection<SovereigntyConfig>('settings').get('sovereignty');
  }

  /**
   * FR-027: full encrypted backup of a persona (v2): key (NIP-49), persona settings and relays, panel
   * configuration and the encrypted MLS group state, all sealed under the backup password.
   */
  async exportBackup(
    personaId: string,
    backupPassword: string,
    opts: { keyPassphrase?: string; scryptLogN?: number; config?: SovereigntyConfig; includeMls?: boolean } = {},
  ): Promise<BackupPackageV2> {
    const persona = await this.get(personaId);
    const logN = opts.scryptLogN ?? 18;
    const store = await this.openPersonaStore(personaId);
    let ncryptsec: string | undefined;
    if (persona.custody === 'local' || persona.custody === 'offline') {
      if (!opts.keyPassphrase) throw new Error('keyPassphrase required to export a local key');
      const enc = await store.collection<string>('key').get('ncryptsec');
      if (!enc) throw new Error('no key material for persona in this device');
      const { secretKey } = await nip49.decryptKeyAsync(enc, opts.keyPassphrase);
      try {
        ncryptsec = await nip49.encryptKeyAsync(secretKey, backupPassword, logN, 0x01);
      } finally {
        wipe(secretKey);
      }
    }
    const contents: BackupContents = { persona };
    const config = opts.config ?? (await this.getConfig(personaId));
    if (config) contents.config = config;
    if (opts.includeMls ?? true) {
      const mls: NonNullable<BackupContents['mls']> = {};
      for (const name of await store.collectionNames('mls-')) mls[name] = await store.collection<unknown>(name).all();
      if (Object.keys(mls).length) contents.mls = mls;
    }
    const contentKey = randomBytes(32);
    try {
      const nonce = randomBytes(24);
      const ct = xchacha20poly1305(contentKey, nonce, BACKUP_AAD).encrypt(utf8ToBytes(JSON.stringify(contents)));
      const pkg: BackupPackageV2 = {
        format: 'sedecim-identity-backup',
        version: 2,
        ...(ncryptsec ? { ncryptsec } : {}),
        contentKey: await nip49.encryptKeyAsync(contentKey, backupPassword, logN, 0x01),
        sealed: toBase64(concatBytes(nonce, ct)),
        createdAt: this.now(),
      };
      await this.log({ action: 'backup.exported', subject: personaId, details: { version: '2', config: String(!!contents.config), mlsCollections: String(Object.keys(contents.mls ?? {}).length) } });
      return pkg;
    } finally {
      wipe(contentKey);
    }
  }

  /** Decrypts a backup's contents (v2 sealed payload, or the clear v1 persona) without writing anything. */
  async readBackup(pkg: BackupPackage, backupPassword: string): Promise<BackupContents> {
    if (pkg?.format !== 'sedecim-identity-backup') throw new Error('unsupported backup format');
    if (pkg.version === 1) return { persona: pkg.persona };
    if (pkg.version !== 2) throw new Error('unsupported backup format');
    const { secretKey: contentKey } = await nip49.decryptKeyAsync(pkg.contentKey, backupPassword);
    try {
      const raw = fromBase64(pkg.sealed);
      const pt = xchacha20poly1305(contentKey, raw.subarray(0, 24), BACKUP_AAD).decrypt(raw.subarray(24));
      const contents = JSON.parse(bytesToUtf8(pt)) as BackupContents;
      if (!contents?.persona?.id || !isHex(contents.persona.pubkey, 32)) throw new Error('malformed backup contents');
      return contents;
    } finally {
      wipe(contentKey);
    }
  }

  /** Restores a v1 or v2 backup: key, persona (relays), panel configuration and MLS group state. */
  async restoreBackup(pkg: BackupPackage, backupPassword: string, keyPassphrase: string, opts: { scryptLogN?: number } = {}): Promise<PersonaConfig> {
    const contents = await this.readBackup(pkg, backupPassword);
    const { persona } = contents;
    if (pkg.ncryptsec) {
      const { secretKey } = await nip49.decryptKeyAsync(pkg.ncryptsec, backupPassword);
      try {
        if (!selfTestKey(secretKey, persona.pubkey).ok) throw new Error('backup key does not match persona pubkey');
        await this.storeKey(persona.id, secretKey, keyPassphrase, opts.scryptLogN);
      } finally {
        wipe(secretKey);
      }
    }
    const store = await this.openPersonaStore(persona.id);
    if (contents.config) await store.collection<SovereigntyConfig>('settings').put('sovereignty', contents.config);
    for (const [name, entries] of Object.entries(contents.mls ?? {})) {
      if (!/^mls-[a-z0-9-]+$/.test(name)) throw new Error(`invalid MLS collection in backup: ${name}`);
      const col = store.collection<unknown>(name);
      for (const e of entries) await col.put(e.id, e.value);
    }
    await this.personas.put(persona.id, persona);
    await this.log({ action: 'backup.restored', subject: persona.id, details: { version: String(pkg.version) } });
    return persona;
  }

  /** Update custody after a verified migration (e.g. managed -> local export). */
  async markCustodyMigrated(personaId: string, to: 'local', secretKey: Uint8Array, keyPassphrase: string): Promise<PersonaConfig> {
    const p = await this.get(personaId);
    if (!selfTestKey(secretKey, p.pubkey).ok) throw new Error('migrated key does not match persona');
    await this.storeKey(personaId, secretKey, keyPassphrase);
    const { managedKeyId: _m, ...rest } = p;
    const next: PersonaConfig = { ...rest, custody: to };
    await this.personas.put(personaId, next);
    await this.log({ action: 'custody.migrated', subject: personaId, details: { from: p.custody, to } });
    return next;
  }
}
