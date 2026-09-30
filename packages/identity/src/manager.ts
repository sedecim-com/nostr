import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import {
  bytesToHex,
  bytesToUtf8,
  concatBytes,
  generateSecretKey,
  getPublicKey,
  hexToBytes,
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
import { assertDistinctFromNsec, generateArchiveKey } from '@sedecim/continuity';
import type { Collection, EncryptedStore } from '@sedecim/encrypted-store';
import type { SovereigntyConfig } from '@sedecim/profiles';
import { LocalSigner } from '@sedecim/signer';
import { MAX_BACKUP_LOG_N, openKeyBackup } from './key-backup';
import type { AuditEntry, BackupContents, BackupPackage, BackupPackageV2, Compartment, IdentityLink, LinkVisibility, PersonaConfig } from './types';
import { findReuse, UsageLedger, type PersonaUse, type ReusePersona, type ReuseWarning } from './usage';

const BACKUP_AAD = utf8ToBytes('sedecim-identity-backup-v2');
/** Persona-store collection used by the delivery engine's outbox (see apps/sovereign-client). */
export const OUTBOX_COLLECTION = 'outbox';
/** VAULT-02: persona-store collection holding the archive key of the Continuity Vault (ADR 0011). */
const ARCHIVE_COLLECTION = 'archive';
/** FR006-07: persona-store collection of its usage ledger (keyed tags, see usage.ts); never part of a backup. */
const USAGE_COLLECTION = 'usage';
const HEX32 = /^[0-9a-f]{64}$/;

/** What recordUsage kept before FR006-07: one account-level list per persona, npubs and file hashes in clear. */
interface LegacyUsage {
  personaId: string;
  contacts?: string[];
  files?: string[];
}

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
  /** FR021-03: only .onion relays, through Tor. */
  onionOnly?: boolean;
  /** Passphrase protecting the NIP-49 copy of the key inside the persona store. */
  keyPassphrase: string;
  scryptLogN?: number;
}

export interface ImportMeta {
  label: string;
  relays: string[];
  compartment?: Compartment;
  network?: 'direct' | 'tor-only';
  /** FR021-03: only .onion relays, through Tor. */
  onionOnly?: boolean;
  scryptLogN?: number;
}

/**
 * FR021-03: an onion-only persona goes through Tor and every one of its relays is a .onion address. The error
 * counts the offending relays without naming them (a relay address may be an IP).
 */
function networkOf(meta: { relays: string[]; compartment?: Compartment; network?: 'direct' | 'tor-only'; onionOnly?: boolean }): Pick<PersonaConfig, 'network' | 'onionOnly'> {
  if (!meta.onionOnly) return { network: meta.network ?? (meta.compartment === 'high-risk' ? 'tor-only' : 'direct') };
  if (meta.network === 'direct') throw new Error('onion-only requires Tor: a direct persona cannot be onion-only');
  const clearnet = meta.relays.filter((r) => !new URL(r).hostname.toLowerCase().endsWith('.onion')).length;
  if (clearnet) throw new Error(`onion-only: every relay must be a .onion address (${clearnet} of ${meta.relays.length} are not)`);
  return { network: 'tor-only', onionOnly: true };
}

const CUSTODY_BANNER: Record<PersonaConfig['custody'], string> = {
  local: 'llave cifrada en este dispositivo',
  offline: 'llave offline',
  external: 'signer externo (NIP-46)',
  'encrypted-backup': 'llave en backup cifrado',
  managed: 'llave gestionada por la plataforma (custodial)',
  'managed-enclave': 'llave gestionada en enclave (custodial)',
};

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
  /** Before FR006-07 only: moved to the persona ledgers and deleted on first use (see `migrateLegacyUsage`). */
  private readonly legacyUsage: Collection<LegacyUsage>;
  /** VAULT-04: archive keys being made, so concurrent callers share one (see `archiveKey`). */
  private readonly creatingArchiveKeys = new Map<string, Promise<string>>();
  /** FR006-07: one ledger per persona, so its key is made once. */
  private readonly ledgers = new Map<string, Promise<UsageLedger>>();
  private legacyMigrated?: Promise<void>;

  constructor(
    accountStore: EncryptedStore,
    /** Opens the isolated store of a persona (separate directory/key per compartment). */
    private readonly openPersonaStore: (personaId: string) => Promise<EncryptedStore>,
    private readonly now: () => number = Date.now,
  ) {
    this.personas = accountStore.collection('personas');
    this.links = accountStore.collection('links');
    this.audit = accountStore.collection('audit');
    this.legacyUsage = accountStore.collection('usage');
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

  private async putArchiveKey(personaId: string, key: Uint8Array) {
    await (await this.openPersonaStore(personaId)).collection<string>(ARCHIVE_COLLECTION).put('key', bytesToHex(key));
  }

  /**
   * VAULT-02: the persona's archive key for the Continuity Vault: 32 random bytes, never the nsec, kept in the
   * persona's encrypted store and carried by every backup. Created on first use for older personas.
   */
  async archiveKey(personaId: string): Promise<Uint8Array> {
    await this.get(personaId);
    const col = (await this.openPersonaStore(personaId)).collection<string>(ARCHIVE_COLLECTION);
    const hex = await col.get('key');
    if (hex) return hexToBytes(hex);
    // VAULT-04: two callers at once (the vault copies of two sends) must not each make a key, or what the first
    // one sealed would never open again. The first call makes it; the others wait for it.
    let creating = this.creatingArchiveKeys.get(personaId);
    if (!creating) {
      creating = (async () => {
        const again = await col.get('key');
        if (again) return again;
        const key = generateArchiveKey();
        const made = bytesToHex(key);
        wipe(key);
        await col.put('key', made);
        await this.log({ action: 'archive_key.created', subject: personaId });
        return made;
      })().finally(() => this.creatingArchiveKeys.delete(personaId));
      this.creatingArchiveKeys.set(personaId, creating);
    }
    return hexToBytes(await creating);
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
        ...networkOf(input),
        createdAt: this.now(),
      };
      await this.storeKey(persona.id, sk, input.keyPassphrase, input.scryptLogN);
      await this.putArchiveKey(persona.id, generateArchiveKey());
      await this.personas.put(persona.id, persona);
      await this.log({ action: 'persona.created', subject: persona.id, details: { custody: 'local', compartment: persona.compartment } });
      return persona;
    } finally {
      wipe(sk);
    }
  }

  /** FR-002: import and validate pubkey/secret correspondence (or register an external/managed signer). */
  async importPersona(input: ImportInput, meta: ImportMeta): Promise<PersonaConfig> {
    const network = networkOf(meta);
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
      ...network,
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
    const { secretKey, pubkey, archiveKey } = await openKeyBackup(json, backupPassword);
    try {
      const persona = await this.importPersona({ secretKey, keyPassphrase, expectedPubkey: pubkey }, meta);
      // VAULT-02: a v2 web backup brings the persona's archive key, so its vault archives open here too.
      if (archiveKey) await this.putArchiveKey(persona.id, archiveKey);
      return persona;
    } finally {
      wipe(secretKey);
      if (archiveKey) wipe(archiveKey);
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

  /**
   * Composer banner: always show who is sending, how the key is held, which network carries it and how linked
   * that identity is (spec §16.1, FR007-05).
   */
  async sendingAs(personaId: string): Promise<string> {
    const p = await this.get(personaId);
    const links = await this.linksOf(personaId);
    const level = links.length === 0 ? 'sin vínculo' : links.some((l) => l.visibility === 'public') ? 'vínculo público' : links.some((l) => l.visibility === 'selective') ? 'vínculo selectivo' : 'vínculo privado';
    const npub = npubEncode(p.pubkey);
    const network = p.onionOnly ? 'Tor-only, solo .onion' : p.network === 'tor-only' ? 'Tor-only' : 'red directa';
    return `Enviando como ${p.label} (${npub.slice(0, 12)}…${npub.slice(-4)}) · ${CUSTODY_BANNER[p.custody]} · ${network} · ${level}`;
  }

  /** FR006-07: the persona's usage ledger, in its own store. */
  private ledger(personaId: string): Promise<UsageLedger> {
    let ledger = this.ledgers.get(personaId);
    if (!ledger) {
      ledger = this.openPersonaStore(personaId).then((store) => new UsageLedger(store.collection<string>(USAGE_COLLECTION)));
      ledger.catch(() => this.ledgers.delete(personaId));
      this.ledgers.set(personaId, ledger);
    }
    return ledger;
  }

  /**
   * FR006-07: what recordUsage kept before (the npubs and file hashes of every persona in clear, in one account-level
   * list) moves once to each persona's own ledger, as keyed tags, and is deleted.
   */
  private migrateLegacyUsage(): Promise<void> {
    this.legacyMigrated ??= (async () => {
      // A value that is not hex (never written by the clients) is dropped rather than blocking every later check.
      const hex = (values: string[] | undefined) => (values ?? []).map((v) => String(v).toLowerCase()).filter((v) => HEX32.test(v));
      for (const { id, value } of await this.legacyUsage.all()) {
        if (value?.personaId && (await this.personas.get(value.personaId))) {
          const ledger = await this.ledger(value.personaId);
          for (const contact of hex(value.contacts)) await ledger.record({ contact });
          for (const fileHash of hex(value.files)) await ledger.record({ fileHash });
        }
        await this.legacyUsage.delete(id);
      }
    })();
    this.legacyMigrated.catch(() => (this.legacyMigrated = undefined));
    return this.legacyMigrated;
  }

  /**
   * FR006-07: notes that the persona used a contact (hex pubkey) and/or a file (`fileDigest`), in its own ledger, so
   * that another persona using them later is warned first.
   */
  async recordUsage(personaId: string, use: PersonaUse): Promise<void> {
    await this.get(personaId);
    await this.migrateLegacyUsage();
    await (await this.ledger(personaId)).record(use);
  }

  /**
   * FR006-07 (spec §14.1): what using `use` from this persona would cross with the other personas of this account: a
   * contact or a file another persona already used (whatever the compartments), and, when one of the two is high-risk,
   * writing to another of your own identities. Nothing is recorded: the caller confirms, then calls `recordUsage`.
   */
  async reuseCheck(personaId: string, use: PersonaUse): Promise<ReuseWarning[]> {
    const me = await this.get(personaId);
    await this.migrateLegacyUsage();
    const ref = (p: PersonaConfig): ReusePersona => ({ id: p.id, label: p.label, pubkey: p.pubkey, highRisk: p.compartment === 'high-risk' });
    const others = (await this.list()).filter((p) => p.id !== me.id).map(ref);
    return findReuse(ref(me), others, (id) => this.ledger(id), use);
  }

  /** The messages of `reuseCheck`. */
  async reuseWarnings(personaId: string, use: PersonaUse): Promise<string[]> {
    return (await this.reuseCheck(personaId, use)).map((w) => w.message);
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
   * configuration, the encrypted MLS group state and the delivery outbox (FR013-03), all sealed under the
   * backup password.
   */
  async exportBackup(
    personaId: string,
    backupPassword: string,
    opts: { keyPassphrase?: string; scryptLogN?: number; config?: SovereigntyConfig; includeMls?: boolean; includeOutbox?: boolean } = {},
  ): Promise<BackupPackageV2> {
    const persona = await this.get(personaId);
    const logN = opts.scryptLogN ?? 18;
    // A backup nobody could restore is worse than none (restores refuse costs above MAX_BACKUP_LOG_N).
    if (logN > MAX_BACKUP_LOG_N) throw new Error(`backup scrypt cost 2^${logN} is above the maximum 2^${MAX_BACKUP_LOG_N} that restores accept`);
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
    const archiveKey = await this.archiveKey(personaId);
    const contents: BackupContents = { persona, archiveKey: bytesToHex(archiveKey) };
    wipe(archiveKey);
    const config = opts.config ?? (await this.getConfig(personaId));
    if (config) contents.config = config;
    if (opts.includeMls ?? true) {
      const mls: NonNullable<BackupContents['mls']> = {};
      for (const name of await store.collectionNames('mls-')) mls[name] = await store.collection<unknown>(name).all();
      if (Object.keys(mls).length) contents.mls = mls;
    }
    if (opts.includeOutbox ?? true) {
      const outbox = await store.collection<unknown>(OUTBOX_COLLECTION).all();
      if (outbox.length) contents.outbox = outbox;
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
      await this.log({ action: 'backup.exported', subject: personaId, details: { version: '2', config: String(!!contents.config), mlsCollections: String(Object.keys(contents.mls ?? {}).length), outbox: String(contents.outbox?.length ?? 0) } });
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
    // VAULT-02: the cost comes from the file; above the maximum it is refused before scrypt runs.
    const { secretKey: contentKey } = await nip49.decryptKeyAsync(pkg.contentKey, backupPassword, { maxLogN: MAX_BACKUP_LOG_N });
    try {
      const raw = fromBase64(pkg.sealed);
      const pt = xchacha20poly1305(contentKey, raw.subarray(0, 24), BACKUP_AAD).decrypt(raw.subarray(24));
      const contents = JSON.parse(bytesToUtf8(pt)) as BackupContents;
      if (!contents?.persona?.id || !isHex(contents.persona.pubkey, 32)) throw new Error('malformed backup contents');
      if (contents.archiveKey !== undefined && (typeof contents.archiveKey !== 'string' || !HEX32.test(contents.archiveKey))) throw new Error('malformed archive key in backup');
      return contents;
    } finally {
      wipe(contentKey);
    }
  }

  /** Restores a v1 or v2 backup: key, persona (relays), panel configuration and MLS group state. */
  async restoreBackup(pkg: BackupPackage, backupPassword: string, keyPassphrase: string, opts: { scryptLogN?: number } = {}): Promise<PersonaConfig> {
    const contents = await this.readBackup(pkg, backupPassword);
    const { persona } = contents;
    const archiveKey = contents.archiveKey ? hexToBytes(contents.archiveKey) : undefined;
    if (pkg.ncryptsec) {
      const { secretKey } = await nip49.decryptKeyAsync(pkg.ncryptsec, backupPassword, { maxLogN: MAX_BACKUP_LOG_N });
      try {
        if (!selfTestKey(secretKey, persona.pubkey).ok) throw new Error('backup key does not match persona pubkey');
        if (archiveKey) assertDistinctFromNsec(archiveKey, secretKey);
        await this.storeKey(persona.id, secretKey, keyPassphrase, opts.scryptLogN);
      } finally {
        wipe(secretKey);
      }
    }
    // VAULT-02: the restored device opens the vault archives with the key the backup carries.
    if (archiveKey) {
      await this.putArchiveKey(persona.id, archiveKey);
      wipe(archiveKey);
    }
    const store = await this.openPersonaStore(persona.id);
    if (contents.config) await store.collection<SovereigntyConfig>('settings').put('sovereignty', contents.config);
    for (const [name, entries] of Object.entries(contents.mls ?? {})) {
      if (!/^mls-[a-z0-9-]+$/.test(name)) throw new Error(`invalid MLS collection in backup: ${name}`);
      const col = store.collection<unknown>(name);
      for (const e of entries) await col.put(e.id, e.value);
    }
    if (contents.outbox?.length) {
      const col = store.collection<unknown>(OUTBOX_COLLECTION);
      for (const e of contents.outbox) if (!(await col.get(e.id))) await col.put(e.id, e.value); // never overwrite newer local state
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
