import { bytesToHex, hexToBytes, nip19, nip49, generateSecretKey, getPublicKey, npubEncode, selfTestKey, wipe, CUSTODY_FACTS, type Signer } from '@sedecim/nostr-core';
import { NetworkBlockedError, RelayPool, type WebSocketFactory } from '@sedecim/relay-pool';
import { formatBunkerUrl, LocalSigner, ManagedSignerClient, Nip07Signer, Nip46Signer, parseBunkerUrl, WEB_NIP46_PERMISSIONS, type AccessTokenProvider } from '@sedecim/signer';
import { raiseSignerAuthUrl } from './authUrl';
import { DeliveryEngine, type OutboxRecord } from '@sedecim/delivery-engine';
import { DmInbox, dmRouter, publishDmRelayList, type DirectMessage, type Receipt, type WrapOptions } from '@sedecim/messaging';
import { preset, validateConfig, type PresetName, type ReceiptPolicy, type SovereigntyConfig } from '@sedecim/profiles';
import { assertDistinctFromNsec, generateArchiveKey } from '@sedecim/continuity';
import type { PersonaBook, PersonaCustody, PersonaRecord } from './vault';

/**
 * One open persona (FR006-02). The SaaS web app is a first-class Nostr client (spec §15): it signs
 * locally or through an external signer and talks WebSocket to the same relays as Buzz; the backend
 * never sees the nsec. Each persona has its own signer, relays and outbox.
 */
export interface PersonaSession {
  persona: PersonaRecord;
  signer: Signer;
  pubkey: string;
  pool: RelayPool;
  engine: DeliveryEngine;
  /** FR010-03: where recipients' DM relay lists are looked up (the persona's relays plus the deployment's). */
  dmDiscovery: string[];
  close(): void;
}

export type NewPersona =
  | { kind: 'create' }
  | { kind: 'import'; secret: string; ncryptsecPass?: string }
  /** A decrypted key backup; a v2 backup also brings the persona's archive key (VAULT-02). */
  | { kind: 'secret'; secretKey: Uint8Array; archiveKey?: Uint8Array }
  | { kind: 'nip07' }
  | { kind: 'nip46'; bunker: string }
  /** Custodial key created in the managed-signer after an explicit opt-in (FR005-07) whose version is recorded (FR005-08). */
  | { kind: 'managed'; baseUrl: string; token: AccessTokenProvider; consentVersion: string }
  /** Already connected through a client-initiated nostrconnect:// offer (FR004-03). */
  | { kind: 'nip46-connected'; signer: Nip46Signer; clientSecretKey: Uint8Array };

/**
 * PANEL-05: a browser cannot guarantee Tor-only, so the web never opens a relay connection for a Tor-only persona
 * (no reads, no kind 10050, no DM discovery). Sends were already blocked; now nothing leaves over clearnet.
 */
const torOnlyBlocked: WebSocketFactory = (url) => {
  throw new NetworkBlockedError('Tor-only: el navegador no conecta con relays por clearnet; usa el cliente soberano.', url);
};

/** Pool for NIP-46 traffic: NIP-42 on the signer relays authenticates the ephemeral client key only. */
const nip46Pool = (clientKey: Uint8Array, webSocketFactory?: WebSocketFactory) => new RelayPool({ signer: new LocalSigner(clientKey), authMode: 'on-demand', webSocketFactory });

const CUSTODY_OF_INPUT: Record<NewPersona['kind'], PersonaCustody> = { create: 'local', import: 'local', secret: 'local', nip07: 'nip07', nip46: 'nip46', 'nip46-connected': 'nip46', managed: 'managed' };

/**
 * PANEL-05: the custody a persona really has, whatever its preset says: the panel and its disclosures describe
 * facts. A key in this browser is 'local', a NIP-07/NIP-46 signer 'external' and the managed-signer 'managed'.
 */
export function realCustody(custody: PersonaCustody): SovereigntyConfig['custody'] {
  return custody === 'local' ? 'local' : custody === 'managed' ? 'managed' : 'external';
}

/** The panel configuration of a persona with its real custody (older personas stored the preset's). */
export function personaConfig(p: PersonaRecord): SovereigntyConfig {
  return { ...p.config, custody: realCustody(p.custody) };
}

const newId = () => bytesToHex(crypto.getRandomValues(new Uint8Array(8)));

export async function createPersona(book: PersonaBook, input: NewPersona, opts: { label: string; relays: string[]; preset: PresetName; deviceKey?: boolean }): Promise<PersonaRecord> {
  // PANEL-05: validated before anything is created (a managed key, a signer connection): e.g. Tor-only is refused
  // in a browser and a quorum above the relays is refused.
  const config = { ...preset(opts.preset), custody: realCustody(CUSTODY_OF_INPUT[input.kind]), ...(opts.deviceKey ? { localProtection: 'device' as const } : {}) };
  const errors = validateConfig(config, 'web', { relays: opts.relays.length }).filter((i) => i.severity === 'error');
  if (errors.length) throw new Error(`El perfil ${opts.preset} no es válido para esta persona: ${errors.map((i) => i.message).join(' ')}`);
  let custody: PersonaRecord['custody'];
  let pubkey: string;
  let secretHex: string | undefined;
  let bunker: string | undefined;
  let nip46ClientSecretHex: string | undefined;
  let managedKeyId: string | undefined;
  let managedConsent: PersonaRecord['managedConsent'];
  const local = (sk: Uint8Array) => {
    if (!selfTestKey(sk).ok) throw new Error('la llave no pasó el self-test');
    custody = 'local';
    pubkey = getPublicKey(sk);
    secretHex = bytesToHex(sk);
    wipe(sk);
  };
  switch (input.kind) {
    case 'create':
      local(generateSecretKey());
      break;
    case 'secret':
      if (input.archiveKey) assertDistinctFromNsec(input.archiveKey, input.secretKey);
      local(input.secretKey);
      break;
    case 'import': {
      const s = input.secret.trim();
      if (s.startsWith('ncryptsec')) local((await nip49.decryptKeyAsync(s, input.ncryptsecPass ?? '')).secretKey);
      else {
        const d = nip19.decode(s);
        if (d.type !== 'nsec') throw new Error('se esperaba nsec o ncryptsec');
        local(d.data);
      }
      break;
    }
    case 'nip07':
      custody = 'nip07';
      pubkey = await new Nip07Signer().getPublicKey();
      break;
    case 'nip46': {
      const clientKey = generateSecretKey();
      const pointer = parseBunkerUrl(input.bunker.trim());
      const remote = new Nip46Signer(pointer, { pool: nip46Pool(clientKey), clientSecretKey: clientKey, permissions: WEB_NIP46_PERMISSIONS, onAuthUrl: raiseSignerAuthUrl });
      await remote.connect();
      custody = 'nip46';
      pubkey = await remote.getPublicKey();
      // Keep the authorized client key, never the (often single-use) bunker secret.
      bunker = formatBunkerUrl({ remoteSignerPubkey: pointer.remoteSignerPubkey, relays: pointer.relays });
      nip46ClientSecretHex = bytesToHex(clientKey);
      remote.close();
      break;
    }
    case 'managed': {
      const key = await ManagedSignerClient.createKey({ baseUrl: input.baseUrl, token: input.token }, { consentVersion: input.consentVersion });
      custody = 'managed';
      pubkey = key.pubkey;
      managedKeyId = key.keyId;
      managedConsent = { version: input.consentVersion, acceptedAt: key.consentAt ?? Date.now() };
      break;
    }
    case 'nip46-connected':
      custody = 'nip46';
      pubkey = await input.signer.getPublicKey();
      bunker = formatBunkerUrl(input.signer.bunker);
      nip46ClientSecretHex = bytesToHex(input.clientSecretKey);
      break;
  }
  const existing = (await book.list()).find((p) => p.pubkey === pubkey!);
  if (existing) throw new Error(`esa llave ya es la persona "${existing.label}"`);
  // VAULT-02: every persona has its own archive key; a restored one keeps the key its backup carries.
  const archiveKey = input.kind === 'secret' && input.archiveKey ? input.archiveKey : generateArchiveKey();
  const archiveKeyHex = bytesToHex(archiveKey);
  wipe(archiveKey);
  const persona: PersonaRecord = { id: newId(), label: opts.label, pubkey: pubkey!, custody: custody!, relays: opts.relays, preset: opts.preset, config, createdAt: Date.now(), archiveKeyHex, ...(secretHex ? { secretHex } : {}), ...(bunker ? { bunker } : {}), ...(nip46ClientSecretHex ? { nip46ClientSecretHex } : {}), ...(managedKeyId ? { managedKeyId } : {}), ...(managedConsent ? { managedConsent } : {}) };
  await book.save(persona);
  return persona;
}

/** VAULT-02: the persona with its archive key, creating one for a persona made before the vault existed. */
export async function ensureArchiveKey(book: PersonaBook, persona: PersonaRecord): Promise<PersonaRecord> {
  if (persona.archiveKeyHex) return persona;
  const key = generateArchiveKey();
  const next = { ...persona, archiveKeyHex: bytesToHex(key) };
  wipe(key);
  await book.save(next);
  return next;
}

/** VAULT-02: installs the archive key restored from a backup of this persona (never its nsec). */
export async function setArchiveKey(book: PersonaBook, persona: PersonaRecord, key: Uint8Array): Promise<PersonaRecord> {
  if (key.length !== 32) throw new Error('la llave de archivo debe tener 32 bytes');
  if (persona.secretHex) {
    const sk = hexToBytes(persona.secretHex);
    try {
      assertDistinctFromNsec(key, sk);
    } finally {
      wipe(sk);
    }
  }
  const next = { ...persona, archiveKeyHex: bytesToHex(key) };
  await book.save(next);
  return next;
}

/** What a managed persona needs to reach its signer; the token proves the Acceso user on each call. */
export interface ManagedEnv {
  baseUrl?: string;
  token?: AccessTokenProvider;
}

export async function openPersona(book: PersonaBook, persona: PersonaRecord, managed: ManagedEnv = {}, routing: { discoveryRelays?: string[] } = {}): Promise<PersonaSession> {
  let signer: Signer;
  const blocked = persona.config.network === 'tor-only' ? torOnlyBlocked : undefined;
  if (persona.custody === 'local') {
    const sk = hexToBytes(persona.secretHex!);
    signer = new LocalSigner(sk, 'local');
    wipe(sk);
  } else if (persona.custody === 'managed') {
    if (!managed.baseUrl || !managed.token) throw new Error('la persona gestionada necesita el managed-signer y una sesión de Acceso');
    signer = new ManagedSignerClient({ baseUrl: managed.baseUrl, keyId: persona.managedKeyId!, token: managed.token });
  } else if (persona.custody === 'nip07') signer = new Nip07Signer();
  else {
    const opts = { permissions: WEB_NIP46_PERMISSIONS, onAuthUrl: raiseSignerAuthUrl };
    if (persona.nip46ClientSecretHex) {
      const clientKey = hexToBytes(persona.nip46ClientSecretHex);
      signer = new Nip46Signer(parseBunkerUrl(persona.bunker!), { ...opts, pool: nip46Pool(clientKey, blocked), clientSecretKey: clientKey });
    } else {
      // Personas created before the client key was stored: connect with the bunker URL as before.
      const clientKey = generateSecretKey();
      const remote = new Nip46Signer(parseBunkerUrl(persona.bunker!), { ...opts, pool: nip46Pool(clientKey, blocked), clientSecretKey: clientKey });
      await remote.connect();
      signer = remote;
    }
  }
  const pool = new RelayPool({ signer, authMode: 'on-demand', webSocketFactory: blocked });
  const dmDiscovery = [...new Set([...persona.relays, ...(routing.discoveryRelays ?? [])])];
  // FR010-03: a DM wrap that could not be routed when it was written (offline) goes to the recipient's DM relays on retry.
  const router = dmRouter(pool, { discoveryRelays: dmDiscovery, fallback: persona.relays });
  const engine = new DeliveryEngine({ store: book.store.collection<OutboxRecord>(`outbox-${persona.id}`), publisher: pool, signer, retry: { baseMs: 2000, maxMs: 60_000 }, router });
  void engine.resume();
  // FR011-02: a relay coming back resumes pending deliveries (the window 'online' event does too).
  const offReconnect = pool.onReconnect(() => void engine.resume());
  return {
    persona,
    signer,
    pubkey: await signer.getPublicKey(),
    pool,
    engine,
    dmDiscovery,
    close: () => {
      offReconnect();
      pool.close();
    },
  };
}

/** FR017-04: publish the persona's DM relay list (kind 10050) so senders route NIP-17 DMs to it. */
export async function publishDmRelays(s: PersonaSession): Promise<void> {
  await s.engine.submit({ event: await publishDmRelayList(s.signer, s.persona.relays) }, { relays: s.persona.relays, quorum: 1 });
}

/**
 * FR009-03: the persona's DM inbox on its own DM relays (its kind 10050). Receipts for its DMs advance the outbox;
 * incoming DMs are answered with the receipts the panel allows, sent to the sender's DM relays. The receipts already
 * sent are kept in the vault, so each goes at most once.
 */
export function openDmInbox(
  book: PersonaBook,
  s: PersonaSession,
  opts: { policy: () => ReceiptPolicy; wrapOptions?: WrapOptions; onMessage?: (m: DirectMessage, live: boolean) => void; onReceipt?: (r: Receipt, rec: OutboxRecord) => void },
): DmInbox<OutboxRecord> {
  return new DmInbox(s.signer, { pool: s.pool, outbox: s.engine, ownRelays: s.persona.relays, discoveryRelays: s.dmDiscovery, sent: book.store.collection<boolean>(`receipts-${s.persona.id}`), ...opts });
}

/**
 * NIP-49 backup (JSON text) protected by a password the user picks now (never the vault password by default).
 * Version 2 (VAULT-02): the persona key when it lives in this browser, and always the archive key, so a persona
 * whose key is in a signer (NIP-07, NIP-46, managed) can still recover its Continuity Vault archives.
 */
export async function backupJson(persona: PersonaRecord, backupPassword: string): Promise<string> {
  if (backupPassword.length < 8) throw new Error('la contraseña del backup debe tener al menos 8 caracteres');
  if (!persona.archiveKeyHex) throw new Error('esta persona aún no tiene llave de archivo');
  const ak = hexToBytes(persona.archiveKeyHex);
  const archiveKey = await nip49.encryptKeyAsync(ak, backupPassword, 16, 0x01);
  wipe(ak);
  let ncryptsec: string | undefined;
  if (persona.custody === 'local' && persona.secretHex) {
    const sk = hexToBytes(persona.secretHex);
    ncryptsec = await nip49.encryptKeyAsync(sk, backupPassword, 16, 0x01);
    wipe(sk);
  }
  return JSON.stringify({ format: 'acceso-nostr-key-backup', version: 2, npub: npubEncode(persona.pubkey), ...(ncryptsec ? { ncryptsec } : {}), archiveKey }, null, 2);
}

export async function exportBackup(persona: PersonaRecord, backupPassword: string): Promise<Blob> {
  return new Blob([await backupJson(persona, backupPassword)], { type: 'application/json' });
}

const CUSTODY_LABEL: Record<PersonaRecord['custody'], string> = { local: 'Llave local (navegador)', nip07: 'Signer externo (NIP-07)', nip46: 'Signer remoto (NIP-46)', managed: 'Llave gestionada por la plataforma (custodial)' };

export function custodyLabel(p: PersonaRecord): string {
  return CUSTODY_LABEL[p.custody];
}

export function custodyFacts(s: PersonaSession): string[] {
  const f = CUSTODY_FACTS[s.signer.custody];
  return [
    `Modo de custodia: ${custodyLabel(s.persona)}.`,
    f.operatorCanSign ? 'La plataforma tiene capacidad técnica de firmar como tú (CUSTODIAL).' : 'La plataforma NO puede firmar como tú.',
    f.operatorCanRecover ? 'La plataforma puede recuperar tu llave.' : 'La plataforma NO puede recuperar tu llave: guarda un backup.',
  ];
}

export function shortNpub(pubkey: string): string {
  const n = npubEncode(pubkey);
  return `${n.slice(0, 12)}…${n.slice(-4)}`;
}

/**
 * FR026-03: managed → local migration with verification. The key is exported under a password the user
 * picks, decrypted here, checked against the persona npub, and possession is proven by signing the
 * service's challenge. Only then does the persona switch to local custody; deleting the managed copy is a
 * separate, explicit step.
 */
export async function migrateManagedToLocal(book: PersonaBook, persona: PersonaRecord, client: ManagedSignerClient, password: string): Promise<{ persona: PersonaRecord; ncryptsec: string }> {
  if (password.length < 12) throw new Error('la contraseña de exportación debe tener al menos 12 caracteres');
  const { ncryptsec, challenge } = await client.exportForMigration(password);
  const { secretKey } = await nip49.decryptKeyAsync(ncryptsec, password);
  if (getPublicKey(secretKey) !== persona.pubkey) throw new Error('la llave exportada no corresponde a esta persona: migración cancelada');
  if (!selfTestKey(secretKey).ok) throw new Error('la llave exportada no pasó el self-test');
  const proof = await new LocalSigner(secretKey).signEvent({ kind: 27235, content: 'migración de custodia', tags: [['challenge', challenge]] });
  await client.confirmMigration(proof);
  const migrated: PersonaRecord = { ...persona, custody: 'local', secretHex: bytesToHex(secretKey), config: { ...persona.config, custody: 'local' } };
  wipe(secretKey);
  await book.save(migrated);
  return { persona: migrated, ncryptsec };
}
