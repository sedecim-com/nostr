import { bytesToHex, hexToBytes, nip19, nip49, generateSecretKey, getPublicKey, npubEncode, selfTestKey, wipe, CUSTODY_FACTS, type Signer } from '@sedecim/nostr-core';
import { RelayPool } from '@sedecim/relay-pool';
import { formatBunkerUrl, LocalSigner, Nip07Signer, Nip46Signer, parseBunkerUrl, WEB_NIP46_PERMISSIONS } from '@sedecim/signer';
import { raiseSignerAuthUrl } from './authUrl';
import { DeliveryEngine, type OutboxRecord } from '@sedecim/delivery-engine';
import { publishDmRelayList } from '@sedecim/messaging';
import { preset, type PresetName } from '@sedecim/profiles';
import type { PersonaBook, PersonaRecord } from './vault';

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
  close(): void;
}

export type NewPersona =
  | { kind: 'create' }
  | { kind: 'import'; secret: string; ncryptsecPass?: string }
  | { kind: 'secret'; secretKey: Uint8Array }
  | { kind: 'nip07' }
  | { kind: 'nip46'; bunker: string }
  /** Already connected through a client-initiated nostrconnect:// offer (FR004-03). */
  | { kind: 'nip46-connected'; signer: Nip46Signer; clientSecretKey: Uint8Array };

/** Pool for NIP-46 traffic: NIP-42 on the signer relays authenticates the ephemeral client key only. */
const nip46Pool = (clientKey: Uint8Array) => new RelayPool({ signer: new LocalSigner(clientKey), authMode: 'on-demand' });

const newId = () => bytesToHex(crypto.getRandomValues(new Uint8Array(8)));

export async function createPersona(book: PersonaBook, input: NewPersona, opts: { label: string; relays: string[]; preset: PresetName; deviceKey?: boolean }): Promise<PersonaRecord> {
  let custody: PersonaRecord['custody'];
  let pubkey: string;
  let secretHex: string | undefined;
  let bunker: string | undefined;
  let nip46ClientSecretHex: string | undefined;
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
    case 'nip46-connected':
      custody = 'nip46';
      pubkey = await input.signer.getPublicKey();
      bunker = formatBunkerUrl(input.signer.bunker);
      nip46ClientSecretHex = bytesToHex(input.clientSecretKey);
      break;
  }
  const existing = (await book.list()).find((p) => p.pubkey === pubkey!);
  if (existing) throw new Error(`esa llave ya es la persona "${existing.label}"`);
  const config = { ...preset(opts.preset), ...(opts.deviceKey ? { localProtection: 'device' as const } : {}) };
  const persona: PersonaRecord = { id: newId(), label: opts.label, pubkey: pubkey!, custody: custody!, relays: opts.relays, preset: opts.preset, config, createdAt: Date.now(), ...(secretHex ? { secretHex } : {}), ...(bunker ? { bunker } : {}), ...(nip46ClientSecretHex ? { nip46ClientSecretHex } : {}) };
  await book.save(persona);
  return persona;
}

export async function openPersona(book: PersonaBook, persona: PersonaRecord): Promise<PersonaSession> {
  let signer: Signer;
  if (persona.custody === 'local') {
    const sk = hexToBytes(persona.secretHex!);
    signer = new LocalSigner(sk, 'local');
    wipe(sk);
  } else if (persona.custody === 'nip07') signer = new Nip07Signer();
  else {
    const opts = { permissions: WEB_NIP46_PERMISSIONS, onAuthUrl: raiseSignerAuthUrl };
    if (persona.nip46ClientSecretHex) {
      const clientKey = hexToBytes(persona.nip46ClientSecretHex);
      signer = new Nip46Signer(parseBunkerUrl(persona.bunker!), { ...opts, pool: nip46Pool(clientKey), clientSecretKey: clientKey });
    } else {
      // Personas created before the client key was stored: connect with the bunker URL as before.
      const clientKey = generateSecretKey();
      const remote = new Nip46Signer(parseBunkerUrl(persona.bunker!), { ...opts, pool: nip46Pool(clientKey), clientSecretKey: clientKey });
      await remote.connect();
      signer = remote;
    }
  }
  const pool = new RelayPool({ signer, authMode: 'on-demand' });
  const engine = new DeliveryEngine({ store: book.store.collection<OutboxRecord>(`outbox-${persona.id}`), publisher: pool, signer, retry: { baseMs: 2000, maxMs: 60_000 } });
  void engine.resume();
  // FR011-02: a relay coming back resumes pending deliveries (the window 'online' event does too).
  const offReconnect = pool.onReconnect(() => void engine.resume());
  return {
    persona,
    signer,
    pubkey: await signer.getPublicKey(),
    pool,
    engine,
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

/** NIP-49 backup protected by a password the user picks now (never the vault password by default). */
export async function exportBackup(persona: PersonaRecord, backupPassword: string): Promise<Blob> {
  if (persona.custody !== 'local' || !persona.secretHex) throw new Error('solo las llaves locales se pueden exportar');
  if (backupPassword.length < 8) throw new Error('la contraseña del backup debe tener al menos 8 caracteres');
  const sk = hexToBytes(persona.secretHex);
  const ncryptsec = await nip49.encryptKeyAsync(sk, backupPassword, 16, 0x01);
  wipe(sk);
  return new Blob([JSON.stringify({ format: 'acceso-nostr-key-backup', version: 1, npub: npubEncode(persona.pubkey), ncryptsec }, null, 2)], { type: 'application/json' });
}

const CUSTODY_LABEL: Record<PersonaRecord['custody'], string> = { local: 'Llave local (navegador)', nip07: 'Signer externo (NIP-07)', nip46: 'Signer remoto (NIP-46)' };

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
