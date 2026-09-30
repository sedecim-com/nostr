/**
 * FR006-07 (spec §14.1): before a persona uses a contact or a file that another persona of this device already used,
 * the user is warned (which persona, and who could relate the two) and must confirm. The web and the sovereign CLI
 * share this module.
 *
 * What makes the check possible is a usage ledger per persona, kept in that persona's own encrypted store (never in a
 * list shared by every persona):
 * - a random 32-byte key of the persona, and
 * - one opaque tag per contact or file it used: HMAC-SHA256(key, "contact:<hex pubkey>" or "file:<sha256 of the file>").
 * The ledger holds no npub, no file hash, no file name and no date, and it never leaves the device: backups and the
 * Continuity Vault do not carry it. A check computes the tag with each other persona's key. Whoever opens the store
 * (the local passphrase) can test whether a given npub or file is in a ledger, but cannot list them, and the tags of two
 * personas cannot be matched without both keys.
 */
import type { Collection } from '@sedecim/encrypted-store';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@sedecim/nostr-core';

/** What a persona is about to use: a contact (hex pubkey) and/or a file (`fileDigest` of its bytes). */
export interface PersonaUse {
  contact?: string;
  fileHash?: string;
}

/** The persona fields the check needs (the CLI's PersonaConfig and the web's PersonaRecord both have them). */
export interface ReusePersona {
  id: string;
  label: string;
  pubkey: string;
  /** A high-risk compartment: writing to another of your own identities is then warned about too. */
  highRisk?: boolean;
}

/**
 * - `identity`: the contact is another of your personas (only when one of the two is high-risk);
 * - `contact` / `file`: another persona already used this contact or sent this file.
 */
export type ReuseKind = 'identity' | 'contact' | 'file';

export interface ReuseWarning {
  kind: ReuseKind;
  /** The other persona involved. */
  personaId: string;
  label: string;
  /** What the user is shown. */
  message: string;
}

/** What each warning says: the other persona, and who could relate the two. */
export const REUSE_MESSAGES: Record<ReuseKind, (label: string) => string> = {
  identity: (label) => `El contacto es otra de tus identidades ("${label}"): escribirle desde esta persona puede relacionar las dos.`,
  contact: (label) => `Ya escribiste o invitaste a este contacto desde tu persona "${label}": si también lo haces desde esta, el contacto, y quien vea el tráfico de las dos, puede deducir que ambas personas son la misma.`,
  file: (label) => `Ya enviaste este mismo archivo desde tu persona "${label}": quien reciba o vea las dos copias puede deducir que ambas personas son la misma.`,
};

/** A reuse the user has not confirmed: nothing was used or sent from this persona. */
export class ReuseNotConfirmedError extends Error {
  constructor(readonly warnings: ReuseWarning[]) {
    super(`compartimentación: ${warnings.map((w) => w.message).join(' ')} No se ha enviado nada: para seguir con esta persona hace falta tu confirmación explícita.`);
  }
}

/** The sha256 (hex) of a file's bytes as the user picked them, before any metadata stripping or encryption. */
export async function fileDigest(data: Uint8Array): Promise<string> {
  const bytes = data.buffer instanceof ArrayBuffer ? (data as Uint8Array<ArrayBuffer>) : data.slice();
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}

const KEY_ENTRY = 'key';
const HEX64 = /^[0-9a-f]{64}$/;

function labels(use: PersonaUse): { contact?: string; file?: string } {
  const out: { contact?: string; file?: string } = {};
  if (use.contact) {
    const c = use.contact.toLowerCase();
    if (!HEX64.test(c)) throw new Error('the contact must be a hex pubkey');
    out.contact = `contact:${c}`;
  }
  if (use.fileHash) {
    const f = use.fileHash.toLowerCase();
    if (!HEX64.test(f)) throw new Error('the file hash must be a hex sha256');
    out.file = `file:${f}`;
  }
  return out;
}

const importKey = (raw: Uint8Array) => crypto.subtle.importKey('raw', raw.slice(), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
const tag = async (key: CryptoKey, label: string) => bytesToHex(new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8ToBytes(label).slice())));

/**
 * One persona's ledger over a collection of its own store. Keep one instance per persona: the key is made on the first
 * record, and two instances making it at once would each write their own (as with the archive key, VAULT-04).
 */
export class UsageLedger {
  private key?: CryptoKey;
  private making?: Promise<CryptoKey>;

  constructor(private readonly col: Collection<string>) {}

  /** The key if the persona recorded anything yet. Not remembered while missing: another instance may make it. */
  private async load(): Promise<CryptoKey | undefined> {
    if (this.key) return this.key;
    const hex = await this.col.get(KEY_ENTRY);
    if (!hex) return undefined;
    const raw = hexToBytes(hex);
    this.key = await importKey(raw);
    raw.fill(0);
    return this.key;
  }

  private async ensureKey(): Promise<CryptoKey> {
    const existing = await this.load();
    if (existing) return existing;
    this.making ??= (async () => {
      const raw = randomBytes(32);
      await this.col.put(KEY_ENTRY, bytesToHex(raw));
      this.key = await importKey(raw);
      raw.fill(0);
      return this.key;
    })().finally(() => (this.making = undefined));
    return this.making;
  }

  /** Whether this persona already used the contact / the file of `use`. */
  async has(use: PersonaUse): Promise<{ contact: boolean; file: boolean }> {
    const l = labels(use);
    const key = await this.load();
    const found = async (label?: string) => !!key && !!label && (await this.col.get(await tag(key, label))) !== undefined;
    return { contact: await found(l.contact), file: await found(l.file) };
  }

  /** Notes that this persona used the contact and/or the file of `use`. */
  async record(use: PersonaUse): Promise<void> {
    const l = labels(use);
    if (!l.contact && !l.file) return;
    const key = await this.ensureKey();
    for (const label of [l.contact, l.file]) if (label) await this.col.put(await tag(key, label), '');
  }
}

/**
 * The warnings for `self` using `use`, against the other personas of the device:
 * - `identity`, every time, when the contact is another persona and one of the two is high-risk;
 * - `contact` / `file`, when another persona's ledger has it and this persona's does not: once confirmed and recorded,
 *   the same crossing is not asked again. The other ledgers are not even opened for what this persona already used.
 */
export async function findReuse(self: ReusePersona, others: readonly ReusePersona[], ledgerOf: (personaId: string) => Promise<UsageLedger>, use: PersonaUse): Promise<ReuseWarning[]> {
  const contact = use.contact?.toLowerCase();
  const mine = await (await ledgerOf(self.id)).has(use);
  const ask: PersonaUse = { ...(contact && !mine.contact ? { contact } : {}), ...(use.fileHash && !mine.file ? { fileHash: use.fileHash } : {}) };
  const out: ReuseWarning[] = [];
  const warn = (kind: ReuseKind, p: ReusePersona) => out.push({ kind, personaId: p.id, label: p.label, message: REUSE_MESSAGES[kind](p.label) });
  for (const p of others) {
    if (p.id === self.id) continue;
    if (contact && contact === p.pubkey.toLowerCase() && (self.highRisk || p.highRisk)) warn('identity', p);
    if (!ask.contact && !ask.fileHash) continue;
    const theirs = await (await ledgerOf(p.id)).has(ask);
    if (theirs.contact) warn('contact', p);
    if (theirs.file) warn('file', p);
  }
  return out;
}
