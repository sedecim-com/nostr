/**
 * Key backup files produced outside the identity manager (FR002-03): the offline key generator
 * (`sedecim-offline-key`, apps/key-generator) and the web client's download (`acceso-nostr-key-backup`).
 * Browser-safe: only nostr-core primitives.
 */
import { nip19, nip49, npubEncode, selfTestKey, wipe } from '@sedecim/nostr-core';

export type KeyBackupFormat = 'sedecim-offline-key' | 'acceso-nostr-key-backup';

export interface ParsedKeyBackup {
  format: KeyBackupFormat;
  npub: string;
  /** hex pubkey decoded from the npub */
  pubkey: string;
  ncryptsec: string;
}

export class KeyBackupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyBackupError';
  }
}

const NCRYPTSEC = /^ncryptsec1[023456789acdefghjklmnpqrstuvwxyz]{152}$/;
const FORMATS: readonly KeyBackupFormat[] = ['sedecim-offline-key', 'acceso-nostr-key-backup'];
/** For error messages: String() throws on objects like {"toString": 0} (found by SEC-03 fuzz). */
const show = (v: unknown) => (typeof v === 'string' || typeof v === 'number' ? String(v) : (JSON.stringify(v) ?? typeof v).slice(0, 40));

/**
 * Validates the shape of a key backup (object or JSON text) without decrypting it. Accepts
 * `sedecim-offline-key` v1 and `acceso-nostr-key-backup` v1; throws KeyBackupError otherwise.
 */
export function parseKeyBackup(json: unknown): ParsedKeyBackup {
  let v = json;
  if (typeof v === 'string') {
    try {
      v = JSON.parse(v);
    } catch {
      throw new KeyBackupError('backup is not valid JSON');
    }
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new KeyBackupError('backup must be a JSON object');
  const o = v as Record<string, unknown>;
  if (typeof o.format !== 'string' || !FORMATS.includes(o.format as KeyBackupFormat)) throw new KeyBackupError(`unsupported backup format: ${show(o.format)}`);
  if (o.version !== 1) throw new KeyBackupError(`unsupported ${o.format} version: ${show(o.version)}`);
  if (typeof o.npub !== 'string') throw new KeyBackupError('backup has no npub');
  if (typeof o.ncryptsec !== 'string' || !NCRYPTSEC.test(o.ncryptsec)) throw new KeyBackupError('backup has no valid NIP-49 ncryptsec');
  let pubkey: string;
  try {
    const d = nip19.decode(o.npub);
    if (d.type !== 'npub') throw new Error();
    pubkey = d.data;
  } catch {
    throw new KeyBackupError('backup npub is not a valid npub');
  }
  if (o.format === 'sedecim-offline-key') {
    const kdf = o.kdf as Record<string, unknown> | undefined;
    if (kdf !== undefined && (typeof kdf !== 'object' || kdf === null || kdf.name !== 'scrypt')) throw new KeyBackupError('unsupported KDF in offline key backup');
  }
  return { format: o.format as KeyBackupFormat, npub: o.npub, pubkey, ncryptsec: o.ncryptsec };
}

/**
 * Decrypts a key backup with its passphrase and verifies that the key derives the declared npub
 * (and passes the BIP-340 self-test). The caller owns `secretKey` and should wipe() it after use.
 */
export async function openKeyBackup(json: unknown, passphrase: string): Promise<{ secretKey: Uint8Array; pubkey: string }> {
  const b = parseKeyBackup(json);
  let secretKey: Uint8Array;
  try {
    secretKey = (await nip49.decryptKeyAsync(b.ncryptsec, passphrase)).secretKey;
  } catch {
    throw new KeyBackupError('cannot decrypt backup: wrong passphrase or corrupted file');
  }
  const test = selfTestKey(secretKey);
  if (!test.ok || test.pubkey !== b.pubkey) {
    wipe(secretKey);
    throw new KeyBackupError(`backup key does not match its npub (${b.npub.slice(0, 12)}… vs ${npubEncode(test.pubkey).slice(0, 12)}…)`);
  }
  return { secretKey, pubkey: b.pubkey };
}
