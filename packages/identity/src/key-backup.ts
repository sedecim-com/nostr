/**
 * Key backup files produced outside the identity manager (FR002-03): the offline key generator
 * (`sedecim-offline-key`, apps/key-generator) and the web client's download (`acceso-nostr-key-backup`).
 * Browser-safe: only nostr-core primitives.
 *
 * `acceso-nostr-key-backup` v2 (VAULT-02) adds the persona's archive key (Continuity Vault, ADR 0011) as a
 * second ncryptsec under the same password. The persona key is optional in v2: a persona whose key lives in
 * a signer (NIP-07, NIP-46, managed) backs up only its archive key.
 */
import { equalBytes, nip19, nip49, npubEncode, selfTestKey, wipe } from '@sedecim/nostr-core';

export type KeyBackupFormat = 'sedecim-offline-key' | 'acceso-nostr-key-backup';

/**
 * VAULT-02: highest scrypt cost (log2 N) a backup may declare: 2^20, about 1 GiB of scrypt memory, the most
 * any of our tools writes (the offline generator offers 16, 18 and 20). A file asking for more is refused
 * before scrypt runs, so a crafted backup cannot exhaust the device that restores it.
 */
export const MAX_BACKUP_LOG_N = 20;

export interface ParsedKeyBackup {
  format: KeyBackupFormat;
  version: number;
  npub: string;
  /** hex pubkey decoded from the npub */
  pubkey: string;
  /** The persona key (NIP-49). Absent only in a v2 web backup of a persona whose key lives in a signer. */
  ncryptsec?: string;
  /** VAULT-02: the persona's archive key (NIP-49, same password), in v2 web backups. */
  archiveKey?: string;
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

/** Checks one NIP-49 string of a backup, including its declared cost, without running scrypt. */
function checkNcryptsec(v: unknown, field: string): string {
  if (typeof v !== 'string' || !NCRYPTSEC.test(v)) throw new KeyBackupError(`backup has no valid NIP-49 ${field}`);
  let logN: number;
  try {
    logN = nip49.ncryptsecLogN(v);
  } catch {
    throw new KeyBackupError(`backup has no valid NIP-49 ${field}`);
  }
  if (logN > MAX_BACKUP_LOG_N) throw new KeyBackupError(`backup ${field} asks for a scrypt cost of 2^${logN}; the maximum is 2^${MAX_BACKUP_LOG_N}`);
  return v;
}

/**
 * Validates the shape of a key backup (object or JSON text) without decrypting it. Accepts
 * `sedecim-offline-key` v1 and `acceso-nostr-key-backup` v1 and v2; throws KeyBackupError otherwise.
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
  const versions = o.format === 'acceso-nostr-key-backup' ? [1, 2] : [1];
  if (typeof o.version !== 'number' || !versions.includes(o.version)) throw new KeyBackupError(`unsupported ${o.format} version: ${show(o.version)}`);
  if (typeof o.npub !== 'string') throw new KeyBackupError('backup has no npub');
  let pubkey: string;
  try {
    const d = nip19.decode(o.npub);
    if (d.type !== 'npub') throw new Error();
    pubkey = d.data;
  } catch {
    throw new KeyBackupError('backup npub is not a valid npub');
  }
  const v2 = o.version === 2;
  if (!v2 || o.ncryptsec !== undefined) checkNcryptsec(o.ncryptsec, 'ncryptsec');
  if (o.archiveKey !== undefined) {
    if (!v2) throw new KeyBackupError('only version 2 backups carry an archive key');
    checkNcryptsec(o.archiveKey, 'archive key');
  }
  if (v2 && o.ncryptsec === undefined && o.archiveKey === undefined) throw new KeyBackupError('backup has neither a key nor an archive key');
  if (o.format === 'sedecim-offline-key') {
    const kdf = o.kdf as Record<string, unknown> | undefined;
    if (kdf !== undefined && (typeof kdf !== 'object' || kdf === null || kdf.name !== 'scrypt')) throw new KeyBackupError('unsupported KDF in offline key backup');
  }
  return {
    format: o.format as KeyBackupFormat,
    version: o.version,
    npub: o.npub,
    pubkey,
    ...(o.ncryptsec !== undefined ? { ncryptsec: o.ncryptsec as string } : {}),
    ...(o.archiveKey !== undefined ? { archiveKey: o.archiveKey as string } : {}),
  };
}

async function decrypt(ncryptsec: string, passphrase: string): Promise<Uint8Array> {
  try {
    return (await nip49.decryptKeyAsync(ncryptsec, passphrase, { maxLogN: MAX_BACKUP_LOG_N })).secretKey;
  } catch {
    throw new KeyBackupError('cannot decrypt backup: wrong passphrase or corrupted file');
  }
}

/**
 * Decrypts a key backup with its passphrase and verifies that the key derives the declared npub
 * (and passes the BIP-340 self-test). A v2 backup also yields the archive key, which must differ from the
 * persona key. The caller owns both arrays and should wipe() them after use.
 */
export async function openKeyBackup(json: unknown, passphrase: string): Promise<{ secretKey: Uint8Array; pubkey: string; archiveKey?: Uint8Array }> {
  const b = parseKeyBackup(json);
  if (!b.ncryptsec) throw new KeyBackupError('this backup only carries the archive key: open the persona with its signer and restore the archive key there');
  const secretKey = await decrypt(b.ncryptsec, passphrase);
  const test = selfTestKey(secretKey);
  if (!test.ok || test.pubkey !== b.pubkey) {
    wipe(secretKey);
    throw new KeyBackupError(`backup key does not match its npub (${b.npub.slice(0, 12)}… vs ${npubEncode(test.pubkey).slice(0, 12)}…)`);
  }
  if (!b.archiveKey) return { secretKey, pubkey: b.pubkey };
  const archiveKey = await decrypt(b.archiveKey, passphrase);
  if (equalBytes(archiveKey, secretKey)) {
    wipe(secretKey);
    wipe(archiveKey);
    throw new KeyBackupError('the archive key in this backup is the persona key');
  }
  return { secretKey, pubkey: b.pubkey, archiveKey };
}

/**
 * VAULT-02: the archive key of a v2 backup, for a persona that already exists (for instance one opened
 * again with its NIP-46 signer on a new device). The backup must belong to `expectedPubkey`.
 */
export async function openArchiveKeyBackup(json: unknown, passphrase: string, expectedPubkey: string): Promise<Uint8Array> {
  const b = parseKeyBackup(json);
  if (b.pubkey !== expectedPubkey) throw new KeyBackupError(`this backup belongs to ${b.npub.slice(0, 12)}…, not to this persona`);
  if (!b.archiveKey) throw new KeyBackupError('this backup has no archive key');
  return decrypt(b.archiveKey, passphrase);
}
