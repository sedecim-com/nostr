/**
 * NIP-49 private key encryption (ncryptsec). Used for encrypted backups and local key storage:
 * scrypt(password, salt, 2^logN, r=8, p=1) -> XChaCha20-Poly1305.
 */
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { scrypt, scryptAsync } from '@noble/hashes/scrypt';
import { bech32 } from '@scure/base';
import { concatBytes, randomBytes } from './utils';

export type KeySecurity = 0x00 | 0x01 | 0x02;
/** 0x00: key known to have been handled insecurely; 0x01: not known; 0x02: unknown/not tracked. */
export const KEY_SECURITY = { INSECURE: 0x00, SECURE: 0x01, UNKNOWN: 0x02 } as const;

const VERSION = 0x02;
const LIMIT = 5000;

function passwordBytes(password: string): Uint8Array {
  return new TextEncoder().encode(password.normalize('NFKC'));
}

function assemble(logn: number, salt: Uint8Array, nonce: Uint8Array, ksb: number, ct: Uint8Array): string {
  const bytes = concatBytes(new Uint8Array([VERSION, logn]), salt, nonce, new Uint8Array([ksb]), ct);
  return bech32.encode('ncryptsec', bech32.toWords(bytes), LIMIT);
}

export function encryptKey(secretKey: Uint8Array, password: string, logn = 16, keySecurity: KeySecurity = 0x02): string {
  if (secretKey.length !== 32) throw new Error('secret key must be 32 bytes');
  const salt = randomBytes(16);
  const nonce = randomBytes(24);
  const key = scrypt(passwordBytes(password), salt, { N: 2 ** logn, r: 8, p: 1, dkLen: 32 });
  const ct = xchacha20poly1305(key, nonce, new Uint8Array([keySecurity])).encrypt(secretKey);
  return assemble(logn, salt, nonce, keySecurity, ct);
}

export async function encryptKeyAsync(secretKey: Uint8Array, password: string, logn = 16, keySecurity: KeySecurity = 0x02): Promise<string> {
  if (secretKey.length !== 32) throw new Error('secret key must be 32 bytes');
  const salt = randomBytes(16);
  const nonce = randomBytes(24);
  const key = await scryptAsync(passwordBytes(password), salt, { N: 2 ** logn, r: 8, p: 1, dkLen: 32 });
  const ct = xchacha20poly1305(key, nonce, new Uint8Array([keySecurity])).encrypt(secretKey);
  return assemble(logn, salt, nonce, keySecurity, ct);
}

function parse(ncryptsec: string) {
  const { prefix, words } = bech32.decode(ncryptsec as `${string}1${string}`, LIMIT);
  if (prefix !== 'ncryptsec') throw new Error('not an ncryptsec');
  const b = new Uint8Array(bech32.fromWords(words));
  if (b.length !== 91) throw new Error('invalid ncryptsec length');
  if (b[0] !== VERSION) throw new Error('unsupported ncryptsec version');
  return { logn: b[1]!, salt: b.slice(2, 18), nonce: b.slice(18, 42), ksb: b[42]!, ct: b.slice(43) };
}

export interface DecryptOptions {
  /**
   * Reject payloads whose scrypt cost exceeds 2^maxLogN before running scrypt. logN is chosen by whoever
   * produced the ncryptsec, so services decrypting untrusted input must cap it (memory ~ 2^logN KiB).
   */
  maxLogN?: number;
}

/** scrypt cost parameter (log2 N) declared by an ncryptsec, without decrypting it. */
export function ncryptsecLogN(ncryptsec: string): number {
  return parse(ncryptsec).logn;
}

function parseCapped(ncryptsec: string, opts: DecryptOptions) {
  const p = parse(ncryptsec);
  if (opts.maxLogN !== undefined && p.logn > opts.maxLogN) throw new Error(`ncryptsec logN ${p.logn} exceeds the allowed maximum ${opts.maxLogN}`);
  return p;
}

export function decryptKey(ncryptsec: string, password: string, opts: DecryptOptions = {}): { secretKey: Uint8Array; keySecurity: number; logn: number } {
  const { logn, salt, nonce, ksb, ct } = parseCapped(ncryptsec, opts);
  const key = scrypt(passwordBytes(password), salt, { N: 2 ** logn, r: 8, p: 1, dkLen: 32 });
  const secretKey = xchacha20poly1305(key, nonce, new Uint8Array([ksb])).decrypt(ct);
  return { secretKey, keySecurity: ksb, logn };
}

export async function decryptKeyAsync(ncryptsec: string, password: string, opts: DecryptOptions = {}) {
  const { logn, salt, nonce, ksb, ct } = parseCapped(ncryptsec, opts);
  const key = await scryptAsync(passwordBytes(password), salt, { N: 2 ** logn, r: 8, p: 1, dkLen: 32 });
  const secretKey = xchacha20poly1305(key, nonce, new Uint8Array([ksb])).decrypt(ct);
  return { secretKey, keySecurity: ksb, logn };
}
