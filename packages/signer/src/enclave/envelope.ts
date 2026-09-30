import { bytesToHex, sha256 } from '@sedecim/nostr-core';

/**
 * FR005-10: secrets sealed to the enclave. The managed-signer (the parent of the Nitro Enclave) must not see what a
 * client imports (ncryptsec and its password) nor the password of an export (with it it would open the ncryptsec it
 * relays). The client encrypts them to the enclave's RSA key, which it takes from an attestation document it verified
 * itself (verifyNitroAttestation), and the parent only relays an opaque string:
 *
 *   ae1.<ek>.<iv>.<ct>                          base64url without padding, at most MAX_ENVELOPE_CHARS
 *   ek  RSA-OAEP (SHA-256, MGF1-SHA-256) of a random AES-256 key, to the attested SPKI (RSA ≥ 2048)
 *   iv  12 random bytes
 *   ct  AES-256-GCM of the JSON content, 16-byte tag at the end, with
 *   AAD `acceso-nostr/enclave-envelope/v1|<purpose>|<owner_tag>|<pubkey or empty>`
 *
 * Content: import `{ncryptsec, password, at}`, export `{password, at}`; `at` is the `timestamp` (ms) of the attestation
 * document the client verified, which the enclave holds against its own clock (the NSM's). This module is shared by the
 * client (sealing, WebCrypto) and the enclave (parsing and checking; it opens with node:crypto). No node:* here.
 */

export type EnvelopePurpose = 'import' | 'export';
export const ENVELOPE_VERSION = 'ae1';
/** Checked before anything is decrypted. */
export const MAX_ENVELOPE_CHARS = 4096;
/** How old `at` may be by the enclave's clock, and how far ahead of it (clock skew). */
export const ENVELOPE_MAX_AGE_MS = 5 * 60_000;
export const ENVELOPE_MAX_SKEW_MS = 60_000;

export class EnvelopeError extends Error {}

/**
 * What binds a sealed key, and a sealed secret, to its owner (`<issuer>#<sub>` of the Acceso token, as the
 * managed-signer names the owner): a SHA-256 with a domain label. The enclave seals it into every key (FR005-09).
 */
export const ownerTag = (owner: string): string => bytesToHex(sha256(new TextEncoder().encode(`acceso-nostr/owner/v1|${owner}`)));

const HEX64 = /^[0-9a-f]{64}$/;

/** The additional data both sides authenticate: a sealed secret opens only for its purpose, owner and key. */
export function envelopeAad(purpose: EnvelopePurpose, ownerTagHex: string, pubkey = ''): Uint8Array<ArrayBuffer> {
  if (purpose !== 'import' && purpose !== 'export') throw new EnvelopeError('unknown purpose');
  if (!HEX64.test(ownerTagHex)) throw new EnvelopeError('owner tag must be 64 hex characters');
  if (pubkey !== '' && !HEX64.test(pubkey)) throw new EnvelopeError('pubkey must be 64 hex characters');
  return new TextEncoder().encode(`acceso-nostr/enclave-envelope/v1|${purpose}|${ownerTagHex}|${pubkey}`);
}

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function toBase64Url(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    const chars = Math.min(4, Math.ceil(((bytes.length - i) * 8) / 6));
    for (let j = 0; j < chars; j++) out += ALPHABET[(n >> (18 - 6 * j)) & 63];
  }
  return out;
}

/** Strict: the URL alphabet, no padding, and the canonical encoding only (unused trailing bits zero). */
export function fromBase64Url(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new EnvelopeError('invalid base64url');
  const out = new Uint8Array(Math.floor((s.length * 6) / 8));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const c of s) {
    acc = ((acc << 6) | ALPHABET.indexOf(c)) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  if (acc & ((1 << bits) - 1)) throw new EnvelopeError('invalid base64url');
  return out;
}

export interface EnvelopeParts {
  ek: Uint8Array;
  iv: Uint8Array;
  /** Ciphertext with the GCM tag in its last 16 bytes. */
  ct: Uint8Array;
}

/** Splits a sealed secret into its parts, or says why it is not one; the size is checked first. */
export function parseEnvelope(envelope: unknown): EnvelopeParts {
  if (typeof envelope !== 'string') throw new EnvelopeError('must be a string');
  if (envelope.length > MAX_ENVELOPE_CHARS) throw new EnvelopeError(`longer than ${MAX_ENVELOPE_CHARS} characters`);
  const parts = envelope.split('.');
  if (parts.length !== 4 || parts[0] !== ENVELOPE_VERSION) throw new EnvelopeError(`not an ${ENVELOPE_VERSION} envelope`);
  const [ek, iv, ct] = parts.slice(1).map(fromBase64Url) as [Uint8Array, Uint8Array, Uint8Array];
  if (ek.length === 0 || ek.length > 1024 || iv.length !== 12 || ct.length < 17) throw new EnvelopeError('wrong part sizes');
  return { ek, iv, ct };
}

export interface ImportSecrets {
  ncryptsec: string;
  password: string;
  at: number;
}
export interface ExportSecret {
  password: string;
  at: number;
}

/** The JSON content of an opened envelope: exactly the fields of its purpose, of the right types. */
export function parseEnvelopeContent(purpose: 'import', plain: Uint8Array): ImportSecrets;
export function parseEnvelopeContent(purpose: 'export', plain: Uint8Array): ExportSecret;
export function parseEnvelopeContent(purpose: EnvelopePurpose, plain: Uint8Array): ImportSecrets | ExportSecret;
export function parseEnvelopeContent(purpose: EnvelopePurpose, plain: Uint8Array): ImportSecrets | ExportSecret {
  let v: unknown;
  try {
    v = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plain));
  } catch {
    throw new EnvelopeError('content is not JSON');
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new EnvelopeError('content is not an object');
  const c = v as Record<string, unknown>;
  const want = purpose === 'import' ? 'at,ncryptsec,password' : 'at,password';
  if (Object.keys(c).sort().join(',') !== want) throw new EnvelopeError(`content must hold exactly ${want}`);
  if (!Number.isSafeInteger(c.at) || (c.at as number) <= 0) throw new EnvelopeError('at must be a timestamp in ms');
  if (typeof c.password !== 'string') throw new EnvelopeError('password must be a string');
  if (purpose === 'import' && typeof c.ncryptsec !== 'string') throw new EnvelopeError('ncryptsec must be a string');
  return c as unknown as ImportSecrets | ExportSecret;
}

/** The enclave's check of `at` against its own clock: a captured envelope is not replayed later. */
export function checkEnvelopeFreshness(at: number, nowMs: number): void {
  if (at > nowMs + ENVELOPE_MAX_SKEW_MS) throw new EnvelopeError('sealed for an attestation from the future');
  if (nowMs - at > ENVELOPE_MAX_AGE_MS) throw new EnvelopeError(`sealed for an attestation older than ${ENVELOPE_MAX_AGE_MS / 1000} s: fetch a new one`);
}

export type EnvelopeRequest =
  | { purpose: 'import'; ownerTag: string; at: number; ncryptsec: string; password: string }
  | { purpose: 'export'; ownerTag: string; pubkey: string; at: number; password: string };

/**
 * Seals a secret to the enclave's RSA key (`spki`, DER), which must come from an attestation document the caller
 * verified. WebCrypto: the browser's, or Node's (≥ 20). Returns the envelope to send instead of the secret.
 */
export async function sealToEnclave(spki: Uint8Array, req: EnvelopeRequest): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new EnvelopeError('sealing to the enclave needs WebCrypto (crypto.subtle)');
  if (!Number.isSafeInteger(req.at) || req.at <= 0) throw new EnvelopeError('at must be the timestamp (ms) of the verified attestation');
  const aad = envelopeAad(req.purpose, req.ownerTag, req.purpose === 'export' ? req.pubkey : '');
  const content = req.purpose === 'import' ? { ncryptsec: req.ncryptsec, password: req.password, at: req.at } : { password: req.password, at: req.at };
  const rsa = await subtle.importKey('spki', spki.slice(), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  if ((rsa.algorithm as RsaHashedKeyAlgorithm).modulusLength < 2048) throw new EnvelopeError('the enclave key must be RSA of at least 2048 bits');
  const raw = crypto.getRandomValues(new Uint8Array(32));
  const plain = new TextEncoder().encode(JSON.stringify(content));
  try {
    const aes = await subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, aes, plain));
    const ek = new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, rsa, raw));
    const envelope = `${ENVELOPE_VERSION}.${toBase64Url(ek)}.${toBase64Url(iv)}.${toBase64Url(ct)}`;
    if (envelope.length > MAX_ENVELOPE_CHARS) throw new EnvelopeError(`the secret is too large to seal (the envelope would exceed ${MAX_ENVELOPE_CHARS} characters)`);
    return envelope;
  } finally {
    raw.fill(0);
    plain.fill(0);
  }
}
