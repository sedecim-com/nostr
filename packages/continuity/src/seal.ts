/**
 * VAULT-02: archives are sealed on the client with an ARCHIVE KEY that is not the nsec (ADR 0011).
 *
 * The archive key is 32 random bytes per persona. It travels inside the identity backup (encrypted with the
 * backup password), never in clear and never to the vault. Three independent keys are derived from it with
 * HKDF-SHA256, so no key is used for two purposes:
 * - `seal`: XChaCha20-Poly1305 key of the envelopes;
 * - `id`: HMAC key that turns a label ("ledger", "event:<id>"…) into an opaque archive id;
 * - `auth`: secp256k1 key that signs NIP-98 requests to the vault. The vault account is therefore unlinkable
 *   to the persona's pubkey, and a remote signer (NIP-46, managed) is never asked to sign vault requests.
 */
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64 } from '@scure/base';
import { bytesToHex, bytesToUtf8, concatBytes, equalBytes, getPublicKey, isValidSecretKey, randomBytes, utf8ToBytes } from '@sedecim/nostr-core';
import { ARCHIVE_FORMAT, ARCHIVE_LENGTH_BYTES, ARCHIVE_NONCE_BYTES, ARCHIVE_VERSION, ArchiveEnvelopeError, isArchiveId, paddedLength, parseArchiveEnvelope, type ArchiveEnvelope } from './envelope';

export const ARCHIVE_KEY_BYTES = 32;
const SALT = utf8ToBytes('sedecim-archive-v1');

export function assertArchiveKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.length !== ARCHIVE_KEY_BYTES) throw new TypeError('archive key must be 32 bytes');
}

function derive(key: Uint8Array, info: string, length = 32): Uint8Array {
  assertArchiveKey(key);
  return hkdf(sha256, key, SALT, utf8ToBytes(info), length);
}

/** A fresh archive key: 32 random bytes, independent of every persona key. */
export function generateArchiveKey(): Uint8Array {
  return randomBytes(ARCHIVE_KEY_BYTES);
}

/** An archive key must never be a persona's secret key (e.g. when importing one from a backup). */
export function assertDistinctFromNsec(key: Uint8Array, secretKey: Uint8Array): void {
  assertArchiveKey(key);
  if (equalBytes(key, secretKey)) throw new Error('the archive key must not be the nsec');
}

/** Fingerprint of the archive key (16 hex), written in clear in every envelope it seals. */
export function archiveKeyId(key: Uint8Array): string {
  return bytesToHex(derive(key, 'key-id', 8));
}

/** Opaque archive id for a label: the vault sees neither the label nor, for events, the event id. */
export function archiveId(key: Uint8Array, label: string): string {
  const k = derive(key, 'id');
  try {
    return bytesToHex(hmac(sha256, k, utf8ToBytes(label)));
  } finally {
    k.fill(0);
  }
}

/** Secret key that signs NIP-98 requests to the vault (the vault account), derived from the archive key. */
export function archiveAuthKey(key: Uint8Array): Uint8Array {
  for (let i = 0; ; i++) {
    const sk = derive(key, i === 0 ? 'auth' : `auth/${i}`);
    if (isValidSecretKey(sk)) return sk;
  }
}

/** The vault account of an archive key: `nostr:<this pubkey>` on the server. */
export function archiveOwnerPubkey(key: Uint8Array): string {
  const sk = archiveAuthKey(key);
  try {
    return getPublicKey(sk);
  } finally {
    sk.fill(0);
  }
}

// The AAD binds the envelope to its key and to the id it is stored under: the vault cannot serve one
// archive in place of another.
const aad = (keyId: string, id: string) => utf8ToBytes(`${ARCHIVE_FORMAT}:${ARCHIVE_VERSION}:${keyId}:${id}`);

/** Seals `plaintext` for archive `id`: framed with its length, padded, XChaCha20-Poly1305 with a random nonce. */
export function sealArchive(key: Uint8Array, id: string, plaintext: Uint8Array | string): ArchiveEnvelope {
  if (!isArchiveId(id)) throw new ArchiveEnvelopeError('archive id must be 64 hex characters');
  const data = typeof plaintext === 'string' ? utf8ToBytes(plaintext) : plaintext;
  const framed = new Uint8Array(ARCHIVE_LENGTH_BYTES + paddedLength(data.length));
  new DataView(framed.buffer).setUint32(0, data.length);
  framed.set(data, ARCHIVE_LENGTH_BYTES);
  const keyId = archiveKeyId(key);
  const nonce = randomBytes(ARCHIVE_NONCE_BYTES);
  const k = derive(key, 'seal');
  try {
    const sealed = xchacha20poly1305(k, nonce, aad(keyId, id)).encrypt(framed);
    return { format: ARCHIVE_FORMAT, version: ARCHIVE_VERSION, key_id: keyId, sealed: base64.encode(concatBytes(nonce, sealed)) };
  } finally {
    k.fill(0);
    framed.fill(0);
  }
}

export class ArchiveKeyMismatchError extends Error {
  constructor() {
    super('archive was sealed with a different archive key');
    this.name = 'ArchiveKeyMismatchError';
  }
}

/** Opens the envelope stored under `id`. Throws if it was sealed with another key, for another id, or altered. */
export function openArchive(key: Uint8Array, id: string, envelope: string | ArchiveEnvelope): Uint8Array {
  if (!isArchiveId(id)) throw new ArchiveEnvelopeError('archive id must be 64 hex characters');
  const { envelope: env, sealed } = parseArchiveEnvelope(typeof envelope === 'string' ? envelope : JSON.stringify(envelope), Infinity);
  const keyId = archiveKeyId(key);
  if (env.key_id !== keyId) throw new ArchiveKeyMismatchError();
  const k = derive(key, 'seal');
  let framed: Uint8Array;
  try {
    framed = xchacha20poly1305(k, sealed.subarray(0, ARCHIVE_NONCE_BYTES), aad(keyId, id)).decrypt(sealed.subarray(ARCHIVE_NONCE_BYTES));
  } catch {
    throw new ArchiveEnvelopeError('archive does not authenticate (wrong id, or altered)');
  } finally {
    k.fill(0);
  }
  try {
    const n = new DataView(framed.buffer, framed.byteOffset, framed.byteLength).getUint32(0);
    const padded = framed.length - ARCHIVE_LENGTH_BYTES;
    if (n > padded || paddedLength(n) !== padded) throw new ArchiveEnvelopeError('archive padding is invalid');
    return framed.slice(ARCHIVE_LENGTH_BYTES, ARCHIVE_LENGTH_BYTES + n);
  } finally {
    framed.fill(0);
  }
}

export const openArchiveText = (key: Uint8Array, id: string, envelope: string | ArchiveEnvelope): string => bytesToUtf8(openArchive(key, id, envelope));
