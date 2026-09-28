/**
 * VAULT-01/02: the archive envelope, the only thing the Continuity Vault ever stores (ADR 0011).
 *
 * `{ "format": "sedecim-archive-envelope", "version": 1, "key_id": <16 hex>, "sealed": <base64> }`
 *
 * `sealed` = nonce (24) ‖ XChaCha20-Poly1305(u32 length ‖ plaintext ‖ zero padding) with its tag (16). The
 * padding hides the exact size (NIP-44's scheme with a 256-byte floor) and the AAD binds the envelope to
 * its key and to the archive id it is stored under (see seal.ts).
 *
 * `validateArchiveEnvelope` is shared by client and server, like the backup vault's validator (FR027-03):
 * exact field allowlist, no plaintext keys in the text, and a ciphertext that is neither readable text nor
 * unpadded. The server cannot prove that bytes are ciphertext; this rejects the likely client bugs
 * (plaintext, base64 of plaintext, a forgotten seal). Browser-safe: no Node APIs.
 */
import { base64 } from '@scure/base';

export const ARCHIVE_FORMAT = 'sedecim-archive-envelope';
export const ARCHIVE_VERSION = 1;
/** Default cap on one stored envelope (text bytes). */
export const MAX_ARCHIVE_ENVELOPE_BYTES = 1024 * 1024;
export const ARCHIVE_NONCE_BYTES = 24;
export const ARCHIVE_TAG_BYTES = 16;
/** Length prefix of the framed plaintext (u32, big endian). */
export const ARCHIVE_LENGTH_BYTES = 4;
/** Smallest padded plaintext: short messages all look the same size. */
export const ARCHIVE_MIN_PADDED = 256;
const MIN_SEALED = ARCHIVE_NONCE_BYTES + ARCHIVE_LENGTH_BYTES + ARCHIVE_MIN_PADDED + ARCHIVE_TAG_BYTES;

export interface ArchiveEnvelope {
  format: typeof ARCHIVE_FORMAT;
  version: typeof ARCHIVE_VERSION;
  /** Fingerprint of the archive key that sealed it (not secret). */
  key_id: string;
  sealed: string;
}

/** Metadata the vault keeps and returns for an archive; it never includes the content. */
export interface ArchiveMeta {
  id: string;
  key_id: string;
  /** Size of the stored envelope text in bytes. */
  size: number;
  /** sha256 (hex) of the stored envelope text. */
  sha256: string;
  created_at: string;
  updated_at: string;
}

export class ArchiveEnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ArchiveEnvelopeError';
  }
}

/** Archive ids are opaque to the vault: 32 bytes in hex, e.g. an HMAC of a label under the archive key. */
export const isArchiveId = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
export const isArchiveKeyId = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{16}$/.test(v);

/** Padded plaintext length: NIP-44's padding (under 25 % overhead above the floor), with a 256-byte floor. */
export function paddedLength(n: number): number {
  if (!Number.isInteger(n) || n < 0) throw new RangeError('invalid plaintext length');
  if (n <= ARCHIVE_MIN_PADDED) return ARCHIVE_MIN_PADDED;
  let next = ARCHIVE_MIN_PADDED;
  while (next < n) next *= 2;
  const chunk = next / 8;
  return chunk * (Math.floor((n - 1) / chunk) + 1);
}

const FIELDS = ['format', 'version', 'key_id', 'sealed'];
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
// Defense in depth over the raw text, as in the backup vault: a bech32 nsec or a run of 64 hex digits
// never belongs in an envelope (random base64 matches either with probability below 1e-24).
const NSEC = /nsec1[023456789acdefghjklmnpqrstuvwxyz]{58}/i;
const HEX64 = /[0-9a-f]{64}/i;

/**
 * Readable text instead of ciphertext: mostly printable ASCII, or valid UTF-8 as a whole. Random bytes of
 * this size (at least 276) pass either test with probability below 1e-30.
 */
function looksLikeText(b: Uint8Array): boolean {
  let printable = 0;
  for (const x of b) if ((x >= 0x20 && x < 0x7f) || x === 0x09 || x === 0x0a || x === 0x0d) printable++;
  if (printable / b.length >= 0.75) return true;
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(b);
    return true;
  } catch {
    return false;
  }
}

/**
 * Checks that `text` is a well-formed sealed archive envelope (without decrypting it) and returns it with
 * its size and the decoded `sealed` bytes. Throws ArchiveEnvelopeError with a reason that never echoes the
 * content.
 */
export function parseArchiveEnvelope(text: string, maxBytes = MAX_ARCHIVE_ENVELOPE_BYTES): { envelope: ArchiveEnvelope; size: number; sealed: Uint8Array } {
  if (typeof text !== 'string') throw new ArchiveEnvelopeError('archive must be JSON text');
  const size = new TextEncoder().encode(text).length;
  if (size > maxBytes) throw new ArchiveEnvelopeError(`archive too large (${size} > ${maxBytes} bytes)`);
  if (NSEC.test(text)) throw new ArchiveEnvelopeError('archive contains a plaintext nsec');
  if (HEX64.test(text)) throw new ArchiveEnvelopeError('archive contains a 32-byte hex value (possible plaintext key or event id)');
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw new ArchiveEnvelopeError('archive is not valid JSON');
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new ArchiveEnvelopeError('archive must be a JSON object');
  const o = v as Record<string, unknown>;
  if (o.format !== ARCHIVE_FORMAT) throw new ArchiveEnvelopeError('unsupported archive format (only sealed archive envelopes are accepted)');
  if (o.version !== ARCHIVE_VERSION) throw new ArchiveEnvelopeError('unsupported archive envelope version');
  for (const k of Object.keys(o)) if (!FIELDS.includes(k)) throw new ArchiveEnvelopeError(`field "${k}" not allowed in an archive envelope`);
  if (!isArchiveKeyId(o.key_id)) throw new ArchiveEnvelopeError('key_id must be 16 hex characters');
  if (typeof o.sealed !== 'string' || !BASE64.test(o.sealed)) throw new ArchiveEnvelopeError('sealed is not base64');
  let sealed: Uint8Array;
  try {
    sealed = base64.decode(o.sealed);
  } catch {
    throw new ArchiveEnvelopeError('sealed is not base64');
  }
  if (sealed.length < MIN_SEALED) throw new ArchiveEnvelopeError('sealed is too short to be a padded XChaCha20-Poly1305 payload');
  const framed = sealed.length - ARCHIVE_NONCE_BYTES - ARCHIVE_TAG_BYTES - ARCHIVE_LENGTH_BYTES;
  if (paddedLength(framed) !== framed) throw new ArchiveEnvelopeError('sealed payload is not padded (v1 pads every archive to hide its size)');
  if (looksLikeText(sealed.subarray(ARCHIVE_NONCE_BYTES))) throw new ArchiveEnvelopeError('sealed looks like encoded plaintext, not ciphertext');
  return { envelope: { format: ARCHIVE_FORMAT, version: ARCHIVE_VERSION, key_id: o.key_id, sealed: o.sealed }, size, sealed };
}

/** Validation only: key id and size of a well-formed envelope. */
export function validateArchiveEnvelope(text: string, maxBytes = MAX_ARCHIVE_ENVELOPE_BYTES): { keyId: string; size: number } {
  const { envelope, size } = parseArchiveEnvelope(text, maxBytes);
  return { keyId: envelope.key_id, size };
}
