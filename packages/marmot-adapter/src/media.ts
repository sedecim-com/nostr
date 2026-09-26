/**
 * MIP-04 (encrypted media in groups), version `mip04-v2` as implemented by the pinned marmot-ts 0.5.1:
 *
 *   media_secret = MLS-Exporter("marmot", "encrypted-media", 32)            (epoch of the carrying message)
 *   file_key     = HKDF-Expand-SHA256(media_secret, "mip04-v2" || 0x00 || sha256(plaintext) || 0x00 ||
 *                                     mime || 0x00 || filename || 0x00 || "key", 32)
 *   ciphertext   = ChaCha20-Poly1305(file_key, nonce(12, random), aad = "mip04-v2" || 0x00 || sha256 ||
 *                                     0x00 || mime || 0x00 || filename)
 *
 * AEAD, AAD and `imeta` parsing are marmot-ts' own helpers; this module adds what marmot-ts leaves to the
 * caller: deriving the key from a *stored* per-epoch media secret (receivers must use the sending epoch,
 * not their current one) and serialising the `imeta` tag.
 */
import { expand } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { MIP04_VERSION, canonicalizeMimeType, decryptMediaFile, encryptMediaFile, getMediaAttachments, parseMediaImetaTag } from '@internet-privacy/marmot-ts';
import { mlsExporter, type ClientState } from 'ts-mls';
import type { GroupMediaAttachment } from './types';

export { MIP04_VERSION };
export const MIP04_EXPORTER_LABEL = 'marmot';
export const MIP04_EXPORTER_CONTEXT = 'encrypted-media';
/** Past-epoch media secrets kept per group (MIP-04: "retain recent epoch media secrets"). */
export const MEDIA_SECRET_RETENTION_EPOCHS = 128;

const enc = new TextEncoder();
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
function unhex(h: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/i.test(h)) throw new Error('invalid hex');
  return Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
}

/** MLS-Exporter("marmot", "encrypted-media", 32) of a group state (the epoch's media secret). */
export function exportMediaSecret(state: ClientState, ciphersuite: unknown): Promise<Uint8Array> {
  return mlsExporter(state.keySchedule.exporterSecret, MIP04_EXPORTER_LABEL, enc.encode(MIP04_EXPORTER_CONTEXT), 32, ciphersuite as never);
}

/** MIP-04 v2 per-file key from an epoch media secret. Equals marmot-ts `deriveMediaEncryptionKey` for that epoch. */
export function deriveMediaFileKey(mediaSecret: Uint8Array, attachment: Pick<GroupMediaAttachment, 'sha256' | 'type' | 'filename'>): Uint8Array {
  if (mediaSecret.length !== 32) throw new Error('media secret must be 32 bytes');
  const sep = new Uint8Array([0]);
  const parts = [enc.encode(MIP04_VERSION), sep, unhex(attachment.sha256), sep, enc.encode(canonicalizeMimeType(attachment.type)), sep, enc.encode(attachment.filename), sep, enc.encode('key')];
  const info = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    info.set(p, o);
    o += p.length;
  }
  return expand(sha256, mediaSecret, info, 32);
}

/** Encrypts `data` with a media secret; returns the ciphertext and the attachment (without `url`). */
export function encryptGroupMedia(mediaSecret: Uint8Array, data: Uint8Array, meta: { filename: string; type: string; alt?: string; dimensions?: string }): { ciphertext: Uint8Array; ciphertextSha256: string; attachment: GroupMediaAttachment } {
  validateFilename(meta.filename);
  const skeleton = { sha256: hex(sha256(data)), type: canonicalizeMimeType(meta.type), filename: meta.filename, size: data.length };
  if (!/^[^/\s]+\/[^/\s]+$/.test(skeleton.type)) throw new Error(`invalid MIME type: ${meta.type}`);
  const { encrypted, attachment } = encryptMediaFile(data, deriveMediaFileKey(mediaSecret, skeleton), skeleton);
  const out: GroupMediaAttachment = { sha256: attachment.sha256, type: attachment.type, filename: attachment.filename, nonce: attachment.nonce, version: attachment.version, size: data.length };
  if (meta.alt) out.alt = meta.alt;
  if (meta.dimensions) out.dimensions = meta.dimensions;
  return { ciphertext: encrypted, ciphertextSha256: hex(sha256(encrypted)), attachment: out };
}

/** Decrypts and verifies (AEAD tag + plaintext SHA-256) a MIP-04 attachment. */
export function decryptGroupMedia(mediaSecret: Uint8Array, ciphertext: Uint8Array, attachment: GroupMediaAttachment): Uint8Array {
  if (attachment.version !== MIP04_VERSION) throw new Error(`unsupported MIP-04 version: ${attachment.version}`);
  return decryptMediaFile(ciphertext, deriveMediaFileKey(mediaSecret, attachment), attachment as never);
}

function validateFilename(name: string) {
  const bytes = enc.encode(name).length;
  // Spaces would break the NIP-92 "key value" entry split only before the value; newlines/NUL never allowed.
  if (bytes === 0 || bytes > 255 || /[\u0000\r\n]/.test(name)) throw new Error('filename must be 1-255 bytes without NUL or newlines');
}

/** NIP-92 `imeta` tag with the MIP-04 fields (`url m x filename n v size …`). */
export function buildMediaImetaTag(a: GroupMediaAttachment & { url: string }): string[] {
  const tag = ['imeta', `url ${a.url}`, `m ${a.type}`, `x ${a.sha256}`, `filename ${a.filename}`, `n ${a.nonce}`, `v ${a.version}`];
  if (a.size !== undefined) tag.push(`size ${a.size}`);
  if (a.dimensions) tag.push(`dim ${a.dimensions}`);
  if (a.blurhash) tag.push(`blurhash ${a.blurhash}`);
  if (a.alt) tag.push(`alt ${a.alt}`);
  return tag;
}

/** Valid MIP-04 v2 attachments of a tag list (invalid or `mip04-v1` tags are ignored, as MIP-04 requires). */
export function parseMediaAttachments(tags: string[][]): GroupMediaAttachment[] {
  return getMediaAttachments(tags).map(toAttachment);
}

export function parseMediaImeta(tag: string[]): GroupMediaAttachment | undefined {
  const a = parseMediaImetaTag(tag);
  return a ? toAttachment(a) : undefined;
}

function toAttachment(a: NonNullable<ReturnType<typeof parseMediaImetaTag>>): GroupMediaAttachment {
  const out: GroupMediaAttachment = { sha256: a.sha256, type: a.type, filename: a.filename, nonce: a.nonce, version: a.version };
  if (a.url) out.url = a.url;
  if (a.size !== undefined) out.size = a.size;
  if (a.dimensions) out.dimensions = a.dimensions;
  if (a.blurhash) out.blurhash = a.blurhash;
  if (a.alt) out.alt = a.alt;
  return out;
}

/** Blossom locators are `server/<sha256 of the stored blob>[.ext]` (BUD-01): the ciphertext hash. */
export function ciphertextHashFromUrl(url: string): string | undefined {
  const last = new URL(url).pathname.split('/').pop() ?? '';
  const m = /^([0-9a-f]{64})(?:\.[a-z0-9]+)?$/i.exec(last);
  return m ? m[1]!.toLowerCase() : undefined;
}
