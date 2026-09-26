/**
 * Metadata sanitizer (spec §13.1): strips EXIF/XMP/IPTC/comments from JPEG, text/time/EXIF chunks
 * from PNG and EXIF/XMP/ICC chunks from WebP before a file leaves the device. HEIC/HEIF/AVIF (ISO
 * BMFF) and unknown formats are reported as unsanitized so policy can decide (requireSanitizable).
 */
export interface SanitizeResult {
  data: Uint8Array;
  format: 'jpeg' | 'png' | 'webp' | 'heif' | 'unknown';
  removed: string[];
  /** true when the format is not understood and metadata could remain */
  unsanitized: boolean;
  /** Why the file could not be sanitized (shown to the user when the upload is refused). */
  reason?: string;
}

function isJpeg(d: Uint8Array) {
  return d[0] === 0xff && d[1] === 0xd8;
}
const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
function isPng(d: Uint8Array) {
  return PNG_SIG.every((b, i) => d[i] === b);
}

function sanitizeJpeg(d: Uint8Array): SanitizeResult {
  const out: number[] = [0xff, 0xd8];
  const removed: string[] = [];
  let i = 2;
  while (i < d.length) {
    if (d[i] !== 0xff) throw new Error('malformed JPEG');
    const marker = d[i + 1]!;
    if (marker === 0xd9) {
      out.push(0xff, 0xd9);
      break;
    }
    if (marker === 0xda) {
      // start of scan: copy the rest verbatim (entropy-coded data)
      for (let j = i; j < d.length; j++) out.push(d[j]!);
      break;
    }
    if (marker >= 0xd0 && marker <= 0xd7) {
      out.push(0xff, marker);
      i += 2;
      continue;
    }
    const len = (d[i + 2]! << 8) | d[i + 3]!;
    const seg = d.subarray(i, i + 2 + len);
    const isApp1 = marker === 0xe1;
    const drop = isApp1 || marker === 0xed || marker === 0xfe || (marker >= 0xe2 && marker <= 0xef && marker !== 0xee);
    if (drop) removed.push(isApp1 ? 'APP1 (EXIF/XMP)' : marker === 0xed ? 'APP13 (IPTC)' : marker === 0xfe ? 'COM' : `APP${marker - 0xe0}`);
    else for (const b of seg) out.push(b);
    i += 2 + len;
  }
  return { data: new Uint8Array(out), format: 'jpeg', removed, unsanitized: false };
}

const PNG_DROP = new Set(['eXIf', 'tEXt', 'zTXt', 'iTXt', 'tIME']);

function sanitizePng(d: Uint8Array): SanitizeResult {
  const parts: Uint8Array[] = [d.subarray(0, 8)];
  const removed: string[] = [];
  let i = 8;
  while (i < d.length) {
    const len = ((d[i]! << 24) | (d[i + 1]! << 16) | (d[i + 2]! << 8) | d[i + 3]!) >>> 0;
    const type = String.fromCharCode(d[i + 4]!, d[i + 5]!, d[i + 6]!, d[i + 7]!);
    const total = 12 + len;
    if (PNG_DROP.has(type)) removed.push(type);
    else parts.push(d.subarray(i, i + total));
    i += total;
    if (type === 'IEND') break;
  }
  const size = parts.reduce((a, p) => a + p.length, 0);
  const data = new Uint8Array(size);
  let o = 0;
  for (const p of parts) {
    data.set(p, o);
    o += p.length;
  }
  return { data, format: 'png', removed, unsanitized: false };
}

const ascii = (d: Uint8Array, at: number, len = 4) => String.fromCharCode(...d.subarray(at, at + len));
const u32le = (d: Uint8Array, at: number) => (d[at]! | (d[at + 1]! << 8) | (d[at + 2]! << 16) | (d[at + 3]! << 24)) >>> 0;

function isWebp(d: Uint8Array) {
  return d.length >= 12 && ascii(d, 0) === 'RIFF' && ascii(d, 8) === 'WEBP';
}

/** WebP metadata chunks and the VP8X flag bit that announces each one. */
const WEBP_DROP: Record<string, { flag: number; label: string }> = {
  EXIF: { flag: 0x08, label: 'EXIF' },
  'XMP ': { flag: 0x04, label: 'XMP' },
  ICCP: { flag: 0x20, label: 'ICCP (ICC profile)' },
};

/**
 * WebP (RIFF): drop EXIF, XMP and ICCP chunks, clear their bits in the VP8X header flags and rewrite
 * the RIFF size. Chunk payloads are padded to an even length (RIFF rule).
 */
function sanitizeWebp(d: Uint8Array): SanitizeResult {
  const riffSize = u32le(d, 4);
  if (riffSize + 8 > d.length || riffSize < 4) throw new Error('malformed WebP: RIFF size exceeds file');
  const end = 8 + riffSize;
  const parts: Uint8Array[] = [];
  const removed: string[] = [];
  let vp8x: Uint8Array | undefined;
  let i = 12;
  while (i < end) {
    if (i + 8 > end) throw new Error('malformed WebP: truncated chunk header');
    const type = ascii(d, i);
    const size = u32le(d, i + 4);
    const total = 8 + size + (size & 1);
    if (i + 8 + size > end) throw new Error(`malformed WebP: chunk ${type} exceeds file`);
    const chunk = d.slice(i, Math.min(i + total, end));
    const drop = WEBP_DROP[type];
    if (drop) removed.push(drop.label);
    else {
      if (type === 'VP8X') vp8x = chunk;
      parts.push(chunk);
    }
    i += total;
  }
  if (vp8x) {
    if (vp8x.length < 18) throw new Error('malformed WebP: short VP8X chunk');
    // Clear the ICC/EXIF/XMP flags unconditionally: stale bits would point to chunks that are gone.
    vp8x[8] = vp8x[8]! & ~(0x20 | 0x08 | 0x04);
  }
  const body = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(12 + body);
  out.set(d.subarray(0, 12));
  const size = 4 + body;
  out[4] = size & 0xff;
  out[5] = (size >>> 8) & 0xff;
  out[6] = (size >>> 16) & 0xff;
  out[7] = (size >>> 24) & 0xff;
  let o = 12;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return { data: out, format: 'webp', removed, unsanitized: false };
}

/** HEIF-family brands (HEIC/HEIF image and sequence, AVIF), from ISO/IEC 23008-12 and AV1-AVIF. */
const HEIF_BRANDS = new Set(['heic', 'heix', 'heim', 'heis', 'hevc', 'hevx', 'hevm', 'hevs', 'mif1', 'msf1', 'mif2', 'avif', 'avis']);

function isHeif(d: Uint8Array) {
  if (d.length < 16 || ascii(d, 4) !== 'ftyp') return false;
  const size = ((d[0]! << 24) | (d[1]! << 16) | (d[2]! << 8) | d[3]!) >>> 0;
  if (HEIF_BRANDS.has(ascii(d, 8))) return true;
  for (let i = 16; i + 4 <= Math.min(size, d.length); i += 4) if (HEIF_BRANDS.has(ascii(d, i))) return true;
  return false;
}

export const HEIF_UNSANITIZED_REASON =
  'HEIC/HEIF/AVIF: EXIF and XMP live in items referenced from the iloc box and removing them safely requires a full ISO BMFF rewrite; convert the image to JPEG, PNG or WebP before sharing it';

export function sanitizeMetadata(data: Uint8Array): SanitizeResult {
  if (isJpeg(data)) return sanitizeJpeg(data);
  if (isPng(data)) return sanitizePng(data);
  if (isWebp(data)) return sanitizeWebp(data);
  if (isHeif(data)) return { data, format: 'heif', removed: [], unsanitized: true, reason: HEIF_UNSANITIZED_REASON };
  return { data, format: 'unknown', removed: [], unsanitized: true, reason: 'unrecognised file format' };
}

/** Replace a user file name with a neutral one (keeps only a safe extension). */
export function neutralFileName(original: string, sha256Hex: string): string {
  const ext = /\.([a-z0-9]{1,8})$/i.exec(original)?.[1]?.toLowerCase();
  return `file-${sha256Hex.slice(0, 12)}${ext ? `.${ext}` : ''}`;
}
