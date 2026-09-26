/**
 * Metadata sanitizer (spec §13.1): strips EXIF/XMP/IPTC/comments from JPEG and text/time/EXIF chunks
 * from PNG before a file leaves the device. Unknown formats are reported so policy can decide.
 */
export interface SanitizeResult {
  data: Uint8Array;
  format: 'jpeg' | 'png' | 'unknown';
  removed: string[];
  /** true when the format is not understood and metadata could remain */
  unsanitized: boolean;
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

export function sanitizeMetadata(data: Uint8Array): SanitizeResult {
  if (isJpeg(data)) return sanitizeJpeg(data);
  if (isPng(data)) return sanitizePng(data);
  return { data, format: 'unknown', removed: [], unsanitized: true };
}

/** Replace a user file name with a neutral one (keeps only a safe extension). */
export function neutralFileName(original: string, sha256Hex: string): string {
  const ext = /\.([a-z0-9]{1,8})$/i.exec(original)?.[1]?.toLowerCase();
  return `file-${sha256Hex.slice(0, 12)}${ext ? `.${ext}` : ''}`;
}
