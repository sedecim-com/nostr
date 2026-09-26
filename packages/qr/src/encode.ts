/**
 * QR Code encoder (ISO/IEC 18004:2015), byte mode only, versions 1–40, error correction L/M/Q/H and
 * automatic mask selection by the four penalty rules of §7.8.3. Pure TypeScript with no dependencies
 * and no platform APIs beyond TextEncoder, so it runs unchanged in browsers, air-gapped pages and Node.
 */

export type QrEcc = 'L' | 'M' | 'Q' | 'H';

export interface QrOptions {
  /** Error correction level (default 'M'). */
  ecc?: QrEcc;
  /** Force a mask pattern 0–7 instead of choosing the lowest penalty (testing/interop only). */
  mask?: number;
  /** Smallest version to consider (default 1). */
  minVersion?: number;
}

export interface QrSymbol {
  version: number;
  ecc: QrEcc;
  mask: number;
  size: number;
  /** modules[y][x], true = dark. No quiet zone. */
  modules: boolean[][];
}

const ECC_INDEX: Record<QrEcc, number> = { L: 0, M: 1, Q: 2, H: 3 };
/** Format information bits for each level (§7.9.1): L=01, M=00, Q=11, H=10. */
const ECC_FORMAT_BITS: Record<QrEcc, number> = { L: 1, M: 0, Q: 3, H: 2 };

// Table 9 of ISO/IEC 18004: error correction codewords per block and number of blocks, indexed
// [level][version]; index 0 is unused.
const ECC_CODEWORDS_PER_BLOCK: readonly (readonly number[])[] = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
];
const NUM_BLOCKS: readonly (readonly number[])[] = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
];

export class QrCapacityError extends Error {
  constructor(bytes: number, ecc: QrEcc) {
    super(`data too long for a QR code: ${bytes} bytes at level ${ecc} (max ${dataCodewords(40, ecc) - 3} bytes)`);
    this.name = 'QrCapacityError';
  }
}

/** Number of modules available for data + ECC codewords (incl. remainder bits) in a version. */
export function rawDataModules(version: number): number {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const numAlign = Math.floor(version / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (version >= 7) result -= 36;
  }
  return result;
}

export function eccLayout(version: number, ecc: QrEcc): { blocks: number; eccPerBlock: number; totalCodewords: number } {
  const i = ECC_INDEX[ecc];
  return { blocks: NUM_BLOCKS[i]![version]!, eccPerBlock: ECC_CODEWORDS_PER_BLOCK[i]![version]!, totalCodewords: Math.floor(rawDataModules(version) / 8) };
}

/** Data codewords (bytes) available in a version/level. */
export function dataCodewords(version: number, ecc: QrEcc): number {
  const l = eccLayout(version, ecc);
  return l.totalCodewords - l.blocks * l.eccPerBlock;
}

/** Maximum payload in byte mode for a version/level. */
export function byteCapacity(version: number, ecc: QrEcc): number {
  const bits = dataCodewords(version, ecc) * 8 - 4 - (version < 10 ? 8 : 16);
  return Math.floor(bits / 8);
}

/** Centre coordinates of the alignment patterns of a version (Annex E). */
export function alignmentPositions(version: number): number[] {
  if (version === 1) return [];
  const numAlign = Math.floor(version / 7) + 2;
  const size = version * 4 + 17;
  const step = Math.floor((version * 8 + numAlign * 3 + 5) / (numAlign * 4 - 4)) * 2;
  const out = [6];
  for (let pos = size - 7; out.length < numAlign; pos -= step) out.splice(1, 0, pos);
  return out;
}

// --- GF(256) with the QR polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]!;
}

export function gfMul(a: number, b: number): number {
  return a === 0 || b === 0 ? 0 : EXP[LOG[a]! + LOG[b]!]!;
}

/** Generator polynomial of the given degree, coefficients high → low without the leading 1. */
function rsGenerator(degree: number): Uint8Array {
  const g = new Uint8Array(degree);
  g[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      g[j] = gfMul(g[j]!, root);
      if (j + 1 < degree) g[j] = g[j]! ^ g[j + 1]!;
    }
    root = gfMul(root, 2);
  }
  return g;
}

/** Reed–Solomon error correction codewords for one block (§7.5.2). */
export function rsEncode(data: ArrayLike<number>, degree: number): Uint8Array {
  const gen = rsGenerator(degree);
  const rem = new Uint8Array(degree);
  for (let i = 0; i < data.length; i++) {
    const factor = data[i]! ^ rem[0]!;
    rem.copyWithin(0, 1);
    rem[degree - 1] = 0;
    for (let j = 0; j < degree; j++) rem[j] = rem[j]! ^ gfMul(gen[j]!, factor);
  }
  return rem;
}

/** 15-bit format information (level + mask, BCH(15,5), XOR 0x5412) (§7.9). */
export function formatBits(ecc: QrEcc, mask: number): number {
  const data = (ECC_FORMAT_BITS[ecc] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  return ((data << 10) | (rem & 0x3ff)) ^ 0x5412;
}

/** 18-bit version information (BCH(18,6)) for versions ≥ 7 (§7.10). */
export function versionBits(version: number): number {
  let rem = version;
  for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
  return (version << 12) | (rem & 0xfff);
}

const MASKS: ReadonlyArray<(x: number, y: number) => boolean> = [
  (x, y) => (x + y) % 2 === 0,
  (_x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

/** Mask condition (true = invert) for pattern `mask` at column x, row y (Table 10). */
export function maskAt(mask: number, x: number, y: number): boolean {
  return MASKS[mask]!(x, y);
}

function encodeData(bytes: Uint8Array, version: number, ecc: QrEcc): Uint8Array {
  const capacity = dataCodewords(version, ecc);
  const bits: number[] = [];
  const push = (value: number, len: number) => {
    for (let i = len - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  push(0b0100, 4); // byte mode
  push(bytes.length, version < 10 ? 8 : 16);
  for (const b of bytes) push(b, 8);
  push(0, Math.min(4, capacity * 8 - bits.length)); // terminator
  push(0, (8 - (bits.length % 8)) % 8);
  const out = new Uint8Array(capacity);
  for (let i = 0; i < bits.length; i++) out[i >>> 3] = out[i >>> 3]! | (bits[i]! << (7 - (i & 7)));
  for (let i = bits.length / 8, pad = 0xec; i < capacity; i++, pad ^= 0xec ^ 0x11) out[i] = pad;
  return out;
}

/** Split into blocks, add RS codewords and interleave (§7.6). */
export function interleave(data: Uint8Array, version: number, ecc: QrEcc): Uint8Array {
  const { blocks, eccPerBlock, totalCodewords } = eccLayout(version, ecc);
  const numShort = blocks - (totalCodewords % blocks);
  const shortLen = Math.floor(totalCodewords / blocks); // data + ecc of a short block
  const dataBlocks: Uint8Array[] = [];
  const eccBlocks: Uint8Array[] = [];
  for (let i = 0, k = 0; i < blocks; i++) {
    const len = shortLen - eccPerBlock + (i < numShort ? 0 : 1);
    const d = data.subarray(k, k + len);
    k += len;
    dataBlocks.push(d);
    eccBlocks.push(rsEncode(d, eccPerBlock));
  }
  const out: number[] = [];
  for (let i = 0; i <= shortLen - eccPerBlock; i++) for (const b of dataBlocks) if (i < b.length) out.push(b[i]!);
  for (let i = 0; i < eccPerBlock; i++) for (const b of eccBlocks) out.push(b[i]!);
  return new Uint8Array(out);
}

class Grid {
  readonly modules: boolean[][];
  readonly reserved: boolean[][];
  constructor(readonly size: number) {
    this.modules = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
    this.reserved = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  }
  fn(x: number, y: number, dark: boolean) {
    this.modules[y]![x] = dark;
    this.reserved[y]![x] = true;
  }
}

function drawFunctionPatterns(g: Grid, version: number) {
  const n = g.size;
  // Timing patterns (row and column 6).
  for (let i = 0; i < n; i++) {
    g.fn(6, i, i % 2 === 0);
    g.fn(i, 6, i % 2 === 0);
  }
  // Finder patterns + separators.
  for (const [cx, cy] of [
    [3, 3],
    [n - 4, 3],
    [3, n - 4],
  ] as const) {
    for (let dy = -4; dy <= 4; dy++)
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx;
        const y = cy + dy;
        if (x < 0 || y < 0 || x >= n || y >= n) continue;
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        g.fn(x, y, d !== 2 && d !== 4);
      }
  }
  // Alignment patterns (skip the three that overlap finders).
  const pos = alignmentPositions(version);
  for (let i = 0; i < pos.length; i++)
    for (let j = 0; j < pos.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === pos.length - 1) || (i === pos.length - 1 && j === 0)) continue;
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) g.fn(pos[i]! + dx, pos[j]! + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  // Reserve format areas (real bits are drawn per mask) and version info.
  drawFormat(g, 0);
  if (version >= 7) {
    const bits = versionBits(version);
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) === 1;
      const a = n - 11 + (i % 3);
      const b = Math.floor(i / 3);
      g.fn(a, b, dark);
      g.fn(b, a, dark);
    }
  }
}

/** Draws the two copies of the format information plus the dark module (§7.9.1, Figure 25). */
function drawFormat(g: Grid, bits: number) {
  const n = g.size;
  const bit = (i: number) => ((bits >>> i) & 1) === 1;
  for (let i = 0; i <= 5; i++) g.fn(8, i, bit(i));
  g.fn(8, 7, bit(6));
  g.fn(8, 8, bit(7));
  g.fn(7, 8, bit(8));
  for (let i = 9; i < 15; i++) g.fn(14 - i, 8, bit(i));
  for (let i = 0; i < 8; i++) g.fn(n - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i++) g.fn(8, n - 15 + i, bit(i));
  g.fn(8, n - 8, true);
}

function placeCodewords(g: Grid, codewords: Uint8Array) {
  const n = g.size;
  let i = 0;
  const total = codewords.length * 8;
  for (let right = n - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    const upward = ((right + 1) & 2) === 0;
    for (let v = 0; v < n; v++) {
      const y = upward ? n - 1 - v : v;
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        if (g.reserved[y]![x]) continue;
        if (i < total) g.modules[y]![x] = ((codewords[i >>> 3]! >>> (7 - (i & 7))) & 1) === 1;
        i++;
      }
    }
  }
}

function applyMask(g: Grid, mask: number) {
  for (let y = 0; y < g.size; y++) for (let x = 0; x < g.size; x++) if (!g.reserved[y]![x] && maskAt(mask, x, y)) g.modules[y]![x] = !g.modules[y]![x];
}

const FINDER_CORE = [true, false, true, true, true, false, true];

/** Total penalty score of a masked symbol (§7.8.3.1, N1=3, N2=3, N3=40, N4=10). */
export function penalty(m: boolean[][]): number {
  const n = m.length;
  let score = 0;
  const at = (x: number, y: number, vertical: boolean) => (vertical ? m[x]![y]! : m[y]![x]!);
  for (const vertical of [false, true]) {
    for (let y = 0; y < n; y++) {
      // Rule 1: runs of five or more same-coloured modules.
      let run = 1;
      for (let x = 1; x < n; x++) {
        if (at(x, y, vertical) === at(x - 1, y, vertical)) run++;
        else {
          if (run >= 5) score += 3 + (run - 5);
          run = 1;
        }
      }
      if (run >= 5) score += 3 + (run - 5);
      // Rule 3: 1:1:3:1:1 finder-like pattern preceded or followed by four light modules. The quiet
      // zone outside the symbol counts as light.
      const light = (from: number, to: number) => {
        for (let k = Math.max(from, 0); k < Math.min(to, n); k++) if (at(k, y, vertical)) return false;
        return true;
      };
      for (let x = 0; x + 7 <= n; x++) {
        let match = true;
        for (let k = 0; k < 7 && match; k++) if (at(x + k, y, vertical) !== FINDER_CORE[k]) match = false;
        if (match && (light(x - 4, x) || light(x + 7, x + 11))) score += 40;
      }
    }
  }
  // Rule 2: 2x2 blocks of the same colour.
  let dark = 0;
  for (let y = 0; y < n; y++)
    for (let x = 0; x < n; x++) {
      if (m[y]![x]) dark++;
      if (x + 1 < n && y + 1 < n) {
        const c = m[y]![x];
        if (c === m[y]![x + 1] && c === m[y + 1]![x] && c === m[y + 1]![x + 1]) score += 3;
      }
    }
  // Rule 4: proportion of dark modules, 10 points per 5 % deviation from 50 %.
  const total = n * n;
  score += Math.floor(Math.abs(dark * 20 - total * 10) / total) * 10;
  return score;
}

/** Encodes text (UTF-8, byte mode) into a QR symbol with version, mask and modules. */
export function encodeQRSymbol(text: string | Uint8Array, opts: QrOptions = {}): QrSymbol {
  const ecc = opts.ecc ?? 'M';
  if (!(ecc in ECC_INDEX)) throw new Error(`invalid error correction level ${String(ecc)}`);
  if (opts.mask !== undefined && !(Number.isInteger(opts.mask) && opts.mask >= 0 && opts.mask <= 7)) throw new Error('mask must be 0–7');
  const bytes = typeof text === 'string' ? new TextEncoder().encode(text) : text;
  let version = Math.max(1, opts.minVersion ?? 1);
  while (version <= 40 && byteCapacity(version, ecc) < bytes.length) version++;
  if (version > 40) throw new QrCapacityError(bytes.length, ecc);

  const codewords = interleave(encodeData(bytes, version, ecc), version, ecc);
  const g = new Grid(version * 4 + 17);
  drawFunctionPatterns(g, version);
  placeCodewords(g, codewords);

  let best = opts.mask ?? -1;
  if (best < 0) {
    let bestScore = Infinity;
    for (let mask = 0; mask < 8; mask++) {
      applyMask(g, mask);
      drawFormat(g, formatBits(ecc, mask));
      const s = penalty(g.modules);
      if (s < bestScore) {
        bestScore = s;
        best = mask;
      }
      applyMask(g, mask); // XOR again to undo
    }
  }
  applyMask(g, best);
  drawFormat(g, formatBits(ecc, best));
  return { version, ecc, mask: best, size: g.size, modules: g.modules };
}

/** Encodes text as a QR code matrix: matrix[y][x], true = dark module, without quiet zone. */
export function encodeQR(text: string, opts: { ecc?: QrEcc; mask?: number } = {}): boolean[][] {
  return encodeQRSymbol(text, opts).modules;
}
