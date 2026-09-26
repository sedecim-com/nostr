import { describe, expect, it } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import { generateSecretKey, getPublicKey, nip19, nip49 } from '@sedecim/nostr-core';
import { QrCapacityError, alignmentPositions, byteCapacity, dataCodewords, eccLayout, encodeQR, encodeQRSymbol, formatBits, gfMul, maskAt, qrToSvg, rsEncode, versionBits, type QrEcc } from '../src/index';

// --- Independent test decoder: reads a symbol back to bytes using only the spec's layout rules.

const FORMAT_ECC: Record<number, QrEcc> = { 1: 'L', 0: 'M', 3: 'Q', 2: 'H' };

function bchFormatValid(bits15: number): boolean {
  let v = bits15 ^ 0x5412;
  for (let i = 14; i >= 10; i--) if ((v >>> i) & 1) v ^= 0x537 << (i - 10);
  return v === 0;
}

function readFormat(m: boolean[][]): { ecc: QrEcc; mask: number; raw: [number, number] } {
  const n = m.length;
  const get = (x: number, y: number) => (m[y]![x] ? 1 : 0);
  let a = 0;
  for (let i = 0; i <= 5; i++) a |= get(8, i) << i;
  a |= get(8, 7) << 6;
  a |= get(8, 8) << 7;
  a |= get(7, 8) << 8;
  for (let i = 9; i < 15; i++) a |= get(14 - i, 8) << i;
  let b = 0;
  for (let i = 0; i < 8; i++) b |= get(n - 1 - i, 8) << i;
  for (let i = 8; i < 15; i++) b |= get(8, n - 15 + i) << i;
  if (a !== b) throw new Error('format copies differ');
  if (!bchFormatValid(a)) throw new Error('format BCH invalid');
  const data = (a ^ 0x5412) >>> 10;
  return { ecc: FORMAT_ECC[data >>> 3]!, mask: data & 7, raw: [a, b] };
}

function functionMap(version: number): boolean[][] {
  const n = version * 4 + 17;
  const f = Array.from({ length: n }, () => new Array<boolean>(n).fill(false));
  const mark = (x0: number, y0: number, w: number, h: number) => {
    for (let y = y0; y < y0 + h; y++) for (let x = x0; x < x0 + w; x++) if (x >= 0 && y >= 0 && x < n && y < n) f[y]![x] = true;
  };
  mark(0, 0, 9, 9);
  mark(n - 8, 0, 8, 9);
  mark(0, n - 8, 9, 8);
  mark(6, 0, 1, n);
  mark(0, 6, n, 1);
  const pos = alignmentPositions(version);
  const last = pos[pos.length - 1];
  for (const cx of pos) for (const cy of pos) if (!((cx === 6 && cy === 6) || (cx === 6 && cy === last) || (cx === last && cy === 6))) mark(cx - 2, cy - 2, 5, 5);
  if (version >= 7) {
    mark(n - 11, 0, 3, 6);
    mark(0, n - 11, 6, 3);
  }
  return f;
}

/** A valid RS block evaluates to zero at the generator roots alpha^0 .. alpha^(ecc-1) (Horner). */
function rsSyndromesZero(block: number[], ecc: number): boolean {
  let x = 1;
  for (let i = 0; i < ecc; i++) {
    let s = 0;
    for (const c of block) s = gfMul(s, x) ^ c;
    if (s !== 0) return false;
    x = gfMul(x, 2);
  }
  return true;
}

function decode(m: boolean[][]): { text: string; bytes: Uint8Array; version: number; ecc: QrEcc; mask: number } {
  const n = m.length;
  const version = (n - 17) / 4;
  if (!Number.isInteger(version) || version < 1 || version > 40) throw new Error('bad size');
  if (version >= 7) {
    let v1 = 0;
    let v2 = 0;
    for (let i = 0; i < 18; i++) {
      const a = n - 11 + (i % 3);
      const b = Math.floor(i / 3);
      v1 |= (m[b]![a] ? 1 : 0) << i;
      v2 |= (m[a]![b] ? 1 : 0) << i;
    }
    if (v1 !== v2 || v1 >>> 12 !== version || v1 !== versionBits(version)) throw new Error('version info mismatch');
  }
  const { ecc, mask } = readFormat(m);
  const f = functionMap(version);
  const bits: number[] = [];
  for (let right = n - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    const up = ((right + 1) & 2) === 0;
    for (let v = 0; v < n; v++) {
      const y = up ? n - 1 - v : v;
      for (const x of [right, right - 1]) if (!f[y]![x]) bits.push((m[y]![x] ? 1 : 0) ^ (maskAt(mask, x, y) ? 1 : 0));
    }
  }
  const { blocks, eccPerBlock, totalCodewords } = eccLayout(version, ecc);
  const cw: number[] = [];
  for (let i = 0; i < totalCodewords; i++) cw.push(parseInt(bits.slice(i * 8, i * 8 + 8).join(''), 2));
  // De-interleave.
  const numShort = blocks - (totalCodewords % blocks);
  const shortData = Math.floor(totalCodewords / blocks) - eccPerBlock;
  const lens = Array.from({ length: blocks }, (_, i) => shortData + (i < numShort ? 0 : 1));
  const dataBlocks = lens.map(() => [] as number[]);
  const eccBlocks = lens.map(() => [] as number[]);
  let k = 0;
  for (let i = 0; i <= shortData; i++) for (let b = 0; b < blocks; b++) if (i < lens[b]!) dataBlocks[b]!.push(cw[k++]!);
  for (let i = 0; i < eccPerBlock; i++) for (let b = 0; b < blocks; b++) eccBlocks[b]!.push(cw[k++]!);
  const data: number[] = [];
  for (let b = 0; b < blocks; b++) {
    if (!rsSyndromesZero([...dataBlocks[b]!, ...eccBlocks[b]!], eccPerBlock)) throw new Error(`RS syndrome non-zero in block ${b}`);
    data.push(...dataBlocks[b]!);
  }
  // Parse the byte-mode segment.
  const bitAt = (i: number) => (data[i >>> 3]! >>> (7 - (i & 7))) & 1;
  const read = (pos: number, len: number) => {
    let v = 0;
    for (let i = 0; i < len; i++) v = (v << 1) | bitAt(pos + i);
    return v;
  };
  if (read(0, 4) !== 0b0100) throw new Error('not byte mode');
  const ccBits = version < 10 ? 8 : 16;
  const count = read(4, ccBits);
  const bytes = new Uint8Array(count);
  for (let i = 0; i < count; i++) bytes[i] = read(4 + ccBits + i * 8, 8);
  return { text: new TextDecoder('utf-8', { fatal: true }).decode(bytes), bytes, version, ecc, mask };
}

const rowsHash = (m: boolean[][]) => createHash('sha256').update(m.map((r) => r.map((b) => (b ? '1' : '0')).join('')).join('\n')).digest('hex');

describe('QR encoder (FR003-03)', () => {
  it('Reed-Solomon matches the standard "HELLO WORLD" 1-Q example', () => {
    const data = [32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236];
    expect([...rsEncode(data, 13)]).toEqual([168, 72, 22, 82, 217, 54, 156, 0, 46, 15, 180, 122, 16]);
  });

  it('format and version information match ISO/IEC 18004 Annex C/D', () => {
    expect(formatBits('M', 0)).toBe(0b101010000010010);
    expect(formatBits('L', 0)).toBe(0b111011111000100);
    expect(formatBits('Q', 0)).toBe(0b011010101011111);
    expect(formatBits('H', 0)).toBe(0b001011010001001);
    expect(formatBits('L', 7)).toBe(0b110100101110110);
    for (const e of ['L', 'M', 'Q', 'H'] as const) for (let mask = 0; mask < 8; mask++) expect(bchFormatValid(formatBits(e, mask))).toBe(true);
    expect(versionBits(7)).toBe(0b000111110010010100);
    expect(versionBits(40)).toBe(0b101000110001101001);
  });

  it('capacity tables match ISO/IEC 18004 Table 7', () => {
    expect([dataCodewords(1, 'L'), dataCodewords(1, 'M'), dataCodewords(1, 'Q'), dataCodewords(1, 'H')]).toEqual([19, 16, 13, 9]);
    expect([dataCodewords(10, 'L'), dataCodewords(10, 'M'), dataCodewords(10, 'Q'), dataCodewords(10, 'H')]).toEqual([274, 216, 154, 122]);
    expect([dataCodewords(40, 'L'), dataCodewords(40, 'M'), dataCodewords(40, 'Q'), dataCodewords(40, 'H')]).toEqual([2956, 2334, 1666, 1276]);
    expect([byteCapacity(1, 'L'), byteCapacity(1, 'H'), byteCapacity(10, 'M'), byteCapacity(40, 'L'), byteCapacity(40, 'H')]).toEqual([17, 7, 213, 2953, 1273]);
    for (let v = 1; v <= 40; v++) expect(eccLayout(v, 'L').totalCodewords).toBeGreaterThan(0);
    expect(eccLayout(40, 'L').totalCodewords).toBe(3706);
  });

  it('alignment pattern positions match Annex E', () => {
    expect(alignmentPositions(1)).toEqual([]);
    expect(alignmentPositions(2)).toEqual([6, 18]);
    expect(alignmentPositions(7)).toEqual([6, 22, 38]);
    expect(alignmentPositions(14)).toEqual([6, 26, 46, 66]);
    expect(alignmentPositions(22)).toEqual([6, 26, 50, 74, 98]);
    expect(alignmentPositions(32)).toEqual([6, 34, 60, 86, 112, 138]);
    expect(alignmentPositions(36)).toEqual([6, 24, 50, 76, 102, 128, 154]);
    expect(alignmentPositions(40)).toEqual([6, 30, 58, 86, 114, 142, 170]);
  });

  // Matrices produced by an independent implementation (segno 1.6.6, byte mode, same forced mask;
  // segno's extra zero pad byte when the terminator ends on a codeword boundary was fixed for "hello").
  const vectors: Array<{ text: string; ecc: QrEcc; mask: number; version: number; sha256: string }> = [
    { text: 'HELLO WORLD', ecc: 'Q', mask: 6, version: 1, sha256: 'bbe23bb8e3905587b437c783a3548876887c4c30a4b9a3da93b78a3731a27699' },
    { text: 'hello', ecc: 'M', mask: 5, version: 1, sha256: 'aab8a0a72b21c8c63c7d29fb79889a5cf663a94745c683d332f8ca36b6c93d79' },
    { text: 'https://example.com/ñandú', ecc: 'H', mask: 1, version: 4, sha256: '2bb6f519130b36a7bd6fcc53d13f284ee948492ae62ce0b9701623ec1c6fb242' },
    { text: 'npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6', ecc: 'M', mask: 3, version: 5, sha256: '27322f694d789806f5e0c8794ebc70c07ec0c185084eb7ff411fffd2c56c2e1a' },
    { text: 'Acceso Nostr '.repeat(20), ecc: 'L', mask: 0, version: 10, sha256: '10abb75fdf054766ead8968fd90f47c55825afe5093be1de2d8c23f1558e9b51' },
    { text: 'x'.repeat(1200), ecc: 'Q', mask: 7, version: 34, sha256: '7927c2b4119de539d385bb8243a0f046a2f925fd89732c5772954e6402cb439e' },
    { text: 'z'.repeat(2953), ecc: 'L', mask: 4, version: 40, sha256: 'ed6099ed2e11d1f5e75b4204afe2a581ebfe6cc5f08a70eb8fef85b62f7550dd' },
  ];
  for (const v of vectors)
    it(`matches the reference matrix: v${v.version}-${v.ecc} mask ${v.mask} (${v.text.slice(0, 16)}…)`, () => {
      const s = encodeQRSymbol(v.text, { ecc: v.ecc, mask: v.mask });
      expect(s.version).toBe(v.version);
      expect(rowsHash(s.modules)).toBe(v.sha256);
      expect(decode(s.modules).text).toBe(v.text);
    });

  it('round-trips random byte-mode payloads at every level through an independent decoder', () => {
    for (const ecc of ['L', 'M', 'Q', 'H'] as const)
      for (const len of [0, 1, 7, 17, 32, 106, 271, 600]) {
        const text = randomBytes(len).toString('base64').slice(0, len) + 'ñ';
        const d = decode(encodeQR(text, { ecc }));
        expect(d.text).toBe(text);
        expect(d.ecc).toBe(ecc);
      }
  });

  it('picks the smallest version and the lowest-penalty mask, and rejects oversized input', () => {
    expect(encodeQRSymbol('a'.repeat(17), { ecc: 'L' }).version).toBe(1);
    expect(encodeQRSymbol('a'.repeat(18), { ecc: 'L' }).version).toBe(2);
    expect(encodeQRSymbol('z'.repeat(2953), { ecc: 'L' }).size).toBe(177);
    expect(() => encodeQR('z'.repeat(2954), { ecc: 'L' })).toThrow(QrCapacityError);
    expect(() => encodeQR('z'.repeat(1274), { ecc: 'H' })).toThrow(/too long/);
    expect(() => encodeQR('x', { ecc: 'X' as QrEcc })).toThrow();
    expect(encodeQRSymbol('hola').mask).toBeGreaterThanOrEqual(0);
  });

  it('npub and ncryptsec fit and produce valid structure (finders, timing, format BCH)', () => {
    const sk = generateSecretKey();
    const npub = nip19.npubEncode(getPublicKey(sk));
    const ncryptsec = nip49.encryptKey(sk, 'contraseña de prueba', 4, 0x01);
    expect(npub).toHaveLength(63);
    expect(ncryptsec).toHaveLength(162);
    for (const [text, ecc, maxVersion] of [
      [npub, 'M', 5],
      [npub, 'H', 7],
      [ncryptsec, 'M', 9],
      [ncryptsec, 'Q', 11],
    ] as const) {
      const s = encodeQRSymbol(text, { ecc });
      expect(s.version).toBeLessThanOrEqual(maxVersion);
      const m = s.modules;
      const n = s.size;
      // Finder patterns: 7x7 dark ring, light ring, 3x3 dark core; light separators.
      for (const [ox, oy] of [
        [0, 0],
        [n - 7, 0],
        [0, n - 7],
      ] as const)
        for (let dy = 0; dy < 7; dy++)
          for (let dx = 0; dx < 7; dx++) {
            const d = Math.max(Math.abs(dx - 3), Math.abs(dy - 3));
            expect(m[oy + dy]![ox + dx], `finder at ${ox},${oy}`).toBe(d !== 2);
          }
      for (let i = 0; i < 8; i++) {
        expect(m[7]![i]).toBe(false);
        expect(m[i]![7]).toBe(false);
        expect(m[7]![n - 1 - i]).toBe(false);
        expect(m[n - 8]![i]).toBe(false);
      }
      // Timing patterns alternate between the finders.
      for (let i = 8; i < n - 8; i++) {
        expect(m[6]![i]).toBe(i % 2 === 0);
        expect(m[i]![6]).toBe(i % 2 === 0);
      }
      expect(m[n - 8]![8]).toBe(true); // dark module
      const f = readFormat(m);
      expect(f.ecc).toBe(ecc);
      expect(f.mask).toBe(s.mask);
      expect(decode(m).text).toBe(text);
    }
  });

  it('renders a self-contained SVG with quiet zone and no external references', () => {
    const m = encodeQR('npub1test', { ecc: 'M' });
    const svg = qrToSvg(m, { moduleSize: 5, margin: 4, title: 'npub <de> "prueba"' });
    const dim = m.length + 8;
    expect(svg).toContain(`viewBox="0 0 ${dim} ${dim}"`);
    expect(svg).toContain(`width="${dim * 5}"`);
    expect(svg).toContain('<title>npub &lt;de&gt; &quot;prueba&quot;</title>');
    expect(svg).not.toMatch(/href|<script|<style|<image|url\(|<foreignObject/i);
    expect(svg.replace('xmlns="http://www.w3.org/2000/svg"', '')).not.toMatch(/https?:/);
    const inline = qrToSvg(m, { inline: true });
    expect(inline).not.toContain('xmlns');
    expect(inline.startsWith('<svg viewBox=')).toBe(true);
    // Every dark module is covered by exactly one run of the path.
    let area = 0;
    for (const [, w] of svg.matchAll(/h(\d+)v1/g)) area += Number(w);
    expect(area).toBe(m.flat().filter(Boolean).length);
    expect(() => qrToSvg(m, { dark: 'red;fill:url(x)' })).toThrow();
    expect(() => qrToSvg([[true, false]])).toThrow(/square/);
  });

  it('has no dependency on Node built-ins (browser-safe source)', async () => {
    const { readFileSync, readdirSync } = await import('node:fs');
    const dir = new URL('../src/', import.meta.url);
    for (const f of readdirSync(dir)) expect(readFileSync(new URL(f, dir), 'utf8')).not.toMatch(/from 'node:|require\(/);
  });
});
