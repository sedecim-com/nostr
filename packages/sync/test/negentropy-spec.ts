/**
 * An independent reading of Negentropy Protocol V1 as the appendix of NIP-77 specifies it, written from the text and
 * not from any implementation, to check the messages the client sends. Test helper, not a test.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@sedecim/nostr-core';

export const PROTOCOL_V1 = 0x61;
export const INFINITY = Number.POSITIVE_INFINITY;
export const MODE = { Skip: 0, Fingerprint: 1, IdList: 2 } as const;

export interface SpecBound {
  /** INFINITY for the special infinity timestamp (encoded as 0) */
  timestamp: number;
  idPrefix: Uint8Array;
}

export interface SpecRange {
  upper: SpecBound;
  mode: number;
  fingerprint?: Uint8Array;
  ids?: string[];
}

export interface SpecMessage {
  version: number;
  ranges: SpecRange[];
  /** every varint was written with as few digits as possible */
  minimalVarints: boolean;
  byteLength: number;
}

export interface SpecItem {
  timestamp: number;
  id: string;
}

/** Varint := <Digit+128>* <Digit>: base-128, most significant digit first, high bit set on every byte but the last. */
export function encodeVarint(n: number): Uint8Array {
  const digits = [n % 128];
  for (let v = Math.floor(n / 128); v > 0; v = Math.floor(v / 128)) digits.unshift(v % 128);
  return Uint8Array.from(digits.map((d, i) => (i < digits.length - 1 ? d + 128 : d)));
}

export function decodeMessage(hex: string): SpecMessage {
  const bytes = hexToBytes(hex);
  let pos = 0;
  let minimal = true;
  const take = (n: number) => {
    if (pos + n > bytes.length) throw new Error('message ends prematurely');
    const out = bytes.subarray(pos, pos + n);
    pos += n;
    return out;
  };
  const varint = () => {
    let value = 0;
    const start = pos;
    for (;;) {
      const b = take(1)[0]!;
      value = value * 128 + (b & 0x7f);
      if ((b & 0x80) === 0) break;
    }
    if (bytes[start] === 0x80) minimal = false; // a leading zero digit
    return value;
  };
  const version = take(1)[0]!;
  const ranges: SpecRange[] = [];
  // "The initial offset starts at 0 and resets at the beginning of each message."
  let previous = 0;
  while (pos < bytes.length) {
    const encoded = varint();
    const timestamp = encoded === 0 ? INFINITY : previous + (encoded - 1);
    if (encoded !== 0) previous = timestamp;
    const length = varint();
    if (length > 32) throw new Error('idPrefix longer than 32 bytes');
    const idPrefix = Uint8Array.from(take(length));
    const mode = varint();
    const range: SpecRange = { upper: { timestamp, idPrefix }, mode };
    if (mode === MODE.Fingerprint) range.fingerprint = Uint8Array.from(take(16));
    else if (mode === MODE.IdList) {
      const n = varint();
      range.ids = Array.from({ length: n }, () => bytesToHex(take(32)));
    } else if (mode !== MODE.Skip) throw new Error(`unknown mode ${mode}`);
    ranges.push(range);
  }
  return { version, ranges, minimalVarints: minimal, byteLength: bytes.length };
}

/** Items sorted by timestamp, then lexically by id (first differing byte). */
export function sortItems(items: SpecItem[]): SpecItem[] {
  return [...items].sort((a, b) => a.timestamp - b.timestamp || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/** item < bound: by timestamp, then by id against the prefix padded with zero bytes to 32. */
export function itemBefore(item: SpecItem, bound: SpecBound): boolean {
  if (item.timestamp !== bound.timestamp) return item.timestamp < bound.timestamp;
  const padded = new Uint8Array(32);
  padded.set(bound.idPrefix);
  return bytesToHex(hexToBytes(item.id)) < bytesToHex(padded);
}

/** The items of each range: lower bound inclusive (the previous upper bound, or 0), upper bound exclusive. */
export function itemsPerRange(message: SpecMessage, items: SpecItem[]): SpecItem[][] {
  const sorted = sortItems(items);
  let i = 0;
  return message.ranges.map((r) => {
    const inRange: SpecItem[] = [];
    while (i < sorted.length && itemBefore(sorted[i]!, r.upper)) inRange.push(sorted[i++]!);
    return inRange;
  });
}

/** Fingerprint Algorithm: sum mod 2^256 of the ids as little-endian integers, then the count as a varint, SHA-256, 16 bytes. */
export function fingerprint(ids: string[]): Uint8Array {
  let sum = 0n;
  for (const id of ids) {
    const b = hexToBytes(id);
    let v = 0n;
    for (let k = 31; k >= 0; k--) v = (v << 8n) | BigInt(b[k]!);
    sum = (sum + v) % (1n << 256n);
  }
  const le = new Uint8Array(32);
  for (let k = 0; k < 32; k++) le[k] = Number((sum >> BigInt(8 * k)) & 0xffn);
  const count = encodeVarint(ids.length);
  const input = new Uint8Array(32 + count.length);
  input.set(le);
  input.set(count, 32);
  return sha256(input).subarray(0, 16);
}

export function compareBounds(a: SpecBound, b: SpecBound): number {
  if (a.timestamp !== b.timestamp) return a.timestamp < b.timestamp ? -1 : 1;
  const pa = new Uint8Array(32);
  const pb = new Uint8Array(32);
  pa.set(a.idPrefix);
  pb.set(b.idPrefix);
  const ha = bytesToHex(pa);
  const hb = bytesToHex(pb);
  return ha < hb ? -1 : ha > hb ? 1 : 0;
}
