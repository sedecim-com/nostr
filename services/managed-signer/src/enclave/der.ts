/** Minimal ASN.1 DER reader/writer: enough for CMS EnvelopedData and simulated X.509 certificates. */

export interface DerNode {
  /** Full identifier octet (class | constructed | number); high tag numbers are not supported. */
  tag: number;
  /** Content octets. */
  value: Uint8Array;
  /** Whole TLV encoding. */
  raw: Uint8Array;
}

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
} as const;

/** Reads one TLV at `pos`; returns the node and the offset right after it. */
export function readDer(buf: Uint8Array, pos = 0): { node: DerNode; next: number } {
  if (pos + 2 > buf.length) throw new Error('der: truncated');
  const tag = buf[pos]!;
  if ((tag & 0x1f) === 0x1f) throw new Error('der: high tag numbers are not supported');
  let len = buf[pos + 1]!;
  let off = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('der: unsupported length');
    if (off + n > buf.length) throw new Error('der: truncated');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off + i]!;
    off += n;
  }
  if (off + len > buf.length) throw new Error('der: truncated');
  return { node: { tag, value: buf.subarray(off, off + len), raw: buf.subarray(pos, off + len) }, next: off + len };
}

/** Children of a constructed node. */
export function derChildren(node: DerNode): DerNode[] {
  if (!(node.tag & 0x20)) throw new Error('der: not a constructed value');
  const out: DerNode[] = [];
  let pos = 0;
  while (pos < node.value.length) {
    const r = readDer(node.value, pos);
    out.push(r.node);
    pos = r.next;
  }
  return out;
}

export function parseDer(buf: Uint8Array): DerNode {
  const { node, next } = readDer(buf, 0);
  if (next !== buf.length) throw new Error('der: trailing bytes');
  return node;
}

export function decodeOid(value: Uint8Array): string {
  if (!value.length) throw new Error('der: empty OID');
  const parts: number[] = [];
  let acc = 0;
  let start = true;
  for (const b of value) {
    if (start && b === 0x80) throw new Error('der: non-minimal OID arc');
    acc = acc * 128 + (b & 0x7f);
    if (acc > Number.MAX_SAFE_INTEGER) throw new Error('der: OID arc too large');
    start = !(b & 0x80);
    if (start) (parts.push(acc), (acc = 0));
  }
  if (!start) throw new Error('der: truncated OID');
  const first = parts.shift()!;
  const a = first < 80 ? Math.floor(first / 40) : 2;
  return [a, first - a * 40, ...parts].join('.');
}

// --- encoder

function len(n: number): Uint8Array {
  if (n < 0x80) return Uint8Array.of(n);
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

export function der(tag: number, ...content: Uint8Array[]): Uint8Array {
  const body = Buffer.concat(content);
  return Buffer.concat([Uint8Array.of(tag), len(body.length), body]);
}

export const seq = (...c: Uint8Array[]) => der(TAG.SEQUENCE, ...c);
export const set = (...c: Uint8Array[]) => der(TAG.SET, ...c);
export const octets = (b: Uint8Array) => der(TAG.OCTET_STRING, b);
export const bitString = (b: Uint8Array) => der(TAG.BIT_STRING, Uint8Array.of(0), b);
export const utf8 = (s: string) => der(TAG.UTF8_STRING, new TextEncoder().encode(s));
export const derNull = () => der(TAG.NULL);
export const bool = (v: boolean) => der(TAG.BOOLEAN, Uint8Array.of(v ? 0xff : 0));
/** Context-specific tag: `[n]` constructed (explicit) or primitive (implicit). */
export const ctx = (n: number, constructed: boolean, ...c: Uint8Array[]) => der(0x80 | (constructed ? 0x20 : 0) | n, ...c);

export function int(v: number | Uint8Array): Uint8Array {
  let b: Uint8Array;
  if (typeof v === 'number') {
    const bytes: number[] = [];
    for (let x = v; x > 0; x = Math.floor(x / 256)) bytes.unshift(x & 0xff);
    b = Uint8Array.from(bytes.length ? bytes : [0]);
  } else {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    b = v.subarray(i);
  }
  return der(TAG.INTEGER, b[0]! & 0x80 ? Buffer.concat([Uint8Array.of(0), b]) : b);
}

export function oid(dotted: string): Uint8Array {
  const [a, b, ...rest] = dotted.split('.').map(Number);
  const out: number[] = [a! * 40 + b!];
  for (const n of rest) {
    const chunk: number[] = [n & 0x7f];
    for (let v = Math.floor(n / 128); v > 0; v = Math.floor(v / 128)) chunk.unshift((v & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return der(TAG.OID, Uint8Array.from(out));
}

/** UTCTime before 2050, GeneralizedTime after (RFC 5280 §4.1.2.5). */
export function time(d: Date): Uint8Array {
  const iso = d.toISOString().replace(/[-:T]/g, '').slice(0, 14);
  return d.getUTCFullYear() < 2050 ? der(TAG.UTC_TIME, new TextEncoder().encode(`${iso.slice(2)}Z`)) : der(TAG.GENERALIZED_TIME, new TextEncoder().encode(`${iso}Z`));
}
