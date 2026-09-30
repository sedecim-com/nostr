/**
 * Minimal CBOR (RFC 8949) codec for Nitro attestation documents (COSE_Sign1). Definite lengths only;
 * maps decode to Map so integer keys (COSE headers, PCR indexes) survive. No node:* APIs: the enclave, its
 * parent and a browser checking an attestation (FR005-10) share it.
 */

export class CborTag {
  constructor(readonly tag: number, readonly value: unknown) {}
}

export type CborValue = number | string | boolean | null | undefined | Uint8Array | CborValue[] | Map<CborValue, CborValue> | CborTag;

class Reader {
  pos = 0;
  constructor(private readonly buf: Uint8Array) {}

  private need(n: number) {
    if (this.pos + n > this.buf.length) throw new Error('cbor: truncated input');
  }
  byte() {
    this.need(1);
    return this.buf[this.pos++]!;
  }
  bytes(n: number) {
    this.need(n);
    const out = new Uint8Array(this.buf.subarray(this.pos, this.pos + n));
    this.pos += n;
    return out;
  }
  uint(info: number): number {
    if (info < 24) return info;
    const width = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0;
    if (!width) throw new Error('cbor: indefinite lengths are not supported');
    const b = this.bytes(width);
    let v = 0n;
    for (const x of b) v = (v << 8n) | BigInt(x);
    if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('cbor: integer out of range');
    return Number(v);
  }
}

function read(r: Reader, depth: number): CborValue {
  if (depth > 32) throw new Error('cbor: nesting too deep');
  const ib = r.byte();
  const major = ib >> 5;
  const info = ib & 0x1f;
  switch (major) {
    case 0:
      return r.uint(info);
    case 1:
      return -1 - r.uint(info);
    case 2:
      return r.bytes(r.uint(info));
    case 3:
      return new TextDecoder('utf-8', { fatal: true }).decode(r.bytes(r.uint(info)));
    case 4: {
      const n = r.uint(info);
      const out: CborValue[] = [];
      for (let i = 0; i < n; i++) out.push(read(r, depth + 1));
      return out;
    }
    case 5: {
      const n = r.uint(info);
      const out = new Map<CborValue, CborValue>();
      for (let i = 0; i < n; i++) {
        const k = read(r, depth + 1);
        if (out.has(k)) throw new Error('cbor: duplicate map key');
        out.set(k, read(r, depth + 1));
      }
      return out;
    }
    case 6:
      return new CborTag(r.uint(info), read(r, depth + 1));
    default:
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      if (info === 23) return undefined;
      if (info === 25) return halfToFloat((r.byte() << 8) | r.byte());
      if (info === 26) return new DataView(r.bytes(4).buffer).getFloat32(0);
      if (info === 27) return new DataView(r.bytes(8).buffer).getFloat64(0);
      throw new Error(`cbor: unsupported simple value ${info}`);
  }
}

function halfToFloat(h: number) {
  const exp = (h >> 10) & 0x1f;
  const mant = h & 0x3ff;
  const val = exp === 0 ? mant * 2 ** -24 : exp === 31 ? (mant ? NaN : Infinity) : (mant + 1024) * 2 ** (exp - 25);
  return h & 0x8000 ? -val : val;
}

/** Decodes exactly one CBOR item; trailing bytes are an error. */
export function decodeCbor(buf: Uint8Array): CborValue {
  const r = new Reader(buf);
  const v = read(r, 0);
  if (r.pos !== buf.length) throw new Error('cbor: trailing bytes');
  return v;
}

function head(major: number, n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('cbor: invalid length/integer');
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 0x100) return Uint8Array.of((major << 5) | 24, n);
  if (n < 0x10000) return Uint8Array.of((major << 5) | 25, n >> 8, n & 0xff);
  if (n < 0x100000000) return Uint8Array.of((major << 5) | 26, n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
  const out = new Uint8Array(9);
  out[0] = (major << 5) | 27;
  new DataView(out.buffer).setBigUint64(1, BigInt(n));
  return out;
}

function write(v: unknown, parts: Uint8Array[]) {
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error('cbor: floats are not supported by the encoder');
    parts.push(v >= 0 ? head(0, v) : head(1, -1 - v));
  } else if (typeof v === 'string') {
    const b = new TextEncoder().encode(v);
    parts.push(head(3, b.length), b);
  } else if (v instanceof Uint8Array) {
    parts.push(head(2, v.length), v);
  } else if (Array.isArray(v)) {
    parts.push(head(4, v.length));
    for (const x of v) write(x, parts);
  } else if (v instanceof Map) {
    parts.push(head(5, v.size));
    for (const [k, x] of v) (write(k, parts), write(x, parts));
  } else if (v instanceof CborTag) {
    parts.push(head(6, v.tag));
    write(v.value, parts);
  } else if (v === null) parts.push(Uint8Array.of(0xf6));
  else if (v === undefined) parts.push(Uint8Array.of(0xf7));
  else if (v === true) parts.push(Uint8Array.of(0xf5));
  else if (v === false) parts.push(Uint8Array.of(0xf4));
  else if (typeof v === 'object') {
    const entries = Object.entries(v as Record<string, unknown>);
    parts.push(head(5, entries.length));
    for (const [k, x] of entries) (write(k, parts), write(x, parts));
  } else throw new Error(`cbor: cannot encode ${typeof v}`);
}

/** Encodes a value (integers, strings, bytes, arrays, Map/objects, null, booleans, tags). */
export function encodeCbor(v: unknown): Uint8Array {
  const parts: Uint8Array[] = [];
  write(v, parts);
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) (out.set(p, at), (at += p.length));
  return out;
}
