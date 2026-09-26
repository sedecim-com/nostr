import { base64 } from '@scure/base';
import type { Collection, EncryptedStore } from '@sedecim/encrypted-store';
import type { GroupStorage } from './types';

/** Tagged JSON codec so MLS state (Uint8Array, bigint, Map, Set) survives an encrypted JSON store. */
export function encodeValue(v: unknown): unknown {
  if (v instanceof Uint8Array) return { $u8: base64.encode(v) };
  if (typeof v === 'bigint') return { $bi: v.toString() };
  if (v instanceof Map) return { $map: [...v.entries()].map(([k, x]) => [encodeValue(k), encodeValue(x)]) };
  if (v instanceof Set) return { $set: [...v].map(encodeValue) };
  if (v === undefined) return { $undef: 1 };
  // JSON turns NaN/±Infinity into null and -0 into 0: tag them (found by SEC-03 fuzz).
  if (typeof v === 'number' && (!Number.isFinite(v) || Object.is(v, -0))) return { $num: Object.is(v, -0) ? '-0' : String(v) };
  if (Array.isArray(v)) return v.map(encodeValue);
  if (v && typeof v === 'object') {
    if (ArrayBuffer.isView(v)) throw new Error(`unsupported typed array ${v.constructor.name}`);
    return { $obj: Object.fromEntries(Object.entries(v).map(([k, x]) => [k, encodeValue(x)])) };
  }
  if (typeof v === 'function' || typeof v === 'symbol') throw new Error(`cannot persist ${typeof v}`);
  return v;
}

export function decodeValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(decodeValue);
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    if ('$u8' in o) return base64.decode(o.$u8 as string);
    if ('$bi' in o) return BigInt(o.$bi as string);
    if ('$map' in o) return new Map((o.$map as unknown[][]).map(([k, x]) => [decodeValue(k), decodeValue(x)]));
    if ('$set' in o) return new Set((o.$set as unknown[]).map(decodeValue));
    if ('$undef' in o) return undefined;
    if ('$num' in o) return Number(o.$num);
    if ('$obj' in o) return Object.fromEntries(Object.entries(o.$obj as Record<string, unknown>).map(([k, x]) => [k, decodeValue(x)]));
  }
  return v;
}

/** GroupStorage over EncryptedStore: MLS secrets are sealed with XChaCha20-Poly1305 at rest. */
export class EncryptedGroupStorage implements GroupStorage {
  private readonly cols = new Map<string, Collection<unknown>>();
  constructor(private readonly store: EncryptedStore) {}
  private col(ns: string) {
    let c = this.cols.get(ns);
    if (!c) {
      c = this.store.collection<unknown>(`mls-${ns}`);
      this.cols.set(ns, c);
    }
    return c;
  }
  async get(ns: string, key: string) {
    const v = await this.col(ns).get(key);
    return v === undefined ? undefined : decodeValue(v);
  }
  async put(ns: string, key: string, value: unknown) {
    await this.col(ns).put(key, encodeValue(value));
  }
  async delete(ns: string, key: string) {
    await this.col(ns).delete(key);
  }
  async keys(ns: string) {
    return (await this.col(ns).all()).map((e) => e.id);
  }
}
