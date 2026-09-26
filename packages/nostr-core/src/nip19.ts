import { bech32 } from '@scure/base';
import { bytesToHex, hexToBytes, utf8ToBytes, bytesToUtf8 } from './utils';

const BECH32_LIMIT = 5000;

export type Nip19Decoded =
  | { type: 'npub'; data: string }
  | { type: 'nsec'; data: Uint8Array }
  | { type: 'note'; data: string }
  | { type: 'nprofile'; data: { pubkey: string; relays: string[] } }
  | { type: 'nevent'; data: { id: string; relays: string[]; author?: string; kind?: number } };

function encodeBytes(prefix: string, bytes: Uint8Array): string {
  return bech32.encode(prefix, bech32.toWords(bytes), BECH32_LIMIT);
}

export function npubEncode(pubkeyHex: string): string {
  return encodeBytes('npub', hexToBytes(pubkeyHex));
}

export function nsecEncode(secretKey: Uint8Array): string {
  return encodeBytes('nsec', secretKey);
}

export function noteEncode(idHex: string): string {
  return encodeBytes('note', hexToBytes(idHex));
}

function encodeTlv(entries: Array<[number, Uint8Array]>): Uint8Array {
  const parts: number[] = [];
  for (const [t, v] of entries) {
    if (v.length > 255) throw new Error('TLV value too long');
    parts.push(t, v.length, ...v);
  }
  return new Uint8Array(parts);
}

function decodeTlv(data: Uint8Array): Map<number, Uint8Array[]> {
  const out = new Map<number, Uint8Array[]>();
  let i = 0;
  while (i < data.length) {
    const t = data[i]!;
    const l = data[i + 1];
    if (l === undefined || i + 2 + l > data.length) throw new Error('malformed TLV');
    const v = data.slice(i + 2, i + 2 + l);
    out.set(t, [...(out.get(t) ?? []), v]);
    i += 2 + l;
  }
  return out;
}

export function nprofileEncode(pubkey: string, relays: string[] = []): string {
  return encodeBytes('nprofile', encodeTlv([[0, hexToBytes(pubkey)], ...relays.map((r) => [1, utf8ToBytes(r)] as [number, Uint8Array])]));
}

export function neventEncode(id: string, relays: string[] = [], author?: string, kind?: number): string {
  const entries: Array<[number, Uint8Array]> = [[0, hexToBytes(id)], ...relays.map((r) => [1, utf8ToBytes(r)] as [number, Uint8Array])];
  if (author) entries.push([2, hexToBytes(author)]);
  if (kind !== undefined) entries.push([3, new Uint8Array([(kind >>> 24) & 0xff, (kind >>> 16) & 0xff, (kind >>> 8) & 0xff, kind & 0xff])]);
  return encodeBytes('nevent', encodeTlv(entries));
}

export function decode(value: string): Nip19Decoded {
  const { prefix, words } = bech32.decode(value as `${string}1${string}`, BECH32_LIMIT);
  const data = new Uint8Array(bech32.fromWords(words));
  switch (prefix) {
    case 'npub':
      if (data.length !== 32) throw new Error('invalid npub length');
      return { type: 'npub', data: bytesToHex(data) };
    case 'nsec':
      if (data.length !== 32) throw new Error('invalid nsec length');
      return { type: 'nsec', data };
    case 'note':
      if (data.length !== 32) throw new Error('invalid note length');
      return { type: 'note', data: bytesToHex(data) };
    case 'nprofile': {
      const tlv = decodeTlv(data);
      const pk = tlv.get(0)?.[0];
      if (!pk || pk.length !== 32) throw new Error('nprofile missing pubkey');
      return { type: 'nprofile', data: { pubkey: bytesToHex(pk), relays: (tlv.get(1) ?? []).map(bytesToUtf8) } };
    }
    case 'nevent': {
      const tlv = decodeTlv(data);
      const id = tlv.get(0)?.[0];
      if (!id || id.length !== 32) throw new Error('nevent missing id');
      const author = tlv.get(2)?.[0];
      const kind = tlv.get(3)?.[0];
      return {
        type: 'nevent',
        data: {
          id: bytesToHex(id),
          relays: (tlv.get(1) ?? []).map(bytesToUtf8),
          ...(author ? { author: bytesToHex(author) } : {}),
          ...(kind && kind.length === 4 ? { kind: ((kind[0]! << 24) | (kind[1]! << 16) | (kind[2]! << 8) | kind[3]!) >>> 0 } : {}),
        },
      };
    }
    default:
      throw new Error(`unsupported NIP-19 prefix: ${prefix}`);
  }
}

/** Accepts hex or npub/nprofile and returns hex pubkey. */
export function normalizePubkey(value: string): string {
  if (/^[0-9a-f]{64}$/.test(value)) return value;
  const d = decode(value);
  if (d.type === 'npub') return d.data;
  if (d.type === 'nprofile') return d.data.pubkey;
  throw new Error('expected npub, nprofile or hex pubkey');
}
