/**
 * Server (non-initiator) side of NIP-77 Negentropy for the test relay. nostr-tools ships storage,
 * fingerprints and the initiator; its `reconcile` does not answer IdList ranges as a responder must,
 * so this class overrides only that loop and reuses everything else (bounds, splitRange, fingerprints).
 */
import { nip77 } from 'nostr-tools';
import { bytesToHex, hexToBytes } from '@sedecim/nostr-core';

const PROTOCOL_VERSION = 0x61;
const ID_SIZE = 32;
const FINGERPRINT_SIZE = 16;
const MODE = { Skip: 0, Fingerprint: 1, IdList: 2 } as const;

/** Minimal byte reader with the shape nostr-tools' decoders expect (length/shift/shiftN). */
class Reader {
  constructor(private raw: Uint8Array) {}
  get length(): number {
    return this.raw.length;
  }
  shift(): number {
    if (this.raw.length === 0) throw new Error('parse ends prematurely');
    const b = this.raw[0]!;
    this.raw = this.raw.subarray(1);
    return b;
  }
  shiftN(n = 1): Uint8Array {
    if (this.raw.length < n) throw new Error('parse ends prematurely');
    const out = this.raw.subarray(0, n);
    this.raw = this.raw.subarray(n);
    return out;
  }
}

/** Byte writer accepting raw bytes or nostr-tools' internal buffers (anything with `unwrap()`). */
class Writer {
  private readonly parts: number[] = [];
  get length(): number {
    return this.parts.length;
  }
  extend(buf: Uint8Array | { unwrap(): Uint8Array }): void {
    for (const b of buf instanceof Uint8Array ? buf : buf.unwrap()) this.parts.push(b);
  }
  bytes(): Uint8Array {
    return Uint8Array.from(this.parts);
  }
}

function decodeVarInt(r: Reader): number {
  let res = 0;
  for (;;) {
    const byte = r.shift();
    res = (res << 7) | (byte & 0x7f);
    if ((byte & 0x80) === 0) return res;
  }
}

function encodeVarInt(n: number): Uint8Array {
  if (n === 0) return new Uint8Array([0]);
  const o: number[] = [];
  while (n !== 0) {
    o.push(n & 0x7f);
    n >>>= 7;
  }
  o.reverse();
  for (let i = 0; i < o.length - 1; i++) o[i]! |= 0x80;
  return Uint8Array.from(o);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export class NegentropyResponder extends nip77.Negentropy {
  constructor(events: Iterable<{ id: string; created_at: number }>) {
    const storage = new nip77.NegentropyStorageVector();
    for (const e of events) storage.insert(e.created_at, e.id);
    storage.seal();
    super(storage);
  }

  /** Answers one client message. Always returns a message (at least the version byte = "done"). */
  respond(queryHex: string): string {
    const query = new Reader(hexToBytes(queryHex));
    this.lastTimestampIn = this.lastTimestampOut = 0;
    const full = new Writer();
    full.extend(new Uint8Array([PROTOCOL_VERSION]));
    // NIP-77: a responder that does not speak the requested version answers with its own version byte only.
    if (query.shift() !== PROTOCOL_VERSION) return bytesToHex(full.bytes());
    const storage = this.storage;
    const size = storage.size();
    let prevBound = this._bound(0);
    let prevIndex = 0;
    let skip = false;
    while (query.length !== 0) {
      const o = new Writer();
      const doSkip = () => {
        if (!skip) return;
        skip = false;
        o.extend(this.encodeBound(prevBound));
        o.extend(encodeVarInt(MODE.Skip));
      };
      const currBound = this.decodeBound(query as never);
      const mode = decodeVarInt(query);
      const lower = prevIndex;
      const upper = storage.findLowerBound(prevIndex, size, currBound);
      if (mode === MODE.Skip) {
        skip = true;
      } else if (mode === MODE.Fingerprint) {
        const theirs = query.shiftN(FINGERPRINT_SIZE);
        if (!sameBytes(theirs, storage.fingerprint(lower, upper))) {
          doSkip();
          this.splitRange(lower, upper, currBound, o as never);
        } else skip = true;
      } else if (mode === MODE.IdList) {
        // The initiator computes have/need; the responder replies with its full id list for the range.
        query.shiftN(decodeVarInt(query) * ID_SIZE);
        doSkip();
        const ids: Uint8Array[] = [];
        storage.iterate(lower, upper, (item) => (ids.push(item.id), true));
        o.extend(this.encodeBound(currBound));
        o.extend(encodeVarInt(MODE.IdList));
        o.extend(encodeVarInt(ids.length));
        for (const id of ids) o.extend(id);
      } else {
        throw new Error('unexpected mode');
      }
      full.extend(o.bytes()); // no frame-size limit: test data sets are small
      prevIndex = upper;
      prevBound = currBound;
    }
    return bytesToHex(full.bytes());
  }
}
