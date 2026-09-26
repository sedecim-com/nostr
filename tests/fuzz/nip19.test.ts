/** SEC-03: NIP-19 bech32 entities and TLV (nprofile / nevent / naddr) — round-trip, differential vs nostr-tools, parser robustness. */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { bech32 } from '@scure/base';
import * as ntNip19 from 'nostr-tools/nip19';
import { nip19, npubEncode, nsecEncode } from '@sedecim/nostr-core';
import { hex32, runs, secretKey, text, throwsCleanly, utf8Len } from './arbitraries';

const relay = text({ maxLength: 60 }).filter((r) => utf8Len(r) <= 255);
const relays = fc.array(relay, { maxLength: 4 });
const kind = fc.integer({ min: 0, max: 2 ** 32 - 1 });
const identifier = text({ maxLength: 60 }).filter((r) => utf8Len(r) <= 255);

/** Outcome of a decoder as comparable data: the decoded value, or just "threw". */
function outcome(fn: () => unknown): unknown {
  try {
    const r = fn() as { type: string; data: unknown };
    return { type: r.type, data: r.data instanceof Uint8Array ? Buffer.from(r.data).toString('hex') : JSON.parse(JSON.stringify(r.data)) };
  } catch (e) {
    if (!(e instanceof Error)) throw e;
    return 'error';
  }
}

describe('NIP-19 (fuzz)', () => {
  it('npub / nsec / note round-trip and match nostr-tools', () => {
    fc.assert(
      fc.property(hex32(), secretKey(), (h, sk) => {
        expect(nip19.decode(npubEncode(h))).toEqual({ type: 'npub', data: h });
        expect(npubEncode(h)).toBe(ntNip19.npubEncode(h));
        expect(nsecEncode(sk)).toBe(ntNip19.nsecEncode(sk));
        expect(nip19.decode(nsecEncode(sk))).toEqual({ type: 'nsec', data: sk });
        expect(nip19.decode(nip19.noteEncode(h))).toEqual({ type: 'note', data: h });
      }),
      runs(100),
    );
  });

  it('nprofile / nevent / naddr round-trip and agree with nostr-tools both ways', () => {
    fc.assert(
      fc.property(hex32(), hex32(), relays, fc.option(kind, { nil: undefined }), fc.boolean(), identifier, kind, (a, b, rs, k, withAuthor, d, ak) => {
        const np = nip19.nprofileEncode(a, rs);
        expect(nip19.decode(np)).toEqual({ type: 'nprofile', data: { pubkey: a, relays: rs } });
        // TLV order is not normative (nostr-tools writes types in reverse): compare by decoding across.
        expect(nip19.decode(ntNip19.nprofileEncode({ pubkey: a, relays: rs }))).toEqual(nip19.decode(np));
        expect(outcome(() => ntNip19.decode(np))).toEqual(outcome(() => nip19.decode(np)));

        const ne = nip19.neventEncode(a, rs, withAuthor ? b : undefined, k);
        expect(nip19.decode(ne)).toEqual({ type: 'nevent', data: { id: a, relays: rs, ...(withAuthor ? { author: b } : {}), ...(k !== undefined ? { kind: k } : {}) } });
        expect(outcome(() => ntNip19.decode(ne))).toEqual(outcome(() => nip19.decode(ne)));
        const theirsNe = ntNip19.neventEncode({ id: a, relays: rs, ...(withAuthor ? { author: b } : {}), ...(k !== undefined ? { kind: k } : {}) });
        expect(nip19.decode(theirsNe)).toEqual(nip19.decode(ne));

        const na = nip19.naddrEncode(d, b, ak, rs);
        expect(nip19.decode(na)).toEqual({ type: 'naddr', data: { identifier: d, pubkey: b, kind: ak, relays: rs } });
        expect(nip19.decode(ntNip19.naddrEncode({ identifier: d, pubkey: b, kind: ak, relays: rs }))).toEqual(nip19.decode(na));
        expect(outcome(() => ntNip19.decode(na))).toEqual(outcome(() => nip19.decode(na)));
      }),
      runs(100),
    );
  });

  it('random TLV payloads decode exactly like nostr-tools (value or clean error)', () => {
    // Structured TLV soup: known and unknown types, right and wrong lengths, truncated tails.
    const entry = fc.tuple(fc.oneof(fc.constantFrom(0, 1, 2, 3), fc.integer({ min: 0, max: 255 })), fc.oneof(fc.uint8Array({ minLength: 32, maxLength: 32 }), fc.uint8Array({ minLength: 4, maxLength: 4 }), fc.uint8Array({ maxLength: 40 })));
    const tlv = fc.tuple(fc.array(entry, { maxLength: 6 }), fc.uint8Array({ maxLength: 3 })).map(([es, tail]) => new Uint8Array([...es.flatMap(([t, v]) => [t, v.length, ...v]), ...tail]));
    fc.assert(
      fc.property(fc.constantFrom('nprofile', 'nevent', 'naddr'), tlv, (prefix, bytes) => {
        const s = bech32.encode(prefix, bech32.toWords(bytes), 5000);
        const ours = outcome(() => nip19.decode(s));
        const theirs = outcome(() => ntNip19.decode(s));
        // nostr-tools reports absent optional nevent fields as explicit undefined.
        const clean = (o: unknown) => JSON.parse(JSON.stringify(o));
        expect(ours).toEqual(clean(theirs));
      }),
      runs(400),
    );
  });

  it('garbage strings throw an Error quickly (never hang)', () => {
    const CHARS = '023456789acdefghjklmnpqrstuvwxyz';
    const bechish = fc.tuple(fc.constantFrom('npub', 'nsec', 'note', 'nprofile', 'nevent', 'naddr', 'nrelay', ''), fc.array(fc.constantFrom(...CHARS), { maxLength: 300 })).map(([p, cs]) => `${p}1${cs.join('')}`);
    fc.assert(
      fc.property(fc.oneof(bechish, fc.string({ maxLength: 300 }), fc.constant('npub1'.padEnd(6000, 'q'))), (s) => {
        const t0 = performance.now();
        expect(throwsCleanly(() => nip19.decode(s))).toBe(true);
        expect(performance.now() - t0).toBeLessThan(250);
      }),
      runs(400),
    );
  });

  it('any single-character change to an nprofile is rejected', () => {
    const CHARS = '023456789acdefghjklmnpqrstuvwxyz';
    fc.assert(
      fc.property(hex32(), relays, fc.nat(), fc.integer({ min: 1, max: 31 }), (pk, rs, pos, dlt) => {
        const s = nip19.nprofileEncode(pk, rs);
        const i = 9 + (pos % (s.length - 9));
        const bad = s.slice(0, i) + CHARS[(CHARS.indexOf(s[i]!) + dlt) % 32] + s.slice(i + 1);
        expect(throwsCleanly(() => nip19.decode(bad))).toBe(true);
      }),
      runs(100),
    );
  });
});
