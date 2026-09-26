/** SEC-03: NIP-44 v2 — round-trip for 1..65535-byte unicode plaintexts, differential vs nostr-tools, mutation rejection. */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { v2 as ntNip44 } from 'nostr-tools/nip44';
import { getPublicKey, nip44 } from '@sedecim/nostr-core';
import { runs, secretKey, text, throwsCleanly, utf8Len } from './arbitraries';

const nonce = () => fc.uint8Array({ minLength: 32, maxLength: 32 });
/** Mostly short texts plus the length boundaries (1 byte, padding steps, 64 KiB - 1). */
const plaintext = fc.oneof(
  { weight: 6, arbitrary: text({ minLength: 1, maxLength: 400 }) },
  { weight: 2, arbitrary: fc.tuple(fc.integer({ min: 1, max: 65535 }), fc.constantFrom('a', 'ñ', '€', '𝄞')).map(([n, c]) => c.repeat(Math.max(1, Math.floor(n / utf8Len(c))))) },
  { weight: 1, arbitrary: fc.constantFrom('x', 'x'.repeat(32), 'x'.repeat(33), 'x'.repeat(256), 'x'.repeat(257), 'x'.repeat(65535)) },
);

describe('NIP-44 v2 (fuzz)', () => {
  it('encrypt → decrypt round-trips and is byte-identical to nostr-tools for the same nonce', () => {
    fc.assert(
      fc.property(secretKey(), secretKey(), plaintext, nonce(), (a, b, pt, n) => {
        fc.pre(utf8Len(pt) >= 1 && utf8Len(pt) <= 65535);
        const ck = nip44.getConversationKey(a, getPublicKey(b));
        expect(ck).toEqual(nip44.getConversationKey(b, getPublicKey(a)));
        expect(ck).toEqual(ntNip44.utils.getConversationKey(a, getPublicKey(b)));
        const payload = nip44.encrypt(pt, ck, n);
        expect(payload).toBe(ntNip44.encrypt(pt, ck, n));
        expect(nip44.decrypt(payload, ck)).toBe(pt);
        expect(Buffer.from(payload, 'base64').length).toBe(1 + 32 + 2 + nip44.calcPaddedLen(utf8Len(pt)) + 32);
      }),
      runs(40),
    );
  });

  it('rejects out-of-range plaintexts', () => {
    const ck = new Uint8Array(32).fill(1);
    expect(throwsCleanly(() => nip44.encrypt('', ck))).toBe(true);
    expect(throwsCleanly(() => nip44.encrypt('x'.repeat(65536), ck))).toBe(true);
  });

  it('any mutated payload is rejected with an Error, never decrypted to something else', () => {
    fc.assert(
      fc.property(secretKey(), secretKey(), text({ minLength: 1, maxLength: 200 }), fc.nat(), fc.integer({ min: 1, max: 255 }), fc.constantFrom('flip', 'truncate', 'extend'), (a, b, pt, pos, x, how) => {
        const ck = nip44.getConversationKey(a, getPublicKey(b));
        const raw = Buffer.from(nip44.encrypt(pt, ck), 'base64');
        let bad: Buffer;
        if (how === 'flip') {
          bad = Buffer.from(raw);
          bad[pos % raw.length]! ^= x;
        } else if (how === 'truncate') bad = raw.subarray(0, pos % raw.length);
        else bad = Buffer.concat([raw, Buffer.alloc(1 + (pos % 64), x)]);
        expect(throwsCleanly(() => nip44.decrypt(bad.toString('base64'), ck))).toBe(true);
        expect(throwsCleanly(() => ntNip44.decrypt(bad.toString('base64'), ck))).toBe(true);
      }),
      runs(150),
    );
  });

  it('a different conversation key never decrypts', () => {
    fc.assert(
      fc.property(secretKey(), secretKey(), secretKey(), text({ minLength: 1, maxLength: 100 }), (a, b, c, pt) => {
        fc.pre(getPublicKey(b) !== getPublicKey(c));
        const payload = nip44.encrypt(pt, nip44.getConversationKey(a, getPublicKey(b)));
        expect(throwsCleanly(() => nip44.decrypt(payload, nip44.getConversationKey(a, getPublicKey(c))))).toBe(true);
      }),
      runs(30),
    );
  });

  it('garbage payloads throw an Error', () => {
    const ck = new Uint8Array(32).fill(7);
    fc.assert(
      fc.property(fc.oneof(fc.string({ maxLength: 400 }), fc.base64String({ minLength: 128, maxLength: 400 }), fc.uint8Array({ minLength: 99, maxLength: 300 }).map((b) => Buffer.from(b).toString('base64'))), (s) => {
        expect(throwsCleanly(() => nip44.decrypt(s, ck))).toBe(true);
      }),
      runs(300),
    );
  });
});
