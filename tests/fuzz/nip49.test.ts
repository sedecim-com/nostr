/** SEC-03: NIP-49 ncryptsec — round-trip (low logN), NFKC passwords, differential vs nostr-tools, wrong password and garbage rejection. */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { bech32 } from '@scure/base';
import * as ntNip49 from 'nostr-tools/nip49';
import { nip49 } from '@sedecim/nostr-core';
import { runs, secretKey, text, throwsCleanly } from './arbitraries';

const logn = fc.integer({ min: 1, max: 4 });
const ksb = fc.constantFrom(0x00, 0x01, 0x02) as fc.Arbitrary<0 | 1 | 2>;
const password = text({ maxLength: 40 });

describe('NIP-49 (fuzz)', () => {
  it('encrypt → decrypt round-trips, accepts any NFKC-equivalent password, and interoperates with nostr-tools', () => {
    fc.assert(
      fc.property(secretKey(), password, logn, ksb, (sk, pw, n, k) => {
        const enc = nip49.encryptKey(sk, pw, n, k);
        expect(enc).toMatch(/^ncryptsec1[023456789acdefghjklmnpqrstuvwxyz]{152}$/);
        expect(nip49.decryptKey(enc, pw)).toEqual({ secretKey: sk, keySecurity: k, logn: n });
        expect(nip49.decryptKey(enc, pw.normalize('NFD')).secretKey).toEqual(sk);
        expect(ntNip49.decrypt(enc, pw)).toEqual(sk);
        expect(nip49.decryptKey(ntNip49.encrypt(sk, pw, n, k), pw).secretKey).toEqual(sk);
      }),
      runs(25),
    );
  });

  it('async variants agree with the sync ones', async () => {
    await fc.assert(
      fc.asyncProperty(secretKey(), password, logn, async (sk, pw, n) => {
        expect((await nip49.decryptKeyAsync(await nip49.encryptKeyAsync(sk, pw, n), pw)).secretKey).toEqual(sk);
        expect((await nip49.decryptKeyAsync(nip49.encryptKey(sk, pw, n), pw)).secretKey).toEqual(sk);
      }),
      runs(10),
    );
  });

  it('a wrong password is rejected', () => {
    fc.assert(
      fc.property(secretKey(), password, password, logn, (sk, pw, other, n) => {
        // Passwords that differ only in trailing U+0000 are equivalent: scrypt's PBKDF2-HMAC zero-pads the
        // key (inherent to NIP-49, same in nostr-tools; see the next test).
        const norm = (p: string) => p.normalize('NFKC').replace(/\0+$/, '');
        fc.pre(norm(pw) !== norm(other));
        expect(throwsCleanly(() => nip49.decryptKey(nip49.encryptKey(sk, pw, n), other))).toBe(true);
      }),
      runs(25),
    );
  });

  it('known property: trailing NUL characters do not change the key (HMAC key padding)', () => {
    const enc = nip49.encryptKey(new Uint8Array(32).fill(1), 'clave', 1);
    expect(nip49.decryptKey(enc, 'clave\0').secretKey).toEqual(new Uint8Array(32).fill(1));
    expect(ntNip49.decrypt(enc, 'clave\0')).toEqual(new Uint8Array(32).fill(1));
  });

  it('mutated or garbage ncryptsec strings throw an Error (bounded work)', () => {
    const structured = fc
      .tuple(fc.oneof(fc.uint8Array({ maxLength: 120 }), fc.uint8Array({ minLength: 91, maxLength: 91 })), fc.integer({ min: 0, max: 255 }), fc.boolean())
      .map(([body, v, cheap]) => {
        const b = new Uint8Array(body);
        // Keep scrypt cheap: a logN byte above 4 is only kept when it is invalid for scrypt (> 20).
        if (b.length > 1) b[1] = cheap ? (b[1]! % 5) : Math.max(21, b[1]!);
        if (b.length > 0 && v % 2 === 0) b[0] = 2;
        return bech32.encode('ncryptsec', bech32.toWords(b), 5000);
      });
    fc.assert(
      fc.property(fc.oneof(structured, fc.string({ maxLength: 200 }), fc.constant('ncryptsec1')), password, (s, pw) => {
        expect(throwsCleanly(() => nip49.decryptKey(s, pw))).toBe(true);
      }),
      runs(200),
    );
  });

  it('any single-character change to a valid ncryptsec is rejected', () => {
    const CHARS = '023456789acdefghjklmnpqrstuvwxyz';
    fc.assert(
      fc.property(secretKey(), fc.nat(), fc.integer({ min: 1, max: 31 }), (sk, pos, d) => {
        const enc = nip49.encryptKey(sk, 'pw', 1);
        const i = 10 + (pos % (enc.length - 10));
        const bad = enc.slice(0, i) + CHARS[(CHARS.indexOf(enc[i]!) + d) % 32] + enc.slice(i + 1);
        expect(throwsCleanly(() => nip49.decryptKey(bad, 'pw'))).toBe(true);
      }),
      runs(60),
    );
  });
});
