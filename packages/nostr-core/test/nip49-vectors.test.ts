import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { bech32 } from '@scure/base';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../src/utils';
import { nip49 } from '../src/index';
import { FILES, render } from './vectors/generate';

// SEC-07 (ADR 0004): exportable NIP-49 vectors, built by vectors/generate.ts without the SDK code under test.
const V = JSON.parse(readFileSync(new URL('./vectors/nip49.vectors.json', import.meta.url), 'utf8'));
/** The fields an ncryptsec carries: version, log_n, salt, nonce, key security byte, ciphertext. */
const fields = (ncryptsec: string) => {
  const b = new Uint8Array(bech32.fromWords(bech32.decode(ncryptsec as `${string}1${string}`, 5000).words));
  return { logN: b[1], salt: bytesToHex(b.slice(2, 18)), nonce: bytesToHex(b.slice(18, 42)), keySecurity: b[42] };
};

describe('NIP-49 vectors', () => {
  it('the vector published in NIP-49 decrypts', () => {
    for (const v of V.official) {
      const r = nip49.decryptKey(v.ncryptsec, v.password);
      expect([bytesToHex(r.secretKey), r.logn]).toEqual([v.sec, v.log_n]);
    }
  });

  it('passwords are NFKC-normalized', () => {
    for (const v of V.normalization) {
      const password = new TextDecoder().decode(hexToBytes(v.password_utf8));
      expect(bytesToHex(utf8ToBytes(password.normalize('NFKC')))).toBe(v.password_nfkc_utf8);
    }
  });

  it('valid: each opens to its key, cost and key security, with the salt and nonce it declares', () => {
    for (const v of V.valid) {
      const r = nip49.decryptKey(v.ncryptsec, v.password);
      expect([bytesToHex(r.secretKey), r.logn, r.keySecurity], v.note).toEqual([v.sec, v.log_n, v.key_security]);
      expect(fields(v.ncryptsec), v.note).toEqual({ logN: v.log_n, salt: v.salt, nonce: v.nonce, keySecurity: v.key_security });
      expect(bytesToHex(utf8ToBytes(v.password.normalize('NFKC')))).toBe(v.password_nfkc_utf8);
      // The password as NFKC leaves it opens the key too: what counts is the normalized form.
      const normalized = new TextDecoder().decode(hexToBytes(v.password_nfkc_utf8));
      expect(bytesToHex(nip49.decryptKey(v.ncryptsec, normalized).secretKey), v.note).toBe(v.sec);
    }
  });

  it('what encryptKey writes opens with the same password and keeps cost and key security', () => {
    const v = V.valid[1];
    const again = nip49.encryptKey(hexToBytes(v.sec), v.password, v.log_n, v.key_security);
    expect(again).not.toBe(v.ncryptsec); // fresh salt and nonce
    const r = nip49.decryptKey(again, v.password);
    expect([bytesToHex(r.secretKey), r.logn, r.keySecurity]).toEqual([v.sec, v.log_n, v.key_security]);
  });

  it('invalid: each case is rejected', () => {
    expect(V.invalid).toHaveLength(5);
    for (const v of V.invalid) {
      const opts = v.max_log_n === undefined ? {} : { maxLogN: v.max_log_n };
      expect(() => nip49.decryptKey(v.ncryptsec, v.password, opts), v.note).toThrow(v.max_log_n === undefined ? undefined : /exceeds the allowed maximum/);
    }
  });
});

describe('exported vector files', () => {
  it('are exactly what vectors/generate.ts writes', () => {
    for (const [name, build] of Object.entries(FILES)) expect(readFileSync(new URL(`./vectors/${name}`, import.meta.url), 'utf8'), name).toBe(render(build));
  });
});
