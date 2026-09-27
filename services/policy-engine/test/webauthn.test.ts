import { describe, expect, it } from 'vitest';
import { cborDecode, verifyRegistration } from '../src/webauthn';
import { cborEncode, TestAuthenticator, type C } from './webauthn-fixture';

const expected = { challenge: 'Y2hhbGxlbmdlLWNoYWxsZW5nZS1jaGFsbGVuZ2UtMTIz', origins: ['https://app.example'], rpId: 'app.example', allowNone: true };
const create = (a: TestAuthenticator, o: Partial<Parameters<TestAuthenticator['create']>[0]> = {}) => a.create({ challenge: expected.challenge, origin: 'https://app.example', rpId: 'app.example', ...o });

describe('WebAuthn registration verification (FR023-07)', () => {
  it('decodes the CBOR subset it needs', () => {
    const m = cborDecode(cborEncode(new Map<C, C>([[1, -7], ['k', new Uint8Array([1, 2])]]))).value as Map<unknown, unknown>;
    expect(m.get(1)).toBe(-7);
    expect(m.get('k')).toEqual(new Uint8Array([1, 2]));
    expect(() => cborDecode(new Uint8Array([0x5a, 0xff, 0xff, 0xff, 0xff]))).toThrow(/truncated/);
  });

  it('accepts packed self-attestation and none', () => {
    const a = new TestAuthenticator();
    const packed = verifyRegistration(create(a), expected);
    expect(packed).toMatchObject({ fmt: 'packed', signCount: 0, userVerified: true, publicKey: { kty: 'EC', crv: 'P-256' } });
    expect(verifyRegistration(create(a, { fmt: 'none' }), expected).fmt).toBe('none');
  });

  it.each([
    ['wrong challenge', { challenge: 'b3RoZXI' }, /challenge/],
    ['wrong origin', { origin: 'https://evil.example' }, /origin/],
    ['wrong RP id', { rpId: 'evil.example' }, /rpIdHash/],
    ['assertion instead of creation', { type: 'webauthn.get' }, /webauthn.create/],
    ['no user presence', { flags: 0x44 }, /presence/],
    ['bad signature', { tamperSig: true }, /signature/],
  ] as const)('rejects %s', (_n, o, err) => {
    expect(() => verifyRegistration(create(new TestAuthenticator(), o), expected)).toThrow(err);
  });

  it('rejects fmt none when attestation is required, and mismatched credential ids', () => {
    const a = new TestAuthenticator();
    expect(() => verifyRegistration(create(a, { fmt: 'none' }), { ...expected, allowNone: false })).toThrow(/attestation required/);
    const c = create(a);
    expect(() => verifyRegistration({ ...c, id: 'AAAA' }, expected)).toThrow(/credential id/);
  });
});
