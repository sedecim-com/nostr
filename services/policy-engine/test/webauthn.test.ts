import { describe, expect, it } from 'vitest';
import { cborDecode, requestOptions, verifyAssertion, verifyRegistration } from '../src/webauthn';
import { cborEncode, TestAuthenticator, type AssertionInput, type C } from './webauthn-fixture';

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

describe('WebAuthn assertion verification (FR023-11)', () => {
  const auth = new TestAuthenticator();
  const registered = verifyRegistration(create(auth), expected);
  const userHandle = new Uint8Array(32).fill(7);
  const want = { challenge: expected.challenge, origins: expected.origins, rpId: expected.rpId, credentialId: registered.credentialId, publicKey: registered.publicKey, userHandle };
  const get = (o: Partial<AssertionInput> = {}, a = auth) => a.get({ challenge: expected.challenge, origin: 'https://app.example', rpId: 'app.example', ...o });

  it('accepts an assertion of the registered credential and returns its counter', () => {
    expect(verifyAssertion(get({ counter: 7 }), want)).toEqual({ signCount: 7, userVerified: true });
    expect(verifyAssertion(get({ flags: 0x01, userHandle }), { ...want, requireUserVerification: false })).toEqual({ signCount: 0, userVerified: false });
    // Authenticator extensions (ED flag) are one CBOR map up to the end of authenticatorData.
    expect(verifyAssertion(get({ extensions: new Map<C, C>([['credProtect', 1]]) }), want).signCount).toBe(0);
  });

  it('builds request options for the one credential of the device', () => {
    expect(requestOptions({ rpId: 'app.example', challenge: 'Y2g', allowCredentials: [registered.credentialId], userVerification: 'required' })).toEqual({
      challenge: 'Y2g',
      rpId: 'app.example',
      allowCredentials: [{ type: 'public-key', id: registered.credentialId }],
      timeout: 300_000,
      userVerification: 'required',
    });
  });

  it.each([
    ['another challenge', { challenge: 'b3RoZXI' }, /challenge mismatch/],
    ['another origin', { origin: 'https://evil.example' }, /origin not allowed/],
    ['another RP id', { rpId: 'evil.example' }, /rpIdHash mismatch/],
    ['a registration ceremony', { type: 'webauthn.create' }, /webauthn.get/],
    ['a cross-origin iframe', { crossOrigin: true }, /cross-origin/],
    ['no user presence', { flags: 0x04 }, /user presence required/],
    ['attested credential data', { flags: 0x45 }, /attested credential data/],
    ['backup state without eligibility', { flags: 0x15 }, /backup/],
    ['extensions flagged but absent', { flags: 0x85 }, /truncated CBOR|extensions/],
    ['a tampered signature', { tamperSig: true }, /signature invalid/],
    ['another credential id', { id: 'AAAAAAAAAAAAAAAAAAAAAA' }, /credential not allowed/],
    ['another user handle', { userHandle: new Uint8Array(32).fill(8) }, /user handle mismatch/],
  ] as const)('rejects %s', (_n, o, err) => {
    expect(() => verifyAssertion(get(o as Partial<AssertionInput>), want)).toThrow(err);
  });

  it('rejects a signature by another key, missing user verification when required, and trailing bytes', () => {
    // Same credential id claimed, signed by another authenticator: the stored key does not verify it.
    expect(() => verifyAssertion(get({ id: auth.id }, new TestAuthenticator()), want)).toThrow(/signature invalid/);
    expect(() => verifyAssertion(get({ flags: 0x01 }), { ...want, requireUserVerification: true })).toThrow(/user verification required/);
    const a = get();
    const trailing = Buffer.concat([Buffer.from(a.response.authenticatorData, 'base64url'), Buffer.from([0])]).toString('base64url');
    expect(() => verifyAssertion({ ...a, response: { ...a.response, authenticatorData: trailing } }, want)).toThrow(/trailing/);
    expect(() => verifyAssertion({ ...a, rawId: 'AAAA' }, want)).toThrow(/credential id/);
    expect(() => verifyAssertion(a, { ...want, publicKey: { kty: 'RSA', n: 'AQAB', e: 'AQAB' } })).toThrow(/not ES256/);
    expect(() => verifyAssertion(a, { ...want, publicKey: { ...registered.publicKey, x: 'AAAA' } })).toThrow(/invalid/);
  });
});
