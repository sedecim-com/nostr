/**
 * Internal review 2026-09: the hand-written WebAuthn CBOR decoder and registration verifier of the
 * policy-engine (FR023-07). Any input must be accepted or rejected with WebAuthnError (a 400), never
 * another exception (a 500) or a hang.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { cborDecode, verifyRegistration, WebAuthnError, type RegistrationCredentialJSON } from '@sedecim/policy-engine';
import { cborEncode, TestAuthenticator, type C } from '../../services/policy-engine/test/webauthn-fixture';
import { runs } from './arbitraries';

const onlyWebAuthnErrors = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    if (!(e instanceof WebAuthnError)) throw new Error(`unexpected ${(e as Error)?.constructor?.name}: ${String(e)}`);
  }
};

/** Values the fixture encoder can write, with unique map keys (canonical CTAP2 CBOR). */
const { value: cborValue } = fc.letrec((tie) => ({
  leaf: fc.oneof(fc.integer({ min: -(2 ** 31), max: 2 ** 32 - 1 }), fc.string({ maxLength: 20 }), fc.uint8Array({ maxLength: 40 })),
  value: fc.oneof(
    { depthSize: 'small' },
    tie('leaf'),
    fc.array(tie('value'), { maxLength: 5 }),
    fc.uniqueArray(fc.tuple(fc.oneof(fc.integer({ min: -100, max: 100 }), fc.string({ maxLength: 8 })), tie('value')), { maxLength: 5, selector: ([k]) => k }).map((e) => new Map(e)),
  ),
})) as { value: fc.Arbitrary<C> };

describe('policy-engine WebAuthn CBOR (fuzz)', () => {
  it('decode ∘ encode is the identity and consumes every byte', () => {
    fc.assert(
      fc.property(cborValue, (v) => {
        const bytes = cborEncode(v);
        const r = cborDecode(bytes);
        expect(r.offset).toBe(bytes.length);
        expect(r.value).toEqual(v);
      }),
      runs(500),
    );
  });

  it('random and mutated bytes only ever yield a value or WebAuthnError', () => {
    const mutated = fc.tuple(cborValue, fc.nat(), fc.integer({ min: 1, max: 255 })).map(([v, i, x]) => {
      const b = cborEncode(v).slice();
      b[i % b.length]! ^= x;
      return b;
    });
    fc.assert(fc.property(fc.oneof(fc.uint8Array({ maxLength: 200 }), mutated), (b) => onlyWebAuthnErrors(() => cborDecode(b))), runs(2000));
  });

  it('regressions: invalid UTF-8, duplicate keys, huge declared lengths, deep nesting', () => {
    expect(() => cborDecode(Uint8Array.of(0x62, 0xc3, 0x28))).toThrow(WebAuthnError);
    expect(() => cborDecode(Uint8Array.of(0xa2, 0x01, 0x02, 0x01, 0x03))).toThrow(/duplicate/);
    expect(() => cborDecode(Uint8Array.of(0x5b, 0, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff))).toThrow(WebAuthnError);
    expect(() => cborDecode(Uint8Array.of(0x9b, 0, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff))).toThrow(WebAuthnError);
    expect(() => cborDecode(new Uint8Array(64).fill(0x81))).toThrow(/too deep/);
  });
});

describe('policy-engine verifyRegistration (fuzz)', () => {
  const auth = new TestAuthenticator();
  const expected = { challenge: 'Y2hhbGxlbmdlLWZ1enotMDAx', origins: ['https://app.example'], rpId: 'app.example', allowNone: true };
  const good = auth.create({ challenge: expected.challenge, origin: expected.origins[0]!, rpId: expected.rpId }) as RegistrationCredentialJSON;
  const attBytes = new Uint8Array(Buffer.from(good.response.attestationObject, 'base64url'));
  const withAtt = (b: Uint8Array): RegistrationCredentialJSON => ({ ...good, response: { ...good.response, attestationObject: Buffer.from(b).toString('base64url') } });

  it('the fixture credential verifies (sanity)', () => {
    expect(verifyRegistration(good, expected).fmt).toBe('packed');
  });

  it('any mutated attestationObject is rejected with WebAuthnError or still verifies the same credential', () => {
    fc.assert(
      fc.property(fc.array(fc.tuple(fc.nat(), fc.integer({ min: 1, max: 255 })), { minLength: 1, maxLength: 4 }), (flips) => {
        const b = attBytes.slice();
        for (const [i, x] of flips) b[i % b.length]! ^= x;
        try {
          const r = verifyRegistration(withAtt(b), expected);
          expect(r.credentialId).toBe(good.id); // a flip in an ignored byte (e.g. aaguid) may still verify
        } catch (e) {
          if (!(e instanceof WebAuthnError)) throw e;
        }
      }),
      runs(1000),
    );
  });

  it('truncations, trailing bytes and garbage attestation statements are WebAuthnError', () => {
    fc.assert(fc.property(fc.nat({ max: attBytes.length - 1 }), (n) => onlyWebAuthnErrors(() => verifyRegistration(withAtt(attBytes.subarray(0, n)), expected))), runs(200));
    expect(() => verifyRegistration(withAtt(new Uint8Array([...attBytes, 0])), expected)).toThrow(/trailing/);
    const att = cborDecode(attBytes).value as Map<C, C>;
    const stmt = att.get('attStmt') as Map<C, C>;
    const variants: Array<Map<C, C>> = [
      new Map([...stmt, ['x5c', [new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01])]]]),
      new Map([...stmt, ['x5c', ['not bytes']]]),
      new Map([...stmt, ['sig', new Uint8Array(3)]]),
    ];
    for (const s of variants) expect(() => verifyRegistration(withAtt(cborEncode(new Map([...att, ['attStmt', s]]))), expected)).toThrow(WebAuthnError);
    // Credential key that is not a point on P-256.
    const authData = (att.get('authData') as Uint8Array).slice();
    authData[authData.length - 1]! ^= 1;
    expect(() => verifyRegistration(withAtt(cborEncode(new Map([...att, ['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]))), expected)).toThrow(WebAuthnError);
  });
});
