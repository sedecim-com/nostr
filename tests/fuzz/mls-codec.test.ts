/**
 * SEC-03: MLS serialization — the tagged-JSON storage codec of the Marmot adapter (encodeValue /
 * decodeValue, which persists ts-mls group state in the encrypted store) and the TLS wire codec of key
 * packages. Real MLS objects come from a marmot-ts session on an in-memory network.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { base64 } from '@scure/base';
import { generateSecretKey, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { MarmotTsProvider, MemoryGroupNetwork, VolatileGroupStorage, decodeValue, encodeValue, mlsCodec } from '@sedecim/marmot-adapter';
import { runs, throwsCleanly } from './arbitraries';

const roundTrip = (v: unknown) => decodeValue(JSON.parse(JSON.stringify(encodeValue(v))));

/** Values shaped like ts-mls state: bytes, bigints, Maps/Sets, undefined, nested objects/arrays. */
const { value: mlsValue } = fc.letrec((tie) => ({
  leaf: fc.oneof(
    fc.uint8Array({ maxLength: 48 }),
    fc.bigInt({ min: -(2n ** 70n), max: 2n ** 70n }),
    fc.integer(),
    fc.double(), // includes NaN, ±Infinity and -0
    fc.string({ maxLength: 20 }),
    fc.boolean(),
    fc.constant(null),
    fc.constant(undefined),
  ),
  value: fc.oneof(
    { depthSize: 'small', withCrossShrink: true },
    tie('leaf'),
    fc.array(tie('value'), { maxLength: 4 }),
    fc.dictionary(fc.string({ maxLength: 8 }), tie('value'), { maxKeys: 4 }),
    fc.array(fc.tuple(fc.oneof(fc.string({ maxLength: 8 }), fc.integer()), tie('value')), { maxLength: 3 }).map((es) => new Map(es)),
    fc.array(fc.oneof(fc.string({ maxLength: 8 }), fc.integer()), { maxLength: 4 }).map((xs) => new Set(xs)),
  ),
}));

describe('MLS codecs (fuzz)', () => {
  let keyPackageBytes: Uint8Array;
  const stored: unknown[] = [];

  beforeAll(async () => {
    const storage = new VolatileGroupStorage();
    const session = await new MarmotTsProvider().openSession({ signer: new LocalSigner(generateSecretKey()), network: new MemoryGroupNetwork(), storage, deviceId: 'fuzz' });
    const evt: NostrEvent = await session.publishKeyPackage(['wss://fuzz.invalid']);
    keyPackageBytes = base64.decode(evt.content);
    const g = await session.createGroup({ name: 'fuzz', relays: ['wss://fuzz.invalid'] });
    await session.send(g.groupId, 'hola');
    for (const ns of ['groups', 'keypackages', 'invites']) for (const k of await storage.keys(ns)) stored.push(await storage.get(ns, k));
    session.close();
  });

  it('storage codec round-trips real ts-mls group and key package state', () => {
    expect(stored.length).toBeGreaterThanOrEqual(2);
    for (const v of stored) expect(roundTrip(v)).toEqual(v);
  });

  it('storage codec round-trips arbitrary MLS-shaped values through JSON', () => {
    for (const v of [-0, NaN, Infinity, -Infinity, [-0], new Map([[-0, NaN]])]) expect(roundTrip(v)).toEqual(v);
    fc.assert(
      fc.property(mlsValue, (v) => {
        expect(roundTrip(v)).toEqual(v);
      }),
      runs(300),
    );
  });

  it('storage decoder only ever returns or throws an Error on arbitrary JSON (tampered store)', () => {
    const tagged = fc.oneof(
      fc.jsonValue(),
      fc.record({ $u8: fc.jsonValue() }),
      fc.record({ $bi: fc.jsonValue() }),
      fc.record({ $map: fc.jsonValue() }),
      fc.record({ $set: fc.jsonValue() }),
      fc.record({ $obj: fc.jsonValue() }),
    );
    fc.assert(
      fc.property(fc.oneof(tagged, fc.array(tagged, { maxLength: 3 }), fc.record({ $obj: fc.dictionary(fc.string(), tagged) })), (v) => {
        throwsCleanly(() => decodeValue(v));
      }),
      runs(400),
    );
  });

  it('key package TLS codec: decode ∘ encode is the identity on a real key package', () => {
    const kp = mlsCodec.decodeKeyPackage(keyPackageBytes);
    expect(kp).toBeDefined();
    expect(mlsCodec.encodeKeyPackage(kp!)).toEqual(keyPackageBytes);
    // Trailing bytes are rejected (plain ts-mls decode() ignores them).
    expect(mlsCodec.decodeKeyPackage(new Uint8Array([...keyPackageBytes, 0]))).toBeUndefined();
  });

  it('mutated key packages decode to undefined, throw an Error, or re-encode canonically', () => {
    fc.assert(
      fc.property(fc.nat(), fc.integer({ min: 1, max: 255 }), fc.constantFrom('flip', 'truncate', 'insert'), (pos, x, how) => {
        const b = keyPackageBytes;
        const i = pos % b.length;
        const bad = how === 'flip' ? b.map((v, j) => (j === i ? v ^ x : v)) : how === 'truncate' ? b.slice(0, i) : new Uint8Array([...b.slice(0, i), x, ...b.slice(i)]);
        let kp;
        try {
          kp = mlsCodec.decodeKeyPackage(bad);
        } catch (e) {
          expect(e).toBeInstanceOf(Error);
          return;
        }
        // Accepted: the object must re-encode and decode to itself (no ambiguous parses).
        if (kp) expect(mlsCodec.decodeKeyPackage(mlsCodec.encodeKeyPackage(kp))).toEqual(kp);
      }),
      runs(300),
    );
  });

  it('random bytes never crash or hang the MLS message / key package decoders', () => {
    fc.assert(
      fc.property(fc.oneof(fc.uint8Array({ maxLength: 600 }), fc.uint8Array({ maxLength: 8 }).map((h) => new Uint8Array([0, 1, ...h, ...new Uint8Array(64)]))), (bytes) => {
        const t0 = performance.now();
        for (const dec of [mlsCodec.decodeMessage, mlsCodec.decodeKeyPackage]) {
          try {
            dec(bytes);
          } catch (e) {
            expect(e).toBeInstanceOf(Error);
          }
        }
        expect(performance.now() - t0).toBeLessThan(250);
      }),
      runs(400),
    );
  });
});
