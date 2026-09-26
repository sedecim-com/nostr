import { describe, expect, it } from 'vitest';
import * as nt from 'nostr-tools';
import { v2 as ntNip44 } from 'nostr-tools/nip44';
import * as ntNip49 from 'nostr-tools/nip49';
import {
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  verifyEvent,
  toUnsigned,
  selfTestKey,
  nip19,
  nip44,
  nip49,
  nip98,
  matchFilter,
  selectHeads,
  bytesToHex,
  type NostrEvent,
} from '../src/index';

describe('NIP-01 events', () => {
  it('signs events that nostr-tools verifies and vice versa (interop)', () => {
    const sk = generateSecretKey();
    const pk = getPublicKey(sk);
    const evt = finalizeEvent(toUnsigned({ kind: 1, content: 'hola', tags: [['t', 'x']] }, pk), sk);
    expect(nt.verifyEvent({ ...evt })).toBe(true);
    const theirs = nt.finalizeEvent({ kind: 1, content: 'hi', tags: [], created_at: 1700000000 }, sk);
    expect(verifyEvent({ ...theirs })).toBe(true);
    expect(nt.getPublicKey(sk)).toBe(pk);
  });

  it('rejects tampered events', () => {
    const sk = generateSecretKey();
    const evt = finalizeEvent(toUnsigned({ kind: 1, content: 'a' }, getPublicKey(sk)), sk);
    expect(verifyEvent({ ...evt, content: 'b' })).toBe(false);
    expect(verifyEvent({ ...evt, sig: evt.sig.replace(/^./, evt.sig[0] === 'a' ? 'b' : 'a') })).toBe(false);
    expect(verifyEvent({ ...evt, kind: 'x' })).toBe(false);
  });

  it('self-tests key derivation and BIP-340 signatures (FR-001)', () => {
    const sk = generateSecretKey();
    const res = selfTestKey(sk, getPublicKey(sk));
    expect(res.ok).toBe(true);
    expect(selfTestKey(sk, '00'.repeat(32)).ok).toBe(false);
  });
});

describe('NIP-19', () => {
  it('matches nostr-tools encodings', () => {
    const sk = generateSecretKey();
    const pk = getPublicKey(sk);
    expect(nip19.npubEncode(pk)).toBe(nt.nip19.npubEncode(pk));
    expect(nip19.nsecEncode(sk)).toBe(nt.nip19.nsecEncode(sk));
    const np = nip19.nprofileEncode(pk, ['wss://r.example']);
    expect(nt.nip19.decode(np)).toEqual({ type: 'nprofile', data: { pubkey: pk, relays: ['wss://r.example'] } });
    const d = nip19.decode(nt.nip19.neventEncode({ id: pk, relays: ['wss://a'], author: pk, kind: 9 }));
    expect(d).toEqual({ type: 'nevent', data: { id: pk, relays: ['wss://a'], author: pk, kind: 9 } });
    expect(nip19.normalizePubkey(nip19.npubEncode(pk))).toBe(pk);
  });
});

describe('NIP-44 v2', () => {
  it('interoperates with nostr-tools in both directions', () => {
    const a = generateSecretKey();
    const b = generateSecretKey();
    const ck = nip44.getConversationKey(a, getPublicKey(b));
    expect(bytesToHex(ck)).toBe(bytesToHex(ntNip44.utils.getConversationKey(b, getPublicKey(a))));
    for (const msg of ['a', 'hola mundo 🌍', 'x'.repeat(1000), 'y'.repeat(65535)]) {
      const ct = nip44.encrypt(msg, ck);
      expect(ntNip44.decrypt(ct, ck)).toBe(msg);
      expect(nip44.decrypt(ntNip44.encrypt(msg, ck), ck)).toBe(msg);
    }
  });

  it('computes padded lengths per spec', () => {
    const cases: Array<[number, number]> = [[1, 32], [32, 32], [33, 64], [37, 64], [45, 64], [49, 64], [64, 64], [65, 96], [100, 128], [111, 128], [200, 224], [250, 256], [320, 320], [383, 384], [384, 384], [400, 448], [500, 512], [512, 512], [515, 640], [700, 768], [800, 896], [900, 1024], [1020, 1024], [65536, 65536]];
    for (const [len, padded] of cases) expect(nip44.calcPaddedLen(len)).toBe(padded);
  });

  it('rejects bad MAC, bad version and empty plaintext', () => {
    const ck = nip44.getConversationKey(generateSecretKey(), getPublicKey(generateSecretKey()));
    const ct = nip44.encrypt('secret', ck);
    const raw = Buffer.from(ct, 'base64');
    raw[raw.length - 1] = raw[raw.length - 1]! ^ 1;
    expect(() => nip44.decrypt(raw.toString('base64'), ck)).toThrow(/MAC/);
    expect(() => nip44.decrypt('#' + ct.slice(1), ck)).toThrow(/version/);
    expect(() => nip44.encrypt('', ck)).toThrow();
  });
});

describe('NIP-49 ncryptsec', () => {
  it('interoperates with nostr-tools', () => {
    const sk = generateSecretKey();
    const ours = nip49.encryptKey(sk, 'contraseña ñ', 4);
    expect(bytesToHex(ntNip49.decrypt(ours, 'contraseña ñ'))).toBe(bytesToHex(sk));
    const theirs = ntNip49.encrypt(sk, 'pw', 4, 0x01);
    const back = nip49.decryptKey(theirs, 'pw');
    expect(bytesToHex(back.secretKey)).toBe(bytesToHex(sk));
    expect(back.keySecurity).toBe(1);
    expect(() => nip49.decryptKey(ours, 'wrong')).toThrow();
  });
});

describe('NIP-98', () => {
  it('builds and verifies http auth headers', () => {
    const sk = generateSecretKey();
    const pk = getPublicKey(sk);
    const body = JSON.stringify({ a: 1 });
    const evt = finalizeEvent(toUnsigned(nip98.buildHttpAuthTemplate('https://api.example/v1/x', 'post', body), pk), sk);
    const header = nip98.encodeAuthHeader(evt);
    expect(nip98.verifyAuthHeader(header, { url: 'https://api.example/v1/x', method: 'POST', body }).pubkey).toBe(pk);
    expect(() => nip98.verifyAuthHeader(header, { url: 'https://api.example/v1/y', method: 'POST', body })).toThrow(/url/);
    expect(() => nip98.verifyAuthHeader(header, { url: 'https://api.example/v1/x', method: 'POST', body: '{}' })).toThrow(/payload/);
    expect(() => nip98.verifyAuthHeader(header, { url: 'https://api.example/v1/x', method: 'POST', body, now: evt.created_at + 600 })).toThrow(/stale/);
  });
});

describe('filters and head selection', () => {
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);
  const mk = (kind: number, created_at: number, tags: string[][] = []): NostrEvent => finalizeEvent(toUnsigned({ kind, content: '', tags, created_at }, pk), sk);

  it('matches tag filters', () => {
    const e = mk(9, 100, [['h', 'group1']]);
    expect(matchFilter({ kinds: [9], '#h': ['group1'] }, e)).toBe(true);
    expect(matchFilter({ kinds: [9], '#h': ['group2'] }, e)).toBe(false);
    expect(matchFilter({ since: 101 }, e)).toBe(false);
  });

  it('selects newest replaceable/addressable heads and keeps regular events', () => {
    const heads = selectHeads([mk(0, 1), mk(0, 5), mk(30000, 3, [['d', 'a']]), mk(30000, 9, [['d', 'a']]), mk(30000, 2, [['d', 'b']]), mk(1, 1), mk(1, 2)]);
    expect(heads.filter((h) => h.kind === 0).map((h) => h.created_at)).toEqual([5]);
    expect(heads.filter((h) => h.kind === 30000).map((h) => h.created_at).sort()).toEqual([2, 9]);
    expect(heads.filter((h) => h.kind === 1)).toHaveLength(2);
  });
});
