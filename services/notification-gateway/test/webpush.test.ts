import { createPublicKey, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decryptAes128gcm } from './ua';
import { b64u, createWebPushSender, encryptAes128gcm, generateVapidKeys, vapidAuthorization, vapidKeysFromPrivate } from '../src/index';

// RFC 8291 §5 / Appendix A worked example.
const RFC = {
  plaintext: 'When I grow up, I want to be a watermelon',
  asPrivate: 'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw',
  asPublic: 'BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8',
  uaPrivate: 'q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94',
  uaPublic: 'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
  salt: 'DGv6ra1nlYgDCS1FRnbzlw',
  authSecret: 'BTBZMqHH6r4Tts7J_aSIgg',
  message:
    'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN',
};

describe('RFC 8291 aes128gcm encryption', () => {
  it('reproduces the RFC 8291 worked example byte for byte', () => {
    const out = encryptAes128gcm({
      plaintext: new TextEncoder().encode(RFC.plaintext),
      uaPublic: b64u.decode(RFC.uaPublic),
      authSecret: b64u.decode(RFC.authSecret),
      asPrivate: b64u.decode(RFC.asPrivate),
      salt: b64u.decode(RFC.salt),
    });
    expect(b64u.encode(out)).toBe(RFC.message);
    // header: salt || rs=4096 || idlen=65 || as_public
    expect(b64u.encode(out.subarray(21, 86))).toBe(RFC.asPublic);
    expect(new DataView(out.buffer, out.byteOffset).getUint32(16)).toBe(4096);
  });

  it('decrypts the RFC message and round-trips with random salt and ephemeral keys', () => {
    expect(new TextDecoder().decode(decryptAes128gcm(b64u.decode(RFC.message), b64u.decode(RFC.uaPrivate), b64u.decode(RFC.authSecret)))).toBe(RFC.plaintext);
    const a = encryptAes128gcm({ plaintext: new TextEncoder().encode('{"v":1}'), uaPublic: b64u.decode(RFC.uaPublic), authSecret: b64u.decode(RFC.authSecret) });
    const b = encryptAes128gcm({ plaintext: new TextEncoder().encode('{"v":1}'), uaPublic: b64u.decode(RFC.uaPublic), authSecret: b64u.decode(RFC.authSecret) });
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    expect(a.length).toBe(b.length);
    expect(new TextDecoder().decode(decryptAes128gcm(a, b64u.decode(RFC.uaPrivate), b64u.decode(RFC.authSecret)))).toBe('{"v":1}');
  });

  it('rejects malformed keys and oversized payloads', () => {
    expect(() => encryptAes128gcm({ plaintext: new Uint8Array(1), uaPublic: new Uint8Array(33), authSecret: new Uint8Array(16) })).toThrow();
    expect(() => encryptAes128gcm({ plaintext: new Uint8Array(1), uaPublic: b64u.decode(RFC.uaPublic), authSecret: new Uint8Array(8) })).toThrow();
    expect(() => encryptAes128gcm({ plaintext: new Uint8Array(5000), uaPublic: b64u.decode(RFC.uaPublic), authSecret: b64u.decode(RFC.authSecret) })).toThrow(/too large/);
  });
});

describe('RFC 8292 VAPID', () => {
  it('keeps a private key with leading zero bytes at 32 bytes', () => {
    const d = new Uint8Array(32);
    d[31] = 7;
    const keys = vapidKeysFromPrivate(d);
    expect(keys.privateKey).toHaveLength(32);
    expect(vapidAuthorization('https://push.example.net/x', keys, 'mailto:ops@example.org')).toMatch(/^vapid t=/);
    for (let i = 0; i < 2000; i++) expect(generateVapidKeys().privateKey).toHaveLength(32);
  });

  it('signs an ES256 JWT for the push service origin with the VAPID key', () => {
    const keys = generateVapidKeys();
    expect(vapidKeysFromPrivate(keys.privateKey).publicKey).toEqual(keys.publicKey);
    const now = 1_700_000_000_000;
    const header = vapidAuthorization('https://push.example.net/wpush/v2/abc?x=1', keys, 'mailto:ops@example.org', now);
    const m = /^vapid t=([^.]+)\.([^.]+)\.([^,]+), k=(.+)$/.exec(header)!;
    expect(m).not.toBeNull();
    expect(JSON.parse(Buffer.from(m[1]!, 'base64url').toString())).toEqual({ typ: 'JWT', alg: 'ES256' });
    const claims = JSON.parse(Buffer.from(m[2]!, 'base64url').toString());
    expect(claims).toEqual({ aud: 'https://push.example.net', exp: now / 1000 + 12 * 3600, sub: 'mailto:ops@example.org' });
    expect(m[4]).toBe(b64u.encode(keys.publicKey));
    const pub = createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', x: b64u.encode(keys.publicKey.subarray(1, 33)), y: b64u.encode(keys.publicKey.subarray(33)) } });
    expect(verify('sha256', Buffer.from(`${m[1]}.${m[2]}`), { key: pub, dsaEncoding: 'ieee-p1363' }, Buffer.from(m[3]!, 'base64url'))).toBe(true);
  });

  it('sends encrypted payloads with aes128gcm headers and empty pushes without a body', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fakeFetch = (async (url: string, init: RequestInit) => (calls.push({ url, init }), new Response(null, { status: 201 }))) as unknown as typeof fetch;
    const sender = createWebPushSender({ vapid: generateVapidKeys(), subject: 'mailto:a@b.c', fetch: fakeFetch });
    const sub = { endpoint: 'https://push.example.net/x', keys: { p256dh: RFC.uaPublic, auth: RFC.authSecret } };
    expect(await sender.send(sub, { payload: new TextEncoder().encode('{"v":1}'), ttlSeconds: 60, urgency: 'normal', topic: 'activity' })).toBe(201);
    expect(await sender.send(sub, { payload: null, ttlSeconds: 60, urgency: 'low' })).toBe(201);
    const [enc, empty] = calls.map((c) => c.init.headers as Record<string, string>);
    expect(enc).toMatchObject({ 'content-encoding': 'aes128gcm', ttl: '60', urgency: 'normal', topic: 'activity' });
    expect(enc!.authorization).toMatch(/^vapid t=/);
    expect(new TextDecoder().decode(decryptAes128gcm(calls[0]!.init.body as Uint8Array, b64u.decode(RFC.uaPrivate), b64u.decode(RFC.authSecret)))).toBe('{"v":1}');
    expect(empty!['content-encoding']).toBeUndefined();
    expect(calls[1]!.init.body).toBeUndefined();
  });
});
