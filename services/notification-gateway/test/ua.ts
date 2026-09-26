import { createDecipheriv, createECDH, createHmac, randomBytes } from 'node:crypto';
import { b64u } from '../src/index';

const hmac = (k: Uint8Array, d: Uint8Array) => createHmac('sha256', k).update(d).digest();

/** Independent user-agent side of RFC 8291 (decrypts one aes128gcm record). */
export function decryptAes128gcm(message: Uint8Array, uaPrivate: Uint8Array, authSecret: Uint8Array): Uint8Array {
  const salt = message.subarray(0, 16);
  const idlen = message[20]!;
  const asPublic = message.subarray(21, 21 + idlen);
  const ua = createECDH('prime256v1');
  ua.setPrivateKey(uaPrivate);
  const ecdhSecret = ua.computeSecret(asPublic);
  const ikm = hmac(hmac(authSecret, ecdhSecret), Buffer.concat([Buffer.from('WebPush: info\0'), ua.getPublicKey(), asPublic, Buffer.of(1)]));
  const prk = hmac(salt, ikm);
  const cek = hmac(prk, Buffer.concat([Buffer.from('Content-Encoding: aes128gcm\0'), Buffer.of(1)])).subarray(0, 16);
  const nonce = hmac(prk, Buffer.concat([Buffer.from('Content-Encoding: nonce\0'), Buffer.of(1)])).subarray(0, 12);
  const body = message.subarray(21 + idlen);
  const d = createDecipheriv('aes-128-gcm', cek, nonce);
  d.setAuthTag(body.subarray(body.length - 16));
  const padded = Buffer.concat([d.update(body.subarray(0, body.length - 16)), d.final()]);
  let end = padded.length - 1;
  while (padded[end] === 0) end--;
  if (padded[end] !== 2) throw new Error('bad padding delimiter');
  return new Uint8Array(padded.subarray(0, end));
}

/** A browser-like push subscription (fresh P-256 key pair and auth secret) for a given endpoint. */
export function fakeSubscription(endpoint: string) {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  const auth = new Uint8Array(randomBytes(16));
  return {
    subscription: { endpoint, keys: { p256dh: b64u.encode(ecdh.getPublicKey()), auth: b64u.encode(auth) } },
    decrypt: (body: Uint8Array) => new TextDecoder().decode(decryptAes128gcm(body, ecdh.getPrivateKey(), auth)),
  };
}
