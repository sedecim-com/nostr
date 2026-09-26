/**
 * Web Push sender: RFC 8291 message encryption (aes128gcm, RFC 8188) and RFC 8292 VAPID, on node:crypto
 * only (the gateway runs on Node; no third-party push library).
 */
import { createCipheriv, createECDH, createHmac, createPrivateKey, randomBytes, sign } from 'node:crypto';

export const b64u = {
  encode: (b: Uint8Array): string => Buffer.from(b).toString('base64url'),
  decode: (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64url')),
};

const hmac = (key: Uint8Array, data: Uint8Array) => new Uint8Array(createHmac('sha256', key).update(data).digest());
const concat = (...parts: Uint8Array[]) => new Uint8Array(Buffer.concat(parts));
const utf8 = (s: string) => new Uint8Array(Buffer.from(s, 'utf8'));

export interface Aes128gcmInput {
  plaintext: Uint8Array;
  /** User agent public key (subscription `keys.p256dh`, 65-byte uncompressed P-256 point). */
  uaPublic: Uint8Array;
  /** Subscription `keys.auth` (16 bytes). */
  authSecret: Uint8Array;
  /** Application server ephemeral private key; random when omitted (only tests pass it). */
  asPrivate?: Uint8Array;
  /** 16-byte salt; random when omitted. */
  salt?: Uint8Array;
  recordSize?: number;
}

/** Encrypts one Web Push message as a single aes128gcm record (RFC 8291 §3.4, §4). */
export function encryptAes128gcm(input: Aes128gcmInput): Uint8Array {
  const rs = input.recordSize ?? 4096;
  if (input.uaPublic.length !== 65 || input.uaPublic[0] !== 0x04) throw new Error('p256dh must be an uncompressed P-256 point');
  if (input.authSecret.length !== 16) throw new Error('auth secret must be 16 bytes');
  if (input.plaintext.length + 1 + 16 > rs) throw new Error('payload too large for one record');
  const ecdh = createECDH('prime256v1');
  if (input.asPrivate) ecdh.setPrivateKey(input.asPrivate);
  else ecdh.generateKeys();
  const asPublic = new Uint8Array(ecdh.getPublicKey());
  const ecdhSecret = new Uint8Array(ecdh.computeSecret(input.uaPublic));
  const salt = input.salt ?? new Uint8Array(randomBytes(16));

  // RFC 8291 §3.3-3.4: combine the ECDH secret with the auth secret, then RFC 8188 key/nonce derivation.
  const prkKey = hmac(input.authSecret, ecdhSecret);
  const keyInfo = concat(utf8('WebPush: info\0'), input.uaPublic, asPublic);
  const ikm = hmac(prkKey, concat(keyInfo, Uint8Array.of(1)));
  const prk = hmac(salt, ikm);
  const cek = hmac(prk, concat(utf8('Content-Encoding: aes128gcm\0'), Uint8Array.of(1))).subarray(0, 16);
  const nonce = hmac(prk, concat(utf8('Content-Encoding: nonce\0'), Uint8Array.of(1))).subarray(0, 12);

  const cipher = createCipheriv('aes-128-gcm', cek, nonce);
  // 0x02: padding delimiter of the last (and only) record.
  const body = concat(cipher.update(concat(input.plaintext, Uint8Array.of(2))), cipher.final(), cipher.getAuthTag());
  const header = new Uint8Array(16 + 4 + 1 + asPublic.length);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, rs);
  header[20] = asPublic.length;
  header.set(asPublic, 21);
  return concat(header, body);
}

export interface VapidKeys {
  /** 65-byte uncompressed P-256 public key (what browsers take as `applicationServerKey`). */
  publicKey: Uint8Array;
  /** 32-byte private scalar. */
  privateKey: Uint8Array;
}

export function generateVapidKeys(): VapidKeys {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  return { publicKey: new Uint8Array(ecdh.getPublicKey()), privateKey: new Uint8Array(ecdh.getPrivateKey()) };
}

export function vapidKeysFromPrivate(privateKey: Uint8Array): VapidKeys {
  if (privateKey.length !== 32) throw new Error('VAPID private key must be 32 bytes');
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(privateKey);
  return { publicKey: new Uint8Array(ecdh.getPublicKey()), privateKey };
}

/** RFC 8292 `Authorization: vapid t=<JWT>, k=<key>` for a push endpoint (JWT valid for 12 h at most). */
export function vapidAuthorization(endpoint: string, keys: VapidKeys, subject: string, now = Date.now(), ttlSeconds = 12 * 3600): string {
  const header = b64u.encode(utf8(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64u.encode(utf8(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(now / 1000) + Math.min(ttlSeconds, 24 * 3600), sub: subject })));
  const key = createPrivateKey({
    format: 'jwk',
    key: { kty: 'EC', crv: 'P-256', d: b64u.encode(keys.privateKey), x: b64u.encode(keys.publicKey.subarray(1, 33)), y: b64u.encode(keys.publicKey.subarray(33, 65)) },
  });
  const signature = sign('sha256', Buffer.from(`${header}.${claims}`), { key, dsaEncoding: 'ieee-p1363' });
  return `vapid t=${header}.${claims}.${b64u.encode(signature)}, k=${b64u.encode(keys.publicKey)}`;
}

export interface PushSubscriptionJSON {
  endpoint: string;
  keys: { p256dh: string; auth: string };
}

export interface WebPushMessage {
  /** null: an empty push (no body, no encryption) that only wakes the service worker. */
  payload: Uint8Array | null;
  ttlSeconds: number;
  urgency: 'very-low' | 'low' | 'normal' | 'high';
  /** Replaces a pending push with the same topic at the push service. */
  topic?: string;
}

export interface WebPushSender {
  send(sub: PushSubscriptionJSON, msg: WebPushMessage): Promise<number>;
}

/** Sends through the push service named by the subscription endpoint. Returns the HTTP status. */
export function createWebPushSender(opts: { vapid: VapidKeys; subject: string; fetch?: typeof fetch; timeoutMs?: number }): WebPushSender {
  const doFetch = opts.fetch ?? fetch;
  return {
    async send(sub, msg) {
      const headers: Record<string, string> = {
        ttl: String(msg.ttlSeconds),
        urgency: msg.urgency,
        authorization: vapidAuthorization(sub.endpoint, opts.vapid, opts.subject),
      };
      if (msg.topic) headers.topic = msg.topic;
      let body: Uint8Array<ArrayBuffer> | undefined;
      if (msg.payload) {
        body = Uint8Array.from(encryptAes128gcm({ plaintext: msg.payload, uaPublic: b64u.decode(sub.keys.p256dh), authSecret: b64u.decode(sub.keys.auth) }));
        headers['content-encoding'] = 'aes128gcm';
        headers['content-type'] = 'application/octet-stream';
      } else headers['content-length'] = '0';
      const res = await doFetch(sub.endpoint, { method: 'POST', headers, ...(body ? { body } : {}), redirect: 'error', signal: AbortSignal.timeout(opts.timeoutMs ?? 10_000) });
      await res.arrayBuffer().catch(() => undefined);
      return res.status;
    },
  };
}
