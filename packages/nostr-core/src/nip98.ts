/** NIP-98 HTTP Auth: used by the platform's own APIs so that clients authenticate with their Nostr key. */
import { sha256 } from '@noble/hashes/sha256';
import { base64 } from '@scure/base';
import { getTagValue, verifyEvent, type NostrEvent, type EventTemplate } from './event';
import { bytesToHex, randomBytes, utf8ToBytes, bytesToUtf8 } from './utils';

export const HTTP_AUTH_KIND = 27235;
/** Accepted clock skew around `created_at`; servers remember used event ids for this long. */
export const MAX_SKEW_SECONDS = 60;

export function payloadHash(body: string | Uint8Array): string {
  return bytesToHex(sha256(typeof body === 'string' ? utf8ToBytes(body) : body));
}

export function buildHttpAuthTemplate(url: string, method: string, body?: string | Uint8Array): EventTemplate {
  const tags = [
    ['u', url],
    ['method', method.toUpperCase()],
    // Servers accept each event id once: without a nonce two identical requests in the same second
    // (or a retry) would produce the same id and the second one would be rejected as a replay.
    ['nonce', bytesToHex(randomBytes(16))],
  ];
  if (body !== undefined && body.length > 0) tags.push(['payload', payloadHash(body)]);
  return { kind: HTTP_AUTH_KIND, tags, content: '' };
}

export function encodeAuthHeader(evt: NostrEvent): string {
  return 'Nostr ' + base64.encode(utf8ToBytes(JSON.stringify(evt)));
}

export interface HttpAuthCheck {
  url: string;
  method: string;
  body?: string | Uint8Array;
  now?: number;
  maxSkewSeconds?: number;
}

export class HttpAuthError extends Error {}

/** Validates an `Authorization: Nostr <base64>` header and returns the authenticated event. */
export function verifyAuthHeader(header: string | undefined, check: HttpAuthCheck): NostrEvent {
  if (!header || !header.startsWith('Nostr ')) throw new HttpAuthError('missing Nostr authorization');
  let evt: unknown;
  try {
    evt = JSON.parse(bytesToUtf8(base64.decode(header.slice(6).trim())));
  } catch {
    throw new HttpAuthError('malformed authorization event');
  }
  if (!verifyEvent(evt)) throw new HttpAuthError('invalid signature');
  if (evt.kind !== HTTP_AUTH_KIND) throw new HttpAuthError('wrong kind');
  const now = check.now ?? Math.floor(Date.now() / 1000);
  if (Math.abs(now - evt.created_at) > (check.maxSkewSeconds ?? MAX_SKEW_SECONDS)) throw new HttpAuthError('stale authorization');
  if (getTagValue(evt, 'u') !== check.url) throw new HttpAuthError('url mismatch');
  if (getTagValue(evt, 'method')?.toUpperCase() !== check.method.toUpperCase()) throw new HttpAuthError('method mismatch');
  const payload = getTagValue(evt, 'payload');
  if (check.body !== undefined && check.body.length > 0) {
    if (payload !== payloadHash(check.body)) throw new HttpAuthError('payload mismatch');
  } else if (payload !== undefined && payload !== payloadHash('')) {
    // Signed for a body that was not sent.
    throw new HttpAuthError('payload mismatch');
  }
  return evt;
}
