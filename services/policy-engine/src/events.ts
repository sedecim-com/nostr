import { createHash, createHmac, createPrivateKey, createPublicKey, sign, timingSafeEqual, verify, type KeyObject } from 'node:crypto';
import type { PolicyAuditEntry } from '@sedecim/policy-client';

/**
 * OPS-16: signed events. Every audit entry written while events are on is also emitted as an event with a stable
 * envelope, serialized canonically (RFC 8785, JCS) and signed with the service's Ed25519 key. It is signed when it is
 * emitted and stored as signed, so its signature still verifies after the key changes (the old public key stays in
 * GET /v1/events/keys).
 */

/** The audit actions: an event's `type` is the action of the audit entry it copies. */
export const EVENT_TYPES = [
  'subject.upsert',
  'subject.reactivate',
  'subject.revoke',
  'resource.upsert',
  'device.register',
  'device.revoke',
  'device.attest',
  'session.assert',
  'rotation.done',
  'directory.upsert',
  'directory.delete',
  'retention.set',
  'webhook.create',
  'webhook.delete',
  'webhook.enable',
  'webhook.disable',
] as const;
export type EventType = (typeof EVENT_TYPES)[number];

/** What an event carries: the audit entry it comes from, never more than that entry holds. */
export interface PolicyEventData {
  /** `id` of the audit entry (GET /v1/audit). */
  audit_id: number;
  actor: string;
  target: string;
  details?: Record<string, unknown>;
}

export interface UnsignedPolicyEvent {
  /** Unique (a UUID): the consumer's idempotency key, also sent as `Idempotency-Key` by the webhooks. */
  id: string;
  type: string;
  /** Epoch ms of the audit entry. */
  created_at: number;
  /** Position in the stream: strictly increasing, with gaps only where a write rolled back. */
  seq: number;
  /** Who emitted it (POLICY_EVENTS_ISSUER, by default PUBLIC_BASE_URL): the verifier pins it. */
  issuer: string;
  data: PolicyEventData;
}

export interface PolicyEvent extends UnsignedPolicyEvent {
  /** RFC 7638 thumbprint of the public key that signed it. */
  kid: string;
  /** Ed25519 signature (base64url) of the canonical JSON of the event without `sig`. */
  sig: string;
}

/** A public key of GET /v1/events/keys (JWK, RFC 8037). */
export interface EventPublicJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid: string;
  alg: 'EdDSA';
  use: 'sig';
}

export interface EventSigningKey {
  kid: string;
  privateKey: KeyObject;
  publicJwk: EventPublicJwk;
}

/**
 * Canonical JSON (RFC 8785, JCS) of plain JSON values: object members sorted by their UTF-16 code units, no whitespace,
 * strings and numbers as ECMAScript's JSON.stringify writes them. Throws on what JSON cannot hold.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonical JSON: numbers must be finite');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object') {
    const members = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${members.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
  }
  throw new TypeError(`canonical JSON: ${typeof value} is not JSON`);
}

/** RFC 7638 thumbprint of an Ed25519 public key (its JWK `x`): the key's `kid`. */
export function jwkThumbprint(x: string): string {
  return createHash('sha256').update(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`).digest('base64url');
}

export const eventPublicJwk = (x: string): EventPublicJwk => ({ kty: 'OKP', crv: 'Ed25519', x, kid: jwkThumbprint(x), alg: 'EdDSA', use: 'sig' });

// DER prefix of a PKCS#8 Ed25519 private key (RFC 8410): the 32-byte seed follows it.
const ED25519_PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const NOT_A_KEY = 'not an Ed25519 private key (PKCS#8 PEM, as `openssl genpkey -algorithm ed25519` writes it, or its 32-byte seed in hex)';

/** The signing key from the contents of POLICY_EVENTS_SIGNING_KEY_FILE. Errors never quote the file. */
export function parseSigningKey(text: string): EventSigningKey {
  const t = text.trim();
  let privateKey: KeyObject;
  try {
    privateKey = /^[0-9a-fA-F]{64}$/.test(t)
      ? createPrivateKey({ key: Buffer.concat([ED25519_PKCS8, Buffer.from(t, 'hex')]), format: 'der', type: 'pkcs8' })
      : createPrivateKey({ key: t, format: 'pem' });
  } catch {
    throw new Error(NOT_A_KEY);
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error(NOT_A_KEY);
  const { x } = createPublicKey(privateKey).export({ format: 'jwk' });
  const publicJwk = eventPublicJwk(x!);
  return { kid: publicJwk.kid, privateKey, publicJwk };
}

/** Signs the event: the signature covers every field and the `kid`, in canonical JSON. */
export function signPolicyEvent(event: UnsignedPolicyEvent, key: EventSigningKey): PolicyEvent {
  const withKid = { ...event, kid: key.kid };
  const sig = sign(null, Buffer.from(canonicalJson(withKid), 'utf8'), key.privateKey).toString('base64url');
  return { ...withKid, sig };
}

export type EventVerification = { ok: true; event: PolicyEvent } | { ok: false; reason: 'malformed' | 'issuer' | 'unknown_kid' | 'signature' };

const isInt = (v: unknown, min: number): v is number => Number.isSafeInteger(v) && (v as number) >= min;
const isStr = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

/**
 * What a consumer does with an event: the shape, the issuer it expects, a key of the JWKS (GET /v1/events/keys) whose
 * thumbprint is the event's `kid`, and the signature over the canonical JSON of everything but `sig`. Never throws.
 */
export function verifyPolicyEvent(input: unknown, opts: { issuer: string; keys: readonly EventPublicJwk[] | { keys: readonly EventPublicJwk[] } }): EventVerification {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return { ok: false, reason: 'malformed' };
  const e = input as Record<string, unknown>;
  const data = e.data as Record<string, unknown> | undefined;
  if (!isStr(e.id) || !isStr(e.type) || !isInt(e.created_at, 0) || !isInt(e.seq, 1) || !isStr(e.issuer) || !isStr(e.kid) || !isStr(e.sig)) return { ok: false, reason: 'malformed' };
  if (!data || typeof data !== 'object' || Array.isArray(data) || !isInt(data.audit_id, 1) || typeof data.actor !== 'string' || typeof data.target !== 'string') return { ok: false, reason: 'malformed' };
  if (e.issuer !== opts.issuer) return { ok: false, reason: 'issuer' };
  const keys = Array.isArray(opts.keys) ? opts.keys : (opts.keys as { keys: readonly EventPublicJwk[] }).keys;
  // A JWKS entry counts only for the kid its key hashes to: a relabelled key verifies nothing.
  const jwk = keys.find((k) => k?.kty === 'OKP' && k.crv === 'Ed25519' && k.kid === e.kid && typeof k.x === 'string' && jwkThumbprint(k.x) === e.kid);
  if (!jwk) return { ok: false, reason: 'unknown_kid' };
  try {
    const { sig, ...signed } = e;
    const publicKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: jwk.x }, format: 'jwk' });
    if (verify(null, Buffer.from(canonicalJson(signed), 'utf8'), publicKey, Buffer.from(sig as string, 'base64url'))) return { ok: true, event: input as PolicyEvent };
  } catch {
    // Not JSON-serializable, or a key or signature that does not decode: a bad signature either way.
  }
  return { ok: false, reason: 'signature' };
}

/**
 * Names an event never carries, at any depth: WebAuthn ceremony material, credentials, tokens and secrets. The audit does
 * not hold them either; an event drops them all the same, so a future audit detail cannot leak to webhook destinations.
 */
export const FORBIDDEN_EVENT_KEYS: readonly string[] = [
  'assertion',
  'attestationObject',
  'authenticatorData',
  'challenge',
  'clientDataJSON',
  'credential',
  'credentialId',
  'credentialPublicKey',
  'nsec',
  'password',
  'publicKey',
  'secret',
  'signature',
  'token',
  'tokenHash',
  'userHandle',
];
const FORBIDDEN = new Set(FORBIDDEN_EVENT_KEYS.map((k) => k.toLowerCase()));

function withoutForbidden(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(withoutForbidden);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).filter(([k]) => !FORBIDDEN.has(k.toLowerCase())).map(([k, x]) => [k, withoutForbidden(x)]));
  return v;
}

/** The data of an audit entry's event: the entry as JSON stores it (what GET /v1/audit returns), minus forbidden names. */
export function eventData(entry: PolicyAuditEntry): PolicyEventData {
  const stored = JSON.parse(JSON.stringify({ audit_id: entry.id, actor: entry.actor, target: entry.target, details: entry.details })) as PolicyEventData;
  return stored.details === undefined ? stored : { ...stored, details: withoutForbidden(stored.details) as Record<string, unknown> };
}

/** The webhook secrets key from the contents of POLICY_WEBHOOK_SECRETS_KEY_FILE: 32 bytes in hex. */
export function parseWebhookSecretsKey(text: string): Buffer {
  const t = text.trim();
  if (!/^[0-9a-fA-F]{64}$/.test(t)) throw new Error('the webhook secrets key must be 32 bytes in hex (64 characters)');
  return Buffer.from(t, 'hex');
}

/**
 * The signing secret of a subscription. It is not stored: it is derived from the webhook secrets key and the
 * subscription's id and random salt (HMAC-SHA256), so a copy of the database or of its backups holds no secret.
 */
export function webhookSecret(secretsKey: Buffer, webhookId: string, salt: string): string {
  return `whsec_${createHmac('sha256', secretsKey).update(`sedecim/policy-webhook-secret/v1\0${webhookId}\0${salt}`).digest('base64url')}`;
}

/** Header of every delivery: `t=<unix seconds>,v1=<hex HMAC-SHA256 of "t.body" with the subscription's secret>`. */
export const WEBHOOK_SIGNATURE_HEADER = 'x-sedecim-signature';
/** How old (or ahead) a delivery's timestamp may be, in seconds, before the receiver treats it as a replay. */
export const WEBHOOK_TOLERANCE_S = 300;

const hmacHex = (secret: string, t: number, body: string) => createHmac('sha256', secret).update(`${t}.${body}`).digest('hex');

export function webhookSignatureHeader(secret: string, body: string, timestampS: number): string {
  return `t=${timestampS},v1=${hmacHex(secret, timestampS, body)}`;
}

/**
 * What a receiver checks (reference implementation): the header parses, its timestamp is within `toleranceS` of `now`
 * and one `v1` is the HMAC of `t.body`, compared in constant time. Never throws.
 */
export function verifyWebhookSignature(header: string | undefined, body: string, secret: string, opts: { now?: number; toleranceS?: number } = {}): { ok: true; timestamp: number } | { ok: false; reason: 'malformed' | 'stale' | 'signature' } {
  if (typeof header !== 'string') return { ok: false, reason: 'malformed' };
  const parts = header.split(',').map((p) => p.trim().split('='));
  const t = Number(parts.find(([k]) => k === 't')?.[1]);
  const v1 = parts.filter(([k, v]) => k === 'v1' && typeof v === 'string').map(([, v]) => v!);
  if (!Number.isSafeInteger(t) || t <= 0 || !v1.length) return { ok: false, reason: 'malformed' };
  if (Math.abs(Math.floor((opts.now ?? Date.now()) / 1000) - t) > (opts.toleranceS ?? WEBHOOK_TOLERANCE_S)) return { ok: false, reason: 'stale' };
  const expected = Buffer.from(hmacHex(secret, t, body), 'hex');
  const match = v1.some((v) => {
    const got = Buffer.from(v, 'hex');
    return got.length === expected.length && timingSafeEqual(got, expected);
  });
  return match ? { ok: true, timestamp: t } : { ok: false, reason: 'signature' };
}
