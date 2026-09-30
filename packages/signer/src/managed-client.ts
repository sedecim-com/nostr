import { verifyEvent, type CustodyMode, type EventTemplate, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { NITRO_ROOT_G1_SHA256, NitroAttestationError, verifyNitroAttestation } from './enclave/attestation';
import { fromBase64Url, ownerTag, sealToEnclave, toBase64Url } from './enclave/envelope';

/** Returns the caller's current Acceso (Cognito) id or access token; called before every request. */
export type AccessTokenProvider = () => Promise<string>;

/**
 * FR005-10: the enclave a client trusts, to seal an import or an export password to it. `pcrs` are the measurements of
 * the enclave image the operator published (`nitro-cli build-enclave` or `describe-eif`: the same values as `enclave_pcr*`
 * in Terraform), 96 hex characters each; PCR8 (the signing certificate of the image) is optional. `rootFingerprints`
 * replaces the pinned AWS Nitro root: only for tests against a simulated enclave.
 */
export interface EnclaveTrust {
  pcrs: { 0: string; 1: string; 2: string; 8?: string };
  rootFingerprints?: string[];
}

const PCR_HEX = /^[0-9a-f]{96}$/i;

/** Without PCR0-2 any enclave image would pass the check, so they are required, and well formed. */
export function checkEnclaveTrust(trust: EnclaveTrust): EnclaveTrust {
  const pcrs = trust?.pcrs;
  for (const i of [0, 1, 2] as const) if (typeof pcrs?.[i] !== 'string' || !PCR_HEX.test(pcrs[i])) throw new Error(`enclave trust: PCR${i} must be 96 hex characters`);
  if (pcrs[8] !== undefined && (typeof pcrs[8] !== 'string' || !PCR_HEX.test(pcrs[8]))) throw new Error('enclave trust: PCR8 must be 96 hex characters');
  if (trust.rootFingerprints !== undefined && !(Array.isArray(trust.rootFingerprints) && trust.rootFingerprints.length > 0 && trust.rootFingerprints.every((f) => typeof f === 'string'))) {
    throw new Error('enclave trust: rootFingerprints must list at least one SHA-256');
  }
  return trust;
}

/**
 * FR005-10: the key owner as the managed-signer names it, `<iss>#<sub>` of the Acceso token, read without verifying the
 * token: the enclave does not take it on trust (it is in the AAD of what is sealed, and an export also needs the token
 * itself as proof). A device session token names nobody.
 */
export function accesoOwner(token: string): string {
  let claims: { iss?: unknown; sub?: unknown } | undefined;
  try {
    claims = JSON.parse(new TextDecoder().decode(fromBase64Url(token.split('.')[1] ?? ''))) as typeof claims;
  } catch {
    claims = undefined;
  }
  if (!claims || typeof claims.iss !== 'string' || !claims.iss || typeof claims.sub !== 'string' || !claims.sub) {
    throw new Error('sealing to the enclave needs the owner (iss and sub) of an Acceso token; a device session names no owner');
  }
  return `${claims.iss}#${claims.sub}`;
}

export interface ManagedSignerConnection {
  baseUrl: string;
  token: AccessTokenProvider;
  fetch?: typeof fetch;
  /**
   * FR005-11: called when the service answers 401 (e.g. a device session that expired or its owner closed), before
   * the request is sent once more with `token()`. A 401 means nothing was done, so the retry cannot repeat anything.
   */
  renew?: () => Promise<void>;
}

export interface ManagedSignerClientOptions extends ManagedSignerConnection {
  keyId: string;
}

/** Key metadata as returned by the managed-signer service. Never contains key material. */
export interface ManagedKeyInfo {
  keyId: string;
  owner: string;
  pubkey: string;
  provider: string;
  version: number;
  state: 'active' | 'export-pending' | 'migrated';
  createdAt: number;
  lastUsed?: number;
  allowedKinds?: number[];
  migratedAt?: number;
  retentionDays: number;
  /** FR005-08: the version of the texts and terms its owner accepted, and when. */
  consentVersion?: string;
  consentAt?: number;
  custody: 'managed' | 'managed-enclave';
  custodial: true;
  disclosure: string;
}

/** FR026-04: a key on its way out of managed custody, until its material is destroyed. */
export interface ClosedManagedKey {
  keyId: string;
  pubkey: string;
  /** Migrated to its owner's custody (FR026-03) or cancelled without migrating. */
  exit: 'migrated' | 'cancelled';
  deletedAt: number;
  /** When the material is destroyed (end of the retention window, DEC-09). */
  destroyAfter: number;
}

/** FR005-11: one entry of a managed key's usage log (DEC-09: kept 12 months). Metadata only, never content. */
export interface ManagedKeyUsage {
  at: number;
  keyId: string;
  action: string;
  kind?: number;
  eventId?: string;
  principal: string;
  /** The device whose session did it, when the call came through one. */
  deviceId?: string;
}

/** FR005-11: a device session of the caller as the managed-signer lists it: never its token. */
export interface ManagedDeviceSession {
  id: string;
  deviceId: string;
  createdAt: number;
  expiresAt: number;
  /** The session the listing was asked with. */
  current?: true;
}

export class ManagedSignerHttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

/**
 * IR-2026-10-03, IR-2026-10-11: the managed-signer wants a more recent sign-in with the Acceso password (RFC 9470
 * step-up) before exporting, migrating, deleting or cancelling the key or closing the other sessions, or because this
 * login is older than the closing of the other sessions. Signing in again and retrying with the new login is the way
 * out; nothing was done.
 */
export class ManagedSignerReauthError extends ManagedSignerHttpError {
  constructor(message: string, readonly maxAgeSeconds?: number) {
    super(401, message);
  }
}

const STEP_UP = 'insufficient_user_authentication';

async function request<T>(conn: ManagedSignerConnection, method: string, path: string, body?: unknown, prefix = '/v1/keys', renewed = false): Promise<T> {
  const token = await conn.token();
  if (!token) throw new ManagedSignerHttpError(401, 'managed signer: no Acceso session');
  const f = conn.fetch ?? fetch;
  const res = await f(`${conn.baseUrl.replace(/\/$/, '')}${prefix}${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    let parsed: { error?: string; error_code?: string; max_age?: number } = {};
    try {
      parsed = JSON.parse(text) as typeof parsed;
    } catch {
      // not JSON
    }
    const message = parsed.error ?? text;
    // A step-up is not an expired session: renewing it would not help, signing in again does.
    if (res.status === 401 && (parsed.error_code === STEP_UP || res.headers.get('www-authenticate')?.includes(`error="${STEP_UP}"`))) {
      throw new ManagedSignerReauthError(`managed signer ${method} ${path || '/'}: ${message}`, typeof parsed.max_age === 'number' ? parsed.max_age : undefined);
    }
    if (res.status === 401 && conn.renew && !renewed) {
      await conn.renew();
      return request<T>(conn, method, path, body, prefix, true);
    }
    throw new ManagedSignerHttpError(res.status, `managed signer ${method} ${path || '/'}: ${res.status} ${message}`);
  }
  return (await res.json()) as T;
}

/**
 * Browser-safe client for the managed-signer service, authorized with the user's Acceso token (FR005-04).
 * CUSTODIAL: the operator has the technical capability to sign as the user. The UI must never present
 * this as non-custodial (spec §1, §8.4).
 */
export class ManagedSignerClient implements Signer {
  readonly custody: CustodyMode = 'managed';
  private pubkey?: string;

  constructor(private readonly opts: ManagedSignerClientOptions) {}

  /** The caller's live managed keys. */
  static async listKeys(conn: ManagedSignerConnection): Promise<ManagedKeyInfo[]> {
    return (await request<{ keys: ManagedKeyInfo[] }>(conn, 'GET', '')).keys;
  }

  /**
   * FR026-04: the caller's keys that left managed custody and are waiting for their material to be destroyed. Once
   * destroyed a key is no longer tied to its owner and stops appearing here.
   */
  static async closedKeys(conn: ManagedSignerConnection): Promise<ClosedManagedKey[]> {
    return (await request<{ keys: ClosedManagedKey[] }>(conn, 'GET', '/closed')).keys;
  }

  /** Creates a managed key for the caller. Only after an explicit, informed opt-in (FR005-07). */
  /** FR005-08: `consentVersion` names the texts and terms the user accepted; the managed-signer records it with the key. */
  static async createKey(conn: ManagedSignerConnection, opts: { allowedKinds?: number[]; consentVersion: string }): Promise<ManagedKeyInfo> {
    return request<ManagedKeyInfo>(conn, 'POST', '', { ...(opts.allowedKinds ? { allowed_kinds: opts.allowedKinds } : {}), consent_version: opts.consentVersion });
  }

  /**
   * Imports a key the user already has (local -> managed migration, after the same explicit opt-in as createKey). Without
   * `enclave` the ncryptsec and its password travel to the managed-signer as they are. FR005-10: with `enclave`, they are
   * sealed here to the enclave the caller trusts, after checking its attestation, and the managed-signer only relays
   * them. `owner` (`<issuer>#<sub>`): only when `conn` goes through a device session, whose token names nobody.
   */
  static async importEncrypted(conn: ManagedSignerConnection, ncryptsec: string, password: string, opts: { consentVersion: string; enclave?: EnclaveTrust; owner?: string }): Promise<ManagedKeyInfo> {
    if (!opts.enclave) return request<ManagedKeyInfo>(conn, 'POST', '/import', { ncryptsec, password, consent_version: opts.consentVersion });
    const owner = opts.owner ?? accesoOwner(await conn.token());
    const { spki, at } = await ManagedSignerClient.enclaveKey(conn, opts.enclave);
    const sealed = await sealToEnclave(spki, { purpose: 'import', ownerTag: ownerTag(owner), at, ncryptsec, password });
    return request<ManagedKeyInfo>(conn, 'POST', '/import', { sealed_secrets: sealed, consent_version: opts.consentVersion });
  }

  /**
   * FR005-10: the enclave's key, from an attestation document asked for with a nonce of this client and verified here
   * (root, chain, signature, PCRs, nonce, freshness), never on the managed-signer's word: it relays the document and
   * could otherwise hand over a key of its own. Throws NitroAttestationError before anything is sealed or sent.
   */
  private static async enclaveKey(conn: ManagedSignerConnection, trust: EnclaveTrust): Promise<{ spki: Uint8Array; at: number }> {
    checkEnclaveTrust(trust);
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const { document } = await request<{ document?: unknown }>(conn, 'GET', `/attestation?nonce=${toBase64Url(nonce)}`, undefined, '/v1/enclave');
    let bytes: Uint8Array;
    try {
      if (typeof document !== 'string') throw new Error();
      bytes = Uint8Array.from(atob(document), (c) => c.charCodeAt(0));
    } catch {
      throw new NitroAttestationError('malformed', 'the managed-signer returned no base64 attestation document');
    }
    const att = verifyNitroAttestation(bytes, { expectedNonce: nonce, expectedPcrs: trust.pcrs, trustedRootFingerprints: trust.rootFingerprints ?? [NITRO_ROOT_G1_SHA256], requirePublicKey: true });
    return { spki: att.publicKey!, at: att.timestamp };
  }

  /**
   * FR024-03: opens a signer session bound to this device. Use the returned token as `token` from then on:
   * it stops working as soon as the organisation revokes the device.
   */
  static async openDeviceSession(conn: ManagedSignerConnection, deviceId: string, opts: { ttlSeconds?: number } = {}): Promise<{ token: string; deviceId: string; expiresAt: string }> {
    const r = await request<{ token: string; device_id: string; expires_at: string }>(conn, 'POST', '', { device_id: deviceId, ...(opts.ttlSeconds ? { ttl_seconds: opts.ttlSeconds } : {}) }, '/v1/device-sessions');
    return { token: r.token, deviceId: r.device_id, expiresAt: r.expires_at };
  }

  /**
   * FR005-11: the caller's open device sessions. `current` marks the one `conn` uses, when it is one. With the Acceso
   * login or any of the caller's sessions.
   */
  static async listDeviceSessions(conn: ManagedSignerConnection): Promise<ManagedDeviceSession[]> {
    return (await request<{ sessions: ManagedDeviceSession[] }>(conn, 'GET', '', undefined, '/v1/device-sessions')).sessions;
  }

  /** FR005-11: closes one of the caller's sessions: any of them with the Acceso login, or a session itself. */
  static async closeDeviceSession(conn: ManagedSignerConnection, id: string): Promise<void> {
    await request(conn, 'DELETE', `/${encodeURIComponent(id)}`, undefined, '/v1/device-sessions');
  }

  /**
   * FR005-11: closes every session of the caller but `except`. Returns how many were closed. IR-2026-10-11: with an
   * Acceso login signed in within the last minutes (else ManagedSignerReauthError); it also cuts off the caller's other
   * logins signed in before now, so a lost device cannot open another session with its login.
   */
  static async closeDeviceSessions(conn: ManagedSignerConnection, opts: { except?: string } = {}): Promise<number> {
    return (await request<{ closed: number }>(conn, 'DELETE', opts.except ? `?except=${encodeURIComponent(opts.except)}` : '', undefined, '/v1/device-sessions')).closed;
  }

  /** FR005-11: this key's usage log, oldest first: what was signed or decrypted with it, when and from which device. */
  async usage(): Promise<ManagedKeyUsage[]> {
    return (await this.call<{ usage: ManagedKeyUsage[] }>('/usage')).usage;
  }

  private call<T>(path: string, body?: unknown, method = body === undefined ? 'GET' : 'POST'): Promise<T> {
    return request<T>(this.opts, method, `/${encodeURIComponent(this.opts.keyId)}${path}`, body);
  }

  describe(): Promise<ManagedKeyInfo> {
    return this.call<ManagedKeyInfo>('');
  }

  async getPublicKey(): Promise<string> {
    if (!this.pubkey) this.pubkey = (await this.describe()).pubkey;
    return this.pubkey;
  }

  async signEvent(template: EventTemplate): Promise<NostrEvent> {
    const { event } = await this.call<{ event: NostrEvent }>('/sign', { template });
    if (!verifyEvent(event) || event.pubkey !== (await this.getPublicKey())) throw new Error('managed signer returned invalid event');
    return event;
  }

  async nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string> {
    return (await this.call<{ ciphertext: string }>('/nip44/encrypt', { peer: peerPubkey, plaintext })).ciphertext;
  }

  async nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string> {
    return (await this.call<{ plaintext: string }>('/nip44/decrypt', { peer: peerPubkey, ciphertext })).plaintext;
  }

  /**
   * FR-026 step 1: ncryptsec of the key plus the challenge to sign with it. IR-2026-10-03: like confirmMigration,
   * deleteKey and cancelCustody, only with an Acceso login signed in within the last minutes, never a device session;
   * else ManagedSignerReauthError. FR005-10: with `enclave`, the password never leaves this client in clear: it is sealed
   * to that enclave, after checking its attestation, for this key and its owner; without it, it goes as it is.
   */
  async exportForMigration(password: string, opts: { enclave?: EnclaveTrust } = {}): Promise<{ ncryptsec: string; challenge: string }> {
    if (!opts.enclave) return this.call('/export', { password });
    const owner = accesoOwner(await this.opts.token());
    const pubkey = await this.getPublicKey();
    const { spki, at } = await ManagedSignerClient.enclaveKey(this.opts, opts.enclave);
    const sealed = await sealToEnclave(spki, { purpose: 'export', ownerTag: ownerTag(owner), pubkey, at, password });
    return this.call('/export', { sealed_password: sealed });
  }

  /** FR-026 step 2: proof = event signed with the exported key carrying the `challenge` tag. */
  async confirmMigration(proof: NostrEvent): Promise<'migrated'> {
    return (await this.call<{ state: 'migrated' }>('/confirm-migration', { proof })).state;
  }

  /** FR-026 step 3: deletes the managed copy; the material is destroyed after the retention window. */
  async deleteKey(): Promise<{ destroyAfter: string }> {
    return { destroyAfter: (await this.call<{ destroy_after: string }>('', undefined, 'DELETE')).destroy_after };
  }

  /**
   * FR026-04: cancels managed custody without migrating (ARCO cancellation). `npub` must be this key's npub, as the
   * user confirmed it. The key stops working at once; its material is destroyed after the retention window, so offer
   * the encrypted backup (exportForMigration) first.
   */
  async cancelCustody(npub: string): Promise<{ destroyAfter: string }> {
    return { destroyAfter: (await this.call<{ destroy_after: string }>('/cancel', { confirm: npub })).destroy_after };
  }
}
