import { nip98, type Signer } from '@sedecim/nostr-core';
import type { Device, Resource, Rule, Sensitivity, Subject } from '@sedecim/policy-client';

export type { Device, Resource, Rule, Sensitivity, Subject };

/** Rotation the MLS group owner must perform after a member lost access (FR-024). */
export interface Rotation {
  id: string;
  at: number;
  resourceId: string;
  reason: string;
  removedPubkey: string;
  status: 'pending' | 'done';
}

/** What revoke endpoints return: the rotations they queued (id/status may be absent). */
export type RotationRequired = Omit<Rotation, 'id' | 'status'> & Partial<Pick<Rotation, 'id' | 'status'>>;

export interface AuditEntry {
  /** Monotonic sequence number, the cursor for `before`. */
  id: number;
  at: number;
  actor: string;
  action: string;
  target: string;
  details?: Record<string, unknown>;
}

/** Internal organizational directory (title/unit ↔ pubkey). Never published to relays. */
export interface DirectoryEntry {
  pubkey: string;
  title?: string;
  unit?: string;
}

export interface RetentionPolicy {
  resourceId: string;
  /** null: no automatic deletion. */
  days: number | null;
  legalHold: boolean;
}

/** WebAuthn creation options as JSON: binary fields are base64url strings. */
export interface CreationOptionsJSON {
  challenge: string;
  rp: { name: string; id?: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ type: 'public-key'; alg: number }>;
  timeout?: number;
  excludeCredentials?: Array<{ type: 'public-key'; id: string; transports?: string[] }>;
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
  extensions?: Record<string, unknown>;
}

/** Registration credential as JSON (base64url binary fields), as sent to /webauthn/register. */
export interface RegistrationCredentialJSON {
  id: string;
  rawId: string;
  type: 'public-key';
  authenticatorAttachment?: string | null;
  response: { clientDataJSON: string; attestationObject: string; transports?: string[] };
  clientExtensionResults: Record<string, unknown>;
}

/** Identity-service link as returned by /v1/links/visible/:pubkey. */
export interface VisibleLink {
  from?: string;
  to?: string;
  visibility: 'private' | 'selective' | 'public';
}

export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

/**
 * JSON request with a NIP-98 Authorization header signed by the admin's signer. The `u` tag is the
 * exact URL (query included) and the payload hash covers the exact body sent.
 */
export async function signedJson<T>(signer: Signer, url: string, method = 'GET', body?: unknown, f: typeof fetch = fetch): Promise<T> {
  const raw = body === undefined ? undefined : JSON.stringify(body);
  const evt = await signer.signEvent(nip98.buildHttpAuthTemplate(url, method, raw));
  const headers: Record<string, string> = { authorization: nip98.encodeAuthHeader(evt) };
  if (raw !== undefined) headers['content-type'] = 'application/json';
  let res: Response;
  try {
    res = await f(url, { method, headers, cache: 'no-store', ...(raw !== undefined ? { body: raw } : {}) });
  } catch {
    throw new ApiError(0, `no se pudo contactar ${new URL(url).origin}`);
  }
  const text = await res.text();
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  if (!res.ok) throw new ApiError(res.status, (json as { error?: string } | undefined)?.error ?? `HTTP ${res.status}`);
  return json as T;
}

const enc = encodeURIComponent;

/** Typed client of the policy-engine admin API (every route is NIP-98, admin pubkeys only). */
export class PolicyAdminApi {
  private readonly base: string;
  constructor(baseUrl: string, private readonly signer: Signer, private readonly f: typeof fetch = (...a) => fetch(...a)) {
    this.base = baseUrl.replace(/\/+$/, '');
  }

  private call<T>(method: string, path: string, body?: unknown) {
    return signedJson<T>(this.signer, this.base + path, method, body, this.f);
  }

  listSubjects = async () => (await this.call<{ subjects: Subject[] }>('GET', '/v1/subjects')).subjects;
  putSubject = (pubkey: string, s: { roles: string[]; attributes: Subject['attributes'] }) => this.call<unknown>('PUT', `/v1/subjects/${enc(pubkey)}`, s);
  revokeSubject = async (pubkey: string) => (await this.call<{ rotations: RotationRequired[] }>('POST', `/v1/subjects/${enc(pubkey)}/revoke`)).rotations;

  listResources = async () => (await this.call<{ resources: Resource[] }>('GET', '/v1/resources')).resources;
  putResource = (id: string, r: Omit<Resource, 'id'>) => this.call<unknown>('PUT', `/v1/resources/${enc(id)}`, { kind: r.kind, sensitivity: r.sensitivity, rules: r.rules, ...(r.members ? { members: r.members } : {}) });

  listDevices = async (owner: string) => (await this.call<{ devices: Device[] }>('GET', `/v1/devices?owner=${enc(owner)}`)).devices;
  registerDevice = (owner: string, trust?: Device['trust']) => this.call<Device>('POST', '/v1/devices', { owner, ...(trust ? { trust } : {}) });
  revokeDevice = async (id: string, reason?: string) => (await this.call<{ rotations: RotationRequired[] }>('POST', `/v1/devices/${enc(id)}/revoke`, reason ? { reason } : {})).rotations;
  webauthnOptions = (id: string) => this.call<CreationOptionsJSON>('POST', `/v1/devices/${enc(id)}/webauthn/options`);
  webauthnRegister = (id: string, credential: RegistrationCredentialJSON) => this.call<Device>('POST', `/v1/devices/${enc(id)}/webauthn/register`, credential);

  /** Newest first; `before` is the `id` of the oldest entry already shown (exclusive). */
  audit = async (q: { limit: number; before?: number }) => {
    const qs = new URLSearchParams({ limit: String(q.limit) });
    if (q.before !== undefined) qs.set('before', String(q.before));
    return (await this.call<{ audit: AuditEntry[] }>('GET', `/v1/audit?${qs}`)).audit;
  };

  pendingRotations = async () => (await this.call<{ rotations: Rotation[] }>('GET', '/v1/rotations?status=pending')).rotations;
  markRotationDone = (id: string) => this.call<unknown>('POST', `/v1/rotations/${enc(id)}/done`);

  directory = async () => (await this.call<{ entries: DirectoryEntry[] }>('GET', '/v1/directory')).entries;
  putDirectory = (pubkey: string, e: { title?: string; unit?: string }) => this.call<unknown>('PUT', `/v1/directory/${enc(pubkey)}`, e);
  deleteDirectory = (pubkey: string) => this.call<unknown>('DELETE', `/v1/directory/${enc(pubkey)}`);

  retention = () => this.call<{ policies: RetentionPolicy[]; notice: string }>('GET', '/v1/retention');
  putRetention = (resourceId: string, p: { days: number | null; legalHold: boolean }) => this.call<unknown>('PUT', `/v1/retention/${enc(resourceId)}`, p);
}

/**
 * identity-service has no admin routes by design (it never lists accounts). The console only offers
 * the NIP-98 lookup any user has: links that are public or selective with the admin in the audience.
 */
export class IdentityLookupApi {
  private readonly base: string;
  constructor(baseUrl: string, private readonly signer: Signer, private readonly f: typeof fetch = (...a) => fetch(...a)) {
    this.base = baseUrl.replace(/\/+$/, '');
  }
  visibleLinks = async (pubkey: string) => (await signedJson<{ links: VisibleLink[] }>(this.signer, `${this.base}/v1/links/visible/${enc(pubkey)}`, 'GET', undefined, this.f)).links;
}
