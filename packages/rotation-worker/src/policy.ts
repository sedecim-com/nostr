import { nip98, type Signer } from '@sedecim/nostr-core';

/** A group rotation the policy-engine asks for after a revocation (FR-024). */
export interface Rotation {
  id: string;
  at: number;
  /** Policy resource of kind 'group': its id is the Marmot (MLS) group id, hex. */
  resourceId: string;
  reason: string;
  /** Every MLS leaf of this pubkey must leave the group. */
  removedPubkey: string;
  status: 'pending' | 'done';
}

export interface RotationSource {
  pending(): Promise<Rotation[]>;
  markDone(id: string): Promise<void>;
}

/** One device revocation of the policy-engine's `GET /v1/revocations` feed (FR024-04). */
export interface DeviceRevocation {
  /** Audit id of the revocation: monotonic, pass the last one handled as `after`. */
  cursor: number;
  at: number;
  deviceId: string;
  reason?: string;
}

/** A page of `GET /v1/revocations`, oldest first. */
export interface RevocationPage {
  revocations: DeviceRevocation[];
  /** Cursor of the newest revocation in the policy-engine (0 if none). */
  latest: number;
  /** Policy-engine clock (epoch ms), the one that stamped `at`. */
  now: number;
}

export class PolicyHttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

export interface PolicyConnection {
  baseUrl: string;
  /** Identity for NIP-98 when there is no `bearer` (its pubkey must then be in POLICY_ADMIN_PUBKEYS). */
  signer: Signer;
  /** Service bearer (one of POLICY_SERVICE_TOKENS) for the rotation contract; NIP-98 of `signer` otherwise. */
  bearer?: string;
  fetch?: typeof fetch;
}

/** Signs a NIP-98 Authorization header for exactly this URL (with query), method and body. */
export async function nip98Header(signer: Signer, url: string, method: string, body = ''): Promise<string> {
  return nip98.encodeAuthHeader(await signer.signEvent(nip98.buildHttpAuthTemplate(url, method, body)));
}

/**
 * Policy-engine client for the rotation contract: `GET /v1/rotations?status=pending`,
 * `POST /v1/rotations/:id/done` and `GET /v1/revocations` (bearer, or admin NIP-98 without one).
 */
export class HttpPolicySource implements RotationSource {
  private readonly base: string;
  constructor(private readonly conn: PolicyConnection) {
    this.base = conn.baseUrl.replace(/\/$/, '');
  }

  private async call<T>(method: string, path: string, useBearer = false): Promise<T> {
    const url = `${this.base}${path}`;
    const authorization = useBearer && this.conn.bearer ? `Bearer ${this.conn.bearer}` : await nip98Header(this.conn.signer, url, method);
    const res = await (this.conn.fetch ?? fetch)(url, { method, headers: { authorization } });
    const text = await res.text();
    if (!res.ok) throw new PolicyHttpError(res.status, `policy-engine ${method} ${path}: ${res.status}`);
    return (text ? JSON.parse(text) : {}) as T;
  }

  async pending(): Promise<Rotation[]> {
    const { rotations } = await this.call<{ rotations?: Partial<Rotation>[] }>('GET', '/v1/rotations?status=pending', true);
    // Defensive: a server that ignores the filter, or rotations without an id, are never acted upon blindly.
    return (rotations ?? []).filter((r): r is Rotation => typeof r.id === 'string' && r.status === 'pending' && typeof r.resourceId === 'string' && typeof r.removedPubkey === 'string');
  }

  async markDone(id: string): Promise<void> {
    await this.call('POST', `/v1/rotations/${encodeURIComponent(id)}/done`, true);
  }

  /** FR024-04: device revocations after `after`, oldest first, used to propagate them to the signers. */
  async revocations(after: number, limit: number): Promise<RevocationPage> {
    const page = await this.call<Partial<RevocationPage>>('GET', `/v1/revocations?after=${after}&limit=${limit}`, true);
    const valid = (r: Partial<DeviceRevocation>) => Number.isSafeInteger(r.cursor) && typeof r.at === 'number' && typeof r.deviceId === 'string' && r.deviceId !== '';
    // Never skip what cannot be read: a malformed page fails the run, and the cursor stays where it is.
    if (!Array.isArray(page.revocations) || !page.revocations.every(valid) || typeof page.latest !== 'number' || typeof page.now !== 'number') {
      throw new PolicyHttpError(502, 'policy-engine GET /v1/revocations: malformed response');
    }
    const revocations = (page.revocations as DeviceRevocation[]).filter((r) => r.cursor > after).sort((a, b) => a.cursor - b.cursor);
    return { revocations, latest: page.latest, now: page.now };
  }
}
