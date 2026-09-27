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

/** Entry of the policy-engine audit log (only the fields used here). */
export interface PolicyAuditEntry {
  at: number;
  action: string;
  target: string;
  details?: Record<string, unknown>;
}

export class PolicyHttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

export interface PolicyConnection {
  baseUrl: string;
  /** Admin identity for NIP-98 (its pubkey must be in POLICY_ADMIN_PUBKEYS). */
  signer: Signer;
  /** Optional service bearer for `POST /v1/rotations/:id/done` (NIP-98 is used otherwise). */
  bearer?: string;
  fetch?: typeof fetch;
}

/** Signs a NIP-98 Authorization header for exactly this URL (with query), method and body. */
export async function nip98Header(signer: Signer, url: string, method: string, body = ''): Promise<string> {
  return nip98.encodeAuthHeader(await signer.signEvent(nip98.buildHttpAuthTemplate(url, method, body)));
}

/**
 * Policy-engine client for the rotation contract: `GET /v1/rotations?status=pending` (admin NIP-98) and
 * `POST /v1/rotations/:id/done` (admin NIP-98 or bearer).
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
    const { rotations } = await this.call<{ rotations?: Partial<Rotation>[] }>('GET', '/v1/rotations?status=pending');
    // Defensive: a server that ignores the filter, or rotations without an id, are never acted upon blindly.
    return (rotations ?? []).filter((r): r is Rotation => typeof r.id === 'string' && r.status === 'pending' && typeof r.resourceId === 'string' && typeof r.removedPubkey === 'string');
  }

  async markDone(id: string): Promise<void> {
    await this.call('POST', `/v1/rotations/${encodeURIComponent(id)}/done`, true);
  }

  /** Audit log (admin NIP-98), used to propagate device revocations. */
  async audit(): Promise<PolicyAuditEntry[]> {
    return (await this.call<{ audit?: PolicyAuditEntry[] }>('GET', '/v1/audit')).audit ?? [];
  }
}
