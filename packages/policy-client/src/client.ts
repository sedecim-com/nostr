import type { Action, Decision } from './evaluate';
import type { RelayGrant, RetentionPolicy } from './admin';

/** HTTP client for the policy-engine service (service-to-service bearer routes). */
export class PolicyEngineClient {
  constructor(private readonly baseUrl: string, private readonly authorization: () => string | Promise<string>, private readonly f: typeof fetch = fetch) {}

  private async call(path: string, init: RequestInit = {}): Promise<Response> {
    return this.f(`${this.baseUrl}${path}`, { ...init, headers: { 'content-type': 'application/json', authorization: await this.authorization() } });
  }

  /** Fails closed: any engine error is a deny. */
  async evaluate(input: { pubkey: string; deviceId?: string; resourceId: string; action: Action }): Promise<Decision> {
    try {
      const res = await this.call('/v1/evaluate', { method: 'POST', body: JSON.stringify(input) });
      if (!res.ok) return { allow: false, reasons: [`policy engine error ${res.status}`] };
      return (await res.json()) as Decision;
    } catch (e) {
      return { allow: false, reasons: [`policy engine unreachable: ${(e as Error).message}`] };
    }
  }

  /** NIP-42 allowlist for the relays (FR023-04). Throws on error so callers keep the last good list. */
  async relayAllowlist(): Promise<string[]> {
    const res = await this.call('/v1/relay/allowlist');
    if (!res.ok) throw new Error(`policy engine error ${res.status}`);
    return ((await res.json()) as { pubkeys: string[] }).pubkeys;
  }

  /** FR023-10: who may publish in each registered channel and group (relay admission by `h`, NIP-29 membership). */
  async relayGrants(): Promise<RelayGrant[]> {
    const res = await this.call('/v1/relay/grants');
    if (!res.ok) throw new Error(`policy engine error ${res.status}`);
    return ((await res.json()) as { grants: RelayGrant[] }).grants;
  }

  /** Retention policies and the replication notice (FR023-08). Throws on error. */
  async retention(): Promise<{ policies: RetentionPolicy[]; notice: string }> {
    const res = await this.call('/v1/retention');
    if (!res.ok) throw new Error(`policy engine error ${res.status}`);
    return (await res.json()) as { policies: RetentionPolicy[]; notice: string };
  }

  async markRotationDone(id: string): Promise<boolean> {
    return (await this.call(`/v1/rotations/${encodeURIComponent(id)}/done`, { method: 'POST', body: '{}' })).ok;
  }
}

/** `Authorization: Bearer <token>` provider for the client. */
export const bearer = (token: string) => () => `Bearer ${token}`;
