import type { Action, Decision } from './evaluate';

/** HTTP client for the policy-engine service. */
export class PolicyEngineClient {
  constructor(private readonly baseUrl: string, private readonly authorization: () => string | Promise<string>, private readonly f: typeof fetch = fetch) {}

  async evaluate(input: { pubkey: string; deviceId?: string; resourceId: string; action: Action }): Promise<Decision> {
    const res = await this.f(`${this.baseUrl}/v1/evaluate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: await this.authorization() },
      body: JSON.stringify(input),
    });
    if (!res.ok) return { allow: false, reasons: [`policy engine error ${res.status}`] };
    return (await res.json()) as Decision;
  }
}
