import { Counter, Registry } from '@sedecim/metrics';

export type SignerOp = 'sign' | 'nip44_encrypt' | 'nip44_decrypt';

/**
 * Prometheus metrics of the managed signer (FR005-06). Labels are coarse classes only: never key ids,
 * owners, pubkeys, device ids or event kinds chosen by the caller.
 */
export class SignerMetrics {
  readonly registry = new Registry();
  readonly operations = this.registry.register(
    new Counter('managed_signer_operations_total', 'Custodial operations by type and result (ok, rate_limited, denied, error).', ['op', 'result']),
  );
  readonly rateLimited = this.registry.register(
    new Counter('managed_signer_rate_limited_total', 'Custodial operations rejected with 429 by the per-key or per-kind limit.', ['op', 'scope']),
  );
  readonly deviceRevocations = this.registry.register(
    new Counter('managed_signer_device_revocations_total', 'Device revocations received (new = first time for that device).', ['result']),
  );
  readonly deviceRejections = this.registry.register(
    new Counter('managed_signer_revoked_device_rejections_total', 'Requests rejected because their device was revoked.', []),
  );

  async render(): Promise<string> {
    return this.registry.render();
  }
}
