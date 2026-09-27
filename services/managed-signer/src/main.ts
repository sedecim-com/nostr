import { fileURLToPath } from 'node:url';
import { hexToBytes } from '@sedecim/nostr-core';
import { CognitoVerifier, createPgPool, migrate } from '@sedecim/service-kit';
import { startMetricsServer } from '@sedecim/metrics/server';
import {
  awsKms,
  awsSecretsManager,
  createManagedSignerApi,
  DEFAULT_AWS_REGION,
  DEFAULT_RATE_LIMITS,
  MemoryDeviceStore,
  parseKindLimits,
  PgDeviceStore,
  type DeviceStore,
  enclaveBackendFromEnv,
  LocalEnvelopeVault,
  ManagedSigner,
  MemoryKeyRegistry,
  PgKeyRegistry,
  SecretsManagerVault,
  type KeyRegistry,
  type Vault,
} from './index';

const env = process.env;
const list = (v: string | undefined) => (v ?? '').split(',').map((s) => s.trim()).filter(Boolean);
const retentionDays = Number(env.MANAGED_SIGNER_RETENTION_DAYS ?? 30);
const region = env.AWS_REGION || DEFAULT_AWS_REGION;

// Vault: local envelope files (self-hosted) or AWS Secrets Manager + KMS (SaaS, DEC-09).
let vault: Vault;
const vaultKind = env.MANAGED_SIGNER_VAULT || 'local';
if (vaultKind === 'aws') {
  if (!env.MANAGED_SIGNER_KMS_KEY_ID) throw new Error('MANAGED_SIGNER_KMS_KEY_ID is required with MANAGED_SIGNER_VAULT=aws');
  const aws = { region, ...(env.MANAGED_SIGNER_AWS_ENDPOINT ? { endpoint: env.MANAGED_SIGNER_AWS_ENDPOINT } : {}) };
  vault = new SecretsManagerVault(awsSecretsManager(aws), awsKms(aws), {
    kmsKeyId: env.MANAGED_SIGNER_KMS_KEY_ID,
    retentionDays,
    ...(env.MANAGED_SIGNER_SECRET_PREFIX ? { prefix: env.MANAGED_SIGNER_SECRET_PREFIX } : {}),
  });
} else if (vaultKind === 'local') {
  if (!env.MANAGED_SIGNER_KEK || !/^[0-9a-f]{64}$/.test(env.MANAGED_SIGNER_KEK)) throw new Error('MANAGED_SIGNER_KEK (64 hex chars) is required with MANAGED_SIGNER_VAULT=local');
  vault = new LocalEnvelopeVault(env.MANAGED_SIGNER_VAULT_DIR ?? '/data/vault', hexToBytes(env.MANAGED_SIGNER_KEK));
} else throw new Error(`MANAGED_SIGNER_VAULT must be 'local' or 'aws', got '${vaultKind}'`);

let registry: KeyRegistry;
let devices: DeviceStore;
if (env.DATABASE_URL) {
  const pool = createPgPool(env.DATABASE_URL);
  await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'managed-signer');
  registry = new PgKeyRegistry(pool);
  devices = new PgDeviceStore(pool);
} else {
  console.warn('DATABASE_URL not set: using an in-memory key registry and device revocations (lost on restart)');
  registry = new MemoryKeyRegistry();
  devices = new MemoryDeviceStore();
}

// Authorization (FR005-04): Acceso end users; the service-token mode only when explicitly enabled.
if (env.MANAGED_SIGNER_TOKENS) throw new Error('MANAGED_SIGNER_TOKENS was renamed to MANAGED_SIGNER_SERVICE_TOKENS (legacy service mode, opt-in)');
const cognito =
  env.COGNITO_USER_POOL_ID && env.COGNITO_CLIENT_ID
    ? new CognitoVerifier({ region: env.COGNITO_REGION || region, userPoolId: env.COGNITO_USER_POOL_ID, clientId: env.COGNITO_CLIENT_ID, ...(env.COGNITO_JWKS_URL ? { jwksUrl: env.COGNITO_JWKS_URL } : {}) })
    : undefined;
const pairs = (v: string | undefined) => Object.fromEntries(list(v).map((p) => p.split(':') as [string, string]));
const serviceTokens = pairs(env.MANAGED_SIGNER_SERVICE_TOKENS);
// FR024-03: who may revoke devices (policy side / rotation worker), token:principal.
const revocationTokens = pairs(env.MANAGED_SIGNER_REVOCATION_TOKENS);
if (!cognito && !Object.keys(serviceTokens).length) throw new Error('configure COGNITO_USER_POOL_ID + COGNITO_CLIENT_ID (Acceso users) or MANAGED_SIGNER_SERVICE_TOKENS');

// FR005-06: per-key and per-kind token buckets (per minute). MANAGED_SIGNER_RATE_LIMITS=off disables them.
const perMin = (v: string | undefined, d: number) => (v ? Number(v) : d);
const rateLimits =
  env.MANAGED_SIGNER_RATE_LIMITS === 'off'
    ? (false as const)
    : {
        perKey: { perMinute: perMin(env.MANAGED_SIGNER_RATE_PER_KEY, DEFAULT_RATE_LIMITS.perKey.perMinute) },
        perKind: { perMinute: perMin(env.MANAGED_SIGNER_RATE_PER_KIND, DEFAULT_RATE_LIMITS.perKind.perMinute) },
        kinds: { ...DEFAULT_RATE_LIMITS.kinds, ...parseKindLimits(env.MANAGED_SIGNER_RATE_KINDS) },
      };
if (rateLimits && !(rateLimits.perKey.perMinute > 0 && rateLimits.perKind.perMinute > 0)) throw new Error('MANAGED_SIGNER_RATE_PER_KEY / _PER_KIND must be positive numbers');

// Signing backend (FR005-05): in-process (default) or a Nitro Enclave that only returns signatures.
const enclave = enclaveBackendFromEnv(env);
if (enclave) await enclave.client.verify();

const core = new ManagedSigner(vault, {
  registry,
  devices,
  retentionDays,
  usageRetentionMonths: Number(env.MANAGED_SIGNER_USAGE_RETENTION_MONTHS ?? 12),
  rateLimits,
  ...(enclave ? { sealedKeys: enclave.client } : {}),
  ...(env.MANAGED_SIGNER_DEVICE_SESSION_TTL_S ? { deviceSessionTtlMs: Number(env.MANAGED_SIGNER_DEVICE_SESSION_TTL_S) * 1000 } : {}),
});
const api = createManagedSignerApi(core, {
  name: 'managed-signer',
  corsOrigins: list(env.CORS_ORIGINS),
  ...(cognito ? { cognito } : {}),
  ...(Object.keys(serviceTokens).length ? { serviceTokens } : {}),
  ...(Object.keys(revocationTokens).length ? { revocationTokens } : {}),
  requireDeviceSession: env.MANAGED_SIGNER_REQUIRE_DEVICE_SESSION === 'true',
});
if (!Object.keys(revocationTokens).length) api.logger.warn('MANAGED_SIGNER_REVOCATION_TOKENS empty: device revocations cannot be received');

// Metrics (FR005-06) on an internal port, never through the public API: operation/limit counters only.
if (env.METRICS_PORT) {
  const m = await startMetricsServer(core.metrics, { port: Number(env.METRICS_PORT), host: env.METRICS_HOST ?? '0.0.0.0' });
  api.logger.info('metrics listening', { url: m.url });
}

// Retention job (DEC-09): usage log older than 12 months, material of keys deleted > retention days ago.
const retention = () =>
  core.runRetention().then(
    (r) => (r.usagePurged || r.keysDestroyed || r.sessionsPurged) && api.logger.info('retention job', { usage_purged: r.usagePurged, keys_destroyed: r.keysDestroyed, sessions_purged: r.sessionsPurged }),
    (err) => api.logger.error('retention job failed', { error: (err as Error).message }),
  );
await retention();
setInterval(retention, Number(env.MANAGED_SIGNER_RETENTION_INTERVAL_MS ?? 3_600_000)).unref();
await api.listen(Number(env.PORT ?? 8084), env.HOST ?? '0.0.0.0');
