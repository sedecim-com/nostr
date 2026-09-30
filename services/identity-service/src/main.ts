import { fileURLToPath } from 'node:url';
import { createPgPool, migrate, migrateReplayStore, PgReplayStore, rateLimitFromEnv, serveMetrics, tracingFromEnv, type ReplayStore } from '@sedecim/service-kit';
import { CognitoVerifier, createIdentityApi, MemoryIdentityRepository, PgIdentityRepository } from './index';

const env = process.env;
let repo;
// IR-2026-09-04: used NIP-98 ids shared by every replica through Postgres; per process without it.
let replayStore: ReplayStore | undefined;
if (env.DATABASE_URL) {
  const pool = createPgPool(env.DATABASE_URL);
  await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'identity-service');
  await migrateReplayStore(pool);
  repo = new PgIdentityRepository(pool);
  replayStore = new PgReplayStore(pool);
} else {
  console.warn('DATABASE_URL not set: using in-memory repository');
  repo = new MemoryIdentityRepository();
}
// SaaS mode: Acceso (Cognito) logins can be attached to accounts. Self-hosted leaves these unset.
const cognito =
  env.COGNITO_USER_POOL_ID && env.COGNITO_CLIENT_ID
    ? new CognitoVerifier({ region: env.COGNITO_REGION ?? 'us-east-1', userPoolId: env.COGNITO_USER_POOL_ID, clientId: env.COGNITO_CLIENT_ID, ...(env.COGNITO_JWKS_URL ? { jwksUrl: env.COGNITO_JWKS_URL } : {}) })
    : undefined;
const corsOrigins = (env.CORS_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
// FR027-03: encrypted backup vault limits (envelope size, versions kept per account).
const backupVault = { ...(env.BACKUP_VAULT_MAX_BYTES ? { maxBytes: Number(env.BACKUP_VAULT_MAX_BYTES) } : {}), ...(env.BACKUP_VAULT_KEEP ? { keep: Number(env.BACKUP_VAULT_KEEP) } : {}) };
const api = createIdentityApi(repo, {
  name: 'identity-service',
  publicBaseUrl: env.PUBLIC_BASE_URL,
  corsOrigins,
  backupVault,
  rateLimit: rateLimitFromEnv(env),
  // NFR007-02: TELEMETRY_LEVEL / TRACE_SAMPLE_RATE / TRACE_EXPORT_URL; off by default.
  tracing: tracingFromEnv(env),
  ...(replayStore ? { replayStore } : {}),
  ...(cognito ? { cognito } : {}),
});
if (env.METRICS_PORT && api.rateLimiter) await serveMetrics(() => api.rateLimiter!.render(), { port: Number(env.METRICS_PORT), host: env.METRICS_HOST ?? '0.0.0.0' });
await api.listen(Number(env.PORT ?? 8082), env.HOST ?? '0.0.0.0');
