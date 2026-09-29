import { fileURLToPath } from 'node:url';
import { createPgPool, migrate, migrateReplayStore, PgReplayStore, rateLimitFromEnv, serveMetrics, type ReplayStore } from '@sedecim/service-kit';
import { CognitoVerifier, createContinuityVaultApi, FileObjectStore, MemoryArchiveRepository, MemoryObjectStore, PgArchiveRepository, VaultSweeper, type ArchiveRepository, type Nip98Policy, type ObjectStore, type VaultLimits } from './index';

const env = process.env;

function positive(name: string): number | undefined {
  const v = env[name];
  if (v === undefined || v === '') return undefined;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error(`${name} must be a positive integer, got '${v}'`);
  return n;
}

// Metadata and envelopes must survive together: both persistent (DATABASE_URL + VAULT_OBJECTS_DIR) or both
// in memory for development. A persistent half would leave rows without objects, or objects without rows.
if (!!env.DATABASE_URL !== !!env.VAULT_OBJECTS_DIR) throw new Error('set both DATABASE_URL and VAULT_OBJECTS_DIR, or neither (in-memory development mode)');
let repo: ArchiveRepository;
let objects: ObjectStore;
// IR-2026-09-04: used NIP-98 ids shared by every replica through Postgres; per process without it.
let replayStore: ReplayStore | undefined;
if (env.DATABASE_URL) {
  const pool = createPgPool(env.DATABASE_URL);
  await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'continuity-vault');
  await migrateReplayStore(pool);
  repo = new PgArchiveRepository(pool);
  replayStore = new PgReplayStore(pool);
  objects = new FileObjectStore(env.VAULT_OBJECTS_DIR!);
} else {
  console.warn('DATABASE_URL and VAULT_OBJECTS_DIR not set: archives kept in memory and lost on restart');
  repo = new MemoryArchiveRepository();
  objects = new MemoryObjectStore();
}
// SaaS mode: Acceso (Cognito) logins can hold vault accounts. Self-hosted leaves these unset.
const cognito =
  env.COGNITO_USER_POOL_ID && env.COGNITO_CLIENT_ID
    ? new CognitoVerifier({ region: env.COGNITO_REGION ?? 'us-east-1', userPoolId: env.COGNITO_USER_POOL_ID, clientId: env.COGNITO_CLIENT_ID, ...(env.COGNITO_JWKS_URL ? { jwksUrl: env.COGNITO_JWKS_URL } : {}) })
    : undefined;
const nip98 = (env.VAULT_NIP98 ?? 'open') as Nip98Policy;
if (!['open', 'allowlist', 'off'].includes(nip98)) throw new Error("VAULT_NIP98 must be 'open', 'allowlist' or 'off'");
const allowedPubkeys = (env.VAULT_ALLOWED_PUBKEYS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
const limits: Partial<VaultLimits> = {};
const maxEnvelopeBytes = positive('VAULT_MAX_ENVELOPE_BYTES');
const maxArchives = positive('VAULT_MAX_ARCHIVES');
const maxBytes = positive('VAULT_MAX_BYTES');
if (maxEnvelopeBytes) limits.maxEnvelopeBytes = maxEnvelopeBytes;
if (maxArchives) limits.maxArchives = maxArchives;
if (maxBytes) limits.maxBytes = maxBytes;
const corsOrigins = (env.CORS_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
// VAULT-05: the most days an archive is kept since its last write, and how often the sweep runs (retention and
// orphan objects). An interval under a minute would only hammer the database.
const retentionDays = positive('VAULT_RETENTION_DAYS');
const sweepEvery = positive('VAULT_SWEEP_INTERVAL_MS') ?? 60 * 60 * 1000;
if (sweepEvery < 60_000) throw new Error(`VAULT_SWEEP_INTERVAL_MS must be at least 60000, got ${sweepEvery}`);
const api = createContinuityVaultApi(repo, objects, {
  name: 'continuity-vault',
  publicBaseUrl: env.PUBLIC_BASE_URL,
  corsOrigins,
  nip98,
  allowedPubkeys,
  limits,
  ...(retentionDays ? { retentionDays } : {}),
  rateLimit: rateLimitFromEnv(env),
  ...(replayStore ? { replayStore } : {}),
  ...(cognito ? { cognito } : {}),
});
if (env.METRICS_PORT && api.rateLimiter) await serveMetrics(() => api.rateLimiter!.render(), { port: Number(env.METRICS_PORT), host: env.METRICS_HOST ?? '0.0.0.0' });
await api.listen(Number(env.PORT ?? 8088), env.HOST ?? '0.0.0.0');
const sweeper = new VaultSweeper(repo, objects, { ...(retentionDays ? { retentionDays } : {}), logger: api.logger });
const sweep = () => void sweeper.sweep().catch((e) => api.logger.error('vault sweep failed', { error: (e as Error).message }));
sweep();
setInterval(sweep, sweepEvery).unref();
