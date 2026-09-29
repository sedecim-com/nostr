import { fileURLToPath } from 'node:url';
import { createPgPool, migrate, migrateReplayStore, PgReplayStore, rateLimitFromEnv, serveMetrics, type ReplayStore } from '@sedecim/service-kit';
import { CognitoVerifier, createContinuityVaultApi, FileObjectStore, MemoryArchiveRepository, MemoryObjectStore, PgArchiveRepository, S3ObjectStore, VaultSweeper, type ArchiveRepository, type Nip98Policy, type ObjectStore, type VaultLimits } from './index';

const env = process.env;

function positive(name: string): number | undefined {
  const v = env[name];
  if (v === undefined || v === '') return undefined;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n <= 0) throw new Error(`${name} must be a positive integer, got '${v}'`);
  return n;
}

// Where the envelopes go: a directory (VAULT_OBJECTS_DIR) or an S3-compatible bucket (VAULT_S3_BUCKET, VAULT-06).
if (env.VAULT_OBJECTS_DIR && env.VAULT_S3_BUCKET) throw new Error('set VAULT_OBJECTS_DIR or VAULT_S3_BUCKET, not both');
const persistentObjects = !!(env.VAULT_OBJECTS_DIR || env.VAULT_S3_BUCKET);
// Metadata and envelopes must survive together: both persistent (DATABASE_URL + a directory or a bucket) or both
// in memory for development. A persistent half would leave rows without objects, or objects without rows.
if (!!env.DATABASE_URL !== persistentObjects) throw new Error('set DATABASE_URL together with VAULT_OBJECTS_DIR or VAULT_S3_BUCKET, or none of them (in-memory development mode)');
if (!!env.VAULT_S3_ACCESS_KEY !== !!env.VAULT_S3_SECRET_KEY) throw new Error('set both VAULT_S3_ACCESS_KEY and VAULT_S3_SECRET_KEY, or neither (default AWS credentials)');
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
  if (env.VAULT_S3_BUCKET) {
    const s3 = new S3ObjectStore({
      bucket: env.VAULT_S3_BUCKET,
      ...(env.VAULT_S3_ENDPOINT ? { endpoint: env.VAULT_S3_ENDPOINT } : {}),
      ...(env.VAULT_S3_REGION ? { region: env.VAULT_S3_REGION } : {}),
      ...(env.VAULT_S3_ACCESS_KEY ? { credentials: { accessKeyId: env.VAULT_S3_ACCESS_KEY, secretAccessKey: env.VAULT_S3_SECRET_KEY! } } : {}),
      ...(env.VAULT_S3_FORCE_PATH_STYLE ? { forcePathStyle: env.VAULT_S3_FORCE_PATH_STYLE === 'true' } : {}),
      ...(env.VAULT_S3_PREFIX ? { prefix: env.VAULT_S3_PREFIX } : {}),
    });
    // A missing bucket or wrong credentials stop the start, not the first upload.
    await s3.check();
    objects = s3;
  } else {
    objects = new FileObjectStore(env.VAULT_OBJECTS_DIR!);
  }
} else {
  console.warn('DATABASE_URL and VAULT_OBJECTS_DIR / VAULT_S3_BUCKET not set: archives kept in memory and lost on restart');
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
