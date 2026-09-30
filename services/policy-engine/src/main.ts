import { fileURLToPath } from 'node:url';
import { createPgPool, migrate, migrateReplayStore, PgReplayStore, rateLimitFromEnv, serveMetrics, type ReplayStore } from '@sedecim/service-kit';
import { createPolicyApi, DEFAULT_ACCESS_LOG_RETENTION_DAYS, MemoryPolicyRepository, parseServiceScopes, PgPolicyRepository, PolicyEngine, type PolicyRepository } from './index';

const env = process.env;
const admins = (env.POLICY_ADMIN_PUBKEYS ?? '').split(',').filter(Boolean);
const tokens = Object.fromEntries((env.POLICY_SERVICE_TOKENS ?? '').split(',').filter(Boolean).map((p) => p.split(':') as [string, string]));
// IR-2026-10-01: each service token only for its principal's scopes (indexer, relay-allowlist and rotation-worker by default).
const serviceScopes = parseServiceScopes(env.POLICY_SERVICE_SCOPES);
for (const principal of new Set(Object.values(tokens))) {
  if (!serviceScopes[principal]?.length) console.warn(`POLICY_SERVICE_TOKENS: principal '${principal}' has no scope: its token is refused everywhere (POLICY_SERVICE_SCOPES)`);
}
if (admins.length === 0) console.warn('POLICY_ADMIN_PUBKEYS empty: admin routes will reject every request');

let repo: PolicyRepository;
// IR-2026-09-04: used NIP-98 ids shared by every replica through Postgres; per process without it.
let replayStore: ReplayStore | undefined;
if (env.DATABASE_URL) {
  const pool = createPgPool(env.DATABASE_URL);
  await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'policy-engine');
  await migrateReplayStore(pool);
  repo = new PgPolicyRepository(pool);
  replayStore = new PgReplayStore(pool);
} else {
  console.warn('DATABASE_URL not set: using in-memory repository (policy state is lost on restart)');
  repo = new MemoryPolicyRepository();
}

// FR023-07: WebAuthn relying party = the web app that registers device passkeys.
const origins = (env.WEBAUTHN_ORIGINS || env.WEB_ORIGIN || 'http://localhost:8080').split(',').map((s) => s.trim()).filter(Boolean);
const webauthn = {
  rpId: env.WEBAUTHN_RP_ID || new URL(origins[0]!).hostname,
  rpName: env.WEBAUTHN_RP_NAME || 'Acceso Nostr',
  origins,
  allowNone: env.WEBAUTHN_REQUIRE_ATTESTATION !== 'true',
};
const corsOrigins = (env.CORS_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
const engine = new PolicyEngine(repo, Date.now, webauthn);
// FR023-12: access decisions are kept ACCESS_LOG_RETENTION_DAYS (90), except on resources under legal hold. Every
// replica prunes; the delete is idempotent.
const accessDays = Number(env.ACCESS_LOG_RETENTION_DAYS ?? DEFAULT_ACCESS_LOG_RETENTION_DAYS);
if (!(Number.isInteger(accessDays) && accessDays > 0)) throw new Error('ACCESS_LOG_RETENTION_DAYS must be a positive whole number of days');
const pruneAccessLog = () =>
  engine.pruneAccessLog(accessDays).then(
    (n) => n > 0 && console.info(`access log: ${n} decisions older than ${accessDays} days deleted`),
    (err: Error) => console.warn(`access log retention failed: ${err.message}`),
  );
setInterval(() => void pruneAccessLog(), Number(env.ACCESS_LOG_PRUNE_INTERVAL_MS ?? 3_600_000)).unref();
void pruneAccessLog();
const api = createPolicyApi(engine, {
  name: 'policy-engine',
  publicBaseUrl: env.PUBLIC_BASE_URL,
  bearerTokens: tokens,
  adminPubkeys: admins,
  accessLogRetentionDays: accessDays,
  corsOrigins,
  rateLimit: rateLimitFromEnv(env),
  ...(replayStore ? { replayStore } : {}),
});
if (env.METRICS_PORT && api.rateLimiter) await serveMetrics(() => api.rateLimiter!.render(), { port: Number(env.METRICS_PORT), host: env.METRICS_HOST ?? '0.0.0.0' });
await api.listen(Number(env.PORT ?? 8083), env.HOST ?? '0.0.0.0');
