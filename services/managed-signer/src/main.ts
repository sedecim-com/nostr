import { CognitoVerifier, rateLimitFromEnv } from '@sedecim/service-kit';
import { startMetricsServer } from '@sedecim/metrics/server';
import { createManagedSignerApi, DEFAULT_AWS_REGION, DEFAULT_RATE_LIMITS, DEFAULT_REAUTH_MAX_AGE_S, DEFAULT_SCRYPT_LIMITS, parseKindLimits, enclaveBackendFromEnv, flagFromEnv, ManagedSigner } from './index';
import { openStorage } from './storage';

const env = process.env;
// FR005-12: the legacy mode (a service token acting for the account in x-account-id) was removed. Refuse to start
// rather than ignore a configuration that still expects it.
for (const legacy of ['MANAGED_SIGNER_SERVICE_TOKENS', 'MANAGED_SIGNER_TOKENS']) {
  if (env[legacy]) throw new Error(`${legacy}: the legacy service mode was removed (FR005-12); callers sign with the user's Acceso token or a device session`);
}
const list = (v: string | undefined) => (v ?? '').split(',').map((s) => s.trim()).filter(Boolean);
const region = env.AWS_REGION || DEFAULT_AWS_REGION;

// Vault (local envelope files or AWS Secrets Manager + KMS, DEC-09), key registry and device store.
const { vault, registry, devices, retentionDays, usageRetentionMonths, persistent } = await openStorage(env);
if (!persistent) console.warn('DATABASE_URL not set: using an in-memory key registry and device revocations (lost on restart)');

// Authorization (FR005-04): Acceso end users, directly or through device sessions.
const cognito =
  env.COGNITO_USER_POOL_ID && env.COGNITO_CLIENT_ID
    ? new CognitoVerifier({ region: env.COGNITO_REGION || region, userPoolId: env.COGNITO_USER_POOL_ID, clientId: env.COGNITO_CLIENT_ID, ...(env.COGNITO_JWKS_URL ? { jwksUrl: env.COGNITO_JWKS_URL } : {}) })
    : undefined;
const pairs = (v: string | undefined) => Object.fromEntries(list(v).map((p) => p.split(':') as [string, string]));
// FR024-03: who may revoke devices (policy side / rotation worker), token:principal.
const revocationTokens = pairs(env.MANAGED_SIGNER_REVOCATION_TOKENS);
if (!cognito) throw new Error('configure COGNITO_USER_POOL_ID + COGNITO_CLIENT_ID (Acceso users)');

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

// IR-2026-09-20: scrypt admission for import/export. MANAGED_SIGNER_SCRYPT_PER_OWNER = perMinute[:burst] per
// owner, _CONCURRENCY = scrypt runs at once per replica, _QUEUE = runs waiting; MANAGED_SIGNER_SCRYPT_LIMITS=off.
const [scryptPerMin, scryptBurst] = (env.MANAGED_SIGNER_SCRYPT_PER_OWNER ?? '').split(':').filter(Boolean).map(Number);
const scryptLimits =
  env.MANAGED_SIGNER_SCRYPT_LIMITS === 'off'
    ? (false as const)
    : {
        perOwner: scryptPerMin !== undefined ? { perMinute: scryptPerMin, ...(scryptBurst !== undefined ? { burst: scryptBurst } : {}) } : DEFAULT_SCRYPT_LIMITS.perOwner,
        maxConcurrent: perMin(env.MANAGED_SIGNER_SCRYPT_CONCURRENCY, DEFAULT_SCRYPT_LIMITS.maxConcurrent),
        maxQueue: perMin(env.MANAGED_SIGNER_SCRYPT_QUEUE, DEFAULT_SCRYPT_LIMITS.maxQueue),
      };
if (scryptLimits && !(scryptLimits.perOwner.perMinute > 0 && (scryptLimits.perOwner.burst ?? 1) > 0 && scryptLimits.maxConcurrent >= 1 && scryptLimits.maxQueue >= 0)) {
  throw new Error('MANAGED_SIGNER_SCRYPT_PER_OWNER / _CONCURRENCY / _QUEUE must be positive numbers');
}

// IR-2026-10-03: how recent (seconds) the Acceso sign-in must be to export, migrate, delete or cancel a key.
const reauthMaxAgeSeconds = Number(env.MANAGED_SIGNER_REAUTH_MAX_AGE_S ?? DEFAULT_REAUTH_MAX_AGE_S);
if (!(Number.isInteger(reauthMaxAgeSeconds) && reauthMaxAgeSeconds > 0 && reauthMaxAgeSeconds <= 3600)) throw new Error('MANAGED_SIGNER_REAUTH_MAX_AGE_S must be a whole number of seconds between 1 and 3600');

// Signing backend (FR005-05): in-process (default) or a Nitro Enclave that only returns signatures.
const enclave = enclaveBackendFromEnv(env);
if (enclave) await enclave.client.verify();
// FR005-10: import secrets and export passwords only sealed by the client to the enclave; the vault tier has no enclave.
const requireSealedSecrets = flagFromEnv(env, 'MANAGED_SIGNER_REQUIRE_SEALED_SECRETS');
if (requireSealedSecrets && !enclave) throw new Error('MANAGED_SIGNER_REQUIRE_SEALED_SECRETS=1 needs MANAGED_SIGNER_BACKEND=enclave: the vault tier decrypts in this process');

const core = new ManagedSigner(vault, {
  registry,
  devices,
  retentionDays,
  usageRetentionMonths,
  rateLimits,
  scryptLimits,
  ...(enclave ? { sealedKeys: enclave.client } : {}),
  ...(requireSealedSecrets ? { requireSealedSecrets } : {}),
  ...(env.MANAGED_SIGNER_DEVICE_SESSION_TTL_S ? { deviceSessionTtlMs: Number(env.MANAGED_SIGNER_DEVICE_SESSION_TTL_S) * 1000 } : {}),
});
const api = createManagedSignerApi(core, {
  name: 'managed-signer',
  corsOrigins: list(env.CORS_ORIGINS),
  cognito,
  ...(Object.keys(revocationTokens).length ? { revocationTokens } : {}),
  requireDeviceSession: env.MANAGED_SIGNER_REQUIRE_DEVICE_SESSION === 'true',
  reauthMaxAgeSeconds,
  // IR-2026-09-05: per-IP buckets (RATE_LIMIT_* env); the per-key signing limits above stay separate.
  rateLimit: rateLimitFromEnv(env),
});
if (!Object.keys(revocationTokens).length) api.logger.warn('MANAGED_SIGNER_REVOCATION_TOKENS empty: device revocations cannot be received');

// Metrics (FR005-06) on an internal port, never through the public API: operation/limit counters only.
if (env.METRICS_PORT) {
  const render = async () => (await core.metrics.render()) + (api.rateLimiter ? await api.rateLimiter.render() : '');
  const m = await startMetricsServer({ render }, { port: Number(env.METRICS_PORT), host: env.METRICS_HOST ?? '0.0.0.0' });
  api.logger.info('metrics listening', { url: m.url });
}

// Retention job (DEC-09): usage log older than 12 months, material of keys deleted > retention days ago, the owner of
// destroyed keys (FR026-04) and login cutoffs as old as the usage log (IR-2026-10-11).
const retention = () =>
  core.runRetention().then(
    (r) =>
      (r.usagePurged || r.keysDestroyed || r.keysScrubbed || r.sessionsPurged || r.loginCutoffsPurged) &&
      api.logger.info('retention job', { usage_purged: r.usagePurged, keys_destroyed: r.keysDestroyed, keys_scrubbed: r.keysScrubbed, sessions_purged: r.sessionsPurged, login_cutoffs_purged: r.loginCutoffsPurged }),
    (err) => api.logger.error('retention job failed', { error: (err as Error).message }),
  );
await retention();
setInterval(retention, Number(env.MANAGED_SIGNER_RETENTION_INTERVAL_MS ?? 3_600_000)).unref();
await api.listen(Number(env.PORT ?? 8084), env.HOST ?? '0.0.0.0');
