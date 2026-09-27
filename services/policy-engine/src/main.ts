import { fileURLToPath } from 'node:url';
import { createPgPool, migrate } from '@sedecim/service-kit';
import { createPolicyApi, MemoryPolicyRepository, PgPolicyRepository, PolicyEngine, type PolicyRepository } from './index';

const env = process.env;
const admins = (env.POLICY_ADMIN_PUBKEYS ?? '').split(',').filter(Boolean);
const tokens = Object.fromEntries((env.POLICY_SERVICE_TOKENS ?? '').split(',').filter(Boolean).map((p) => p.split(':') as [string, string]));
if (admins.length === 0) console.warn('POLICY_ADMIN_PUBKEYS empty: admin routes will reject every request');

let repo: PolicyRepository;
if (env.DATABASE_URL) {
  const pool = createPgPool(env.DATABASE_URL);
  await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'policy-engine');
  repo = new PgPolicyRepository(pool);
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
const api = createPolicyApi(new PolicyEngine(repo, Date.now, webauthn), { name: 'policy-engine', publicBaseUrl: env.PUBLIC_BASE_URL, bearerTokens: tokens, adminPubkeys: admins, corsOrigins });
await api.listen(Number(env.PORT ?? 8083), env.HOST ?? '0.0.0.0');
