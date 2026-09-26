import { fileURLToPath } from 'node:url';
import { createPgPool, migrate } from '@sedecim/service-kit';
import { CognitoVerifier, createIdentityApi, MemoryIdentityRepository, PgIdentityRepository } from './index';

const env = process.env;
let repo;
if (env.DATABASE_URL) {
  const pool = createPgPool(env.DATABASE_URL);
  await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'identity-service');
  repo = new PgIdentityRepository(pool);
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
const api = createIdentityApi(repo, { name: 'identity-service', publicBaseUrl: env.PUBLIC_BASE_URL, corsOrigins, ...(cognito ? { cognito } : {}) });
await api.listen(Number(env.PORT ?? 8082), env.HOST ?? '0.0.0.0');
