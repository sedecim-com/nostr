import { fileURLToPath } from 'node:url';
import { createPgPool, migrate } from '@sedecim/service-kit';
import { createIdentityApi, MemoryIdentityRepository, PgIdentityRepository } from './index';

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
const api = createIdentityApi(repo, { name: 'identity-service', publicBaseUrl: env.PUBLIC_BASE_URL });
await api.listen(Number(env.PORT ?? 8082), env.HOST ?? '0.0.0.0');
