// FR023-04: relay allowlist sync job (compose service `relay-allowlist`, profile `institutional`).
import { bearer, PolicyEngineClient } from '@sedecim/policy-client';
import { createPgPool, Service } from '@sedecim/service-kit';
import { createLogger } from '@sedecim/telemetry-policy';
import { AdmissionServer, AllowlistSync, BuzzAllowlistSink, FileAllowlistSink, type AllowlistSink } from './allowlist-sync';

const env = process.env;
const logger = createLogger({ base: { service: 'relay-allowlist' }, minimizeIp: true });
const list = (v?: string) => (v ?? '').split(',').map((s) => s.trim()).filter(Boolean);

if (!env.POLICY_ENGINE_TOKEN) throw new Error('POLICY_ENGINE_TOKEN is required (one of the policy-engine POLICY_SERVICE_TOKENS)');
const client = new PolicyEngineClient(env.POLICY_ENGINE_URL ?? 'http://policy-engine:8083', bearer(env.POLICY_ENGINE_TOKEN));

const sinks: AllowlistSink[] = [];
if (env.BUZZ_DATABASE_URL) sinks.push(new BuzzAllowlistSink(createPgPool(env.BUZZ_DATABASE_URL), list(env.BUZZ_ALLOWLIST_HOSTS)));
if (env.ALLOWLIST_FILE) sinks.push(new FileAllowlistSink(env.ALLOWLIST_FILE));

let admission: AdmissionServer | undefined;
if (env.ALLOWLIST_GRPC_PORT !== '') {
  admission = new AdmissionServer();
  const port = await admission.listen(Number(env.ALLOWLIST_GRPC_PORT ?? 50051), env.HOST ?? '0.0.0.0');
  logger.info('nauthz admission server listening', { port });
}
if (!sinks.length && !admission) logger.warn('no sink configured (BUZZ_DATABASE_URL, ALLOWLIST_FILE, ALLOWLIST_GRPC_PORT)');

const sync = new AllowlistSync({
  fetch: () => client.relayAllowlist(),
  sinks,
  ...(admission ? { admission } : {}),
  extraPubkeys: list(env.ALLOWLIST_EXTRA_PUBKEYS),
  intervalMs: Number(env.ALLOWLIST_SYNC_INTERVAL_MS ?? 30_000),
  log: (msg, fields) => logger.info(msg, fields),
});
sync.start();

const health = new Service({ name: 'relay-allowlist', logger });
health.get('/health', () => ({ ok: sync.lastSyncAt !== undefined && !sync.lastError, pubkeys: sync.current.length, lastSyncAt: sync.lastSyncAt ?? null, lastError: sync.lastError ?? null }));
await health.listen(Number(env.PORT ?? 8087), env.HOST ?? '0.0.0.0');
