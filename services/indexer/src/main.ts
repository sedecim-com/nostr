import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';
import { generateSecretKey, getPublicKey, hexToBytes, nip19, npubEncode } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { createPgPool, migrate } from '@sedecim/service-kit';
import { createLogger, type TelemetryLevel } from '@sedecim/telemetry-policy';
import { NostrMetricsExporter, parseRegionMap, startAckProbe } from '@sedecim/metrics';
import { startMetricsServer } from '@sedecim/metrics/server';
import { bearer, PolicyEngineClient } from '@sedecim/policy-client';
import { createIndexerApi, DEFAULT_MIRROR_KINDS, enforceRetention, Indexer, MemoryEventRepository, PgEventRepository, plainCodec, sealedCodec, type IndexerPolicy } from './index';

const env = process.env;
const logger = createLogger({ base: { service: 'indexer' }, minimizeIp: true });
const relays = (env.INDEXER_RELAYS ?? 'ws://relay:3000').split(',').map((s) => s.trim()).filter(Boolean);
const codec = env.MIRROR_AT_REST_KEY ? sealedCodec(hexToBytes(env.MIRROR_AT_REST_KEY)) : plainCodec;

let repo;
if (env.DATABASE_URL) {
  const pool = createPgPool(env.DATABASE_URL);
  const applied = await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'indexer');
  logger.info('migrations applied', { applied: applied.join(',') || 'none' });
  repo = new PgEventRepository(pool, codec);
} else {
  logger.warn('DATABASE_URL not set: using in-memory repository');
  repo = new MemoryEventRepository(codec);
}

const kinds = env.INDEXER_KINDS ? env.INDEXER_KINDS.split(',').map(Number) : DEFAULT_MIRROR_KINDS;
// Relays such as Buzz refuse anonymous REQs: the mirror authenticates (NIP-42) with a service identity.
// It only mirrors what that identity may read; allowlist its npub on private relays.
function serviceKey(): Uint8Array {
  const raw = env.INDEXER_NSEC?.trim();
  if (!raw) {
    logger.warn('INDEXER_NSEC not set: using an ephemeral service identity (set it to allowlist the mirror)');
    return generateSecretKey();
  }
  if (raw.startsWith('nsec1')) {
    const d = nip19.decode(raw);
    if (d.type !== 'nsec') throw new Error('INDEXER_NSEC must be an nsec or 64 hex chars');
    return d.data;
  }
  return hexToBytes(raw);
}
// Buzz resolves the tenant from the Host header (unknown hosts get a 404) and expects the NIP-42 relay tag
// to be ws(s)://<that host>. When we dial an internal address (ws://relay:3000) we present the public one.
// INDEXER_RELAY_PUBLIC_URL: one URL for every relay, or `internal=public` pairs separated by commas.
function publicUrlMap(): ((url: string) => string) | undefined {
  const raw = env.INDEXER_RELAY_PUBLIC_URL?.trim();
  if (!raw) return undefined;
  if (!raw.includes('=')) return () => raw;
  const map = new Map(raw.split(',').map((p) => p.split('=').map((s) => s.trim()) as [string, string]));
  return (url) => map.get(url) ?? url;
}
const publicUrl = publicUrlMap();
const webSocketFactory = (u: string) => {
  const host = publicUrl ? new URL(publicUrl(u)).host : undefined;
  return new WebSocket(u, host && host !== new URL(u).host ? { headers: { host } } : {}) as unknown as WebSocketLike;
};
const serviceSecret = serviceKey();
logger.info('mirror service identity', { npub: npubEncode(getPublicKey(serviceSecret)) });
const pool = new RelayPool({ webSocketFactory, signer: new LocalSigner(serviceSecret), authMode: 'auto', authRelayUrl: publicUrl });

// NFR004-01 / FR011-03: optional Prometheus exporter on its own internal port (never on the public API).
// TELEMETRY_LEVEL=none (or no METRICS_PORT) keeps it off; relay labels are hosts only (onion relays hashed).
if (env.METRICS_PORT) {
  const level = (env.TELEMETRY_LEVEL ?? 'standard') as TelemetryLevel;
  if (!['standard', 'minimal', 'none'].includes(level)) throw new Error('TELEMETRY_LEVEL must be standard, minimal or none');
  const exporter = NostrMetricsExporter.forProfile({ telemetry: level }, { regions: parseRegionMap(env.RELAY_REGIONS), defaultRegion: env.RELAY_DEFAULT_REGION ?? 'unknown', labelSalt: env.METRICS_LABEL_SALT });
  if (!exporter) logger.info('metrics disabled by telemetry level', { telemetryLevel: level });
  else {
    exporter.attachPool(pool);
    const m = await startMetricsServer(exporter, { port: Number(env.METRICS_PORT), host: env.METRICS_HOST ?? '0.0.0.0' });
    logger.info('metrics exporter listening', { url: m.url, telemetryLevel: level });
    const every = Number(env.ACK_PROBE_INTERVAL_MS ?? 0);
    // The mirror only subscribes; a synthetic probe (empty ephemeral event) measures ACK latency per relay.
    if (every > 0) startAckProbe({ pool, signer: new LocalSigner(serviceSecret), relays, intervalMs: every, ...(env.ACK_PROBE_KIND ? { kind: Number(env.ACK_PROBE_KIND) } : {}) });
  }
}

const indexer = new Indexer(pool, repo, { relays, filters: [{ kinds }], communityId: env.COMMUNITY_ID, logger, channelRefreshMs: Number(env.INDEXER_CHANNEL_REFRESH_MS ?? 30_000) });
void indexer.start().then(() => logger.info('initial backfill complete', { ingested: indexer.ingested }));

// Institutional mode (FR023-05, FR023-08): reads filtered by the policy-engine and retention enforced on the
// mirror. Both need POLICY_ENGINE_URL and a service token listed in the engine's POLICY_SERVICE_TOKENS.
let policy: IndexerPolicy | undefined;
if (env.POLICY_ENGINE_URL) {
  if (!env.POLICY_ENGINE_TOKEN) throw new Error('POLICY_ENGINE_TOKEN is required with POLICY_ENGINE_URL');
  const client = new PolicyEngineClient(env.POLICY_ENGINE_URL, bearer(env.POLICY_ENGINE_TOKEN));
  const workspaceId = env.INDEXER_POLICY_WORKSPACE || env.COMMUNITY_ID;
  policy = { evaluate: (i) => client.evaluate(i), ...(workspaceId ? { workspaceId } : {}) };
  logger.info('institutional mode: reads evaluated by the policy-engine', { workspace: workspaceId ?? 'none' });
  const every = Number(env.RETENTION_INTERVAL_MS ?? 3_600_000);
  if (every > 0) {
    const runRetention = async () => {
      try {
        const res = await enforceRetention(repo, (await client.retention()).policies);
        const deleted = res.reduce((n, r) => n + r.deleted, 0);
        if (deleted) logger.info('retention applied', { deleted, resources: res.filter((r) => r.deleted).map((r) => r.resourceId).join(',') });
      } catch (err) {
        logger.warn('retention run failed', { error: (err as Error).message });
      }
    };
    void runRetention();
    setInterval(() => void runRetention(), every).unref();
  }
}

const api = createIndexerApi(repo, { name: 'indexer', publicBaseUrl: env.PUBLIC_BASE_URL, requireAuth: env.INDEXER_REQUIRE_AUTH === 'true', logger, ...(policy ? { policy } : {}) });
await api.listen(Number(env.PORT ?? 8081), env.HOST ?? '0.0.0.0');
