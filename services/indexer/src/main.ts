import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';
import { hexToBytes } from '@sedecim/nostr-core';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { createPgPool, migrate } from '@sedecim/service-kit';
import { createLogger } from '@sedecim/telemetry-policy';
import { createIndexerApi, DEFAULT_MIRROR_KINDS, Indexer, MemoryEventRepository, PgEventRepository, plainCodec, sealedCodec } from './index';

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
const pool = new RelayPool({ webSocketFactory: (u) => new WebSocket(u) as unknown as WebSocketLike });
const indexer = new Indexer(pool, repo, { relays, filters: [{ kinds }], communityId: env.COMMUNITY_ID, logger });
void indexer.start().then(() => logger.info('initial backfill complete', { ingested: indexer.ingested }));

const api = createIndexerApi(repo, { name: 'indexer', publicBaseUrl: env.PUBLIC_BASE_URL, requireAuth: env.INDEXER_REQUIRE_AUTH === 'true', logger });
await api.listen(Number(env.PORT ?? 8081), env.HOST ?? '0.0.0.0');
