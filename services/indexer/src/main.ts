import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';
import { generateSecretKey, getPublicKey, hexToBytes, nip19, npubEncode } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
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
const indexer = new Indexer(pool, repo, { relays, filters: [{ kinds }], communityId: env.COMMUNITY_ID, logger, channelRefreshMs: Number(env.INDEXER_CHANNEL_REFRESH_MS ?? 30_000) });
void indexer.start().then(() => logger.info('initial backfill complete', { ingested: indexer.ingested }));

const api = createIndexerApi(repo, { name: 'indexer', publicBaseUrl: env.PUBLIC_BASE_URL, requireAuth: env.INDEXER_REQUIRE_AUTH === 'true', logger });
await api.listen(Number(env.PORT ?? 8081), env.HOST ?? '0.0.0.0');
