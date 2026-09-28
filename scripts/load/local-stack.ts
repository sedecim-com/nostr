// Local target for the load tool (docs/load-testing.md): the in-memory test relay behaving like Buzz
// (NIP-42 required, channel-scoped fan-out) plus N in-process indexer replicas with their read API.
// The test relay has no NIP-29: `groupKey` plays the relay key that signs channel state, advertised as its
// NIP-11 `self` so the mirror trusts the member lists signed with it (FR014-05).
// Prints one JSON line {relay, indexers, groupKey} and runs until SIGTERM/SIGINT.
//   npx tsx scripts/load/local-stack.ts [--indexers N] [--database-url postgres://…]
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';
import { bytesToHex, generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { createPgPool, migrate } from '@sedecim/service-kit';
import {
  createIndexerApi,
  DEFAULT_MIRROR_KINDS,
  GroupAuthorities,
  Indexer,
  MemoryEventRepository,
  MemoryShardCoordinator,
  PgEventRepository,
  PgShardCoordinator,
  type EventRepository,
  type ShardCoordinator,
} from '@sedecim/indexer';

export interface LocalStack {
  relay: string;
  indexers: string[];
  /** Hex secret that signs channel state in place of the relay (the load tool's `groupKey`). */
  groupKey: string;
  stop(): Promise<void>;
}

export async function startLocalStack(opts: { indexers?: number; databaseUrl?: string } = {}): Promise<LocalStack> {
  const groupKey = generateSecretKey();
  const relay = new TestRelay({ requireAuth: true, authNoticeOnReq: true, channelScopedFanout: true, self: getPublicKey(groupKey) });
  await relay.start();
  const shared = { repo: new MemoryEventRepository() as EventRepository, coord: new MemoryShardCoordinator() as ShardCoordinator };
  const pgPools: Array<{ end(): Promise<void> }> = [];
  if (opts.databaseUrl) {
    const pool = createPgPool(opts.databaseUrl);
    pgPools.push(pool);
    await migrate(pool, fileURLToPath(new URL('../../services/indexer/migrations', import.meta.url)), 'indexer');
  }
  const replicas = await Promise.all(
    Array.from({ length: Math.max(0, opts.indexers ?? 1) }, async (_, i) => {
      let { repo, coord } = shared;
      if (opts.databaseUrl) {
        const pool = createPgPool(opts.databaseUrl);
        pgPools.push(pool);
        repo = new PgEventRepository(pool);
        coord = new PgShardCoordinator(pool);
      }
      const pool = new RelayPool({ webSocketFactory: (u) => new WebSocket(u) as unknown as WebSocketLike, signer: new LocalSigner(generateSecretKey()), authMode: 'auto' });
      // As in production: the relay key comes from its NIP-11 `self`.
      const groups = new GroupAuthorities();
      const idx = new Indexer(pool, repo, { relays: [relay.url], filters: [{ kinds: DEFAULT_MIRROR_KINDS }], coordinator: coord, replicaId: `local-${i}`, channelRefreshMs: 1000, heartbeatMs: 1000, authorities: groups });
      await idx.start();
      const api = createIndexerApi(repo, { name: `indexer-${i}`, requireAuth: true, groups });
      const url = await api.listen(0, '127.0.0.1');
      return { idx, pool, api, url };
    }),
  );
  return {
    relay: relay.url,
    indexers: replicas.map((r) => r.url),
    groupKey: bytesToHex(groupKey),
    async stop() {
      for (const r of replicas) {
        await r.idx.stop();
        r.pool.close();
        await r.api.close();
      }
      await relay.stop();
      await Promise.all(pgPools.map((p) => p.end()));
    },
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const arg = (name: string) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
  const stack = await startLocalStack({ indexers: Number(arg('--indexers') ?? 1), databaseUrl: arg('--database-url') });
  process.stdout.write(JSON.stringify({ relay: stack.relay, indexers: stack.indexers, groupKey: stack.groupKey }) + '\n');
  for (const sig of ['SIGTERM', 'SIGINT'] as const) process.once(sig, () => void stack.stop().finally(() => process.exit(0)));
}
