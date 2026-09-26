import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned } from '@sedecim/nostr-core';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { FilterWindowSync, NegentropySync, syncHistory } from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;

describe('history sync (FR-013)', () => {
  const a = new TestRelay();
  const b = new TestRelay();
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);
  let pool: RelayPool;
  const base = 1_700_000_000;

  beforeAll(async () => {
    await a.start();
    await b.start();
    for (let i = 0; i < 120; i++) {
      const e = finalizeEvent(toUnsigned({ kind: 1, content: `m${i}`, created_at: base + i * 3600 }, pk), sk);
      a.inject(e);
      if (i % 2 === 0) b.inject(e);
    }
    pool = new RelayPool({ webSocketFactory: factory });
  });
  afterAll(async () => {
    pool.close();
    await a.stop();
    await b.stop();
  });

  it('rebuilds full history with window/pagination fallback and dedup across relays', async () => {
    const window = new FilterWindowSync(pool, { since: base, until: base + 120 * 3600, windowSeconds: 24 * 3600, pageLimit: 7 });
    const report = await syncHistory([a.url, b.url], { kinds: [1], authors: [pk] }, [new NegentropySync(), window]);
    expect(report.events).toHaveLength(120);
    expect(new Set(report.events.map((e) => e.content)).size).toBe(120);
    expect(report.perRelay[a.url]!.strategy).toBe('req-window');
    expect(report.perRelay[b.url]!.count).toBeGreaterThanOrEqual(60);
  });
});
