import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned, type NostrEvent } from '@sedecim/nostr-core';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { FilterWindowSync, NegentropySync, fetchSupportedNips, syncHistory } from '../src/index';

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
    const report = await syncHistory([a.url, b.url], { kinds: [1], authors: [pk] }, [new NegentropySync(pool, { timeoutMs: 2_000 }), window]);
    expect(report.events).toHaveLength(120);
    expect(new Set(report.events.map((e) => e.content)).size).toBe(120);
    expect(report.perRelay[a.url]!.strategy).toBe('req-window');
    expect(report.perRelay[a.url]!.attempts[0]).toMatchObject({ strategy: 'nip77-negentropy', supported: false });
    expect(report.perRelay[b.url]!.count).toBeGreaterThanOrEqual(60);
    expect([...report.seenOn.get(report.events[0]!.id)!].sort()).toEqual([a.url, b.url].sort());
  });

  it('honours an older `since` carried by the filter (window strategy)', async () => {
    const window = new FilterWindowSync(pool, { since: base + 100 * 3600, until: base + 120 * 3600, windowSeconds: 24 * 3600 });
    const report = await syncHistory([a.url], { kinds: [1], authors: [pk], since: base + 90 * 3600 }, [window]);
    expect(report.events).toHaveLength(30);
  });
});

describe('NIP-77 Negentropy (FR013-02)', () => {
  const neg = new TestRelay({ supportsNegentropy: true });
  const plain = new TestRelay();
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);
  const base = 1_710_000_000;
  const events: NostrEvent[] = [];
  let pool: RelayPool;
  const filter = { kinds: [1], authors: [pk] };
  const window = () => new FilterWindowSync(pool, { since: base - 3600, until: base + 400 * 60, windowSeconds: 3 * 3600, pageLimit: 50 });

  beforeAll(async () => {
    await neg.start();
    await plain.start();
    for (let i = 0; i < 600; i++) {
      // enough events for fingerprint splitting (several rounds); a few events share a timestamp so bounds need id prefixes
      const e = finalizeEvent(toUnsigned({ kind: 1, content: `n${i}`, created_at: base + Math.floor(i / 3) * 60 }, pk), sk);
      events.push(e);
      neg.inject(e);
      plain.inject(e);
    }
    pool = new RelayPool({ webSocketFactory: factory });
  });
  afterAll(async () => {
    pool.close();
    await neg.stop();
    await plain.stop();
  });

  it('detects support through NIP-11 and through a NEG-OPEN probe', async () => {
    expect(await fetchSupportedNips(neg.url)).toContain(77);
    expect(await fetchSupportedNips(plain.url)).not.toContain(77);
    expect(await new NegentropySync(pool, { detect: 'probe', timeoutMs: 2_000 }).supported(neg.url)).toBe(true);
    expect(await new NegentropySync(pool, { detect: 'probe', timeoutMs: 2_000 }).supported(plain.url)).toBe(false);
    expect(await new NegentropySync(pool, { detect: 'nip11' }).supported(plain.url)).toBe(false);
  });

  it('transfers only the missing events', async () => {
    const localOnly = finalizeEvent(toUnsigned({ kind: 1, content: 'only here', created_at: base + 5 }, pk), sk);
    const local = [...events.filter((_, i) => i % 12 !== 0), localOnly]; // 50 missing locally
    const missing = new Set(events.filter((_, i) => i % 12 === 0).map((e) => e.id));
    const strategy = new NegentropySync(pool, { local: () => local, batchSize: 20 });
    const sentBefore = neg.sentEvents;
    const report = await syncHistory([neg.url], filter, [strategy, window()]);
    expect(report.perRelay[neg.url]!.strategy).toBe('nip77-negentropy');
    expect(report.events).toHaveLength(50);
    expect(report.events.every((e) => missing.has(e.id))).toBe(true);
    expect(neg.sentEvents - sentBefore).toBe(50);
    expect(strategy.stats.get(neg.url)).toMatchObject({ need: 50, have: 1, fetched: 50 });
    expect(strategy.stats.get(neg.url)!.rounds).toBeGreaterThan(1);
  });

  it('with an empty local store it fetches everything by id', async () => {
    const strategy = new NegentropySync(pool);
    const report = await syncHistory([neg.url], filter, [strategy, window()]);
    expect(report.events.map((e) => e.id).sort()).toEqual(events.map((e) => e.id).sort());
    expect(report.perRelay[neg.url]!.strategy).toBe('nip77-negentropy');
  });

  it('falls back to REQ windows when the relay does not support NIP-77', async () => {
    const sentBefore = plain.sentEvents;
    const report = await syncHistory([plain.url], filter, [new NegentropySync(pool, { timeoutMs: 2_000 }), window()]);
    expect(report.perRelay[plain.url]!.strategy).toBe('req-window');
    expect(report.perRelay[plain.url]!.attempts.map((x) => [x.strategy, x.supported])).toEqual([
      ['nip77-negentropy', false],
      ['req-window', true],
    ]);
    expect(report.events).toHaveLength(600);
    expect(plain.sentEvents - sentBefore).toBeGreaterThanOrEqual(600);
  });

  it('falls back automatically when the relay aborts the session mid-way (NEG-ERR)', async () => {
    neg.faults.negErrorAfterMessages = 1;
    try {
      const local = events.filter((_, i) => i % 10 !== 0);
      const report = await syncHistory([neg.url], filter, [new NegentropySync(pool, { local: () => local }), window()]);
      const r = report.perRelay[neg.url]!;
      expect(r.strategy).toBe('req-window');
      expect(r.attempts[0]).toMatchObject({ strategy: 'nip77-negentropy', supported: true });
      expect(r.attempts[0]!.error).toMatch(/aborted/);
      expect(report.events).toHaveLength(600);
    } finally {
      neg.faults.negErrorAfterMessages = null;
    }
  });
});
