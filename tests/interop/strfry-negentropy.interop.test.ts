/**
 * Opt-in: the NIP-77 client and the event cache against a real strfry. It runs only when STRFRY_URL points at one (a
 * strfry with `relay.negentropy.enabled = true`, the default of its strfry.conf); without it the suite is skipped, and
 * nothing here claims interoperability with strfry (docs/event-cache.md says how to run it).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { bytesToHex, finalizeEvent, generateSecretKey, getPublicKey, randomBytes, toUnsigned, type Filter } from '@sedecim/nostr-core';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { EventCache, NegentropySync, syncWithCache } from '@sedecim/sync';

const STRFRY_URL = process.env.STRFRY_URL;
const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;

describe.skipIf(!STRFRY_URL)('NIP-77 with the cached set against a real strfry (FR013-05)', () => {
  const url = STRFRY_URL!;
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);
  // A tag of this run only, and times of the last hour: strfry's default config refuses events more than 15 minutes
  // in the future or more than 3 years old.
  const run = bytesToHex(randomBytes(8));
  const now = Math.floor(Date.now() / 1000);
  const note = (content: string, created_at: number) => finalizeEvent(toUnsigned({ kind: 1, content, tags: [['t', run]], created_at }, pk), sk);
  const events = Array.from({ length: 300 }, (_, i) => note(`strfry interop ${i}`, now - 3600 + Math.floor(i / 3) * 10));
  const filter = (since?: number): Filter => ({ kinds: [1], authors: [pk], '#t': [run], ...(since !== undefined ? { since } : {}) });
  let pool: RelayPool;

  const newCache = () => EventCache.open(EncryptedStore.withKey(new MemoryBackend(), randomBytes(32)));
  const negentropy = (cache: EventCache, frameSizeLimit?: number) =>
    new NegentropySync(pool, { local: (relay, f) => cache.localSet(f, relay), known: (id) => cache.get(id), requireEose: true, timeoutMs: 15_000, ...(frameSizeLimit ? { frameSizeLimit } : {}) });

  beforeAll(async () => {
    pool = new RelayPool({ webSocketFactory: factory });
    for (const e of events) {
      const r = await pool.publishTo(e, url);
      expect(r.ok, r.message).toBe(true);
    }
  }, 120_000);
  afterAll(() => pool.close());

  it('downloads only what the cache lacks, and a second sync downloads nothing (FR013-05)', async () => {
    const cache = await newCache();
    await cache.put(events.filter((_, i) => i % 3 !== 0), { relay: url });
    const n = negentropy(cache);
    expect(await n.supported(url)).toBe(true);
    const first = await syncWithCache({ cache, relays: [url], filter, strategies: () => [n], mode: 'full' });
    expect(first.perRelay[url]).toMatchObject({ strategy: 'nip77-negentropy', advanced: true });
    expect(n.stats.get(url)).toMatchObject({ need: 100, fetched: 100, have: 0 });
    expect(first.events.map((e) => e.id).sort()).toEqual(events.map((e) => e.id).sort());
    const second = await syncWithCache({ cache, relays: [url], filter, strategies: () => [n] });
    expect(second.perRelay[url]).toMatchObject({ strategy: 'nip77-negentropy', advanced: true });
    expect(n.stats.get(url)).toMatchObject({ need: 0, fetched: 0 });
    expect(second.received).toBe(0);
  }, 120_000);

  it('reconciles with the smallest frame size limit and ids that only the client has (FR013-05)', async () => {
    const cache = await newCache();
    const localOnly = Array.from({ length: 200 }, (_, i) => note(`solo local ${i}`, now - 3600 + i * 7));
    await cache.put([...events.filter((_, i) => i % 2 === 0), ...localOnly], { relay: url });
    const n = negentropy(cache, 4096);
    const r = await syncWithCache({ cache, relays: [url], filter, strategies: () => [n], mode: 'full' });
    expect(r.perRelay[url]).toMatchObject({ strategy: 'nip77-negentropy', advanced: true });
    expect(n.stats.get(url)).toMatchObject({ need: 150, fetched: 150, have: 200 });
  }, 120_000);
});
