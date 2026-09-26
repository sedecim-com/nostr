/**
 * FR013-04: NIP-59 gift wraps carry created_at randomised up to 2 days in the past. A sync that starts
 * at the last-sync time must widen its window (dmInboxFilter) so no message is lost, whatever strategy.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, getPublicKey, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { DEFAULT_TIMESTAMP_JITTER_SECONDS, createDirectMessage, dmInboxFilter, wrapRumor } from '@sedecim/messaging';
import { FilterWindowSync, NegentropySync, rebuildHistory, syncHistory, type SyncStrategy } from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
const TWO_DAYS = 2 * 24 * 3600;

describe('gift wrap sync with randomised timestamps (FR013-04)', () => {
  // Both relays behave like Buzz for kind 1059: NIP-42 required and REQs scoped to #p == authenticated key.
  const neg = new TestRelay({ requireAuth: true, pGatedKinds: [1059], supportsNegentropy: true });
  const plain = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  const alice = new LocalSigner(generateSecretKey());
  const bobKey = generateSecretKey();
  const bob = new LocalSigner(bobKey);
  const bobPk = getPublicKey(bobKey);
  const now = Math.floor(Date.now() / 1000);
  const lastSync = now - 600; // Bob's device last synced 10 minutes ago
  const sent: string[] = []; // rumor ids of messages sent after lastSync
  const bobWraps: NostrEvent[] = [];
  let pool: RelayPool;

  const window = () => new FilterWindowSync(pool, { since: lastSync, windowSeconds: 6 * 3600, pageLimit: 10 });
  const inbox = () => dmInboxFilter(bobPk, lastSync);

  beforeAll(async () => {
    await neg.start();
    await plain.start();
    const publish = (e: NostrEvent) => {
      neg.inject(e);
      plain.inject(e);
    };
    // Explicit backdating across the whole NIP-59 range, including both edges.
    for (const back of [0, 1, 3600, 86_400, TWO_DAYS - 1, TWO_DAYS]) {
      const msg = await createDirectMessage(alice, { recipients: [bobPk], content: `back ${back}` }, { now: now - back, timestampJitterSeconds: 0 });
      sent.push(msg.rumor.id);
      for (const w of msg.wraps) publish(w.event);
      bobWraps.push(msg.wraps.find((w) => w.recipient === bobPk)!.event);
    }
    // Default NIP-59 jitter (0..2 days).
    for (let i = 0; i < 24; i++) {
      const msg = await createDirectMessage(alice, { recipients: [bobPk], content: `jitter ${i}` }, { now });
      sent.push(msg.rumor.id);
      for (const w of msg.wraps) publish(w.event);
      bobWraps.push(msg.wraps.find((w) => w.recipient === bobPk)!.event);
    }
    // Duplicate: the same rumor wrapped again (a retry from another device) — new wrap id, same message.
    const first = await createDirectMessage(alice, { recipients: [bobPk], content: 'retry me' }, { now });
    sent.push(first.rumor.id);
    publish(first.wraps.find((w) => w.recipient === bobPk)!.event);
    publish(await wrapRumor(alice, first.rumor, bobPk, { now }));
    // Older than the widened window: already synced before lastSync, must not be fetched again.
    const old = await createDirectMessage(alice, { recipients: [bobPk], content: 'old' }, { now: lastSync - TWO_DAYS - 60, timestampJitterSeconds: 0 });
    for (const w of old.wraps) publish(w.event);
    pool = new RelayPool({ webSocketFactory: factory, signer: bob });
  });
  afterAll(async () => {
    pool.close();
    await neg.stop();
    await plain.stop();
  });

  it('wraps really span the full 0–2 day range', () => {
    const ages = bobWraps.map((w) => now - w.created_at);
    expect(Math.min(...ages)).toBe(0);
    expect(Math.max(...ages)).toBe(TWO_DAYS);
    expect(ages.every((a) => a >= 0 && a <= DEFAULT_TIMESTAMP_JITTER_SECONDS)).toBe(true);
    expect(inbox().since).toBe(lastSync - TWO_DAYS);
  });

  const cases: Array<[string, () => string[], () => SyncStrategy[], string]> = [
    ['NIP-77', () => [neg.url], () => [new NegentropySync(pool), window()], 'nip77-negentropy'],
    ['REQ windows', () => [plain.url], () => [new NegentropySync(pool, { timeoutMs: 2_000 }), window()], 'req-window'],
  ];
  for (const [label, relays, strategies, expected] of cases) {
    it(`recovers every message via ${label} (none lost)`, async () => {
      const report = await syncHistory(relays(), inbox(), strategies());
      expect(report.perRelay[relays()[0]!]!.strategy).toBe(expected);
      const ids = new Set(report.events.map((e) => e.id));
      expect(bobWraps.filter((w) => !ids.has(w.id))).toEqual([]);
      expect(report.events.every((e) => e.created_at >= lastSync - TWO_DAYS)).toBe(true);
    });
  }

  it('merges both relays and both strategies without duplicates', async () => {
    const h = await rebuildHistory({ relays: [neg.url, plain.url], pubkey: bobPk, since: lastSync, strategies: [new NegentropySync(pool, { detect: 'probe' }), window()], signer: bob });
    expect(h.reports.dms.perRelay[neg.url]!.strategy).toBe('nip77-negentropy');
    expect(h.reports.dms.perRelay[plain.url]!.strategy).toBe('req-window');
    expect(new Set(h.wraps.map((w) => w.id)).size).toBe(h.wraps.length);
    expect(h.dms.map((m) => m.rumor.id).sort()).toEqual([...sent].sort()); // retry wrap collapsed, old one excluded
    expect(h.dms.some((m) => m.rumor.content === 'old')).toBe(false);
    expect(h.undecryptable).toBe(0);
  });
});
