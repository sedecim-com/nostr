/**
 * A round holds its copy of a record while it waits for relays; a receipt (or a reconciliation) can land meanwhile,
 * e.g. when the recipient answers before the relay's OK reaches the sender. The round's save must not undo it, a
 * receipt must not wait for a slow relay, and a receipt's state never moves back.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { DeliveryEngine, type EventLookup, type OutboxRecord, type Publisher } from '../src/index';

const signer = new LocalSigner(generateSecretKey());
const dm = { template: { kind: 1059, content: 'wrap', tags: [] } };
const toBob = { groupId: 'rumor-1', meta: { recipient: 'bob' } };
const receipt = { rumorId: 'rumor-1', type: 'delivered' as const, from: 'bob' };
const memStore = () => EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(3)).collection<OutboxRecord>('outbox');
const tick = (ms = 10) => new Promise((r) => setTimeout(r, ms));

/** A publisher whose answer for each relay the test releases by hand. */
function manualRelays() {
  const waiting = new Map<string, Array<(ok: boolean) => void>>();
  const publisher: Publisher = {
    publishTo: (_evt, relay) =>
      new Promise((resolve) => {
        const q = waiting.get(relay) ?? [];
        q.push((ok) => resolve({ relay, ok, message: ok ? '' : 'error: connection failed: relay down', latencyMs: 1 }));
        waiting.set(relay, q);
      }),
  };
  const answer = async (relay: string, ok: boolean) => {
    for (let i = 0; i < 200 && !waiting.get(relay)?.length; i++) await tick(5);
    const next = waiting.get(relay)?.shift();
    if (!next) throw new Error(`no publish waiting on ${relay}`);
    next(ok);
  };
  return { publisher, answer, waitingOn: (relay: string) => waiting.get(relay)?.length ?? 0 };
}

describe('a receipt that lands while a round is publishing', () => {
  const engines: DeliveryEngine[] = [];
  const engine = (o: Partial<ConstructorParameters<typeof DeliveryEngine>[0]> & { publisher: Publisher }) => {
    const e = new DeliveryEngine({ signer, store: memStore(), retry: { baseMs: 60_000, maxMs: 60_000 }, ...o });
    engines.push(e);
    return e;
  };
  afterEach(() => engines.splice(0).forEach((e) => e.stop()));

  it('is kept when the relay OK arrives after it', async () => {
    const relays = manualRelays();
    const e = engine({ publisher: relays.publisher });
    const sending = e.submit(dm, { relays: ['ws://a'], wait: true, ...toBob });
    for (let i = 0; i < 200 && !relays.waitingOn('ws://a'); i++) await tick(5);
    // The recipient read it and answered before our relay's OK came back.
    const acked = await e.applyReceipt(receipt);
    expect(acked).toMatchObject({ state: 'RECIPIENT_ACKED', meta: { receiptBeforeQuorum: 'true' } });
    await relays.answer('ws://a', true);
    const done = await sending;
    expect(done.state).toBe('RECIPIENT_ACKED');
    const stored = (await e.get(done.opId))!;
    expect(stored.state).toBe('RECIPIENT_ACKED');
    expect(stored.relayStatus['ws://a']!.acceptedAt).toBeGreaterThan(0);
    expect(stored.history.map((h) => h.state)).toContain('RECIPIENT_ACKED');
  });

  it('does not wait for a slow relay of a retry round, and that round keeps it', async () => {
    const relays = manualRelays();
    const e = engine({ publisher: relays.publisher });
    // Replicated on a, still pending on b: a later round retries b.
    const sending = e.submit(dm, { relays: ['ws://a', 'ws://b'], quorum: 1, wait: true, ...toBob });
    await relays.answer('ws://a', true);
    await relays.answer('ws://b', false);
    const first = await sending;
    expect(first.state).toBe('REPLICATED');
    const retry = e.resume();
    for (let i = 0; i < 200 && !relays.waitingOn('ws://b'); i++) await tick(5);
    // b hangs; the receipt is applied now, not when b answers.
    expect((await e.applyReceipt(receipt))!.state).toBe('RECIPIENT_ACKED');
    await relays.answer('ws://b', false);
    await retry;
    const stored = (await e.get(first.opId))!;
    expect(stored.state).toBe('RECIPIENT_ACKED');
    expect(stored.relayStatus['ws://b']!.attemptCount).toBe(2);
  });

  it('never moves back from a receipt, while its pending relays are still retried', async () => {
    const relays = manualRelays();
    const e = engine({ publisher: relays.publisher });
    const sending = e.submit(dm, { relays: ['ws://a'], wait: true, ...toBob });
    await relays.answer('ws://a', false);
    const queued = await sending;
    expect(queued.state).toBe('QUEUED');
    // The recipient got it anyway (our relay's OK was lost): delivered, before any relay counted it.
    expect((await e.applyReceipt(receipt))!.state).toBe('RECIPIENT_ACKED');
    const retry = e.resume();
    await relays.answer('ws://a', false);
    await retry;
    const stored = (await e.get(queued.opId))!;
    expect(stored).toMatchObject({ state: 'RECIPIENT_ACKED', meta: { receiptBeforeQuorum: 'true' } });
    expect(stored.nextAttemptAt).toBeGreaterThan(0);
  });

  it('keeps a relay reconcile found holding the event while the round published', async () => {
    const relays = manualRelays();
    let onB = false;
    const lookup: EventLookup = { has: async (relay) => relay === 'ws://b' && onB };
    const e = engine({ publisher: relays.publisher, lookup });
    const sending = e.submit(dm, { relays: ['ws://a', 'ws://b'], quorum: 2, wait: true });
    for (let i = 0; i < 200 && relays.waitingOn('ws://a') + relays.waitingOn('ws://b') < 2; i++) await tick(5);
    // b stored the event though its OK never arrives; reconcile sees it there mid-round.
    onB = true;
    await e.reconcile();
    await relays.answer('ws://a', true);
    await relays.answer('ws://b', false);
    const done = await sending;
    const stored = (await e.get(done.opId))!;
    expect(stored.relayStatus['ws://b']).toMatchObject({ ackMessage: 'reconciled: event present on relay' });
    expect(stored.relayStatus['ws://b']!.lastError).toBeUndefined();
    expect(stored.state).toBe('REPLICATED');
  });
});
