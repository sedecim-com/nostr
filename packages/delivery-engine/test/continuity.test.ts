/**
 * VAULT-04: the Continuity Vault as a track of the delivery state machine, apart from the relay ACKs. Best-effort
 * copies go beside the publishing and never delay it; `required-for-resilient` publishes only once the copy exists;
 * off makes no copy.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { generateSecretKey, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { CONTINUITY_HELD, CONTINUITY_HELD_NO_VAULT, DeliveryEngine, type ContinuityPolicy, type ContinuitySink, type OutboxRecord, type Publisher } from '../src/index';

const signer = new LocalSigner(generateSecretKey());
const fast = { baseMs: 20, maxMs: 80 };
const note = { template: { kind: 1, content: 'nota', tags: [] } };

async function until(fn: () => Promise<boolean> | boolean, ms = 4000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await fn()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('condition not met in time');
}

const memStore = () => EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(2)).collection<OutboxRecord>('outbox');

/** A relay stand-in that records what it accepted, and when. */
function relays(opts: { down?: boolean } = {}) {
  const accepted: Array<{ id: string; at: number }> = [];
  const state = { down: !!opts.down };
  const publisher: Publisher = {
    async publishTo(evt, relay) {
      if (state.down) return { relay, ok: false, message: 'error: connection failed: relay down', latencyMs: 1 };
      accepted.push({ id: evt.id, at: Date.now() });
      return { relay, ok: true, message: '', latencyMs: 1 };
    },
  };
  return { publisher, accepted, state };
}

/** A vault stand-in: fails while `down`, and records the events it holds. */
function vault(opts: { down?: boolean } = {}) {
  const held: Array<{ id: string; at: number }> = [];
  const state = { down: !!opts.down, attempts: 0 };
  const sink: ContinuitySink = {
    async backup(event: NostrEvent) {
      state.attempts++;
      if (state.down) throw new Error('vault unavailable');
      held.push({ id: event.id, at: Date.now() });
    },
  };
  return { sink, held, state };
}

describe('Continuity Vault in the delivery state machine (VAULT-04)', () => {
  const engines: DeliveryEngine[] = [];
  const engine = (o: ConstructorParameters<typeof DeliveryEngine>[0]) => {
    const e = new DeliveryEngine({ signer, retry: fast, ...o });
    engines.push(e);
    return e;
  };
  afterEach(() => engines.splice(0).forEach((e) => e.stop()));

  it('best-effort: relay publishing and the vault copy are independent tracks', async () => {
    const r = relays();
    const v = vault({ down: true });
    const e = engine({ store: memStore(), publisher: r.publisher, continuity: { policy: () => 'best-effort', sink: v.sink } });
    // The vault is down: the send goes out anyway, and the copy stays pending.
    const rec = await e.submit(note, { relays: ['ws://a'], wait: true });
    expect(rec.state).toBe('REPLICATED');
    expect(rec.continuity).toMatchObject({ policy: 'best-effort', state: 'PENDING', lastError: 'vault unavailable' });
    expect(r.accepted).toHaveLength(1);
    expect((await e.stats()).continuityPending).toBe(1);
    // Once the vault answers, the copy lands on its own schedule; the relay is not published to again.
    v.state.down = false;
    await until(async () => (await e.get(rec.opId))!.continuity!.state === 'CONTINUITY_BACKED_UP');
    const done = (await e.get(rec.opId))!;
    expect(done.state).toBe('REPLICATED');
    expect(done.continuity!.backedUpAt).toBeGreaterThan(0);
    expect(done.continuity!.lastError).toBeUndefined();
    expect(v.held.map((h) => h.id)).toEqual([done.event!.id]);
    expect(r.accepted).toHaveLength(1);
    expect((await e.stats()).continuityPending).toBe(0);

    // The other way round: backed up while no relay accepts it yet.
    r.state.down = true;
    const queued = await e.submit(note, { relays: ['ws://a'], wait: true });
    expect(queued.state).toBe('QUEUED');
    expect(queued.continuity!.state).toBe('CONTINUITY_BACKED_UP');
    expect(queued.blockedReason).toBeUndefined();
  });

  it('required-for-resilient: nothing goes to the relays until the copy is in the vault', async () => {
    const r = relays();
    const v = vault({ down: true });
    const e = engine({ store: memStore(), publisher: r.publisher, continuity: { policy: () => 'required-for-resilient', sink: v.sink } });
    const held = await e.submit(note, { relays: ['ws://a', 'ws://b'], quorum: 2, wait: true });
    expect(held).toMatchObject({ state: 'QUEUED', blockedReason: CONTINUITY_HELD, continuity: { policy: 'required-for-resilient', state: 'PENDING' } });
    expect(r.accepted).toHaveLength(0);
    expect(Object.values(held.relayStatus).every((s) => s.attemptCount === 0)).toBe(true);
    expect(held.nextAttemptAt).toBeGreaterThan(0);

    v.state.down = false;
    await until(async () => (await e.get(held.opId))!.state === 'REPLICATED');
    const sent = (await e.get(held.opId))!;
    expect(sent.continuity!.state).toBe('CONTINUITY_BACKED_UP');
    expect(sent.blockedReason).toBeUndefined();
    // The copy existed before the first relay accepted the event.
    expect(v.held[0]!.at).toBeLessThanOrEqual(Math.min(...r.accepted.map((a) => a.at)));
    expect(r.accepted).toHaveLength(2);
  });

  it('without a vault a required send stays held, and relaxing the policy releases it', async () => {
    const r = relays();
    let policy: ContinuityPolicy = 'required-for-resilient';
    const e = engine({ store: memStore(), publisher: r.publisher, continuity: { policy: () => policy } });
    const held = await e.submit(note, { relays: ['ws://a'], wait: true });
    expect(held).toMatchObject({ state: 'QUEUED', blockedReason: CONTINUITY_HELD_NO_VAULT });
    expect(held.nextAttemptAt).toBeUndefined(); // nothing to retry until the policy or the vault changes
    expect(r.accepted).toHaveLength(0);
    // Best-effort without a vault makes no copy at all: nothing pending is recorded.
    policy = 'best-effort';
    expect((await e.submit(note, { relays: ['ws://a'], wait: true })).continuity).toBeUndefined();
    // Off: the held send goes out, without a copy.
    policy = 'off';
    await e.resume();
    const sent = (await e.get(held.opId))!;
    expect(sent.state).toBe('REPLICATED');
    expect(sent.continuity).toBeUndefined();
    expect(sent.blockedReason).toBeUndefined();
  });

  it('a held send relaxed to best-effort goes out and keeps copying beside it', async () => {
    const r = relays();
    const v = vault({ down: true });
    let policy: ContinuityPolicy = 'required-for-resilient';
    const e = engine({ store: memStore(), publisher: r.publisher, retry: { baseMs: 60_000, maxMs: 60_000 }, continuity: { policy: () => policy, sink: v.sink } });
    const held = await e.submit(note, { relays: ['ws://a'], wait: true });
    expect(held.blockedReason).toBe(CONTINUITY_HELD);
    policy = 'best-effort';
    await e.resume();
    const sent = (await e.get(held.opId))!;
    expect(sent).toMatchObject({ state: 'REPLICATED', continuity: { policy: 'best-effort', state: 'PENDING' } });
    expect(sent.blockedReason).toBeUndefined();
    v.state.down = false;
    await e.resume();
    expect((await e.get(held.opId))!.continuity!.state).toBe('CONTINUITY_BACKED_UP');
  });

  it('off makes no copy; a best-effort copy is given up after maxAttempts, a required one never', async () => {
    const r = relays();
    const off = engine({ store: memStore(), publisher: r.publisher, continuity: { policy: () => 'off', sink: vault().sink } });
    expect((await off.submit(note, { relays: ['ws://a'], wait: true })).continuity).toBeUndefined();

    const v = vault({ down: true });
    const best = engine({ store: memStore(), publisher: r.publisher, retry: { ...fast, maxAttempts: 2 }, continuity: { policy: () => 'best-effort', sink: v.sink } });
    const rec = await best.submit(note, { relays: ['ws://a'], wait: true });
    await until(async () => (await best.get(rec.opId))!.continuity!.state === 'FAILED');
    const given = (await best.get(rec.opId))!;
    expect(given.continuity!.attemptCount).toBe(2);
    expect(given.state).toBe('REPLICATED');
    expect(given.nextAttemptAt).toBeUndefined();

    const w = vault({ down: true });
    const req = engine({ store: memStore(), publisher: r.publisher, retry: { ...fast, maxAttempts: 2 }, continuity: { policy: () => 'required-for-resilient', sink: w.sink } });
    const kept = await req.submit(note, { relays: ['ws://a'], wait: true });
    await until(() => w.state.attempts >= 4);
    expect((await req.get(kept.opId))!).toMatchObject({ state: 'QUEUED', blockedReason: CONTINUITY_HELD, continuity: { state: 'PENDING' } });
  });

  it('a pending copy survives a restart: resume re-drives it', async () => {
    const store = memStore();
    const r = relays();
    const first = engine({ store, publisher: r.publisher, retry: { baseMs: 60_000, maxMs: 60_000 }, continuity: { policy: () => 'best-effort', sink: vault({ down: true }).sink } });
    const rec = await first.submit(note, { relays: ['ws://a'], wait: true });
    expect(rec.continuity!.state).toBe('PENDING');
    first.stop();
    const v = vault();
    const second = engine({ store, publisher: r.publisher, continuity: { policy: () => 'best-effort', sink: v.sink } });
    await second.resume();
    expect((await second.get(rec.opId))!.continuity!.state).toBe('CONTINUITY_BACKED_UP');
    expect(v.held.map((h) => h.id)).toEqual([rec.event!.id]);
    expect(r.accepted).toHaveLength(1);
  });
});
