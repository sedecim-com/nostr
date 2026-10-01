/**
 * PANEL-06: the outbox forgets the operation of a message that expired or that its author deleted, for good: no retry
 * publishes it again and no round in flight writes it back.
 */
import { describe, expect, it } from 'vitest';
import { generateSecretKey, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { DeliveryEngine, type OutboxRecord, type Publisher, type RecordStore } from '../src/index';

const signer = new LocalSigner(generateSecretKey());
const memStore = () => EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(4)).collection<OutboxRecord>('outbox');

describe('forgetting an operation (PANEL-06)', () => {
  it('PANEL-06: a forgotten operation is gone, a round in flight does not write it back, and resume() leaves it out', async () => {
    const published: NostrEvent[] = [];
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    const publisher: Publisher = {
      async publishTo(evt, relay) {
        published.push(evt);
        await gate; // the round waits here, as for a slow relay
        return { relay, ok: false, message: 'error: connection failed: offline', latencyMs: 1 };
      },
    };
    const store = memStore();
    const engine = new DeliveryEngine({ store, publisher, signer, retry: { baseMs: 10, maxMs: 10 } });
    const rec = await engine.submit({ template: { kind: 1, content: 'caduca', tags: [] } }, { relays: ['wss://a.example'], opId: 'op-1' });
    await engine.submit({ template: { kind: 1, content: 'se queda', tags: [] } }, { relays: ['wss://a.example'], opId: 'op-2' });
    while (published.length < 2) await new Promise((r) => setTimeout(r, 5));

    await engine.forget(rec.opId);
    expect(await engine.get('op-1')).toBeUndefined();
    release(); // the round of op-1 ends now, after the forget
    const resumed = await engine.resume();
    expect(resumed.map((r) => r.opId)).toEqual(['op-2']);
    expect(await engine.get('op-1')).toBeUndefined();
    expect((await engine.list()).map((r) => r.opId)).toEqual(['op-2']);
    engine.stop();
  });

  it('PANEL-06: a store that cannot delete refuses to forget, and a new operation under a forgotten id is stored as usual', async () => {
    const backing = memStore();
    const readOnly: RecordStore = { put: (id, v) => backing.put(id, v), get: (id) => backing.get(id), all: () => backing.all() };
    const ok: Publisher = { publishTo: async (_e, relay) => ({ relay, ok: true, message: '', latencyMs: 1 }) };
    const strict = new DeliveryEngine({ store: readOnly, publisher: ok, signer });
    await strict.submit({ template: { kind: 1, content: 'x', tags: [] } }, { relays: ['wss://a.example'], opId: 'op-x', wait: true });
    await expect(strict.forget('op-x')).rejects.toThrow(/cannot delete/);

    const engine = new DeliveryEngine({ store: memStore(), publisher: ok, signer });
    await engine.submit({ template: { kind: 1, content: 'primero', tags: [] } }, { relays: ['wss://a.example'], opId: 'op-y', wait: true });
    await engine.forget('op-y');
    const again = await engine.submit({ template: { kind: 1, content: 'otro', tags: [] } }, { relays: ['wss://a.example'], opId: 'op-y', wait: true });
    expect(again.state).toBe('REPLICATED');
    expect((await engine.get('op-y'))!.event!.content).toBe('otro');
  });
});
