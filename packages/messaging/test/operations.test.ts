import { describe, expect, it } from 'vitest';
import { generateSecretKey, getPublicKey, type EventTemplate, type Filter, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { DeliveryEngine, type OutboxRecord, type Publisher } from '@sedecim/delivery-engine';
import { DirectMessenger, DmRelayCache, OperationMismatchError, unwrap, wrapOpId, type DmOperation, type RelayQuery } from '../src/index';

// FR011-05 (scope §11.1, §11.2): retrying a send from the web or the CLI makes no other rumor and no other event,
// and the wraps are made only after the operation is stored.

const aliceSk = generateSecretKey();
const alicePk = getPublicKey(aliceSk);
const bob = new LocalSigner(generateSecretKey());

/** Alice's signer, logging what it does and able to fail one signature (a NIP-07 prompt the user dismisses). */
function aliceSigner(log: string[]) {
  const inner = new LocalSigner(aliceSk);
  const s = {
    failNextSeal: false,
    getPublicKey: () => inner.getPublicKey(),
    async signEvent(t: EventTemplate) {
      if (t.kind === 13 && s.failNextSeal) {
        s.failNextSeal = false;
        throw new Error('the user dismissed the signer');
      }
      log.push(`sign:${t.kind}`);
      return inner.signEvent(t);
    },
    async nip44Encrypt(pk: string, text: string) {
      log.push('encrypt');
      return inner.nip44Encrypt(pk, text);
    },
    nip44Decrypt: (pk: string, text: string) => inner.nip44Decrypt(pk, text),
  };
  return s as typeof s & Signer;
}

function setup() {
  const log: string[] = [];
  const signer = aliceSigner(log);
  const published: NostrEvent[] = [];
  const net = { up: false };
  const publisher: Publisher = {
    async publishTo(evt, relay) {
      published.push(evt);
      return net.up ? { relay, ok: true, message: '', latencyMs: 1 } : { relay, ok: false, message: 'error: connection failed: offline', latencyMs: 1 };
    },
  };
  const store = EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(5));
  // No automatic retry inside a test: only the user's retry sends again.
  const engine = new DeliveryEngine({ store: store.collection<OutboxRecord>('outbox'), publisher, signer, retry: { baseMs: 60_000, maxMs: 60_000 } });
  const ops = store.collection<DmOperation>('dm-ops');
  const operations = {
    get: (id: string) => ops.get(id),
    async put(id: string, op: DmOperation) {
      log.push('store-operation');
      await ops.put(id, op);
    },
  };
  const bobList: RelayQuery = { query: async (_urls: string[], _filters: Filter[]) => [await bob.signEvent({ kind: 10050, content: '', tags: [['relay', 'wss://bob-dm.example']] })] };
  const opts = { pool: bobList, outbox: engine, operations, ownRelays: ['wss://alice.example'], cache: new DmRelayCache(), wait: true };
  const messenger = new DirectMessenger(signer, { nip17: true, readReceipts: false });
  return { log, signer, published, net, engine, ops, opts, messenger };
}

describe('a DM as a client operation (FR011-05)', () => {
  it('stores the rumor before any seal or wrap exists', async () => {
    const t = setup();
    await t.messenger.sendDmOnce('op-1', { recipients: [await bob.getPublicKey()], content: 'hola' }, t.opts);
    expect(t.log[0]).toBe('store-operation');
    expect(t.log.indexOf('store-operation')).toBeLessThan(t.log.indexOf('encrypt'));
    const op = (await t.ops.get('op-1'))!;
    expect(op.rumor.content).toBe('hola');
    expect(op.targets).toEqual([await bob.getPublicKey(), alicePk]);
    expect(op.queuedAt).toBeDefined();
    t.engine.stop();
  });

  it('a retry under the same id makes no other rumor and no other event, and sends what was queued again', async () => {
    const t = setup();
    const bobPk = await bob.getPublicKey();
    const first = await t.messenger.sendDmOnce('op-2', { recipients: [bobPk], content: 'sin red' }, t.opts);
    expect(first.deliveries.map((d) => d.record.state)).toEqual(['QUEUED', 'QUEUED']);
    const wraps = new Set(first.deliveries.map((d) => d.record.event!.id));
    const seals = t.log.filter((l) => l === 'sign:13').length;

    t.net.up = true;
    const retry = await t.messenger.sendDmOnce('op-2', { recipients: [bobPk], content: 'sin red' }, t.opts);
    expect(retry.rumor.id).toBe(first.rumor.id);
    expect(retry.deliveries.map((d) => d.record.state)).toEqual(['REPLICATED', 'REPLICATED']);
    expect(new Set(retry.deliveries.map((d) => d.record.event!.id))).toEqual(wraps);
    expect(t.log.filter((l) => l === 'sign:13').length).toBe(seals);
    expect(await t.engine.list()).toHaveLength(2);
    expect(new Set(t.published.map((e) => e.id))).toEqual(wraps);
    // The recipient's wrap went where their kind 10050 says, both times.
    expect(retry.deliveries[0]).toMatchObject({ recipient: bobPk, relays: ['wss://bob-dm.example'], source: 'dm-relays' });
    expect(retry.deliveries[1]).toMatchObject({ recipient: alicePk, relays: ['wss://alice.example'], source: 'self' });
    t.engine.stop();
  });

  it('when the signer fails half way, the retry makes only the missing wrap, of the same rumor', async () => {
    const t = setup();
    const bobPk = await bob.getPublicKey();
    t.net.up = true;
    // Bob's wrap is queued, then the seal of Alice's own copy is refused.
    const signSeal = t.signer.signEvent.bind(t.signer);
    let seals = 0;
    t.signer.signEvent = async (tmpl: EventTemplate) => {
      if (tmpl.kind === 13 && ++seals === 2) t.signer.failNextSeal = true;
      return signSeal(tmpl);
    };
    await expect(t.messenger.sendDmOnce('op-3', { recipients: [bobPk], content: 'a medias' }, t.opts)).rejects.toThrow(/dismissed/);
    const [bobWrap] = await t.engine.list();
    expect((await t.engine.list()).map((r) => r.opId)).toEqual([wrapOpId('op-3', bobPk)]);

    const retry = await t.messenger.sendDmOnce('op-3', { recipients: [bobPk], content: 'a medias' }, t.opts);
    const records = await t.engine.list();
    expect(records.map((r) => r.opId).sort()).toEqual([wrapOpId('op-3', bobPk), wrapOpId('op-3', alicePk)].sort());
    expect(retry.deliveries[0]!.record.event!.id).toBe(bobWrap!.event!.id);
    const own = records.find((r) => r.opId === wrapOpId('op-3', alicePk))!;
    expect((await unwrap(t.signer, own.event!)).rumor.id).toBe(retry.rumor.id);
    expect((await unwrap(bob, bobWrap!.event!)).rumor.id).toBe(retry.rumor.id);
    t.engine.stop();
  });

  it('refuses another text or recipient under the same id: that is a new message, not a retry', async () => {
    const t = setup();
    const bobPk = await bob.getPublicKey();
    await t.messenger.sendDmOnce('op-4', { recipients: [bobPk], content: 'primero' }, t.opts);
    await expect(t.messenger.sendDmOnce('op-4', { recipients: [bobPk], content: 'otro texto' }, t.opts)).rejects.toThrow(OperationMismatchError);
    await expect(t.messenger.sendDmOnce('op-4', { recipients: [alicePk], content: 'primero' }, t.opts)).rejects.toThrow(OperationMismatchError);
    expect(await t.engine.list()).toHaveLength(2);
    t.engine.stop();
  });

  it('a file message builds its input (the upload) only on the first try', async () => {
    const t = setup();
    const bobPk = await bob.getPublicKey();
    let uploads = 0;
    const input = async () => (uploads++, { recipients: [bobPk], url: 'https://blossom.example/f', mimeType: 'image/png', sha256: 'ab'.repeat(32) });
    const first = await t.messenger.sendFileOnce('op-5', input, t.opts);
    const retry = await t.messenger.sendFileOnce('op-5', input, t.opts);
    expect(uploads).toBe(1);
    expect(retry.rumor.id).toBe(first.rumor.id);
    expect(retry.rumor.kind).toBe(15);
    expect(await t.engine.list()).toHaveLength(2);
    t.engine.stop();
  });
});
