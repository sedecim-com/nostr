import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import * as nt from 'nostr-tools';
import { generateSecretKey, getPublicKey, type Filter, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { DeliveryEngine, type OutboxRecord } from '@sedecim/delivery-engine';
import { createReceipt, DirectMessenger, DmRelayCache, dmRouter, openDirectMessage, parseReceipt, publishDmRelayList, resolveDmRelays, unwrap, type RelayQuery } from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
const flags = { nip17: true, readReceipts: true };

function engineFor(pool: RelayPool, signer: LocalSigner) {
  return new DeliveryEngine({ store: EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(2)).collection<OutboxRecord>('outbox'), publisher: pool, signer });
}

/** Fake pool returning fixed events and counting lookups. */
function fakePool(events: NostrEvent[]): RelayQuery & { calls: number } {
  return {
    calls: 0,
    async query(_urls: string[], _filters: Filter[]) {
      this.calls++;
      return events;
    },
  };
}

describe('DM relay lists (FR-010, FR-017)', () => {
  const bobSk = generateSecretKey();
  const bob = new LocalSigner(bobSk);
  const bobPk = getPublicKey(bobSk);
  const opts = (cache = new DmRelayCache()) => ({ fallback: ['wss://own.example'], discoveryRelays: ['wss://discovery.example'], cache });

  it('builds a signed kind 10050 with one relay tag per URL', async () => {
    const evt = await publishDmRelayList(bob, ['wss://inbox.example/', 'wss://inbox.example', 'https://not-a-relay.example']);
    expect(nt.verifyEvent(evt as nt.Event)).toBe(true);
    expect(evt.kind).toBe(10050);
    expect(evt.tags).toEqual([['relay', 'wss://inbox.example']]);
    await expect(publishDmRelayList(bob, [])).rejects.toThrow(/at least one/);
  });

  it('prefers the newest 10050, then NIP-65 read relays, then the fallback', async () => {
    const old10050 = await bob.signEvent({ kind: 10050, content: '', tags: [['relay', 'wss://old.example']], created_at: 100 });
    const new10050 = await bob.signEvent({ kind: 10050, content: '', tags: [['relay', 'wss://dm.example']], created_at: 200 });
    const nip65 = await bob.signEvent({
      kind: 10002,
      content: '',
      tags: [['r', 'wss://both.example'], ['r', 'wss://read.example', 'read'], ['r', 'wss://write.example', 'write']],
    });
    expect(await resolveDmRelays(fakePool([old10050, new10050, nip65]), bobPk, opts())).toEqual({ relays: ['wss://dm.example'], source: 'dm-relays' });
    expect(await resolveDmRelays(fakePool([nip65]), bobPk, opts())).toEqual({ relays: ['wss://both.example', 'wss://read.example'], source: 'nip65-read' });
    expect(await resolveDmRelays(fakePool([]), bobPk, opts())).toEqual({ relays: ['wss://own.example'], source: 'fallback' });
  });

  it('ignores lists not signed by the recipient and caches per pubkey with a TTL', async () => {
    const mallory = new LocalSigner(generateSecretKey());
    const forged = await mallory.signEvent({ kind: 10050, content: '', tags: [['relay', 'wss://evil.example']] });
    expect((await resolveDmRelays(fakePool([forged]), bobPk, opts())).source).toBe('fallback');

    let now = 0;
    const cache = new DmRelayCache(1000, () => now);
    const pool = fakePool([await bob.signEvent({ kind: 10050, content: '', tags: [['relay', 'wss://dm.example']] })]);
    await resolveDmRelays(pool, bobPk, opts(cache));
    await resolveDmRelays(pool, bobPk, opts(cache));
    expect(pool.calls).toBe(1);
    now = 1001;
    await resolveDmRelays(pool, bobPk, opts(cache));
    expect(pool.calls).toBe(2);
  });

  it('falls back when discovery throws', async () => {
    const failing: RelayQuery = { query: async () => Promise.reject(new Error('offline')) };
    expect(await resolveDmRelays(failing, bobPk, opts())).toEqual({ relays: ['wss://own.example'], source: 'fallback' });
  });

  it('never caches finding nothing: offline it looks like a recipient without lists (FR010-03)', async () => {
    const cache = new DmRelayCache();
    const offline = fakePool([]);
    expect((await resolveDmRelays(offline, bobPk, opts(cache))).source).toBe('fallback');
    expect((await resolveDmRelays(offline, bobPk, opts(cache))).source).toBe('fallback');
    expect(offline.calls).toBe(2);
    // With the network back the list is used at once, not after the cache TTL.
    const online = fakePool([await bob.signEvent({ kind: 10050, content: '', tags: [['relay', 'wss://dm.example']] })]);
    expect(await resolveDmRelays(online, bobPk, opts(cache))).toEqual({ relays: ['wss://dm.example'], source: 'dm-relays' });
  });

  it('dmRouter re-resolves the wraps for recipients only, never the sender copy (FR010-03)', async () => {
    const pool = fakePool([await bob.signEvent({ kind: 10050, content: '', tags: [['relay', 'wss://dm.example']] })]);
    const route = dmRouter(pool, opts());
    expect(await route({ meta: { recipient: bobPk, dmRelaySource: 'fallback' } })).toEqual({ relays: ['wss://dm.example'], meta: { dmRelaySource: 'dm-relays' } });
    const notRouted: Array<Record<string, string> | undefined> = [{ recipient: bobPk, dmRelaySource: 'self' }, { recipient: bobPk }, undefined];
    for (const meta of notRouted) expect(await route({ meta })).toBeUndefined();
    expect(pool.calls).toBe(1);
  });
});

describe('DirectMessenger.send routing and receipts (FR-010, FR-009)', () => {
  const shared = new TestRelay();
  const bobInbox = new TestRelay();
  const aliceSigner = new LocalSigner(generateSecretKey());
  const bobSigner = new LocalSigner(generateSecretKey());
  let bobPk: string;
  let pool: RelayPool;
  let engine: DeliveryEngine;

  beforeAll(async () => {
    await shared.start();
    await bobInbox.start();
    bobPk = await bobSigner.getPublicKey();
    pool = new RelayPool({ webSocketFactory: factory, signer: aliceSigner });
    engine = engineFor(pool, aliceSigner);
  });
  afterAll(async () => {
    engine.stop();
    pool.close();
    await shared.stop();
    await bobInbox.stop();
  });

  it("publishes the recipient's wrap on its DM relays and the sender's copy on its own relays", async () => {
    shared.inject(await publishDmRelayList(bobSigner, [bobInbox.url]));
    const messenger = new DirectMessenger(aliceSigner, flags);
    const { message, deliveries } = await messenger.send({ recipients: [bobPk], content: 'a tu inbox' }, { pool, outbox: engine, ownRelays: [shared.url], cache: new DmRelayCache(), wait: true });
    const toBob = deliveries.find((d) => d.recipient === bobPk)!;
    const self = deliveries.find((d) => d.recipient !== bobPk)!;
    expect(toBob).toMatchObject({ relays: [bobInbox.url], source: 'dm-relays' });
    expect(toBob.record.state).toBe('REPLICATED');
    expect(toBob.record.meta).toEqual({ recipient: bobPk, dmRelaySource: 'dm-relays' });
    expect(toBob.record.groupId).toBe(message.rumor.id);
    expect(self.source).toBe('self');
    expect(bobInbox.events.has(toBob.record.event!.id)).toBe(true);
    expect(shared.events.has(toBob.record.event!.id)).toBe(false);
    expect(shared.events.has(self.record.event!.id)).toBe(true);
  });

  it('a DM written offline goes to the recipient DM relays when the network is back (FR010-03)', async () => {
    const [own, inbox] = [new TestRelay(), new TestRelay()];
    await own.start();
    await inbox.start();
    const dana = new LocalSigner(generateSecretKey());
    const danaPk = await dana.getPublicKey();
    own.inject(await publishDmRelayList(dana, [inbox.url]));
    const cache = new DmRelayCache();
    const offlinePool = new RelayPool({ webSocketFactory: factory, signer: aliceSigner });
    const route = { discoveryRelays: [own.url], fallback: [own.url], cache, timeoutMs: 1000 };
    const outbox = new DeliveryEngine({
      store: EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(3)).collection<OutboxRecord>('outbox'),
      publisher: offlinePool,
      signer: aliceSigner,
      retry: { baseMs: 100, maxMs: 400 },
      router: dmRouter(offlinePool, route),
    });
    try {
      own.faults.offline = true;
      inbox.faults.offline = true;
      const { deliveries } = await new DirectMessenger(aliceSigner, flags).send({ recipients: [danaPk], content: 'escrito sin red' }, { pool: offlinePool, outbox, ownRelays: [own.url], ...route, wait: true });
      const queued = deliveries.find((d) => d.recipient === danaPk)!;
      expect(queued).toMatchObject({ source: 'fallback', relays: [own.url] });
      expect(queued.record.state).toBe('QUEUED');

      own.faults.offline = false;
      inbox.faults.offline = false;
      let rec = queued.record;
      for (let i = 0; i < 100 && rec.state !== 'REPLICATED'; i++) {
        await new Promise((r) => setTimeout(r, 100));
        rec = (await outbox.get(rec.opId))!;
      }
      expect(rec).toMatchObject({ state: 'REPLICATED', relays: [inbox.url], meta: { recipient: danaPk, dmRelaySource: 'dm-relays' } });
      expect(inbox.events.has(rec.event!.id)).toBe(true);
      expect(own.events.has(rec.event!.id)).toBe(false); // never left on the sender relays
      expect((await openDirectMessage(dana, rec.event!)).rumor.content).toBe('escrito sin red');
    } finally {
      outbox.stop();
      offlinePool.close();
      await own.stop();
      await inbox.stop();
    }
  }, 30_000);

  it('flags recipients without DM relays (source fallback) and stores it on the outbox record', async () => {
    const carolPk = getPublicKey(generateSecretKey());
    const { deliveries } = await new DirectMessenger(aliceSigner, flags).send({ recipients: [carolPk], content: 'sin 10050' }, { pool, outbox: engine, ownRelays: [shared.url], cache: new DmRelayCache(), wait: true });
    const toCarol = deliveries.find((d) => d.recipient === carolPk)!;
    expect(toCarol.source).toBe('fallback');
    expect((await engine.get(toCarol.record.opId))!.meta?.dmRelaySource).toBe('fallback');
  });

  it('incoming receipts from the recipient advance the operation, never backwards; others are ignored', async () => {
    const { message, deliveries } = await new DirectMessenger(aliceSigner, flags).send({ recipients: [bobPk], content: 'léelo' }, { pool, outbox: engine, ownRelays: [shared.url], cache: new DmRelayCache(), wait: true });
    const opId = deliveries.find((d) => d.recipient === bobPk)!.record.opId;
    // Bob opens the DM and answers with gift-wrapped receipts
    const opened = await openDirectMessage(bobSigner, deliveries.find((d) => d.recipient === bobPk)!.record.event!);
    const receive = async (from: LocalSigner, type: 'delivered' | 'read') => {
      const { event } = await createReceipt(from, await aliceSigner.getPublicKey(), opened.rumor.id, type);
      return engine.applyReceipt(parseReceipt(await unwrap(aliceSigner, event))!);
    };
    expect(opened.rumor.id).toBe(message.rumor.id);

    const mallory = new LocalSigner(generateSecretKey());
    expect(await receive(mallory, 'read')).toBeUndefined();
    expect((await engine.get(opId))!.state).toBe('REPLICATED');

    expect((await receive(bobSigner, 'delivered'))!.state).toBe('RECIPIENT_ACKED');
    expect((await receive(bobSigner, 'read'))!.state).toBe('READ');
    expect((await receive(bobSigner, 'delivered'))!.state).toBe('READ');
    // the sender's own copy is untouched
    const selfCopy = deliveries.find((d) => d.recipient !== bobPk)!.record.opId;
    expect((await engine.get(selfCopy))!.state).toBe('REPLICATED');
  });
});
