/**
 * FR009-03: receipts reach the sender (they go to the sender's DM relays, kind 10050) and the inbox reads the
 * persona's own DM relays once or in the background, applying receipts to the outbox and answering messages with
 * the receipts the profile allows, at most once each.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, getTagValue, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { DeliveryEngine, type OutboxRecord } from '@sedecim/delivery-engine';
import { APP_RECEIPT_KIND, DirectMessenger, DmInbox, DmRelayCache, FeatureDisabledError, publishDmRelayList, unwrap, type DirectMessage, type Receipt } from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
const flags = { nip17: true, readReceipts: false };

async function until<T>(fn: () => Promise<T | undefined> | T | undefined, what: string, ms = 5000): Promise<T> {
  for (let t = 0; t < ms; t += 50) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`timed out waiting for ${what}`);
}

/** One persona: its signer, pool, outbox and receipt policy, reading and writing on its DM relay. */
function persona(relay: TestRelay, discovery: string[], fill: number) {
  const signer = new LocalSigner(generateSecretKey());
  const pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'on-demand' });
  const engine = new DeliveryEngine({ store: EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(fill)).collection<OutboxRecord>('outbox'), publisher: pool, signer });
  const sent = EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(fill + 1)).collection<boolean>('receipts');
  const policy = { delivered: true, read: false };
  const messages: Array<{ m: DirectMessage; live: boolean }> = [];
  const receipts: Array<{ r: Receipt; rec: OutboxRecord }> = [];
  const inbox = (ownRelays = [relay.url]) =>
    new DmInbox(signer, {
      pool,
      outbox: engine,
      ownRelays,
      discoveryRelays: discovery,
      policy: () => policy,
      sent,
      cache: new DmRelayCache(),
      timeoutMs: 2000,
      onMessage: (m, live) => messages.push({ m, live }),
      onReceipt: (r, rec) => receipts.push({ r, rec }),
    });
  const send = async (to: string, content: string) => {
    const { deliveries } = await new DirectMessenger(signer, flags).send({ recipients: [to], content }, { pool, outbox: engine, ownRelays: [relay.url], discoveryRelays: discovery, cache: new DmRelayCache(), wait: true });
    return deliveries.find((d) => d.recipient === to)!;
  };
  return { signer, pool, engine, policy, messages, receipts, inbox, send, close: () => (engine.stop(), pool.close()) };
}

/** Receipt wraps for `to` on a relay: [type, rumor id] of each one `reader` can open. */
async function receiptsOn(relay: TestRelay, reader: LocalSigner): Promise<string[][]> {
  const me = await reader.getPublicKey();
  const out: string[][] = [];
  for (const e of relay.received.filter((x: NostrEvent) => x.kind === 1059 && getTagValue(x, 'p') === me)) {
    const u = await unwrap(reader, e).catch(() => undefined);
    if (u?.rumor.kind === APP_RECEIPT_KIND) out.push([getTagValue(u.rumor, 'receipt')!, getTagValue(u.rumor, 'e')!]);
  }
  return out;
}

describe('receipts reach the sender and the inbox reads in the background (FR009-03)', () => {
  // Like the reference relays: NIP-42, and gift wraps only reach their authenticated recipient.
  const aliceRelay = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  const bobRelay = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  let alice: ReturnType<typeof persona>;
  let bob: ReturnType<typeof persona>;
  let alicePk: string;
  let bobPk: string;

  beforeAll(async () => {
    await aliceRelay.start();
    await bobRelay.start();
    const discovery = [aliceRelay.url, bobRelay.url];
    alice = persona(aliceRelay, discovery, 1);
    bob = persona(bobRelay, discovery, 3);
    alicePk = await alice.signer.getPublicKey();
    bobPk = await bob.signer.getPublicKey();
    // Each persona's DM relay list, where the other looks it up.
    for (const r of [aliceRelay, bobRelay]) {
      r.inject(await publishDmRelayList(alice.signer, [aliceRelay.url]));
      r.inject(await publishDmRelayList(bob.signer, [bobRelay.url]));
    }
  });
  afterAll(async () => {
    alice.close();
    bob.close();
    await aliceRelay.stop();
    await bobRelay.stop();
  });

  it("a delivered receipt goes to the sender's DM relays, and the sender's inbox moves the DM to RECIPIENT_ACKED", async () => {
    const toBob = await alice.send(bobPk, 'hola bob');
    expect(toBob).toMatchObject({ source: 'dm-relays', relays: [bobRelay.url] });
    const bobInbox = bob.inbox();
    const got = await bobInbox.sync();
    expect(got.map((m) => m.rumor.content)).toEqual(['hola bob']);

    // Bob's receipt is queued for Alice's DM relays (never only Bob's), routed like a DM, so a retry re-routes it.
    const queued = await until(async () => (await bob.engine.list()).find((r) => r.meta?.receipt === 'delivered'), "Bob's receipt");
    expect(queued).toMatchObject({ relays: [aliceRelay.url], meta: { recipient: alicePk, dmRelaySource: 'dm-relays', receipt: 'delivered' } });
    await until(async () => (await receiptsOn(aliceRelay, alice.signer)).length > 0, 'the receipt on Alice relay');
    expect(await receiptsOn(bobRelay, alice.signer)).toEqual([]);

    const aliceInbox = alice.inbox();
    await aliceInbox.sync();
    expect((await alice.engine.get(toBob.record.opId))!.state).toBe('RECIPIENT_ACKED');
    expect(alice.receipts.map(({ r, rec }) => [r.type, r.from, rec.state])).toEqual([['delivered', bobPk, 'RECIPIENT_ACKED']]);

    // At most one receipt of each type per message, even from a new inbox (the sent store survives it).
    await bob.inbox().sync();
    await bobInbox.sync();
    expect((await bob.engine.list()).filter((r) => r.meta?.receipt)).toHaveLength(1);
  });

  it('read receipts go only when the profile allows them, once the user has seen the message', async () => {
    const toBob = await alice.send(bobPk, 'léelo');
    const bobInbox = bob.inbox();
    const m = (await bobInbox.sync()).find((x) => x.rumor.content === 'léelo')!;
    await bobInbox.markRead(m);
    await until(async () => (await receiptsOn(aliceRelay, alice.signer)).some(([, id]) => id === m.rumor.id), 'the delivered receipt');
    expect((await receiptsOn(aliceRelay, alice.signer)).filter(([, id]) => id === m.rumor.id).map(([t]) => t)).toEqual(['delivered']);

    bob.policy.read = true; // a panel change applies at once
    await bobInbox.markRead(m);
    await bobInbox.markRead(m);
    await until(async () => (await receiptsOn(aliceRelay, alice.signer)).some(([t, id]) => t === 'read' && id === m.rumor.id), 'the read receipt');
    expect((await receiptsOn(aliceRelay, alice.signer)).filter(([, id]) => id === m.rumor.id).map(([t]) => t).sort()).toEqual(['delivered', 'read']);
    await alice.inbox().sync();
    expect((await alice.engine.get(toBob.record.opId))!.state).toBe('READ');
    bob.policy.read = false;

    // The messenger enforces the opt-in too.
    await expect(new DirectMessenger(bob.signer, flags).receipt(alicePk, m.rumor.id, 'read', { pool: bob.pool, outbox: bob.engine, ownRelays: [bobRelay.url] })).rejects.toBeInstanceOf(FeatureDisabledError);
  });

  it('in the background, DMs and receipts arrive without asking, flagged as live', async () => {
    const aliceInbox = alice.inbox();
    const bobInbox = bob.inbox();
    await aliceInbox.start();
    await bobInbox.start();
    try {
      alice.messages.length = 0;
      const toAlice = await bob.send(alicePk, 'en segundo plano');
      const seen = await until(() => alice.messages.find(({ m }) => m.rumor.content === 'en segundo plano'), 'the live DM');
      expect(seen.live).toBe(true);
      // Alice's delivered receipt reaches Bob's live inbox, which advances his DM.
      await until(async () => (await bob.engine.get(toAlice.record.opId))!.state === 'RECIPIENT_ACKED', "Bob's DM acknowledged");
      expect(bob.receipts.at(-1)).toMatchObject({ r: { type: 'delivered', from: alicePk } });
    } finally {
      aliceInbox.close();
      bobInbox.close();
    }
  });

  it('a profile without receipts sends none, and receipts from anyone but the recipient are ignored', async () => {
    const quiet = persona(bobRelay, [aliceRelay.url, bobRelay.url], 5);
    const quietPk = await quiet.signer.getPublicKey();
    quiet.policy.delivered = false;
    bobRelay.inject(await publishDmRelayList(quiet.signer, [bobRelay.url]));
    aliceRelay.inject(await publishDmRelayList(quiet.signer, [bobRelay.url]));
    try {
      const toQuiet = await alice.send(quietPk, 'sin acuses');
      await quiet.inbox().sync();
      expect(quiet.messages.map(({ m }) => m.rumor.content)).toContain('sin acuses');
      expect((await quiet.engine.list()).filter((r) => r.meta?.receipt)).toEqual([]);
      // Bob (not the recipient) acknowledges Alice's DM to Quiet: nothing moves.
      const forged = await new DirectMessenger(bob.signer, flags).receipt(alicePk, toQuiet.record.groupId!, 'delivered', { pool: bob.pool, outbox: bob.engine, ownRelays: [bobRelay.url], discoveryRelays: [aliceRelay.url], wait: true });
      expect(forged.relays).toEqual([aliceRelay.url]);
      await alice.inbox().sync();
      expect((await alice.engine.get(toQuiet.record.opId))!.state).toBe('REPLICATED');
    } finally {
      quiet.close();
    }
  });

  it("reads the relays of the persona's own kind 10050 too, even if another client published it", async () => {
    const extra = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
    await extra.start();
    const dana = persona(bobRelay, [aliceRelay.url, bobRelay.url], 7);
    const danaPk = await dana.signer.getPublicKey();
    try {
      aliceRelay.inject(await publishDmRelayList(dana.signer, [extra.url]));
      bobRelay.inject(await publishDmRelayList(dana.signer, [extra.url]));
      expect(await alice.send(danaPk, 'a tu otro relay')).toMatchObject({ relays: [extra.url] });
      const inbox = dana.inbox([bobRelay.url]);
      expect(await inbox.relays()).toEqual([bobRelay.url, extra.url]);
      expect((await inbox.sync()).map((m) => m.rumor.content)).toEqual(['a tu otro relay']);
    } finally {
      dana.close();
      await extra.stop();
    }
  });
});
