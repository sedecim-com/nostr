/**
 * PANEL-06 (§12.2): disappearing DMs (NIP-17 with an NIP-40 `expiration`) and the deletion of one's own (NIP-17 with a
 * gift-wrapped kind 5), as this client sends, reads and forgets them. The test relay keeps serving expired events, as
 * a relay that does not honour NIP-40 does; the clock is injected, nothing sleeps until a message expires.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { createRumor, eventExpiration, generateSecretKey, getPublicKey, getTagValue, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { DeliveryEngine, type OutboxRecord, type Publisher } from '@sedecim/delivery-engine';
import {
  APP_RECEIPT_KIND,
  DirectMessenger,
  directMessageRumor,
  dmDeletionRumor,
  DmInbox,
  DmRelayCache,
  NotYourMessageError,
  publishDmRelayList,
  purgeExpiredCopies,
  roundedExpiration,
  unwrap,
  wrapRumor,
  type DirectMessage,
  type DmOperation,
} from '../src/index';

const DAY = 86_400;
const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
const flags = { nip17: true, readReceipts: false };

async function until<T>(fn: () => Promise<T | undefined> | T | undefined, what: string, ms = 5000): Promise<T> {
  for (let t = 0; t < ms; t += 25) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`timed out waiting for ${what}`);
}

describe('the expiration of what is sent (PANEL-06)', () => {
  it('PANEL-06: the expiration is rounded up to the next UTC midnight, so the relay learns the day and not the time', () => {
    const t0 = Date.UTC(2026, 9, 1, 13, 37, 5) / 1000;
    expect(roundedExpiration(7, t0)).toBe(Date.UTC(2026, 9, 9) / 1000);
    // Every message of that length sent that day carries the same value.
    expect(roundedExpiration(7, Date.UTC(2026, 9, 1, 0, 0, 1) / 1000)).toBe(roundedExpiration(7, Date.UTC(2026, 9, 1, 23, 59, 59) / 1000));
    // On a boundary: exactly `days` later. Never shorter than asked, less than a day longer.
    expect(roundedExpiration(1, Date.UTC(2026, 9, 1) / 1000)).toBe(Date.UTC(2026, 9, 2) / 1000);
    for (const t of [t0, t0 + 1, t0 + 40_000]) {
      const e = roundedExpiration(30, t);
      expect(e % DAY).toBe(0);
      expect(e - t).toBeGreaterThanOrEqual(30 * DAY);
      expect(e - t).toBeLessThan(31 * DAY);
    }
    expect(() => roundedExpiration(0, t0)).toThrow();
  });

  /** Alice's outbox over a fake network that records each publish. */
  function alice(up = true) {
    const signer = new LocalSigner(generateSecretKey());
    const published: NostrEvent[] = [];
    const net = { up };
    const publisher: Publisher = {
      async publishTo(evt, relay) {
        published.push(evt);
        return net.up ? { relay, ok: true, message: '', latencyMs: 1 } : { relay, ok: false, message: 'error: connection failed: offline', latencyMs: 1 };
      },
    };
    const store = EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(9));
    const engine = new DeliveryEngine({ store: store.collection<OutboxRecord>('outbox'), publisher, signer, retry: { baseMs: 60_000, maxMs: 60_000 } });
    const operations = store.collection<DmOperation>('dm-ops');
    const opts = { pool: { query: async () => [] }, outbox: engine, operations, ownRelays: ['wss://alice.example'], cache: new DmRelayCache(), wait: true };
    return { signer, published, net, engine, operations, opts, messenger: new DirectMessenger(signer, flags) };
  }

  it('PANEL-06: every new gift wrap and its seal carry the expiration, the sender’s own copy too; without one, none does', async () => {
    const a = alice();
    const bob = new LocalSigner(generateSecretKey());
    const bobPk = await bob.getPublicKey();
    const at = roundedExpiration(7, Math.floor(Date.now() / 1000));
    await a.messenger.sendDmOnce('op-exp', { recipients: [bobPk], content: 'se borra sola', expiration: at }, a.opts);
    expect(a.published).toHaveLength(2);
    for (const wrap of a.published) expect(eventExpiration(wrap)).toBe(at);
    const toBob = a.published.find((w) => getTagValue(w, 'p') === bobPk)!;
    const own = a.published.find((w) => getTagValue(w, 'p') !== bobPk)!;
    expect(eventExpiration((await unwrap(bob, toBob)).seal)).toBe(at);
    expect(eventExpiration((await unwrap(a.signer, own)).seal)).toBe(at);
    // NIP-17 asks for the wrap and the seal: the rumor (what is stored) stays as it was.
    expect((await unwrap(bob, toBob)).rumor.tags.some((t) => t[0] === 'expiration')).toBe(false);
    expect((await a.operations.get('op-exp'))!.expiration).toBe(at);

    // Negative control: a conversation without expiration sends wraps and seals without the tag.
    const before = a.published.length;
    await a.messenger.sendDmOnce('op-plain', { recipients: [bobPk], content: 'se queda' }, a.opts);
    const plain = a.published.slice(before);
    expect(plain).toHaveLength(2);
    for (const wrap of plain) expect(wrap.tags.some((t) => t[0] === 'expiration')).toBe(false);
    expect((await unwrap(bob, plain.find((w) => getTagValue(w, 'p') === bobPk)!)).seal.tags).toEqual([]);
    expect((await a.operations.get('op-plain'))!.expiration).toBeUndefined();
    a.engine.stop();
  });

  it('PANEL-06: a retry keeps the expiration the message was written with, even if the conversation changed since', async () => {
    const a = alice(false);
    const bobPk = getPublicKey(generateSecretKey());
    const first = roundedExpiration(1, Math.floor(Date.now() / 1000));
    await a.messenger.sendDmOnce('op-1', { recipients: [bobPk], content: 'escrito sin red', expiration: first }, a.opts);
    a.net.up = true;
    // The user changed the conversation to 90 days and retries the same send: the message keeps its expiration.
    await a.messenger.sendDmOnce('op-1', { recipients: [bobPk], content: 'escrito sin red', expiration: roundedExpiration(90, Math.floor(Date.now() / 1000)) }, a.opts);
    expect(new Set(a.published.map((e) => e.id)).size).toBe(2);
    for (const wrap of a.published) expect(eventExpiration(wrap)).toBe(first);
    a.engine.stop();
  });

  it('PANEL-06: purge forgets the sent operation and every outbox wrap of an expired message, and never touches one without expiration', async () => {
    const a = alice();
    const bobPk = getPublicKey(generateSecretKey());
    const at = roundedExpiration(1, Math.floor(Date.now() / 1000));
    await a.messenger.sendDmOnce('op-exp', { recipients: [bobPk], content: 'efímero', expiration: at }, a.opts);
    await a.messenger.sendDmOnce('op-keep', { recipients: [bobPk], content: 'permanente' }, a.opts);
    const copies = { operations: a.operations, outbox: a.engine };
    expect(await purgeExpiredCopies(copies, at - 1)).toEqual({ operations: 0, outbox: 0, wrapIds: [], next: at });
    const expiringId = (await a.operations.get('op-exp'))!.rumor.id;
    const expiringWraps = (await a.engine.list()).filter((r) => r.groupId === expiringId).map((r) => r.event!.id);

    const purged = await purgeExpiredCopies(copies, at);
    expect(purged).toMatchObject({ operations: 1, outbox: 2 });
    expect(purged.wrapIds.sort()).toEqual(expiringWraps.sort());
    expect(purged.next).toBeUndefined();
    expect(await a.operations.get('op-exp')).toBeUndefined();
    expect((await a.engine.list()).map((r) => r.opId).sort()).toEqual([`op-keep:${bobPk}`, `op-keep:${await a.signer.getPublicKey()}`].sort());
    // Negative control: ten years on, the message without expiration is still there.
    expect(await purgeExpiredCopies(copies, at + 3650 * DAY)).toEqual({ operations: 0, outbox: 0, wrapIds: [] });
    expect((await a.operations.get('op-keep'))!.rumor.content).toBe('permanente');
    a.engine.stop();
  });
});

describe('the expiration and the deletion of what is read (PANEL-06)', () => {
  // Like the reference relays: NIP-42, and gift wraps only reach their authenticated recipient. No NIP-40.
  const relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  const clock = { now: Date.now() };
  const pools: RelayPool[] = [];
  const engines: DeliveryEngine[] = [];

  /** A device of a persona: its outbox, its stores and DM inboxes reading the test relay with the shared clock. */
  function device(sk: Uint8Array, fill: number) {
    const signer = new LocalSigner(sk);
    const pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'on-demand' });
    pools.push(pool);
    const store = EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(fill));
    const engine = new DeliveryEngine({ store: store.collection<OutboxRecord>('outbox'), publisher: pool, signer });
    engines.push(engine);
    const operations = store.collection<DmOperation>('dm-ops');
    const tombstones = store.collection<boolean>('dm-deleted');
    const shown: DirectMessage[] = [];
    const removed: Array<{ ids: string[]; reason: string }> = [];
    const contacts = new Set<string>();
    const inbox = (opts: { tombstones?: boolean } = {}) =>
      new DmInbox(signer, {
        pool,
        outbox: engine,
        ownRelays: [relay.url],
        policy: () => ({ delivered: true, read: false }),
        isContact: async (pk) => contacts.has(pk),
        sent: store.collection<boolean>('receipts'),
        ...(opts.tombstones === false ? {} : { tombstones }),
        cache: new DmRelayCache(),
        timeoutMs: 2000,
        now: () => clock.now,
        onMessage: (m) => shown.push(m),
        onRemoved: (gone, reason) => removed.push({ ids: gone.map((m) => m.rumor.id), reason }),
      });
    const route = { pool, outbox: engine, operations, ownRelays: [relay.url], cache: new DmRelayCache(), wait: true };
    const messenger = new DirectMessenger(signer, flags);
    return { signer, pool, engine, operations, tombstones, shown, removed, contacts, inbox, route, messenger };
  }

  const aliceSk = generateSecretKey();
  const alicePk = getPublicKey(aliceSk);
  const bobSk = generateSecretKey();
  const bobPk = getPublicKey(bobSk);
  let alice: ReturnType<typeof device>;
  let aliceLaptop: ReturnType<typeof device>;
  let bob: ReturnType<typeof device>;

  beforeAll(async () => {
    await relay.start();
    alice = device(aliceSk, 1);
    aliceLaptop = device(aliceSk, 2);
    bob = device(bobSk, 3);
    bob.contacts.add(alicePk);
    for (const sk of [aliceSk, bobSk]) relay.inject(await publishDmRelayList(new LocalSigner(sk), [relay.url]));
  });
  afterAll(async () => {
    for (const e of engines) e.stop();
    for (const p of pools) p.close();
    await relay.stop();
  });

  const send = async (content: string, expiration?: number) => {
    const opId = `op-${content}`;
    const { rumor } = await alice.messenger.sendDmOnce(opId, { recipients: [bobPk], content, ...(expiration ? { expiration } : {}) }, alice.route);
    return rumor;
  };

  it('PANEL-06: an expired message is never shown or answered, and a held one leaves when the clock passes it, though the relay still serves it', async () => {
    const at = roundedExpiration(1, Math.floor(Date.now() / 1000));
    const fleeting = await send('efímero', at);
    const lasting = await send('permanente');
    clock.now = (at - 60) * 1000;
    const inbox = bob.inbox();
    expect((await inbox.sync()).map((m) => m.rumor.content).sort()).toEqual(['efímero', 'permanente']);
    expect(inbox.nextExpiration()).toBe(at);
    // Bob's delivered receipt of the disappearing message asks to expire with it; the other one does not.
    const receipts = await until(async () => {
      const recs = (await bob.engine.list()).filter((r) => r.meta?.receipt === 'delivered');
      return recs.length === 2 ? recs : undefined;
    }, 'both receipts');
    const receiptOf = async (rumorId: string) => {
      for (const r of receipts) if ((await unwrap(alice.signer, r.event!)).rumor.tags.some((t) => t[0] === 'e' && t[1] === rumorId)) return r;
    };
    expect((await unwrap(alice.signer, (await receiptOf(fleeting.id))!.event!)).rumor.kind).toBe(APP_RECEIPT_KIND);
    expect(eventExpiration((await receiptOf(fleeting.id))!.event!)).toBe(at);
    expect(eventExpiration((await receiptOf(lasting.id))!.event!)).toBeUndefined();

    // The clock reaches the expiration: the message leaves the inbox, the other one stays.
    clock.now = at * 1000;
    expect(inbox.purgeExpired().map((m) => m.rumor.id)).toEqual([fleeting.id]);
    expect(bob.removed.at(-1)).toEqual({ ids: [fleeting.id], reason: 'expired' });
    expect(inbox.list().map((m) => m.rumor.content)).toEqual(['permanente']);
    // The relay (no NIP-40) still serves the expired wrap; a fresh inbox reads it and ignores it.
    const wrap = [...relay.events.values()].find((e) => getTagValue(e, 'p') === bobPk && eventExpiration(e) === at);
    expect(wrap).toBeDefined();
    bob.shown.length = 0;
    expect((await bob.inbox().sync()).map((m) => m.rumor.content)).toEqual(['permanente']);
    expect(bob.shown.map((m) => m.rumor.id)).not.toContain(fleeting.id);
    // Negative control: years later, the message without expiration is still shown.
    clock.now = (at + 3650 * DAY) * 1000;
    expect((await bob.inbox().sync()).map((m) => m.rumor.content)).toEqual(['permanente']);
    clock.now = Date.now();
  });

  it('PANEL-06: an expired message read for the first time gets no receipt', async () => {
    const at = roundedExpiration(1, Math.floor(Date.now() / 1000));
    const late = await send('llega tarde', at);
    clock.now = (at + 1) * 1000;
    // sync() resolves once every wrap was handled, receipts included.
    await bob.inbox().sync();
    for (const r of (await bob.engine.list()).filter((x) => x.meta?.receipt)) expect((await unwrap(alice.signer, r.event!)).rumor.tags.some((t) => t[1] === late.id)).toBe(false);
    clock.now = Date.now();
  });

  it('PANEL-06: the deletion reaches the contact’s client through the test relay and it removes the message; the persona’s other device too', async () => {
    const m = await send('me arrepiento');
    const bobInbox = bob.inbox();
    expect((await bobInbox.sync()).map((x) => x.rumor.id)).toContain(m.id);
    const laptop = aliceLaptop.inbox();
    expect((await laptop.sync()).map((x) => x.rumor.id)).toContain(m.id); // the sender's own copy, read on her other device

    const { rumor, deliveries } = await alice.messenger.deleteDmOnce(`delete:${m.id}`, { rumor: m }, alice.route);
    expect(rumor).toMatchObject({ kind: 5, pubkey: alicePk });
    expect(getTagValue(rumor, 'e')).toBe(m.id);
    expect(deliveries.map((d) => d.recipient).sort()).toEqual([alicePk, bobPk].sort());
    // Gift-wrapped like any message: the relay cannot tell it from one.
    for (const d of deliveries) expect(d.record.event!.kind).toBe(1059);

    await bobInbox.sync();
    expect(bobInbox.list().map((x) => x.rumor.id)).not.toContain(m.id);
    expect(bob.removed.at(-1)).toEqual({ ids: [m.id], reason: 'deleted' });
    await laptop.sync();
    expect(laptop.list().map((x) => x.rumor.id)).not.toContain(m.id);
    // A later session of Bob does not bring it back from the relay, which still serves both wraps.
    expect((await bob.inbox().sync()).map((x) => x.rumor.id)).not.toContain(m.id);
    expect(await bob.tombstones.get(`rumor:${m.id}:${alicePk}`)).toBe(true);
    // Retrying the deletion makes no other request.
    const again = await alice.messenger.deleteDmOnce(`delete:${m.id}`, { rumor: m }, alice.route);
    expect(again.rumor.id).toBe(rumor.id);
  });

  it('PANEL-06: a deletion read before its message still removes it', async () => {
    const m = await directMessageRumor(alice.signer, { recipients: [bobPk], content: 'borrado antes de leerlo' });
    const keep = await directMessageRumor(alice.signer, { recipients: [bobPk], content: 'sigue aquí' });
    // The pool hands an inbox the oldest wraps first: the deletion's wrap is older than the message's, so it is read first.
    const t = Math.floor(Date.now() / 1000);
    const at = (now: number) => ({ timestampJitterSeconds: 0, now });
    const ordered = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
    await ordered.start();
    try {
      const deletionWrap = await wrapRumor(alice.signer, dmDeletionRumor(m), bobPk, at(t - 20));
      const messageWrap = await wrapRumor(alice.signer, m, bobPk, at(t - 10));
      for (const w of [deletionWrap, messageWrap, await wrapRumor(alice.signer, keep, bobPk, at(t))]) ordered.inject(w);
      expect(deletionWrap.created_at).toBeLessThan(messageWrap.created_at);
      const pool = new RelayPool({ webSocketFactory: factory, signer: bob.signer, authMode: 'on-demand' });
      pools.push(pool);
      // No tombstone store: what this inbox read is enough, in either order.
      const fresh = new DmInbox(bob.signer, { pool, outbox: bob.engine, ownRelays: [ordered.url], policy: () => ({ delivered: false, read: false }), sent: EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(7)).collection<boolean>('receipts') });
      expect((await fresh.sync()).map((x) => x.rumor.content)).toEqual(['sigue aquí']);
    } finally {
      await ordered.stop();
    }
  });

  it('PANEL-06: deleting a message someone else wrote is refused before anything is sent, and a forged deletion does not hide it', async () => {
    const m = await send('mío');
    const before = relay.received.length;
    const bobRecords = (await bob.engine.list()).length;
    await expect(bob.messenger.deleteDmOnce(`delete:${m.id}`, { rumor: m }, bob.route)).rejects.toBeInstanceOf(NotYourMessageError);
    expect(relay.received.length).toBe(before);
    expect((await bob.engine.list()).length).toBe(bobRecords);
    expect(await bob.operations.get(`delete:${m.id}`)).toBeUndefined();

    // Mallory asks Bob to delete Alice's message: Bob's client keeps it.
    const mallory = new LocalSigner(generateSecretKey());
    const forged = createRumor({ kind: 5, content: '', tags: [['e', m.id], ['k', '14']] }, await mallory.getPublicKey());
    relay.inject(await wrapRumor(mallory, forged, bobPk));
    // Or seals a deletion that claims to be Alice's: the unwrap refuses it (the seal signer is not the author).
    relay.inject(await wrapRumor(mallory, createRumor({ kind: 5, content: '', tags: [['e', m.id]] }, alicePk), bobPk));
    const inbox = bob.inbox({ tombstones: false });
    expect((await inbox.sync()).map((x) => x.rumor.id)).toContain(m.id);
    expect(inbox.forget(m.id, await mallory.getPublicKey())).toBeUndefined();
    expect(inbox.list().map((x) => x.rumor.id)).toContain(m.id);
  });
});
