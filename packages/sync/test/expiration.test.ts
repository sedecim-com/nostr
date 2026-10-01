/**
 * PANEL-06: a relay that does not honour NIP-40 keeps serving what expired (the test relay is one). Rebuilding the
 * history leaves it out (channel events, our own activity, gift wraps by their tag and by their seal's), counted once.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, getPublicKey, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { createDirectMessage, createSeal, createWrap, directMessageRumor } from '@sedecim/messaging';
import { FilterWindowSync, rebuildHistory } from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
const DAY = 86_400;

describe('rebuilding the history leaves out what expired (PANEL-06)', () => {
  const relay = new TestRelay();
  const alice = new LocalSigner(generateSecretKey());
  const bobKey = generateSecretKey();
  const bob = new LocalSigner(bobKey);
  const bobPk = getPublicKey(bobKey);
  const now = Math.floor(Date.now() / 1000);
  // The clock of the rebuild, ten days ahead: what expires before it is still in the future for the relay.
  const T = now + 10 * DAY;
  let pool: RelayPool;
  let channelKept: NostrEvent;
  let channelGone: NostrEvent;

  const toBob = async (content: string, expiration?: number) => {
    const msg = await createDirectMessage(alice, { recipients: [bobPk], content, ...(expiration !== undefined ? { expiration } : {}) }, { now, timestampJitterSeconds: 0 });
    relay.inject(msg.wraps.find((w) => w.recipient === bobPk)!.event);
  };
  const rebuild = (atSeconds: number) =>
    rebuildHistory({ relays: [relay.url], pubkey: bobPk, channels: ['sala'], strategies: [new FilterWindowSync(pool, { since: 0, windowSeconds: now + 1, pageLimit: 100 })], signer: bob, now: () => atSeconds * 1000 });

  beforeAll(async () => {
    await relay.start();
    await toBob('sin caducidad');
    await toBob('caduca después', T + DAY);
    await toBob('caducado', T - DAY);
    // Another client's message whose expiration only its seal shows.
    const rumor = await directMessageRumor(alice, { recipients: [bobPk], content: 'caducado en el sello' });
    relay.inject(createWrap(await createSeal(alice, rumor, bobPk, { expiration: T - DAY, now, timestampJitterSeconds: 0 }), bobPk, { now, timestampJitterSeconds: 0 }));
    channelKept = await bob.signEvent({ kind: 9, content: 'en la sala', tags: [['h', 'sala']], created_at: now });
    channelGone = await bob.signEvent({ kind: 9, content: 'en la sala, caducado', tags: [['h', 'sala'], ['expiration', String(T - 1)]], created_at: now });
    relay.inject(channelKept);
    relay.inject(channelGone);
    pool = new RelayPool({ webSocketFactory: factory, signer: bob });
  });
  afterAll(async () => {
    pool.close();
    await relay.stop();
  });

  it('keeps what has not expired and leaves out, once each, what has', async () => {
    const h = await rebuild(T);
    expect(h.dms.map((m) => m.rumor.content).sort()).toEqual(['caduca después', 'sin caducidad']);
    // Neither the wrap whose own tag passed nor the one whose seal's did: the history export and the vault push take these.
    expect(h.wraps).toHaveLength(2);
    expect(h.channels.sala!.map((e) => e.id)).toEqual([channelKept.id]);
    expect(h.own.map((e) => e.id)).toEqual([channelKept.id]);
    // The expired channel message came twice (the channel and our own activity) and counts once.
    expect(h.expired).toBe(3);
    expect(h.undecryptable).toBe(0);
  });

  it('negative control: before anything expires nothing is left out, and a message without expiration never is', async () => {
    const before = await rebuild(now);
    expect(before.dms).toHaveLength(4);
    expect(before.expired).toBe(0);
    const muchLater = await rebuild(T + 3650 * DAY);
    expect(muchLater.dms.map((m) => m.rumor.content)).toEqual(['sin caducidad']);
    expect(muchLater.channels.sala!.map((e) => e.id)).toEqual([channelKept.id]);
  });
});
