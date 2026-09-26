import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import * as ntNip17 from 'nostr-tools/nip17';
import * as ntNip59 from 'nostr-tools/nip59';
import { createRumor, finalizeEvent, generateSecretKey, getPublicKey, nip44, toUnsigned } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import {
  createDirectMessage,
  openDirectMessage,
  dmInboxFilter,
  unwrap,
  createWrap,
  createReceipt,
  parseReceipt,
  chatMessage,
  channelFilter,
  DirectMessenger,
  FeatureDisabledError,
  UnwrapError,
  GIFT_WRAP_KIND,
} from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;

describe('NIP-17 / NIP-59', () => {
  const aliceKey = generateSecretKey();
  const bobKey = generateSecretKey();
  const alice = new LocalSigner(aliceKey);
  const bob = new LocalSigner(bobKey);
  const bobPk = getPublicKey(bobKey);
  const alicePk = getPublicKey(aliceKey);

  it('wraps for recipient and sender copy with ephemeral keys and randomized timestamps', async () => {
    const now = Math.floor(Date.now() / 1000);
    const msg = await createDirectMessage(alice, { recipients: [bobPk], content: 'hola Bob' });
    expect(msg.wraps.map((w) => w.recipient).sort()).toEqual([alicePk, bobPk].sort());
    for (const w of msg.wraps) {
      expect(w.event.kind).toBe(GIFT_WRAP_KIND);
      expect(w.event.pubkey).not.toBe(alicePk);
      expect(w.event.created_at).toBeLessThanOrEqual(now);
      expect(w.event.content).not.toContain('hola');
    }
    const opened = await openDirectMessage(bob, msg.wraps.find((w) => w.recipient === bobPk)!.event);
    expect(opened.rumor.content).toBe('hola Bob');
    expect(opened.sender).toBe(alicePk);
    const own = await openDirectMessage(alice, msg.wraps.find((w) => w.recipient === alicePk)!.event);
    expect(own.roomId).toBe(opened.roomId);
  });

  it('interoperates with nostr-tools NIP-17 in both directions', async () => {
    const msg = await createDirectMessage(alice, { recipients: [bobPk], content: 'interop →' });
    const theirRumor = ntNip17.unwrapEvent(msg.wraps.find((w) => w.recipient === bobPk)!.event, bobKey);
    expect(theirRumor.content).toBe('interop →');
    expect(theirRumor.pubkey).toBe(alicePk);
    const wrap = ntNip17.wrapEvent(bobKey, { publicKey: alicePk }, 'interop ←');
    const opened = await openDirectMessage(alice, wrap);
    expect(opened.rumor.content).toBe('interop ←');
    expect(opened.sender).toBe(bobPk);
    const generic = ntNip59.wrapEvent({ kind: 14, content: 'generic', tags: [['p', alicePk]] }, bobKey, alicePk);
    expect((await unwrap(alice, generic)).rumor.content).toBe('generic');
  });

  it('rejects a seal whose signer differs from the rumor author (impersonation)', async () => {
    const mallory = generateSecretKey();
    const rumor = createRumor({ kind: 14, content: 'soy Alice', tags: [['p', bobPk]] }, alicePk);
    const ck = nip44.getConversationKey(mallory, bobPk);
    const seal = finalizeEvent(toUnsigned({ kind: 13, content: nip44.encrypt(JSON.stringify(rumor), ck), tags: [] }, getPublicKey(mallory)), mallory);
    await expect(unwrap(bob, createWrap(seal, bobPk))).rejects.toBeInstanceOf(UnwrapError);
  });

  it('builds gift-wrapped receipts', async () => {
    const { event } = await createReceipt(bob, alicePk, 'a'.repeat(64), 'read');
    const parsed = parseReceipt(await unwrap(alice, event));
    expect(parsed).toEqual({ rumorId: 'a'.repeat(64), type: 'read', from: bobPk });
  });

  it('keeps NIP-17 behind a feature flag (FR-017)', async () => {
    const off = new DirectMessenger(alice);
    expect(() => off.compose({ recipients: [bobPk], content: 'x' })).toThrow(FeatureDisabledError);
    const on = new DirectMessenger(alice, { nip17: true, readReceipts: false });
    expect((await on.compose({ recipients: [bobPk], content: 'x' })).wraps).toHaveLength(2);
  });
});

describe('NIP-17 E2E against a Buzz-like relay (gate §6.2)', () => {
  const relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059], rejectCreatedAtSkewSeconds: 600 });
  const aliceSigner = new LocalSigner(generateSecretKey());
  const bobSigner = new LocalSigner(generateSecretKey());
  let alicePool: RelayPool;
  let bobPool: RelayPool;

  beforeAll(async () => {
    await relay.start();
    alicePool = new RelayPool({ webSocketFactory: factory, signer: aliceSigner, authMode: 'auto' });
    bobPool = new RelayPool({ webSocketFactory: factory, signer: bobSigner, authMode: 'auto' });
  });
  afterAll(async () => {
    alicePool.close();
    bobPool.close();
    await relay.stop();
  });

  it('documents the incompatibility: default 2-day jitter is rejected by strict-freshness relays', async () => {
    const bobPk = await bobSigner.getPublicKey();
    let rejected = 0;
    for (let i = 0; i < 5; i++) {
      const msg = await createDirectMessage(aliceSigner, { recipients: [bobPk], content: 'jitter' });
      const res = await alicePool.publishTo(msg.wraps[0]!.event, relay.url);
      if (!res.ok) rejected++;
    }
    expect(rejected).toBeGreaterThan(0);
  });

  it('delivers with an explicit relay adapter (bounded jitter) and a #p-scoped inbox subscription', async () => {
    const bobPk = await bobSigner.getPublicKey();
    const msg = await createDirectMessage(aliceSigner, { recipients: [bobPk], content: 'vía Buzz' }, { timestampJitterSeconds: 300 });
    const res = await alicePool.publish(msg.wraps.find((w) => w.recipient === bobPk)!.event, [relay.url]);
    expect(res[0]!.ok).toBe(true);
    const got = await bobPool.query([relay.url], [dmInboxFilter(bobPk)], 3000);
    const opened = await Promise.all(got.map((w) => openDirectMessage(bobSigner, w).catch(() => undefined)));
    expect(opened.some((o) => o?.rumor.content === 'vía Buzz')).toBe(true);
    // subscriptions without our own #p are refused by p-gated relays
    const leaked = await bobPool.query([relay.url], [{ kinds: [1059] }], 1500);
    expect(leaked).toHaveLength(0);
  });

  it('publishes NIP-29 channel messages readable by any client on the same relay (FR-014/FR-015)', async () => {
    const evt = await aliceSigner.signEvent(chatMessage('general', 'hola canal'));
    expect((await alicePool.publishTo(evt, relay.url)).ok).toBe(true);
    const got = await bobPool.query([relay.url], [channelFilter('general')], 3000);
    expect(got.map((e) => e.content)).toContain('hola canal');
  });
});
