/**
 * OPS-06: can the notification gateway tell that someone has activity, on real relays, without read access to their
 * DMs? It authenticates with its own identity, as deployed (NOTIFY_NSEC), and probes each relay with a canary gift
 * wrap between two throwaway keys.
 * - Buzz (pinned, at BUZZ_RELAY_URL in the CI stack job) and the secure relay (nostr-rs-relay with nip42_dms, at
 *   MARMOT_RELAY_URL) deliver gift wraps only to their recipient: the gateway observes neither, refuses
 *   registrations there, and the web offers no switch.
 * - The same pinned nostr-rs-relay with nip42_dms off (OPEN_RELAY_URL, started by the stack job) is observable: a
 *   NIP-17 DM to a registered npub triggers an opaque push.
 * ADR 0010, «Matriz real por relay».
 */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createECDH, randomBytes } from 'node:crypto';
import WebSocket from 'ws';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { normalizeRelayUrl, RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { createDirectMessage } from '@sedecim/messaging';
import { OPAQUE_PUSH_PAYLOAD, OPAQUE_PUSH_TOPIC } from '@sedecim/profiles';
import { createWebPushSender, generateVapidKeys, NotificationGateway, type WebPushMessage } from '@sedecim/notification-gateway';

const GATED = [process.env.BUZZ_RELAY_URL, process.env.MARMOT_RELAY_URL].filter((u): u is string => !!u);
const OPEN = process.env.OPEN_RELAY_URL;
const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;
// The gateway's own NIP-42 identity, as NOTIFY_NSEC in production.
const gatewayPool = () => new RelayPool({ webSocketFactory: factory, signer: new LocalSigner(generateSecretKey()), authMode: 'auto' });

function subscription() {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  return { endpoint: `https://fcm.googleapis.com/fcm/send/ops06-${randomBytes(4).toString('hex')}`, keys: { p256dh: ecdh.getPublicKey().toString('base64url'), auth: randomBytes(16).toString('base64url') } };
}

// A skipped describe still runs its body to collect the tests: everything that dials a relay starts in beforeAll.
describe.skipIf(!GATED.length)('notification gateway on the deployed relays (OPS-06)', () => {
  let pool: RelayPool;
  let gateway: NotificationGateway;
  beforeAll(() => {
    pool = gatewayPool();
    gateway = new NotificationGateway({ pool, sender: createWebPushSender({ vapid: generateVapidKeys(), subject: 'mailto:interop@example.org' }), relays: GATED.map((url) => ({ public: url })) });
  });
  afterAll(() => {
    gateway.stop();
    pool.close();
  });

  it('sees no gift wrap for someone else on any of them, so it registers no push there', async () => {
    const found = await gateway.probeRelays(8000);
    for (const o of found) console.log(`OPS-06 ${o.relay}: observable=${o.observable} (${o.reason ?? 'canary delivered'})`);
    expect(found.map((o) => o.observable)).toEqual(GATED.map(() => false));
    expect(() => gateway.register(getPublicKey(generateSecretKey()), { subscription: subscription(), profile: 'convenience', relays: GATED })).toThrow(/without read access to your DMs/);
    expect(gateway.size).toBe(0);
  }, 30_000);
});

describe.skipIf(!OPEN)('notification gateway on nostr-rs-relay without gift-wrap gating (OPS-06)', () => {
  const pushes: WebPushMessage[] = [];
  let pool: RelayPool;
  let gateway: NotificationGateway;
  let sender: RelayPool;
  beforeAll(() => {
    pool = gatewayPool();
    gateway = new NotificationGateway({ pool, sender: { send: async (_sub, msg) => (pushes.push(msg), 201) }, relays: [{ public: OPEN! }], delayFor: () => 0 });
    sender = new RelayPool({ webSocketFactory: factory });
  });
  afterAll(() => {
    gateway.stop();
    pool.close();
    sender.close();
  });

  it('sees the canary, and a NIP-17 DM to a registered npub triggers an opaque push', async () => {
    expect((await gateway.probeRelays(8000)).map((o) => o.observable)).toEqual([true]);
    const bob = getPublicKey(generateSecretKey());
    expect(gateway.register(bob, { subscription: subscription(), profile: 'convenience', relays: [OPEN!] }).relays).toEqual([normalizeRelayUrl(OPEN!)]);
    const alice = new LocalSigner(generateSecretKey());
    // The watch REQ opens in the background and what arrives before its EOSE is ignored: send until one DM counts.
    await vi.waitFor(
      async () => {
        if (!pushes.length) {
          const dm = await createDirectMessage(alice, { recipients: [bob], content: 'hola' });
          expect((await sender.publishTo(dm.wraps.find((w) => w.recipient === bob)!.event, OPEN!)).ok).toBe(true);
        }
        expect(pushes.length).toBeGreaterThan(0);
      },
      { timeout: 20_000, interval: 2_000 },
    );
    expect(new TextDecoder().decode(pushes[0]!.payload!)).toBe(OPAQUE_PUSH_PAYLOAD);
    expect(pushes[0]!.topic).toBe(OPAQUE_PUSH_TOPIC);
  }, 40_000);
});
