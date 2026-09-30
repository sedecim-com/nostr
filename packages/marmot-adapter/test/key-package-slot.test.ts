/**
 * Kind 30443 is addressable: the relay keeps one key package per `d` slot, the newest by created_at and, within the same
 * second, the one with the lower id (NIP-01). The rotation worker failed in CI (main at 15f7d34) when a restart published
 * a key package in the second of the one its previous run had rotated in: the relay dropped the new one with an OK and
 * publishKeyPackage gave up. Here the clock is set back into that second, as a restart landing there would see it.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { TestRelay } from '@sedecim/test-relay';
import { EncryptedGroupStorage, MarmotTsProvider, PoolGroupNetwork } from '../src/index';

const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;

describe('key packages on the device slot', () => {
  const relay = new TestRelay({ pGatedKinds: [1059] });
  const pools: RelayPool[] = [];
  beforeAll(async () => relay.start());
  afterEach(() => vi.restoreAllMocks());
  afterAll(async () => {
    pools.forEach((p) => p.close());
    await relay.stop();
  });

  const member = (sk: Uint8Array, backend: MemoryBackend, key: number) => {
    const signer = new LocalSigner(sk);
    const pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'auto' });
    pools.push(pool);
    return { signer, storage: new EncryptedGroupStorage(EncryptedStore.withKey(backend, new Uint8Array(32).fill(key))), network: new PoolGroupNetwork(pool, [relay.url]) };
  };

  it('a key package signed in the second of the one it replaces waits for the next second, so the relay keeps it', async () => {
    const bobSk = generateSecretKey();
    const bobStore = new MemoryBackend();
    const openBob = () => new MarmotTsProvider().openSession({ ...member(bobSk, bobStore, 2), deviceId: 'bob' });
    const alice = await new MarmotTsProvider().openSession({ ...member(generateSecretKey(), new MemoryBackend(), 1), deviceId: 'alice' });
    const bob = await openBob();
    const onRelay = () => member(generateSecretKey(), new MemoryBackend(), 3).network.query([relay.url], [{ kinds: [30443], authors: [bob.pubkey] }]);
    const g = await alice.createGroup({ name: 'slot', relays: [relay.url] });
    const first = await bob.publishKeyPackage([relay.url]);
    await alice.invite(g.groupId, first);
    await bob.acceptInvites(); // uses up the key package and rotates it: another one on the same slot
    const [rotated] = await onRelay();
    expect(rotated!.id).not.toBe(first.id);
    bob.close();

    const restarted = await openBob(); // same storage, same slot
    const realNow = Date.now.bind(Date);
    const start = realNow();
    vi.spyOn(Date, 'now').mockImplementation(() => rotated!.created_at * 1000 + 500 + (realNow() - start));
    const fresh = await restarted.publishKeyPackage([relay.url]);
    expect(fresh.created_at).toBeGreaterThan(rotated!.created_at);
    expect((await onRelay()).map((e) => e.id)).toEqual([fresh.id]);
    restarted.close();
    alice.close();
  }, 60_000);
});
