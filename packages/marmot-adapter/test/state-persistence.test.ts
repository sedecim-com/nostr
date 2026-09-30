/**
 * Encrypting an MLS application message advances the sender's ratchet, and marmot-ts only stores the group state on its
 * next commit or ingest. If the state is not stored at once, a restart makes the next message use the same generation
 * again: the same key (only RFC 9420's random reuse guard keeps the nonces apart), and the recipients, who already used
 * up that generation, cannot read it: it is lost. Same storage across two sessions stands for two runs of the CLI, or
 * a reloaded browser.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { TestRelay } from '@sedecim/test-relay';
import { EncryptedGroupStorage, MarmotTsProvider, PoolGroupNetwork, type GroupNetwork } from '../src/index';

const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;

describe('MLS group state is stored as soon as a message is encrypted', () => {
  const relay = new TestRelay({ pGatedKinds: [1059] });
  const pools: RelayPool[] = [];
  beforeAll(async () => relay.start());
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

  /** Alice and Bob in a group, and a way to open Alice again from her stored state (a restart). */
  async function group(name: string, network?: (inner: GroupNetwork) => GroupNetwork) {
    const aliceSk = generateSecretKey();
    const aliceStore = new MemoryBackend();
    const openAlice = () => {
      const m = member(aliceSk, aliceStore, 1);
      return new MarmotTsProvider().openSession({ ...m, network: network ? network(m.network) : m.network, deviceId: 'alice' });
    };
    const alice = await openAlice();
    const bob = await new MarmotTsProvider().openSession({ ...member(generateSecretKey(), new MemoryBackend(), 2), deviceId: 'bob' });
    const g = await alice.createGroup({ name, relays: [relay.url] });
    await alice.invite(g.groupId, await bob.publishKeyPackage([relay.url]));
    await bob.acceptInvites();
    await bob.sync(g.groupId);
    await alice.sync(g.groupId);
    return { alice, bob, openAlice, groupId: g.groupId };
  }

  it('a message sent right before a restart does not share its generation with the next one', async () => {
    const { alice, bob, openAlice, groupId } = await group('restart');
    await alice.send(groupId, 'uno');
    alice.close();
    const again = await openAlice(); // nothing ingested in between: only what was stored counts
    await again.send(groupId, 'dos');
    expect((await bob.sync(groupId)).map((m) => m.content).sort()).toEqual(['dos', 'uno']);
    again.close();
    bob.close();
  }, 60_000);

  it('a message no relay took still used up its key: delivered later, it is not a twin of the next one', async () => {
    // The first group message after the setup finds the network down; its ciphertext is kept (FR025-12).
    let down = false;
    const refused: NostrEvent[] = [];
    const published: string[] = [];
    const flaky = (inner: GroupNetwork): GroupNetwork => ({
      publish: async (relays, event) => {
        if (!down) return published.push(event.id), inner.publish(relays, event);
        refused.push(event);
        return relays.map((relay) => ({ relay, ok: false, message: 'error: connection failed: offline' }));
      },
      query: (relays, filters, timeoutMs) => inner.query(relays, filters, timeoutMs),
      subscribe: (relays, filters, onEvent) => inner.subscribe(relays, filters, onEvent),
      inboxRelays: (pubkey) => inner.inboxRelays(pubkey),
    });
    const { alice, bob, openAlice, groupId } = await group('offline', flaky);
    down = true;
    expect((await alice.send(groupId, 'sin red')).pending).toBe(true);
    alice.close();
    down = false;
    const again = await openAlice();
    await again.send(groupId, 'con red');
    // The kept message went first, with the ciphertext it was given then.
    expect(published).toContain(refused[0]!.id);
    expect(await again.pendingOperations()).toEqual([]);
    expect((await bob.sync(groupId)).map((m) => m.content).sort()).toEqual(['con red', 'sin red']);
    again.close();
    bob.close();
  }, 60_000);
});
