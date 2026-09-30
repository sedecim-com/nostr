/**
 * FR025-12: with Tor or the network down, a group message or commit stays pending and is sent again, instead of
 * failing. Real MLS (marmot-ts) between three members over a test relay; each member's network can be taken down,
 * lose the OK of what it publishes, or be refused for good.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { TestRelay } from '@sedecim/test-relay';
import { EncryptedGroupStorage, MarmotTsProvider, PoolGroupNetwork, type ExtendedGroupSession, type GroupNetwork } from '../src/index';

const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;

/**
 * `down`: nothing goes out and queries find nothing (an unreachable relay). `lost-ok`: the relay stores the event but
 * the OK never arrives. `refuse`: the relay refuses for good. `no-welcome`: only gift wraps (Welcomes) fail. `blind`:
 * publishing works but queries find nothing (a member that commits without having seen the others' commits).
 */
type Mode = 'up' | 'down' | 'lost-ok' | 'refuse' | 'no-welcome' | 'blind';

interface Member {
  session: ExtendedGroupSession;
  net: { mode: Mode; published: NostrEvent[]; refused: NostrEvent[] };
  reopen(): Promise<ExtendedGroupSession>;
}

describe('FR025-12: group operations without network stay pending and go out later', () => {
  const relay = new TestRelay({ pGatedKinds: [1059] });
  const pools: RelayPool[] = [];
  beforeAll(async () => relay.start());
  afterAll(async () => {
    pools.forEach((p) => p.close());
    await relay.stop();
  });

  async function member(name: string): Promise<Member> {
    const sk = generateSecretKey();
    const backend = new MemoryBackend();
    const net: Member['net'] = { mode: 'up', published: [], refused: [] };
    const open = async () => {
      const signer = new LocalSigner(sk);
      const pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'auto' });
      pools.push(pool);
      const inner = new PoolGroupNetwork(pool, [relay.url]);
      const network: GroupNetwork = {
        publish: async (relays, event) => {
          const m = net.mode;
          if (m === 'up' || m === 'blind' || (m === 'no-welcome' && event.kind !== 1059)) return net.published.push(event), inner.publish(relays, event);
          if (m === 'lost-ok') {
            net.published.push(event);
            await inner.publish(relays, event);
            return relays.map((relay) => ({ relay, ok: false, message: 'error: timeout waiting for OK' }));
          }
          net.refused.push(event);
          return relays.map((relay) => ({ relay, ok: false, message: m === 'refuse' ? 'restricted: not allowed here' : 'error: connection failed: offline' }));
        },
        query: (relays, filters, timeoutMs) => (net.mode === 'down' || net.mode === 'blind' ? Promise.resolve([]) : inner.query(relays, filters, timeoutMs)),
        subscribe: (relays, filters, onEvent) => inner.subscribe(relays, filters, onEvent),
        inboxRelays: (pubkey) => inner.inboxRelays(pubkey),
      };
      const storage = new EncryptedGroupStorage(EncryptedStore.withKey(backend, new Uint8Array(32).fill(name.charCodeAt(0))));
      return new MarmotTsProvider().openSession({ signer, network, storage, deviceId: name });
    };
    const m: Member = { session: await open(), net, reopen: async () => (m.session.close(), (m.session = await open())) };
    return m;
  }

  /** Alice (admin), Bob and Carol in a group, everyone synced. */
  async function trio(name: string) {
    const [alice, bob, carol] = await Promise.all([member('alice'), member('bob'), member('carol')]);
    const g = await alice.session.createGroup({ name, relays: [relay.url] });
    for (const m of [bob, carol]) {
      await alice.session.invite(g.groupId, await m.session.publishKeyPackage([relay.url]));
      await m.session.acceptInvites();
    }
    for (const m of [alice, bob, carol]) await m.session.sync(g.groupId);
    return { alice, bob, carol, groupId: g.groupId };
  }

  const read = async (m: Member, groupId: string) => (await m.session.sync(groupId).catch(() => [])).map((x) => x.content);
  const close = (...ms: Member[]) => ms.forEach((m) => m.session.close());

  it('a message sent without network is kept and goes out once the network is back', async () => {
    const { alice, bob, carol, groupId } = await trio('mensaje');
    alice.net.mode = 'down';
    const sent = await alice.session.send(groupId, 'sin red');
    expect(sent.pending).toBe(true);
    const [op] = await alice.session.pendingOperations(groupId);
    expect(op).toMatchObject({ groupId, type: 'message', rumorId: sent.rumorId, attempts: 1 });
    expect(op!.lastError).toContain('offline');
    expect((await alice.session.group(groupId)).pending).toHaveLength(1);
    // Still down: retrying keeps it (and the same ciphertext: no key is used up for nothing).
    expect(await alice.session.retryPending()).toHaveLength(1);
    expect(new Set(alice.net.refused.map((e) => e.id)).size).toBe(1);
    alice.net.mode = 'up';
    expect(await alice.session.retryPending()).toEqual([]);
    expect(alice.net.published.map((e) => e.id)).toContain(alice.net.refused[0]!.id);
    expect(await read(bob, groupId)).toEqual(['sin red']);
    expect(await read(carol, groupId)).toEqual(['sin red']);
    close(alice, bob, carol);
  }, 120_000);

  it('a message kept while the group moved to another epoch is encrypted again for the new one', async () => {
    const { alice, bob, carol, groupId } = await trio('epoca');
    alice.net.mode = 'down';
    expect((await alice.session.send(groupId, 'tarde')).pending).toBe(true);
    // Meanwhile Bob rotates his keys: a commit Alice has not seen. Members in the new epoch cannot read the old ciphertext.
    const before = (await bob.session.group(groupId)).epoch;
    expect((await bob.session.rotate(groupId)).epoch).toBe(before + 1);
    alice.net.mode = 'up';
    expect(await alice.session.retryPending()).toEqual([]);
    expect(alice.net.published.map((e) => e.id)).not.toContain(alice.net.refused[0]!.id);
    expect((await alice.session.group(groupId)).epoch).toBe(before + 1);
    expect(await read(bob, groupId)).toEqual(['tarde']);
    expect(await read(carol, groupId)).toEqual(['tarde']);
    close(alice, bob, carol);
  }, 120_000);

  it('a removal without network waits, is not kept twice, and is committed once the network is back', async () => {
    const { alice, bob, carol, groupId } = await trio('expulsion');
    const epoch = (await alice.session.group(groupId)).epoch;
    alice.net.mode = 'down';
    const h = await alice.session.removeMember(groupId, carol.session.pubkey);
    expect(h.members).toContain(carol.session.pubkey);
    expect(h.epoch).toBe(epoch);
    expect(h.pending).toMatchObject([{ type: 'remove', target: carol.session.pubkey }]);
    // The admin asks again (or a worker retries): still one operation.
    await alice.session.removeMember(groupId, carol.session.pubkey);
    // The network is back, but no sync yet: a message written after the removal waits behind it, since Carol must
    // never read it (only a sync can tell whether the removal is already on a relay).
    alice.net.mode = 'up';
    expect((await alice.session.send(groupId, 'sin carol')).pending).toBe(true);
    expect((await alice.session.pendingOperations(groupId)).map((o) => o.type)).toEqual(['remove', 'message']);
    expect(await alice.session.retryPending()).toEqual([]);
    const after = await alice.session.group(groupId);
    expect(after.members).not.toContain(carol.session.pubkey);
    expect(after.epoch).toBe(epoch + 1);
    expect(await read(bob, groupId)).toEqual(['sin carol']);
    expect(await read(carol, groupId)).not.toContain('sin carol');
    close(alice, bob, carol);
  }, 120_000);

  it('a commit a relay stored without its OK arriving is applied by the next sync, not made again', async () => {
    const { alice, bob, carol, groupId } = await trio('ok-perdido');
    const epoch = (await alice.session.group(groupId)).epoch;
    alice.net.mode = 'lost-ok';
    expect((await alice.session.removeMember(groupId, carol.session.pubkey)).pending).toHaveLength(1);
    alice.net.mode = 'up';
    // Bob already applies it: it is on the relay.
    await bob.session.sync(groupId);
    expect((await bob.session.group(groupId)).epoch).toBe(epoch + 1);
    // A restart in between: the commit and the state it leads to were kept with the group state.
    await alice.reopen();
    const commitsBefore = alice.net.published.length;
    expect(await alice.session.retryPending()).toEqual([]);
    expect(alice.net.published.length).toBe(commitsBefore); // nothing published again
    const after = await alice.session.group(groupId);
    expect(after.epoch).toBe(epoch + 1);
    expect(after.members).not.toContain(carol.session.pubkey);
    // Same epoch as Bob's, not a fork: he reads her.
    expect((await alice.session.send(groupId, 'misma época')).pending).toBeUndefined();
    expect(await read(bob, groupId)).toEqual(['misma época']);
    close(alice, bob, carol);
  }, 120_000);

  it('if another commit takes the epoch first, the pending one is built again on top of it', async () => {
    const { alice, bob, carol, groupId } = await trio('carrera');
    const epoch = (await alice.session.group(groupId)).epoch;
    alice.net.mode = 'down';
    await alice.session.removeMember(groupId, carol.session.pubkey);
    await bob.session.rotate(groupId); // epoch + 1, while Alice's removal waits
    alice.net.mode = 'up';
    expect(await alice.session.retryPending()).toEqual([]);
    const after = await alice.session.group(groupId);
    expect(after.epoch).toBe(epoch + 2);
    expect(after.members).not.toContain(carol.session.pubkey);
    await bob.session.sync(groupId);
    expect((await bob.session.group(groupId)).epoch).toBe(epoch + 2);
    await alice.session.send(groupId, 'después de la carrera');
    expect(await read(bob, groupId)).toEqual(['después de la carrera']);
    expect(await read(carol, groupId)).not.toContain('después de la carrera');
    close(alice, bob, carol);
  }, 120_000);

  it('when a commit of ours that lost its OK races another one, this device applies the one the members apply', async () => {
    const { alice, bob, carol, groupId } = await trio('carrera-con-ok-perdido');
    const dave = await member('dave');
    await alice.session.invite(groupId, await dave.session.publishKeyPackage([relay.url]));
    await dave.session.acceptInvites();
    for (const m of [alice, bob, carol, dave]) await m.session.sync(groupId);
    alice.net.mode = 'lost-ok';
    await alice.session.removeMember(groupId, carol.session.pubkey); // on the relay, unconfirmed
    alice.net.mode = 'up';
    // A second later Bob, who has not seen it, commits in the same epoch: MIP-03 puts the earlier one first.
    await new Promise((r) => setTimeout(r, 1100));
    bob.net.mode = 'blind';
    await bob.session.rotate(groupId);
    bob.net.mode = 'up';
    await dave.session.sync(groupId); // Dave, who saw both, applies Alice's
    expect((await dave.session.group(groupId)).members).not.toContain(carol.session.pubkey);
    expect(await alice.session.retryPending()).toEqual([]);
    expect((await alice.session.group(groupId)).members).not.toContain(carol.session.pubkey);
    await alice.session.send(groupId, 'la misma época que dave');
    expect(await read(dave, groupId)).toEqual(['la misma época que dave']);
    close(alice, bob, carol, dave);
  }, 180_000);

  it('an invitation whose Welcome found no relay is sent again: the member added can join', async () => {
    const { alice, bob, carol, groupId } = await trio('bienvenida');
    const dave = await member('dave');
    const kp = await dave.session.publishKeyPackage([relay.url]);
    alice.net.mode = 'no-welcome';
    const h = await alice.session.invite(groupId, kp);
    expect(h.members).toContain(dave.session.pubkey); // the commit went out
    expect(h.pending).toMatchObject([{ type: 'welcome', target: dave.session.pubkey }]);
    expect(await dave.session.acceptInvites()).toEqual([]);
    alice.net.mode = 'up';
    expect(await alice.session.retryPending()).toEqual([]);
    expect((await dave.session.acceptInvites()).map((g) => g.groupId)).toEqual([groupId]);
    await alice.session.send(groupId, 'hola dave');
    expect(await read(dave, groupId)).toContain('hola dave');
    close(alice, bob, carol, dave);
  }, 120_000);

  it('what every relay refuses for good is not kept: it fails at once, or is shown as failed until discarded', async () => {
    const { alice, bob, carol, groupId } = await trio('rechazo');
    alice.net.mode = 'refuse';
    await expect(alice.session.send(groupId, 'rechazado')).rejects.toThrow(/restricted: not allowed here/);
    expect(await alice.session.pendingOperations()).toEqual([]);
    // Written without network, then refused when it could go out: kept as failed, not retried.
    alice.net.mode = 'down';
    await alice.session.send(groupId, 'luego rechazado');
    alice.net.mode = 'refuse';
    const [failed] = await alice.session.retryPending();
    expect(failed!.failed).toMatch(/restricted/);
    const attempts = failed!.attempts;
    alice.net.mode = 'up';
    expect((await alice.session.retryPending())[0]!.attempts).toBe(attempts);
    await alice.session.discardPending(failed!.id);
    expect(await alice.session.pendingOperations()).toEqual([]);
    close(alice, bob, carol);
  }, 120_000);
});
