/**
 * VAULT-03: a clean device rebuilds the persona's history from the Continuity Vault with nothing but its backup
 * (key and archive key, no MLS state, no ledger) while the relay has lost everything: the channel, the DMs in both
 * directions, the Marmot group conversation and the delivery ledger come back complete.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createContinuityVaultApi, MemoryArchiveRepository, MemoryObjectStore } from '@sedecim/continuity-vault';
import { createLogger } from '@sedecim/telemetry-policy';
import { TestRelay } from '@sedecim/test-relay';
import { SovereignClient } from '../src/index';

const silent = createLogger({ write: () => {} });

describe('restore from the Continuity Vault with empty relays (VAULT-03)', () => {
  let relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  const objects = new MemoryObjectStore();
  const vault = createContinuityVaultApi(new MemoryArchiveRepository(), objects, { name: 'vault-restore', logger: silent });
  let vaultUrl: string;
  const clients: SovereignClient[] = [];
  const newClient = async () => {
    const c = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'vault-restore-')), passphrase: 'pass', scryptLogN: 4, retry: { baseMs: 20, maxMs: 50 } });
    clients.push(c);
    return c;
  };

  beforeAll(async () => {
    await relay.start();
    vaultUrl = await vault.listen();
  });
  afterAll(async () => {
    for (const c of clients) c.close();
    await vault.close();
    await relay.stop();
  });

  it('channel, DMs both ways, the group conversation and the ledger come back 100 %', async () => {
    const a = await newClient();
    const alice = await a.createPersona({ label: 'Alice', relays: [relay.url] });
    const bob = await a.createPersona({ label: 'Bob', relays: [relay.url] });
    await a.publishDmRelays(alice.id);
    await a.publishDmRelays(bob.id);

    // The fixture: a channel, DMs in both directions, a Marmot group conversation.
    await a.sendChannel(alice.id, 'general', 'primer mensaje del canal');
    await a.sendChannel(bob.id, 'general', 'bob responde en el canal');
    await a.sendChannel(alice.id, 'general', 'alice cierra el hilo');
    await a.sendDm(alice.id, bob.pubkey, 'dm de alice a bob');
    await a.sendDm(bob.id, alice.pubkey, 'dm de bob a alice');
    await a.groupPublishKeyPackage(bob.id);
    const g = await a.groupCreate(alice.id, 'Redacción');
    await a.groupInvite(alice.id, g.groupId, bob.pubkey);
    expect((await a.groupAccept(bob.id)).map((x) => x.groupId)).toEqual([g.groupId]);
    await a.groupSend(alice.id, g.groupId, 'alice escribe al grupo');
    expect((await a.groupSync(bob.id, g.groupId)).map((m) => m.content)).toContain('alice escribe al grupo');
    await a.groupSend(bob.id, g.groupId, 'bob contesta al grupo');
    expect((await a.groupSync(alice.id, g.groupId)).map((m) => m.content)).toContain('bob contesta al grupo');

    // What Alice's history is, as the relay and this device know it before anything is lost.
    const before = await a.syncHistory(alice.id);
    const channel = before.channels['general']!.map((e) => e.id).sort();
    const dms = before.dms.map((m) => m.rumor.content).sort();
    // Same-second messages: compared as sets.
    const groupSet = (ms: Array<{ rumorId: string; sender: string; content: string }>) => ms.map((m) => `${m.rumorId} ${m.sender} ${m.content}`).sort();
    const group = groupSet(await a.groupHistory(alice.id, g.groupId));
    const ledger = (await a.outbox(alice.id)).map((r) => r.opId).sort();
    expect(channel).toHaveLength(3);
    expect(dms).toEqual(['dm de alice a bob', 'dm de bob a alice']);
    expect((await a.groupHistory(alice.id, g.groupId)).map((m) => m.content).sort()).toEqual(['alice escribe al grupo', 'bob contesta al grupo']);

    const pushed = await a.vaultPush(alice.id, vaultUrl);
    expect(pushed.groupMessages.uploaded).toBe(2);
    expect(pushed.snapshots).toEqual(['ledger', 'mls']);
    let held = '';
    for await (const k of objects.list()) held += new TextDecoder().decode((await objects.get(k))!);
    for (const t of ['primer mensaje', 'dm de alice', 'alice escribe al grupo', alice.pubkey, 'Redacción']) expect(held).not.toContain(t);

    // A backup with the key and the archive key only (no MLS state, no ledger), then the relay loses everything.
    const pkg = await (await a.identities()).exportBackup(alice.id, 'contraseña del backup', { keyPassphrase: 'pass', scryptLogN: 4, includeMls: false, includeOutbox: false });
    const port = relay.port;
    await relay.stop();
    relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059], port });
    await relay.start();
    expect(relay.received).toHaveLength(0);

    const c = await newClient();
    await c.restoreBackup(pkg, 'contraseña del backup');
    expect(await c.groupHistory(alice.id)).toEqual([]);
    const restored = await c.vaultRestore(alice.id, vaultUrl);
    expect(restored).toMatchObject({ skipped: 0, rejected: 0, groupMessages: 2, mls: 'restored', missing: 0 });
    expect(restored.published).toBe(restored.events);
    expect(restored.ledger).toBe(ledger.length);

    // 100 % of the fixture, read back as any client would: from the (refilled) relay and this device.
    const after = await c.syncHistory(alice.id);
    expect(after.channels['general']!.map((e) => e.id).sort()).toEqual(channel);
    expect(after.dms.map((m) => m.rumor.content).sort()).toEqual(dms);
    expect(groupSet(await c.groupHistory(alice.id, g.groupId))).toEqual(group);
    expect((await c.outbox(alice.id)).map((r) => r.opId).sort()).toEqual(expect.arrayContaining(ledger));

    // The group is back, but as a copy of the other device's leaf: it must rejoin before sending (FR025-06).
    expect((await c.groupList(alice.id)).map((x) => x.groupId)).toEqual([g.groupId]);
    await expect(c.groupSend(alice.id, g.groupId, 'desde la copia')).rejects.toThrow(/rejoin|restor/i);

    // Restoring again adds nothing twice.
    const again = await c.vaultRestore(alice.id, vaultUrl, { republish: false });
    expect(again).toMatchObject({ published: 0, ledger: 0, mls: 'kept' });
    expect(await c.groupHistory(alice.id, g.groupId)).toHaveLength(2);
  }, 120_000);
});
