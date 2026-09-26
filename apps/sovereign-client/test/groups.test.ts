import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TestRelay, TestSocksServer } from '@sedecim/test-relay';
import { SovereignClient } from '../src/index';

const ONION = 'marmotgroupsrelayabcdefghijklmnopqrstuvwxyz234567abcdefgh.onion';

describe('sovereign client — Marmot/MLS high-security groups (FR-025)', () => {
  const relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  const onion = new TestRelay({ publicUrl: `ws://${ONION}`, pGatedKinds: [1059] });
  let socks: TestSocksServer;
  let dir: string;
  let client: SovereignClient;

  beforeAll(async () => {
    await relay.start();
    await onion.start();
    socks = new TestSocksServer({ [ONION]: { host: '127.0.0.1', port: onion.port } });
    await socks.start();
    dir = await mkdtemp(join(tmpdir(), 'sovereign-groups-'));
    client = new SovereignClient({ dataDir: dir, passphrase: 'pass', scryptLogN: 4, socksPort: socks.port });
  });
  afterAll(async () => {
    client.close();
    await socks.stop();
    await relay.stop();
    await onion.stop();
  });

  it('create → invite → join → message → remove → rotate over an authenticated, p-gated relay', async () => {
    const alice = await client.createPersona({ label: 'Alice', relays: [relay.url] });
    const bob = await client.createPersona({ label: 'Bob', relays: [relay.url] });
    const carol = await client.createPersona({ label: 'Carol', relays: [relay.url] });
    await client.groupPublishKeyPackage(bob.id);
    await client.groupPublishKeyPackage(carol.id);
    const g = await client.groupCreate(alice.id, 'Redacción');
    await client.groupInvite(alice.id, g.groupId, bob.pubkey);
    const inv = await client.groupInvite(alice.id, g.groupId, carol.pubkey);
    expect(inv.members.sort()).toEqual([alice.pubkey, bob.pubkey, carol.pubkey].sort());
    expect((await client.groupAccept(bob.id)).map((x) => x.groupId)).toEqual([g.groupId]);
    expect((await client.groupAccept(carol.id)).map((x) => x.groupId)).toEqual([g.groupId]);

    await client.groupSend(alice.id, g.groupId, 'hola equipo');
    expect((await client.groupSync(bob.id, g.groupId)).map((m) => m.content)).toContain('hola equipo');
    expect((await client.groupSync(carol.id, g.groupId)).map((m) => m.content)).toContain('hola equipo');

    await client.groupRemove(alice.id, g.groupId, bob.pubkey);
    await client.groupSend(alice.id, g.groupId, 'solo alice y carol');
    expect((await client.groupSync(carol.id, g.groupId)).map((m) => m.content)).toContain('solo alice y carol');
    const leaked = await client.groupSync(bob.id, g.groupId).catch(() => []);
    expect(leaked.map((m) => m.content)).not.toContain('solo alice y carol');

    const before = (await client.groupList(carol.id)).find((x) => x.groupId === g.groupId)!.epoch;
    expect((await client.groupRotate(carol.id, g.groupId)).epoch).toBeGreaterThan(before);
    await client.groupSend(carol.id, g.groupId, 'tras rotación');
    expect((await client.groupSync(alice.id, g.groupId)).map((m) => m.content)).toContain('tras rotación');

    for (const e of relay.events.values()) for (const p of ['hola equipo', 'solo alice y carol', 'tras rotación', 'Redacción']) expect(e.content).not.toContain(p);
  });

  it('MLS state on disk is encrypted and survives a restart', async () => {
    const files = await readdir(dir, { recursive: true });
    for (const f of files.filter((x) => String(x).includes('mls-'))) {
      const raw = await readFile(join(dir, String(f)), 'utf8').catch(() => '');
      expect(raw).not.toMatch(/Redacción|privatePackage|\$u8/);
    }
    const restarted = new SovereignClient({ dataDir: dir, passphrase: 'pass', scryptLogN: 4 });
    try {
      const alice = (await (await restarted.identities()).list()).find((p) => p.label === 'Alice')!;
      const [g] = await restarted.groupList(alice.id);
      expect(g!.name).toBe('Redacción');
      await restarted.groupSend(alice.id, g!.groupId, 'después del reinicio');
      const carol = (await (await restarted.identities()).list()).find((p) => p.label === 'Carol')!;
      expect((await restarted.groupSync(carol.id, g!.groupId)).map((m) => m.content)).toContain('después del reinicio');
    } finally {
      restarted.close();
    }
  });

  it('full backup restores relays, panel config and MLS group state on a clean device (FR027-02)', async () => {
    const alice = (await (await client.identities()).list()).find((p) => p.label === 'Alice')!;
    const pkg = await client.exportBackup(alice.id, 'backup-pass', { scryptLogN: 4 });
    expect(JSON.stringify(pkg)).not.toMatch(/Redacción|mls-|\$u8|127\.0\.0\.1/);
    const clean = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-restore-')), passphrase: 'otra-pass', scryptLogN: 4 });
    try {
      const restored = await clean.restoreBackup(JSON.parse(JSON.stringify(pkg)), 'backup-pass');
      expect(restored).toEqual(alice);
      expect(await (await clean.identities()).getConfig(alice.id)).toEqual(client.profileFor(alice));
      const [g] = await clean.groupList(alice.id);
      expect(g!.name).toBe('Redacción');
      await clean.groupSend(alice.id, g!.groupId, 'desde el backup');
      const carol = (await (await client.identities()).list()).find((p) => p.label === 'Carol')!;
      expect((await client.groupSync(carol.id, g!.groupId)).map((m) => m.content)).toContain('desde el backup');
    } finally {
      clean.close();
    }
  });

  it('Tor-only personas run groups over an onion relay via SOCKS only', async () => {
    const other = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-other-')), passphrase: 'p2', scryptLogN: 4, socksPort: socks.port });
    try {
      const a = await client.createPersona({ label: 'Fuente A', relays: [`ws://${ONION}`], highRisk: true });
      const b = await other.createPersona({ label: 'Fuente B', relays: [`ws://${ONION}`], highRisk: true });
      await other.groupPublishKeyPackage(b.id);
      const g = await client.groupCreate(a.id, 'celda');
      await client.groupInvite(a.id, g.groupId, b.pubkey);
      await other.groupAccept(b.id);
      await client.groupSend(a.id, g.groupId, 'por tor');
      expect((await other.groupSync(b.id, g.groupId)).map((m) => m.content)).toContain('por tor');
      expect(socks.requests.length).toBeGreaterThan(0);
      expect(socks.requests.every((r) => r.host === ONION && r.addressType === 'domain')).toBe(true);
      expect([...onion.events.values()].some((e) => e.kind === 445)).toBe(true);
    } finally {
      other.close();
    }
  });

  it('refuses to invite another of your own high-risk identities (compartmentation)', async () => {
    const x = await client.createPersona({ label: 'Riesgo X', relays: [`ws://${ONION}`], highRisk: true });
    const y = await client.createPersona({ label: 'Riesgo Y', relays: [`ws://${ONION}`], highRisk: true });
    const g = await client.groupCreate(x.id, 'aislado');
    await expect(client.groupInvite(x.id, g.groupId, y.pubkey)).rejects.toThrow(/compartimentación/);
  });
});
