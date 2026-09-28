import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { heicWithGps, TestBlossomServer, TestRelay, TestSocksServer, tinyPng } from '@sedecim/test-relay';
import { publishServerList, UnsanitizableFileError } from '@sedecim/blossom-client';
import { MediaKeyUnavailableError, type ExtendedGroupSession } from '@sedecim/marmot-adapter';
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

  it('full backup restores relays, panel config and MLS group state on a clean device, as a new leaf (FR027-02, FR025-06)', async () => {
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
      // The restored state is the source device's leaf: never used to send (cloned leaves break FS).
      expect(g!.restored).toBe(true);
      expect((await clean.device(alice.id)).id).not.toBe(alice.id);
      await expect(clean.groupSend(alice.id, g!.groupId, 'con la hoja clonada')).rejects.toThrow(/rejoin/);
      expect(await clean.groupRejoin(alice.id)).toEqual([{ groupId: g!.groupId, status: 'joined' }]);
      const after = (await clean.groupList(alice.id))[0]!;
      expect(after.restored).toBeUndefined();
      expect(after.devices!.filter((d) => d.pubkey === alice.pubkey)).toEqual([expect.objectContaining({ self: true })]);
      await clean.groupSend(alice.id, g!.groupId, 'desde el backup');
      const carol = (await (await client.identities()).list()).find((p) => p.label === 'Carol')!;
      expect((await client.groupSync(carol.id, g!.groupId)).map((m) => m.content)).toContain('desde el backup');
      // The source device's leaf was removed: it no longer reads the group.
      await client.groupSend(carol.id, g!.groupId, 'solo la hoja nueva');
      expect(await client.groupSync(alice.id, g!.groupId).then((m) => m.map((x) => x.content), () => [])).not.toContain('solo la hoja nueva');
      expect((await clean.groupSync(alice.id, g!.groupId)).map((m) => m.content)).toContain('solo la hoja nueva');
    } finally {
      clean.close();
    }
  });

  it('one persona on two (then three) devices in the same group; member proposes, admin commits (FR025-06/09)', async () => {
    const dana = await client.createPersona({ label: 'Dana', relays: [relay.url] });
    const erin = await client.createPersona({ label: 'Erin', relays: [relay.url] });
    // An additional device: key-only backup (no MLS state) imported on another installation.
    const keyOnly = await client.exportBackup(dana.id, 'pw', { scryptLogN: 4, includeMls: false });
    const second = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-dev2-')), passphrase: 'p2', scryptLogN: 4 });
    const third = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-dev3-')), passphrase: 'p3', scryptLogN: 4 });
    try {
      await second.restoreBackup(JSON.parse(JSON.stringify(keyOnly)), 'pw');
      await second.setDeviceLabel(dana.id, 'Portátil');
      expect((await second.device(dana.id)).id).not.toBe((await client.device(dana.id)).id);
      await client.groupPublishKeyPackage(dana.id);
      await second.groupPublishKeyPackage(dana.id);

      const g = await client.groupCreate(erin.id, 'multi');
      const inv = await client.groupInvite(erin.id, g.groupId, dana.pubkey);
      expect(inv.devices!.filter((d) => d.pubkey === dana.pubkey)).toHaveLength(2);
      expect((await client.groupAccept(dana.id)).map((x) => x.groupId)).toEqual([g.groupId]);
      expect((await second.groupAccept(dana.id)).map((x) => x.groupId)).toEqual([g.groupId]);

      await client.groupSend(erin.id, g.groupId, 'hola dana');
      expect((await client.groupSync(dana.id, g.groupId)).map((m) => m.content)).toContain('hola dana');
      expect((await second.groupSync(dana.id, g.groupId)).map((m) => m.content)).toContain('hola dana');
      await second.groupSend(dana.id, g.groupId, 'desde el portátil');
      const onFirst = await client.groupSync(dana.id, g.groupId);
      expect(onFirst.find((m) => m.content === 'desde el portátil')?.sender).toBe(dana.pubkey);
      expect((await client.groupDevices(erin.id, g.groupId)).find((d) => d.label === 'Portátil')?.pubkey).toBe(dana.pubkey);

      // A third device, requested by a non-admin device of Dana: proposal -> admin commit.
      await third.restoreBackup(JSON.parse(JSON.stringify(keyOnly)), 'pw');
      await third.groupPublishKeyPackage(dana.id);
      const req = await second.groupAddDevice(dana.id, g.groupId);
      expect(req.committed).toBe(false);
      await expect(second.groupCommit(dana.id, g.groupId)).rejects.toThrow(/admin/);
      const pending = await client.groupProposals(erin.id, g.groupId);
      expect(pending).toEqual([expect.objectContaining({ type: 'add', proposer: dana.pubkey, target: dana.pubkey, admissible: true })]);
      expect((await client.groupCommit(erin.id, g.groupId)).devices!.filter((d) => d.pubkey === dana.pubkey)).toHaveLength(3);
      expect((await third.groupAccept(dana.id)).map((x) => x.groupId)).toEqual([g.groupId]);
      await client.groupSend(erin.id, g.groupId, 'ya sois tres');
      expect((await third.groupSync(dana.id, g.groupId)).map((m) => m.content)).toContain('ya sois tres');
      expect((await second.groupSync(dana.id, g.groupId)).map((m) => m.content)).toContain('ya sois tres');

      // Removing the persona removes every device.
      expect((await client.groupRemove(erin.id, g.groupId, dana.pubkey)).devices).toHaveLength(1);
      await client.groupSend(erin.id, g.groupId, 'sin dana');
      for (const c of [client, second, third]) {
        expect(await c.groupSync(dana.id, g.groupId).then((m) => m.map((x) => x.content), () => [])).not.toContain('sin dana');
      }
    } finally {
      second.close();
      third.close();
    }
  });

  it('MIP-04: encrypted group media via the Blossom list (kind 10063) and the blob-store fallback (FR025-05)', async () => {
    const blossom = new TestBlossomServer();
    const blobStore = new TestBlossomServer();
    await blossom.start();
    await blobStore.start();
    const media = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-media-')), passphrase: 'pm', scryptLogN: 4, blobStore: blobStore.url });
    try {
      const fran = await media.createPersona({ label: 'Fran', relays: [relay.url] });
      const gus = await media.createPersona({ label: 'Gus', relays: [relay.url] });
      const hugo = await media.createPersona({ label: 'Hugo', relays: [relay.url] });
      const s = await media.session(fran.id);
      await s.pool.publish(await publishServerList(s.signer, [blossom.url]), [relay.url]);
      await media.groupPublishKeyPackage(gus.id);
      await media.groupPublishKeyPackage(hugo.id);
      const g = await media.groupCreate(fran.id, 'fotos');
      await media.groupInvite(fran.id, g.groupId, gus.pubkey);
      await media.groupInvite(fran.id, g.groupId, hugo.pubkey);
      await media.groupAccept(gus.id);
      await media.groupAccept(hugo.id);

      // A PNG with a tEXt chunk: its metadata is removed before encrypting (FR-019).
      const photo = tinyPng('acta de la asamblea');
      const sent = await media.groupSendFile(fran.id, g.groupId, { data: photo, filename: 'acta.png', mimeType: 'image/png', caption: 'el acta' });
      expect(sent.attachment.url!.startsWith(blossom.url)).toBe(true); // the user's server list comes first
      const [msg] = await media.groupSync(gus.id, g.groupId);
      expect(msg!.content).toBe('el acta');
      expect(msg!.media![0]).toMatchObject({ filename: 'acta.png', type: 'image/png', version: 'mip04-v2' });
      const got = await media.groupFetchFile(gus.id, g.groupId, msg!.media![0]!.sha256);
      expect(Buffer.from(got.data).equals(Buffer.from(tinyPng()))).toBe(true);
      for (const b of blossom.blobs.values()) expect(Buffer.from(b.data).includes(Buffer.from(tinyPng().subarray(8)))).toBe(false);

      // FR019-03: a HEIC with GPS cannot be cleaned, so it is refused before any upload, whatever its declared type.
      const stored = blossom.blobs.size + blobStore.blobs.size;
      await expect(media.groupSendFile(fran.id, g.groupId, { data: heicWithGps(), filename: 'IMG_0042.HEIC', mimeType: 'application/octet-stream' })).rejects.toBeInstanceOf(UnsanitizableFileError);
      expect(blossom.blobs.size + blobStore.blobs.size).toBe(stored);

      // Hugo is removed; the next file uses an epoch he never reaches. Gus has no list: blob-store fallback.
      await media.groupSync(hugo.id, g.groupId);
      await media.groupRemove(fran.id, g.groupId, hugo.pubkey);
      await media.groupSync(gus.id, g.groupId);
      const next = await media.groupSendFile(gus.id, g.groupId, { data: new TextEncoder().encode('segunda'), filename: 'b.txt', mimeType: 'text/plain' });
      expect(next.attachment.url!.startsWith(blobStore.url)).toBe(true);
      expect(new TextDecoder().decode((await media.groupFetchFile(fran.id, g.groupId, next.attachment.sha256)).data)).toBe('segunda');
      await expect(media.groupFetchFile(hugo.id, g.groupId, next.attachment.sha256)).rejects.toThrow();
      const hugoSession = (await media.groupSession(hugo.id)) as ExtendedGroupSession;
      const ct = blobStore.blobs.get(next.attachment.url!.split('/').pop()!)!.data;
      await expect(hugoSession.decryptMedia(g.groupId, ct, next.attachment, next.epoch)).rejects.toBeInstanceOf(MediaKeyUnavailableError);
    } finally {
      media.close();
      await blossom.stop();
      await blobStore.stop();
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
