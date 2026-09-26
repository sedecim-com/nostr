import { describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { createGroupEvent, deriveMediaEncryptionKey } from '@internet-privacy/marmot-ts';
import { createCommit, defaultProposalTypes, unsafeTestingAuthenticationService } from 'ts-mls';
import { generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import {
  MarmotTsProvider,
  MediaKeyUnavailableError,
  MemoryGroupNetwork,
  NotGroupAdminError,
  PendingProposalsError,
  RestoredGroupStateError,
  VolatileGroupStorage,
  buildMediaImetaTag,
  ciphertextHashFromUrl,
  deriveMediaFileKey,
  isExtendedGroupSession,
  parseMediaImeta,
  type ExtendedGroupSession,
} from '../src/index';

const RELAYS = ['wss://relay.invalid'];
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

function world() {
  const network = new MemoryGroupNetwork();
  const provider = new MarmotTsProvider();
  const open = async (signer: LocalSigner, deviceId: string, opts: { storage?: VolatileGroupStorage; label?: string; clonedState?: boolean } = {}) => {
    const storage = opts.storage ?? new VolatileGroupStorage();
    const s = await provider.openSession({ signer, network, storage, deviceId, ...(opts.label ? { deviceLabel: opts.label } : {}), ...(opts.clonedState ? { clonedState: true } : {}) });
    return { s, storage };
  };
  const persona = () => new LocalSigner(generateSecretKey());
  return { network, open, persona };
}

const contents = async (s: ExtendedGroupSession, gid: string) => (await s.sync(gid)).map((m) => m.content);
/** Internal MarmotGroup of a session (to forge messages marmot-ts itself would refuse to send). */
const internalGroup = (s: ExtendedGroupSession, gid: string) => (s as unknown as { client: { groups: { get(id: string): Promise<any> } } }).client.groups.get(gid);

describe('multi-device personas (FR025-06)', () => {
  it('a persona with two devices participates in the same group; a third device is added later; removal drops every leaf', async () => {
    const w = world();
    const [alice, bob] = [w.persona(), w.persona()];
    const { s: a } = await w.open(alice, 'alice-desk');
    const { s: b1 } = await w.open(bob, 'bob-phone', { label: 'Móvil' });
    const { s: b2 } = await w.open(bob, 'bob-laptop', { label: 'Portátil' });
    expect(isExtendedGroupSession(a)).toBe(true);
    await b1.publishKeyPackage(RELAYS);
    await b2.publishKeyPackage(RELAYS);

    const g = await a.createGroup({ name: 'redacción', relays: RELAYS });
    expect((await a.findKeyPackages(b1.pubkey, RELAYS)).length).toBe(2);
    const inv = await a.invitePersona(g.groupId, b1.pubkey, RELAYS);
    expect(inv.devices!.filter((d) => d.pubkey === b1.pubkey)).toHaveLength(2);
    expect(inv.members.sort()).toEqual([a.pubkey, b1.pubkey].sort());

    expect((await b1.acceptInvites()).map((x) => x.groupId)).toEqual([g.groupId]);
    expect((await b2.acceptInvites()).map((x) => x.groupId)).toEqual([g.groupId]);

    await a.send(g.groupId, 'hola bob');
    expect(await contents(b1, g.groupId)).toContain('hola bob');
    expect(await contents(b2, g.groupId)).toContain('hola bob');

    await b1.send(g.groupId, 'desde el móvil');
    const onLaptop = await b2.sync(g.groupId);
    expect(onLaptop.find((m) => m.content === 'desde el móvil')).toMatchObject({ sender: b1.pubkey, epoch: expect.any(Number) });
    expect(await contents(a, g.groupId)).toContain('desde el móvil');

    // Devices announced themselves inside the group (labels never leave MLS).
    const devs = await a.devices(g.groupId);
    expect(devs.filter((d) => d.pubkey === b1.pubkey).map((d) => [d.deviceId, d.label]).sort()).toEqual([
      ['bob-laptop', 'Portátil'],
      ['bob-phone', 'Móvil'],
    ]);
    expect(devs.find((d) => d.self)).toMatchObject({ pubkey: a.pubkey, deviceId: 'alice-desk' });

    // A third device: only its key package is missing (the others rotated theirs after joining).
    const { s: b3 } = await w.open(bob, 'bob-tablet');
    const tabletKp = await b3.publishKeyPackage(RELAYS);
    const missing = await a.missingDeviceKeyPackages(g.groupId, b1.pubkey, RELAYS);
    expect(missing).toHaveLength(1);
    // The `d` slot is a random 64-hex value per device (MDK requirement), never the device id.
    const slot = missing[0]!.tags.find((t) => t[0] === 'd')?.[1];
    expect(slot).toMatch(/^[0-9a-f]{64}$/);
    expect(slot).toBe(tabletKp.tags.find((t) => t[0] === 'd')?.[1]);
    const withTablet = await a.invitePersona(g.groupId, b1.pubkey, RELAYS);
    expect(withTablet.devices!.filter((d) => d.pubkey === b1.pubkey)).toHaveLength(3);
    await expect(a.invitePersona(g.groupId, b1.pubkey, RELAYS)).rejects.toThrow(/already in the group/);
    expect((await b3.acceptInvites()).map((x) => x.groupId)).toEqual([g.groupId]);
    // Devices already in the group ignore the Welcome meant for the new one.
    expect(await b1.acceptInvites()).toEqual([]);
    await b1.sync(g.groupId);
    await b2.sync(g.groupId);
    await a.send(g.groupId, 'tres dispositivos');
    for (const s of [b1, b2, b3]) expect(await contents(s, g.groupId)).toContain('tres dispositivos');

    // Removing the persona removes all its leaves.
    const after = await a.removeMember(g.groupId, b1.pubkey);
    expect(after.members).toEqual([a.pubkey]);
    expect(after.devices).toHaveLength(1);
    await a.send(g.groupId, 'bob ya no está');
    for (const s of [b1, b2, b3]) expect(await s.sync(g.groupId).then((m) => m.map((x) => x.content), () => [])).not.toContain('bob ya no está');
  }, 60_000);

  it('an admin removes a single device (leaf) and keeps the rest of the persona', async () => {
    const w = world();
    const [alice, bob] = [w.persona(), w.persona()];
    const { s: a } = await w.open(alice, 'a');
    const { s: b1 } = await w.open(bob, 'b1');
    const { s: b2 } = await w.open(bob, 'b2');
    await b1.publishKeyPackage(RELAYS);
    await b2.publishKeyPackage(RELAYS);
    const g = await a.createGroup({ name: 'g', relays: RELAYS });
    await a.invitePersona(g.groupId, b1.pubkey, RELAYS);
    await b1.acceptInvites();
    await b2.acceptInvites();
    await a.sync(g.groupId);
    const lost = (await a.devices(g.groupId)).find((d) => d.deviceId === 'b2')!;
    const h = await a.removeDevice(g.groupId, lost.leafIndex);
    expect(h.members.sort()).toEqual([a.pubkey, b1.pubkey].sort());
    expect(h.devices!.map((d) => d.deviceId).sort()).toEqual(['a', 'b1']);
    await a.send(g.groupId, 'sin el portátil perdido');
    expect(await contents(b1, g.groupId)).toContain('sin el portátil perdido');
    expect(await b2.sync(g.groupId).then((m) => m.map((x) => x.content), () => [])).not.toContain('sin el portátil perdido');
  }, 60_000);
});

describe('backup restore never clones a leaf (FR025-06)', () => {
  it('admin: the restored device joins as a new leaf and the cloned leaf is removed', async () => {
    const w = world();
    const [alice, bob] = [w.persona(), w.persona()];
    const { s: a, storage } = await w.open(alice, 'alice-old');
    const { s: b } = await w.open(bob, 'bob');
    await b.publishKeyPackage(RELAYS);
    const g = await a.createGroup({ name: 'g', relays: RELAYS });
    await a.invite(g.groupId, (await b.findKeyPackage(b.pubkey, RELAYS))!);
    await b.acceptInvites();

    const { s: restored } = await w.open(alice, 'alice-new', { storage: storage.clone() });
    expect(await restored.restoredGroups()).toEqual([g.groupId]);
    expect((await restored.group(g.groupId)).restored).toBe(true);
    await expect(restored.send(g.groupId, 'con la hoja clonada')).rejects.toBeInstanceOf(RestoredGroupStateError);
    await expect(restored.rotate(g.groupId)).rejects.toBeInstanceOf(RestoredGroupStateError);

    const r = await restored.rejoin(g.groupId, RELAYS);
    expect(r.status).toBe('joined');
    expect(r.group.restored).toBeUndefined();
    const aliceLeaves = r.group.devices!.filter((d) => d.pubkey === a.pubkey);
    expect(aliceLeaves).toHaveLength(1);
    expect(aliceLeaves[0]).toMatchObject({ self: true, deviceId: 'alice-new' });
    expect(await restored.restoredGroups()).toEqual([]);

    await b.sync(g.groupId);
    await b.send(g.groupId, 'hola dispositivo restaurado');
    expect(await contents(restored, g.groupId)).toContain('hola dispositivo restaurado');
    await restored.send(g.groupId, 'ya con hoja propia');
    expect(await contents(b, g.groupId)).toContain('ya con hoja propia');
    // The source device's leaf is gone: it cannot read the new epoch any more.
    expect(await a.sync(g.groupId).then((m) => m.map((x) => x.content), () => [])).not.toContain('ya con hoja propia');
  }, 60_000);

  it('non-admin: the cloned leaf proposes Add(new leaf) + Remove(itself) and the admin commits', async () => {
    const w = world();
    const [alice, bob] = [w.persona(), w.persona()];
    const { s: a } = await w.open(alice, 'alice');
    const { s: b, storage } = await w.open(bob, 'bob-old');
    await b.publishKeyPackage(RELAYS);
    const g = await a.createGroup({ name: 'g', relays: RELAYS });
    await a.invite(g.groupId, (await a.findKeyPackage(b.pubkey, RELAYS))!);
    await b.acceptInvites();

    const { s: restored } = await w.open(bob, 'bob-new', { storage: storage.clone() });
    const first = await restored.rejoin(g.groupId, RELAYS);
    expect(first.status).toBe('pending');
    await a.sync(g.groupId);
    const pending = await a.pendingProposals(g.groupId);
    expect(pending.map((p) => p.type).sort()).toEqual(['add', 'remove']);
    expect(pending.every((p) => p.admissible && p.proposer === b.pubkey)).toBe(true);
    await a.commitProposals(g.groupId);
    const second = await restored.rejoin(g.groupId, RELAYS);
    expect(second.status).toBe('joined');
    expect(second.group.devices!.filter((d) => d.pubkey === b.pubkey)).toEqual([expect.objectContaining({ self: true, deviceId: 'bob-new' })]);
    await a.send(g.groupId, 'bienvenido de nuevo');
    expect(await contents(restored, g.groupId)).toContain('bienvenido de nuevo');
    expect(await b.sync(g.groupId).then((m) => m.map((x) => x.content), () => [])).not.toContain('bienvenido de nuevo');
  }, 60_000);

  it('older backups without an owner record are treated as restored when the caller says so', async () => {
    const w = world();
    const alice = w.persona();
    const { s: a, storage } = await w.open(alice, 'x');
    const g = await a.createGroup({ name: 'g', relays: RELAYS });
    const copy = storage.clone();
    await copy.delete('device', 'owner');
    const { s: legacy } = await w.open(alice, 'y', { storage: copy.clone() });
    expect(await legacy.restoredGroups()).toEqual([]); // cannot tell without the hint (documented gap)
    const { s: hinted } = await w.open(alice, 'z', { storage: copy.clone(), clonedState: true });
    expect(await hinted.restoredGroups()).toEqual([g.groupId]);
  });
});

describe('proposals by non-admin members, commits by the admin (FR025-09)', () => {
  async function trio() {
    const w = world();
    const [alice, bob, carol, dave] = [w.persona(), w.persona(), w.persona(), w.persona()];
    const { s: a } = await w.open(alice, 'a');
    const { s: b } = await w.open(bob, 'b');
    const { s: c } = await w.open(carol, 'c');
    const { s: d } = await w.open(dave, 'd');
    for (const s of [b, c, d]) await s.publishKeyPackage(RELAYS);
    const g = await a.createGroup({ name: 'g', relays: RELAYS });
    await a.invite(g.groupId, (await a.findKeyPackage(b.pubkey, RELAYS))!);
    await b.acceptInvites();
    return { w, a, b, c, d, g };
  }

  it('a member proposes, the admin commits; members cannot commit', async () => {
    const { a, b, c, g } = await trio();
    const kpC = (await b.findKeyPackages(c.pubkey, RELAYS))[0]!;
    const proposed = await b.proposeAdd(g.groupId, [kpC]);
    expect(proposed).toEqual([expect.objectContaining({ type: 'add', proposer: b.pubkey, target: c.pubkey, admissible: true })]);
    await expect(b.send(g.groupId, 'bloqueado')).rejects.toBeInstanceOf(PendingProposalsError);
    await expect(b.commitProposals(g.groupId)).rejects.toBeInstanceOf(NotGroupAdminError);
    await expect(b.invite(g.groupId, kpC)).rejects.toBeInstanceOf(NotGroupAdminError);

    const report = await a.syncWithReport(g.groupId);
    expect(report.proposals).toBe(1);
    expect((await a.pendingProposals(g.groupId)).map((p) => p.ref)).toEqual(proposed.map((p) => p.ref));
    const h = await a.commitProposals(g.groupId);
    expect(h.members.sort()).toEqual([a.pubkey, b.pubkey, c.pubkey].sort());
    expect(h.pendingProposals).toBe(0);
    expect((await c.acceptInvites()).map((x) => x.groupId)).toEqual([g.groupId]);
    expect((await b.syncWithReport(g.groupId)).commits).toBe(1);
    await b.send(g.groupId, 'carol ya está');
    expect(await contents(c, g.groupId)).toContain('carol ya está');

    // Removing someone else is only committed explicitly; proposals against an admin are never admissible.
    await b.proposeRemove(g.groupId, { pubkey: a.pubkey });
    await a.sync(g.groupId);
    expect((await a.pendingProposals(g.groupId))[0]).toMatchObject({ type: 'remove', target: a.pubkey, admissible: false });
    await expect(a.commitProposals(g.groupId)).rejects.toThrow(/no admissible/);
    await a.rotate(g.groupId); // self-update drops the pending proposal (it becomes stale)
    expect((await b.group(g.groupId)).members).toContain(a.pubkey);
    await b.proposeRemove(g.groupId, { pubkey: c.pubkey });
    await a.sync(g.groupId);
    const [rm] = await a.pendingProposals(g.groupId);
    expect(rm).toMatchObject({ type: 'remove', target: c.pubkey, admissible: true });
    expect((await a.commitProposals(g.groupId, { refs: [rm!.ref] })).members).not.toContain(c.pubkey);
  }, 60_000);

  it('commits from non-admins are rejected by every member (MIP-03)', async () => {
    const { w, a, b, d, g } = await trio();
    const before = await a.group(g.groupId);
    const bg = await internalGroup(b, g.groupId);
    await expect(bg.commit({ extraProposals: [] })).rejects.toThrow(/Not a group admin/);
    // Forge the commit marmot-ts refuses to build: Bob adds Dave by himself.
    const kpD = (await b.findKeyPackages(d.pubkey, RELAYS))[0]!;
    const { getKeyPackage } = await import('@internet-privacy/marmot-ts');
    const { commit } = await createCommit({
      context: { cipherSuite: bg.ciphersuite, authService: unsafeTestingAuthenticationService },
      state: bg.state,
      wireAsPublicMessage: false,
      ratchetTreeExtension: true,
      extraProposals: [{ proposalType: defaultProposalTypes.add, add: { keyPackage: getKeyPackage(kpD as never) } } as never],
    });
    await w.network.publish(RELAYS, (await createGroupEvent({ message: commit, state: bg.state, ciphersuite: bg.ciphersuite })) as never);
    const report = await a.syncWithReport(g.groupId);
    expect(report.rejectedCommits).toBe(1);
    const after = await a.group(g.groupId);
    expect(after.epoch).toBe(before.epoch);
    expect(after.members).not.toContain(d.pubkey);
    await a.send(g.groupId, 'sigo en la misma época');
    expect(await contents(b, g.groupId)).toContain('sigo en la misma época');
  }, 60_000);

  it('stale proposals across epochs are not committed and must be sent again', async () => {
    const { a, b, c, g } = await trio();
    const kpC = (await b.findKeyPackages(c.pubkey, RELAYS))[0]!;
    await b.proposeAdd(g.groupId, [kpC]);
    const epoch = (await a.group(g.groupId)).epoch;
    // The admin moves the group to a new epoch without committing the proposal.
    expect((await a.rotate(g.groupId)).epoch).toBe(epoch + 1);
    await expect(a.commitProposals(g.groupId)).rejects.toThrow(/no pending proposals/);
    await b.sync(g.groupId);
    expect(await b.pendingProposals(g.groupId)).toEqual([]);
    expect((await b.group(g.groupId)).members).not.toContain(c.pubkey);
    expect(await c.acceptInvites()).toEqual([]);
    // Re-proposed in the new epoch, it goes through.
    await b.proposeAdd(g.groupId, [(await b.findKeyPackages(c.pubkey, RELAYS))[0]!]);
    expect((await a.commitProposals(g.groupId)).members).toContain(c.pubkey);
    expect((await c.acceptInvites()).map((x) => x.groupId)).toEqual([g.groupId]);
  }, 60_000);
});

describe('MIP-04 encrypted media in groups (FR025-05)', () => {
  it('uploads and downloads media with keys derived from the MLS exporter; removed members cannot decrypt newer media', async () => {
    const w = world();
    const [alice, bob, carol] = [w.persona(), w.persona(), w.persona()];
    const { s: a } = await w.open(alice, 'a');
    const { s: b } = await w.open(bob, 'b');
    const { s: c } = await w.open(carol, 'c');
    await b.publishKeyPackage(RELAYS);
    await c.publishKeyPackage(RELAYS);
    const g = await a.createGroup({ name: 'g', relays: RELAYS });
    await a.inviteMany(g.groupId, [(await a.findKeyPackage(b.pubkey, RELAYS))!, (await a.findKeyPackage(c.pubkey, RELAYS))!]);
    await b.acceptInvites();
    await c.acceptInvites();

    const blobs = new Map<string, Uint8Array>();
    const upload = async (ct: Uint8Array, hash: string) => {
      expect(hex(sha256(ct))).toBe(hash);
      blobs.set(hash, ct);
      return { url: `https://blossom.invalid/${hash}` };
    };
    const fetchBlob = (url: string) => blobs.get(ciphertextHashFromUrl(url)!)!;
    const photo = new TextEncoder().encode('JPEG… foto de la manifestación');
    const ref1 = await a.sendMedia(g.groupId, { data: photo, filename: 'foto.jpg', type: 'Image/JPEG; q=1' }, upload, 'mirad');

    // The key is MIP-04's: equals marmot-ts' derivation from the live MLS state.
    const ag = await internalGroup(a, g.groupId);
    const live = await deriveMediaEncryptionKey(ag.state, ag.ciphersuite, ref1.attachment as never);
    const { exportMediaSecret } = await import('../src/media');
    expect(hex(deriveMediaFileKey(await exportMediaSecret(ag.state, ag.ciphersuite), ref1.attachment))).toBe(hex(live));

    const [msg] = await b.sync(g.groupId);
    expect(msg).toMatchObject({ content: 'mirad', epoch: ref1.epoch });
    const imeta = msg!.tags!.find((t) => t[0] === 'imeta')!;
    expect(imeta.map((e) => e.split(' ')[0])).toEqual(['imeta', 'url', 'm', 'x', 'filename', 'n', 'v', 'size']);
    expect(msg!.media).toEqual([expect.objectContaining({ type: 'image/jpeg', filename: 'foto.jpg', version: 'mip04-v2', sha256: hex(sha256(photo)) })]);
    const att = msg!.media![0]!;
    expect(new TextDecoder().decode(await b.decryptMedia(g.groupId, fetchBlob(att.url!), att, msg!.epoch!))).toBe('JPEG… foto de la manifestación');
    expect(await b.mediaReference(g.groupId, att.sha256)).toMatchObject({ epoch: ref1.epoch, sender: a.pubkey });
    // Tampering is detected (AEAD), and a relay/server only ever sees ciphertext.
    const bad = fetchBlob(att.url!).slice();
    bad[0]! ^= 1;
    await expect(b.decryptMedia(g.groupId, bad, att, msg!.epoch!)).rejects.toThrow();
    expect(Buffer.from(fetchBlob(att.url!)).includes(Buffer.from('manifestación'))).toBe(false);

    // Carol is removed; newer media is encrypted under an epoch she never reaches.
    await a.removeMember(g.groupId, c.pubkey);
    const ref2 = await a.sendMedia(g.groupId, { data: new TextEncoder().encode('segunda foto'), filename: 'b.png', type: 'image/png' }, upload);
    expect(ref2.epoch).toBeGreaterThan(ref1.epoch);
    await c.sync(g.groupId).catch(() => []);
    await expect(c.decryptMedia(g.groupId, fetchBlob(ref2.attachment.url!), ref2.attachment, ref2.epoch)).rejects.toBeInstanceOf(MediaKeyUnavailableError);
    // Remaining members decrypt new media, and still old media (past-epoch media secrets are retained).
    await b.sync(g.groupId);
    expect(new TextDecoder().decode(await b.decryptMedia(g.groupId, fetchBlob(ref2.attachment.url!), ref2.attachment, ref2.epoch))).toBe('segunda foto');
    expect(new TextDecoder().decode(await b.decryptMedia(g.groupId, fetchBlob(att.url!), att, ref1.epoch))).toContain('manifestación');
  }, 60_000);

  it('imeta round trip and rejection of malformed / v1 tags', () => {
    const a = { url: 'https://s.invalid/' + 'ab'.repeat(32), sha256: 'cd'.repeat(32), type: 'image/png', filename: 'x y.png', nonce: '00'.repeat(12), version: 'mip04-v2', size: 3 };
    expect(parseMediaImeta(buildMediaImetaTag(a))).toEqual(a);
    expect(parseMediaImeta(buildMediaImetaTag({ ...a, version: 'mip04-v1' }))).toBeUndefined();
    expect(parseMediaImeta(buildMediaImetaTag({ ...a, nonce: 'zz' }))).toBeUndefined();
    expect(ciphertextHashFromUrl(a.url)).toBe('ab'.repeat(32));
    expect(ciphertextHashFromUrl('https://s.invalid/nothash')).toBeUndefined();
  });
});
