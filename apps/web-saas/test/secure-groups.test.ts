/**
 * FR025-14: «Grupos seguros» in the web does what only the sovereign client did (several devices per persona, key
 * rotation, proposals and encrypted files), through the same functions the view calls (src/lib/groups.ts), with the
 * real Marmot adapter, per-browser vaults and in-process relays and Blossom servers. The secure relay behaves like the
 * deployment's nostr-rs-relay: NIP-42 challenge, gift wraps only for their authenticated recipient.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AttachmentTooLargeError, ciphertextUploader, MAX_ATTACHMENT_BYTES, publishServerList, UnsanitizableFileError } from '@sedecim/blossom-client';
import { EncryptedStore, MemoryBackend, type Vault } from '@sedecim/encrypted-store';
import { MediaKeyUnavailableError, type ExtendedGroupSession, type GroupSession } from '@sedecim/marmot-adapter';
import { hexToBytes, npubEncode, randomBytes } from '@sedecim/nostr-core';
import { heicWithGps, TestBlossomServer, TestRelay, tinyPng } from '@sedecim/test-relay';
import type { DeploymentConfig } from '../src/lib/config';
import {
  addGroupDevices,
  checkGroupFileSize,
  decideProposals,
  dropGroupSession,
  exclusive,
  fetchGroupFile,
  forgetRemovedGroup,
  groupErrorMessage,
  GroupHistory,
  groupMediaDownloader,
  groupMediaUploader,
  inviteMembers,
  membership,
  missingDevices,
  openGroupSession,
  parseMembers,
  pendingProposals,
  prepareGroupFile,
  proposeChange,
  removeGroupDevice,
  retryPendingGroupOperations,
  saveGroupDeviceLabel,
  sendGroupFile,
} from '../src/lib/groups';
import { createPersona, openPersona, type PersonaSession } from '../src/lib/session';
import { PersonaBook, type PersonaRecord } from '../src/lib/vault';

/** One browser: its own vault, one persona open in it, and that persona's MLS session. */
interface Browser {
  backend: MemoryBackend;
  key: Uint8Array;
  book: PersonaBook;
  persona: PersonaRecord;
  s: PersonaSession;
  gs: GroupSession;
  history: GroupHistory;
}

const contents = async (b: Browser, groupId: string) => (await b.history.list(groupId)).map((m) => m.content);

describe('web secure groups: devices, rotation, proposals and encrypted files (FR025-14)', () => {
  const general = new TestRelay();
  const secure = new TestRelay({ silentDmKinds: [4, 44, 1059], silentAuthOk: true });
  let cfg: DeploymentConfig;
  let groupRelays: string[];
  const opened: Browser[] = [];

  beforeAll(async () => {
    await general.start();
    await secure.start();
    groupRelays = [secure.url];
    cfg = { mode: 'self-hosted', relays: [general.url], secureRelays: groupRelays };
  });
  afterAll(async () => {
    for (const b of opened) {
      await dropGroupSession(b.s);
      b.s.close();
    }
    await secure.stop();
    await general.stop();
  });

  async function browser(label: string, opts: { secretKey?: Uint8Array; device?: string; config?: DeploymentConfig } = {}): Promise<Browser> {
    const backend = new MemoryBackend();
    const key = randomBytes(32);
    const book = new PersonaBook({ store: EncryptedStore.withKey(backend, key) } as unknown as Vault);
    const persona = await createPersona(book, opts.secretKey ? { kind: 'secret', secretKey: new Uint8Array(opts.secretKey) } : { kind: 'create' }, { label, relays: [general.url], preset: 'convenience' });
    const s = await openPersona(book, persona);
    const gs = opts.device ? await saveGroupDeviceLabel(s, book.store, opts.config ?? cfg, opts.device) : await openGroupSession(s, book.store, opts.config ?? cfg);
    const b = { backend, key, book, persona, s, gs, history: new GroupHistory(book.store, persona.id) };
    opened.push(b);
    return b;
  }

  /** The same browser, restarted: the MLS session is dropped and opened again from the vault. */
  async function restart(b: Browser, config = cfg) {
    await dropGroupSession(b.s);
    b.gs = await openGroupSession(b.s, b.book.store, config);
  }

  const secretOf = (b: Browser) => hexToBytes(b.persona.secretHex!);
  const publishKeyPackage = (b: Browser) => exclusive(b.gs, (g) => g.publishKeyPackage(groupRelays));
  const accept = async (b: Browser) => (await exclusive(b.gs, (g) => g.acceptInvites())).map((h) => h.groupId);
  const sync = (b: Browser, groupId: string) => exclusive(b.gs, (g) => g.sync(groupId));
  const send = (b: Browser, groupId: string, text: string) => exclusive(b.gs, (g) => g.send(groupId, text));
  const handle = (b: Browser, groupId: string) => exclusive(b.gs, (g) => g.group(groupId));

  /** Alice creates a group and every other browser joins it with all its devices. */
  async function group(admin: Browser, members: Browser[], name = 'Redacción') {
    for (const m of members) await publishKeyPackage(m);
    const g = await exclusive(admin.gs, (x) => x.createGroup({ name, relays: groupRelays }));
    const personas = [...new Set(members.map((m) => m.persona.pubkey))];
    await exclusive(admin.gs, (x) => inviteMembers(x, g.groupId, personas, groupRelays));
    for (const m of members) expect(await accept(m)).toEqual([g.groupId]);
    return g.groupId;
  }

  it('a persona in three browsers: invited with every device, a new one proposed by a member device and confirmed by the admin; a removed device learns it is out and reads nothing new (FR025-14)', async () => {
    const alice = await browser('Alice');
    const bob1 = await browser('Bob', { device: 'Móvil' });
    const bob2 = await browser('Bob', { secretKey: secretOf(bob1), device: 'Portátil' });
    const bob = bob1.persona.pubkey;
    await publishKeyPackage(bob1);
    await publishKeyPackage(bob2);
    const g = await exclusive(alice.gs, (x) => x.createGroup({ name: 'Redacción', relays: groupRelays }));

    // An invitation takes every current device of the persona, in one commit.
    const inv = await exclusive(alice.gs, (x) => inviteMembers(x, g.groupId, [bob], groupRelays));
    expect(inv).toMatchObject({ added: [bob], missing: [] });
    expect(inv.group.epoch).toBe(g.epoch + 1);
    expect(inv.group.devices!.filter((d) => d.pubkey === bob)).toHaveLength(2);
    expect(await accept(bob1)).toEqual([g.groupId]);
    expect(await accept(bob2)).toEqual([g.groupId]);
    await send(alice, g.groupId, 'hola bob');
    for (const b of [bob1, bob2]) {
      await sync(b, g.groupId);
      expect(await contents(b, g.groupId)).toContain('hola bob');
    }
    // Each device announced its name inside the group.
    await sync(alice, g.groupId);
    expect((await handle(alice, g.groupId)).devices!.filter((d) => d.pubkey === bob).map((d) => d.label).sort()).toEqual(['Móvil', 'Portátil']);

    // Renamed later, members keep the old name until it is announced again; the device itself shows the new one.
    bob1.gs = await saveGroupDeviceLabel(bob1.s, bob1.book.store, cfg, 'Móvil nuevo');
    expect((await handle(bob1, g.groupId)).devices!.find((d) => d.self)?.label).toBe('Móvil nuevo');
    await sync(alice, g.groupId);
    expect((await handle(alice, g.groupId)).devices!.some((d) => d.label === 'Móvil nuevo')).toBe(false);
    // An admin's name goes out again whenever it adds someone.
    alice.gs = await saveGroupDeviceLabel(alice.s, alice.book.store, cfg, 'Escritorio');

    // A third browser: a device of Bob that is not an admin proposes it, Alice confirms it.
    const bob3 = await browser('Bob', { secretKey: secretOf(bob1), device: 'Tableta' });
    await publishKeyPackage(bob3);
    const candidates = await exclusive(bob1.gs, (x) => missingDevices(x, g.groupId, bob, groupRelays));
    expect(candidates).toHaveLength(1);
    const asked = await exclusive(bob1.gs, (x) => addGroupDevices(x, g.groupId, candidates));
    expect(asked.committed).toBe(false);
    const blocked = await send(bob1, g.groupId, 'bloqueado').catch((e: unknown) => e);
    expect(groupErrorMessage(blocked)).toMatch(/propuestas sin decidir/);
    await sync(alice, g.groupId);
    const pending = await exclusive(alice.gs, (x) => pendingProposals(x, g.groupId));
    expect(pending).toEqual([expect.objectContaining({ type: 'add', proposer: bob, target: bob, admissible: true })]);
    const decided = await exclusive(alice.gs, (x) => decideProposals(x, g.groupId, pending.map((p) => p.ref)));
    expect(decided.devices!.filter((d) => d.pubkey === bob)).toHaveLength(3);
    expect(decided.pendingProposals).toBe(0);
    expect(await accept(bob3)).toEqual([g.groupId]);
    await send(alice, g.groupId, 'ya sois tres');
    for (const b of [bob1, bob2, bob3]) {
      await sync(b, g.groupId);
      expect(await contents(b, g.groupId)).toContain('ya sois tres');
    }
    expect((await handle(bob1, g.groupId)).devices!.find((d) => d.pubkey === alice.persona.pubkey)?.label).toBe('Escritorio');

    // Alice removes the laptop only: the persona stays with its other devices; the laptop knows it is out.
    const laptop = (await handle(alice, g.groupId)).devices!.find((d) => d.label === 'Portátil')!;
    const after = await exclusive(alice.gs, (x) => removeGroupDevice(x, g.groupId, laptop.leafIndex));
    expect(after.members).toContain(bob);
    expect(after.devices!.filter((d) => d.pubkey === bob)).toHaveLength(2);
    await send(alice, g.groupId, 'sin el portátil');
    await sync(bob2, g.groupId).catch(() => undefined);
    expect(membership(await handle(bob2, g.groupId), bob)).toBe('device-removed');
    expect(await contents(bob2, g.groupId)).not.toContain('sin el portátil');
    // What it read before stays where it was read.
    expect(await contents(bob2, g.groupId)).toContain('hola bob');
    for (const b of [bob1, bob3]) {
      await sync(b, g.groupId);
      expect(await contents(b, g.groupId)).toContain('sin el portátil');
      expect(membership(await handle(b, g.groupId), bob)).toBe('member');
    }
    // What the view tells it to do to come back: forget the group here and have another device propose it again.
    bob2.gs = await forgetRemovedGroup(bob2.s, bob2.book.store, cfg, g.groupId);
    const again = await exclusive(bob1.gs, (x) => missingDevices(x, g.groupId, bob, groupRelays));
    expect(again).toHaveLength(1);
    expect((await exclusive(bob1.gs, (x) => addGroupDevices(x, g.groupId, again))).committed).toBe(false);
    await sync(alice, g.groupId);
    await exclusive(alice.gs, async (x) => decideProposals(x, g.groupId, (await pendingProposals(x, g.groupId)).map((p) => p.ref)));
    expect(await accept(bob2)).toEqual([g.groupId]);
    await send(alice, g.groupId, 'otra vez dentro');
    await sync(bob2, g.groupId);
    expect(await contents(bob2, g.groupId)).toContain('otra vez dentro');
    expect(membership(await handle(bob2, g.groupId), bob)).toBe('member');
    // The secure relay only ever held ciphertext: no text, group name or device name.
    for (const e of secure.events.values()) for (const t of ['hola bob', 'ya sois tres', 'Redacción', 'Móvil', 'Portátil', 'Escritorio']) expect(e.content).not.toContain(t);
  }, 300_000);

  it('rotating keys moves everyone to a new epoch without losing a message, a copy of the old keys reads nothing sent after, and a rotation without a relay waits, survives a restart and goes out (FR025-14)', async () => {
    const alice = await browser('Alice');
    const bob = await browser('Bob');
    const carol = await browser('Carol');
    const gid = await group(alice, [bob, carol]);
    await sync(alice, gid);
    await send(carol, gid, 'antes de rotar');

    // Someone copies Bob's browser (its sealed vault and the key that opens it) before he rotates.
    const stolenBackend = new MemoryBackend();
    for (const [k, v] of bob.backend.data) stolenBackend.data.set(k, v.slice());
    const stolenBook = new PersonaBook({ store: EncryptedStore.withKey(stolenBackend, bob.key) } as unknown as Vault);
    const stolenSession = await openPersona(stolenBook, bob.persona);
    const stolen: Browser = { backend: stolenBackend, key: bob.key, book: stolenBook, persona: bob.persona, s: stolenSession, gs: await openGroupSession(stolenSession, stolenBook.store, cfg), history: new GroupHistory(stolenBook.store, bob.persona.id) };
    opened.push(stolen);

    const before = (await handle(bob, gid)).epoch;
    const rotated = await exclusive(bob.gs, (g) => g.rotate(gid));
    expect(rotated.epoch).toBe(before + 1);
    // Nothing is lost: the rotation read what was waiting in the old epoch first.
    expect(await contents(bob, gid)).toContain('antes de rotar');
    for (const b of [alice, carol]) {
      await sync(b, gid);
      expect((await handle(b, gid)).epoch).toBe(before + 1);
    }
    await send(carol, gid, 'después de rotar');
    for (const b of [alice, bob]) {
      await sync(b, gid);
      expect(await contents(b, gid)).toContain('después de rotar');
    }
    // The copy still opens the old epoch, and nothing sent after the rotation.
    await sync(stolen, gid).catch(() => undefined);
    expect(await contents(stolen, gid)).toContain('antes de rotar');
    expect(await contents(stolen, gid)).not.toContain('después de rotar');

    // No relay takes anything: the rotation waits instead of failing.
    const epoch = (await handle(carol, gid)).epoch;
    secure.faults.rejectReason = 'error: relay caído';
    try {
      const waiting = await exclusive(carol.gs, (g) => g.rotate(gid));
      expect(waiting.epoch).toBe(epoch);
      expect(waiting.pending?.map((p) => [p.type, p.failed])).toEqual([['rotate', undefined]]);
      // It survives closing the session and opening it again from the vault.
      await restart(carol);
      expect((await handle(carol, gid)).pending).toEqual([expect.objectContaining({ type: 'rotate' })]);
    } finally {
      secure.faults.rejectReason = null;
    }
    expect(await exclusive(carol.gs, (g) => retryPendingGroupOperations(g, gid))).toEqual([]);
    expect((await handle(carol, gid)).epoch).toBe(epoch + 1);
    await sync(alice, gid);
    expect((await handle(alice, gid)).epoch).toBe(epoch + 1);
    await send(alice, gid, 'tras la rotación pendiente');
    await sync(carol, gid);
    expect(await contents(carol, gid)).toContain('tras la rotación pendiente');
  }, 300_000);

  it('a member proposes an add and a removal: pending proposals block sending and survive a restart; the admin confirms one, which discards the other, and rejecting rotates (FR025-14)', async () => {
    const alice = await browser('Alice');
    const bob = await browser('Bob');
    const carol = await browser('Carol');
    const dave = await browser('Dave');
    const gid = await group(alice, [bob, carol]);
    await publishKeyPackage(dave);
    const [A, B, C, D] = [alice, bob, carol, dave].map((b) => b.persona.pubkey) as [string, string, string, string];

    // What can be proposed: npub or hex, once each, never another persona of this browser, nobody already in.
    expect(parseMembers(`${npubEncode(D)}, ${D}\n${C}`, [B], [A, B, C])).toEqual([D]);
    expect(() => parseMembers(npubEncode(D), [B, D])).toThrow(/compartimentación/);
    expect(() => parseMembers('npub1nohay', [B])).toThrow(/no es una npub válida/);

    const proposedAdd = await exclusive(bob.gs, (g) => proposeChange(g, gid, { add: D }, groupRelays));
    expect(proposedAdd).toEqual([expect.objectContaining({ type: 'add', proposer: B, target: D, admissible: true })]);
    const proposedRemove = await exclusive(bob.gs, (g) => proposeChange(g, gid, { remove: C }, groupRelays));
    expect(proposedRemove).toEqual([expect.objectContaining({ type: 'remove', proposer: B, target: C, admissible: true })]);
    expect(groupErrorMessage(await send(bob, gid, 'bloqueado').catch((e: unknown) => e))).toMatch(/hasta que un admin las confirme o las rechace/);

    // The pending proposals live in the sealed MLS state: a restart keeps them, for the admin and for the member.
    await sync(alice, gid);
    await restart(alice);
    await restart(bob);
    const pending = await exclusive(alice.gs, (g) => pendingProposals(g, gid));
    expect(pending.map((p) => p.type).sort()).toEqual(['add', 'remove']);
    expect(await exclusive(bob.gs, (g) => pendingProposals(g, gid))).toHaveLength(2);
    expect((await handle(alice, gid)).pendingProposals).toBe(2);

    // Alice confirms the add only: Dave comes in, Carol stays (her removal is discarded with the epoch).
    const confirmed = await exclusive(alice.gs, (g) => decideProposals(g, gid, [pending.find((p) => p.type === 'add')!.ref]));
    expect(confirmed.members.sort()).toEqual([A, B, C, D].sort());
    expect(confirmed.pendingProposals).toBe(0);
    expect(await accept(dave)).toEqual([gid]);
    await sync(bob, gid);
    expect(await exclusive(bob.gs, (g) => pendingProposals(g, gid))).toEqual([]);
    await send(bob, gid, 'dave ya está');
    for (const b of [carol, dave]) {
      await sync(b, gid);
      expect(await contents(b, gid)).toContain('dave ya está');
    }

    // Proposed again, the removal is rejected: Alice rotates her keys, which discards it; Carol stays.
    await exclusive(bob.gs, (g) => proposeChange(g, gid, { remove: C }, groupRelays));
    await sync(alice, gid);
    const epoch = (await handle(alice, gid)).epoch;
    expect(await exclusive(alice.gs, (g) => pendingProposals(g, gid))).toHaveLength(1);
    const rejected = await exclusive(alice.gs, (g) => decideProposals(g, gid, []));
    expect(rejected.epoch).toBe(epoch + 1);
    expect(rejected.members).toContain(C);
    expect(rejected.pendingProposals).toBe(0);
    await sync(bob, gid);
    expect(await exclusive(bob.gs, (g) => pendingProposals(g, gid))).toEqual([]);
    await send(bob, gid, 'carol sigue');
    await sync(carol, gid);
    expect(await contents(carol, gid)).toContain('carol sigue');
    // Stale proposals cannot be confirmed any more, and the web says why.
    const stale = await exclusive(alice.gs, (g) => decideProposals(g, gid, [pending[0]!.ref])).catch((e: unknown) => e);
    expect(groupErrorMessage(stale)).toMatch(/ya no están pendientes/);

    // A rotation by any member, not only by an admin, discards what was pending.
    await exclusive(bob.gs, (g) => proposeChange(g, gid, { remove: D }, groupRelays));
    await sync(carol, gid);
    expect(await exclusive(carol.gs, (g) => pendingProposals(g, gid))).toHaveLength(1);
    await exclusive(carol.gs, (g) => g.rotate(gid));
    await sync(alice, gid);
    expect(await exclusive(alice.gs, (g) => pendingProposals(g, gid))).toEqual([]);
    expect((await handle(alice, gid)).members).toContain(D);

    // Without a relay a proposal does not wait (unlike messages and commits): it fails, and the web says so.
    await sync(bob, gid);
    secure.faults.rejectReason = 'error: relay caído';
    try {
      const offline = await exclusive(bob.gs, (g) => proposeChange(g, gid, { remove: D }, groupRelays)).catch((e: unknown) => e);
      expect(groupErrorMessage(offline)).toMatch(/la propuesta no salió/);
    } finally {
      secure.faults.rejectReason = null;
    }
    expect(await exclusive(bob.gs, (g) => pendingProposals(g, gid))).toEqual([]);
  }, 300_000);

  it('a file goes without its metadata and encrypted, only ciphertext reaches Blossom, members open it with its hash checked, a tampered copy is refused and a removed member cannot open newer files (FR025-14)', async () => {
    const primary = new TestBlossomServer();
    const second = new TestBlossomServer();
    const blobStore = new TestBlossomServer();
    await primary.start();
    await second.start();
    await blobStore.start();
    const withBlobStore = { ...cfg, blobStore: blobStore.url };
    try {
      const alice = await browser('Alice', { config: withBlobStore });
      const bob = await browser('Bob', { config: withBlobStore });
      const carol = await browser('Carol', { config: withBlobStore });
      const gid = await group(alice, [bob, carol], 'Fotos');
      // Alice's Blossom list (kind 10063) names two servers; the deployment adds its blob-store.
      await alice.s.pool.publish(await publishServerList(alice.s.signer, [primary.url, second.url]), [general.url]);

      // The picture's metadata goes before it is encrypted; an image whose metadata cannot be removed is refused first.
      const photo = tinyPng('acta secreta de la asamblea');
      const data = prepareGroupFile(photo, 'image/png', true);
      expect(Buffer.from(data).includes(Buffer.from('acta secreta'))).toBe(false);
      const heic = (() => {
        try {
          prepareGroupFile(heicWithGps(), 'image/heic', true);
        } catch (e) {
          return e;
        }
      })();
      expect(heic).toBeInstanceOf(UnsanitizableFileError);
      expect(groupErrorMessage(heic)).toMatch(/No se pueden quitar los metadatos/);

      const upload = await groupMediaUploader(alice.s, withBlobStore);
      const ref = await exclusive(alice.gs, (g) => sendGroupFile(g, gid, { data, filename: 'acta.png', type: 'image/png' }, upload, 'el acta'));
      expect(ref.attachment.url!.startsWith(primary.url)).toBe(true);
      // The ciphertext is on every server of the list and on the blob-store, uploaded under Alice's npub.
      for (const server of [primary, second, blobStore]) {
        expect(server.blobs.size).toBe(1);
        for (const b of server.blobs.values()) {
          expect(b.uploader).toBe(alice.persona.pubkey);
          expect(Buffer.from(b.data).includes(Buffer.from(tinyPng().subarray(8)))).toBe(false);
        }
      }
      // A name MIP-04 cannot carry is refused before anything is uploaded.
      await expect(exclusive(alice.gs, (g) => sendGroupFile(g, gid, { data, filename: 'acta\u2028falsa.png', type: 'image/png' }, upload))).rejects.toThrow(/nombre de archivo/);
      expect(primary.blobs.size).toBe(1);

      // Bob gets the message with its file, sent by Alice, and opens it: the bytes Alice sent, without the metadata.
      await sync(bob, gid);
      const msg = (await bob.history.list(gid)).find((m) => m.media?.length)!;
      expect(msg).toMatchObject({ content: 'el acta', sender: alice.persona.pubkey });
      expect(msg.media![0]).toMatchObject({ filename: 'acta.png', type: 'image/png', version: 'mip04-v2' });
      const got = await fetchGroupFile(bob.gs, gid, msg.media![0]!.sha256, groupMediaDownloader(bob.s));
      expect(Buffer.from(got.data).equals(Buffer.from(tinyPng()))).toBe(true);
      // Alice keeps her own message with its file too.
      expect((await alice.history.list(gid)).find((m) => m.id === ref.rumorId)?.media?.[0]?.sha256).toBe(msg.media![0]!.sha256);
      // The file survives a restart (history and media key in the vault) and the vault archive keeps it.
      await restart(bob, withBlobStore);
      expect((await bob.history.list(gid)).find((m) => m.id === msg.id)?.media).toHaveLength(1);
      expect((await fetchGroupFile(bob.gs, gid, msg.media![0]!.sha256, groupMediaDownloader(bob.s))).data.length).toBe(tinyPng().length);
      const archived = (await bob.history.archived()).find((m) => m.rumorId === msg.id)!;
      expect(archived.tags?.some((t) => t[0] === 'imeta')).toBe(true);
      const elsewhere = new GroupHistory(EncryptedStore.withKey(new MemoryBackend(), randomBytes(32)) as never, 'otro');
      await elsewhere.restore([archived]);
      expect((await elsewhere.list(gid))[0]?.media?.[0]).toMatchObject({ filename: 'acta.png', sha256: msg.media![0]!.sha256 });

      // The shared URL fails: the file comes from the other servers of the sender's list, still checked.
      await primary.stop();
      const nowhere = await exclusive(alice.gs, (g) => sendGroupFile(g, gid, { data, filename: 'otra.png', type: 'image/png' }, ciphertextUploader([primary.url], alice.s.signer))).catch((e: unknown) => e);
      expect(groupErrorMessage(nowhere)).toMatch(/Ningún servidor aceptó el archivo cifrado/);
      expect((await fetchGroupFile(bob.gs, gid, msg.media![0]!.sha256, groupMediaDownloader(bob.s))).data.length).toBe(tinyPng().length);
      // A server that serves other bytes is refused before anything is decrypted.
      second.corruptDownloads = true;
      const tampered = await fetchGroupFile(bob.gs, gid, msg.media![0]!.sha256, groupMediaDownloader(bob.s)).catch((e: unknown) => e);
      expect(groupErrorMessage(tampered)).toMatch(/Ningún servidor entregó el archivo cifrado/);
      second.corruptDownloads = false;

      // Carol is removed; a newer file uses an epoch she never reaches. Bob opens the new one and still the old one.
      await sync(carol, gid);
      await exclusive(alice.gs, (g) => g.removeMember(gid, carol.persona.pubkey));
      await sync(bob, gid);
      await sync(carol, gid).catch(() => undefined);
      expect(membership(await handle(carol, gid).catch(() => undefined), carol.persona.pubkey)).toBe('removed');
      const upload2 = await groupMediaUploader(alice.s, withBlobStore);
      const next = await exclusive(alice.gs, (g) => sendGroupFile(g, gid, { data: new TextEncoder().encode('segundo documento'), filename: 'b.txt', type: 'text/plain' }, upload2));
      expect(next.epoch).toBeGreaterThan(ref.epoch);
      await sync(bob, gid);
      expect(new TextDecoder().decode((await fetchGroupFile(bob.gs, gid, next.attachment.sha256, groupMediaDownloader(bob.s))).data)).toBe('segundo documento');
      expect((await fetchGroupFile(bob.gs, gid, msg.media![0]!.sha256, groupMediaDownloader(bob.s))).data.length).toBe(tinyPng().length);
      const ciphertext = second.blobs.get(next.attachment.url!.split('/').pop()!)!.data;
      await expect((carol.gs as ExtendedGroupSession).decryptMedia(gid, ciphertext, next.attachment, next.epoch)).rejects.toBeInstanceOf(MediaKeyUnavailableError);
      expect(groupErrorMessage(new MediaKeyUnavailableError(next.epoch))).toMatch(/no tiene la clave de la época/);
      await expect(fetchGroupFile(carol.gs, gid, next.attachment.sha256, groupMediaDownloader(carol.s))).rejects.toThrow(/adjunto desconocido/);

      // A download waits outside the session's queue: the group keeps working while a server is slow.
      let releaseDownload!: () => void;
      const downloadHeld = new Promise<void>((r) => (releaseDownload = r));
      const slowDownload = fetchGroupFile(bob.gs, gid, next.attachment.sha256, async (hash, url, sender) => {
        await downloadHeld;
        return groupMediaDownloader(bob.s)(hash, url, sender);
      });
      expect(await Promise.race([handle(bob, gid).then(() => 'free'), new Promise((r) => setTimeout(() => r('held'), 5000))])).toBe('free');
      releaseDownload();
      expect(new TextDecoder().decode((await slowDownload).data)).toBe('segundo documento');
      // An upload holds the queue while it runs (the epoch must not change under it): the limit the docs state.
      let releaseUpload!: () => void;
      const uploadHeld = new Promise<void>((r) => (releaseUpload = r));
      const sending = exclusive(alice.gs, (g) =>
        sendGroupFile(g, gid, { data: new TextEncoder().encode('lento'), filename: 'lento.txt', type: 'text/plain' }, async (ciphertext, sha256) => {
          await uploadHeld;
          return upload2(ciphertext, sha256);
        }),
      );
      const waitingForIt = handle(alice, gid);
      expect(await Promise.race([waitingForIt.then(() => 'free'), new Promise((r) => setTimeout(() => r('held'), 3000))])).toBe('held');
      releaseUpload();
      await sending;
      await waitingForIt;
    } finally {
      await primary.stop().catch(() => undefined);
      await second.stop();
      await blobStore.stop();
    }
  }, 300_000);
});

describe('web secure groups: the size of a file (FR018-06)', () => {
  it('FR018-06: a group file over the limit is refused with its size before it is read or sent, and the limit itself goes', async () => {
    expect(() => checkGroupFileSize(MAX_ATTACHMENT_BYTES.group)).not.toThrow();
    const over = () => checkGroupFileSize(MAX_ATTACHMENT_BYTES.group + 1);
    expect(over).toThrow(AttachmentTooLargeError);
    expect(over).toThrow('El archivo pesa 25,1 MB y los archivos de los grupos seguros pueden pesar como mucho 25,0 MB.');
    // Whoever prepares or sends the bytes without having checked gets the same refusal, with the wording of a group.
    expect(() => prepareGroupFile(new Uint8Array(MAX_ATTACHMENT_BYTES.group + 1), 'application/octet-stream', false)).toThrow(/los archivos de los grupos seguros/);
    const upload = async () => {
      throw new Error('nothing is uploaded');
    };
    await expect(sendGroupFile({} as GroupSession, 'g', { data: new Uint8Array(MAX_ATTACHMENT_BYTES.group + 1), filename: 'grande.bin', type: 'application/octet-stream' }, upload)).rejects.toBeInstanceOf(AttachmentTooLargeError);
  });
});
