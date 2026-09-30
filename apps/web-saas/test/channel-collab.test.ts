/**
 * FR015-04: reactions, replies and deletions of the web's NIP-29 channels, sent through the persona's outbox to a relay
 * that applies Buzz's rules (TestRelay groupModeration), and read by another client as the web reads a channel.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { EncryptedStore, MemoryBackend, type Vault } from '@sedecim/encrypted-store';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned, type NostrEvent } from '@sedecim/nostr-core';
import { channelFilters, channelView, deleteEvent, groupAdmins, replyMessage } from '@sedecim/messaging';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { LocalSigner } from '@sedecim/signer';
import { TestRelay } from '@sedecim/test-relay';
import { canDelete, publishToChannel, reactionToggle, REACTIONS } from '../src/lib/channels';
import { createPersona, openPersona, type PersonaSession } from '../src/lib/session';
import { PersonaBook } from '../src/lib/vault';

const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;
const newBook = () => new PersonaBook({ store: EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(3)) } as unknown as Vault);

describe('reactions, replies and deletions in the web’s channels (FR015-04)', () => {
  const relaySk = generateSecretKey();
  // Buzz: NIP-11 self, channel-scoped fan-out and its ingest rules for replies, reactions and deletions.
  const relay = new TestRelay({ self: getPublicKey(relaySk), channelScopedFanout: true, groupModeration: true });
  const [adminSk, bobSk] = [generateSecretKey(), generateSecretKey()];
  const admin = new LocalSigner(adminSk);
  const bob = new LocalSigner(bobSk);
  const pools: RelayPool[] = [];
  let web: PersonaSession;
  let reader: RelayPool;
  const G = 'sala';
  const relaySigned = (kind: number, tags: string[][]) => finalizeEvent(toUnsigned({ kind, content: '', tags }, getPublicKey(relaySk)), relaySk);
  const post = async (signer: LocalSigner, template: { kind: number; content: string; tags?: string[][] }) => {
    const pool = new RelayPool({ webSocketFactory: factory, signer });
    pools.push(pool);
    const evt = await signer.signEvent(template);
    return { evt, res: await pool.publishTo(evt, relay.url) };
  };
  /** What another client sees, reading the channel as the web does. */
  const seen = async () => {
    const [events, state] = await Promise.all([reader.query([relay.url], channelFilters(G), 3000), reader.query([relay.url], [{ kinds: [39000, 39001], '#d': [G] }], 3000)]);
    return channelView(events, { groupId: G, me: getPublicKey(bobSk), admins: groupAdmins(state, G) });
  };

  beforeAll(async () => {
    await relay.start();
    relay.inject(relaySigned(39000, [['d', G], ['name', 'Sala']]));
    relay.inject(relaySigned(39001, [['d', G], ['p', getPublicKey(adminSk), 'admin']]));
    const book = newBook();
    web = await openPersona(book, await createPersona(book, { kind: 'create' }, { label: 'Web', relays: [relay.url], preset: 'convenience' }));
    reader = new RelayPool({ webSocketFactory: factory, signer: new LocalSigner(generateSecretKey()) });
    pools.push(reader);
  });
  afterAll(async () => {
    web?.close();
    pools.forEach((p) => p.close());
    await relay.stop();
  });

  it('FR015-04: a reaction reaches the other clients and toggling it off deletes it (kind 5)', async () => {
    const { evt: msg } = await post(bob, { kind: 9, content: 'hola sala', tags: [['h', G]] });
    const entry = () => seen().then((v) => v.messages.find((m) => m.event.id === msg.id)!);
    const [react] = await publishToChannel(web, reactionToggle(G, await entry(), REACTIONS[0]));
    expect(react).toMatchObject({ kind: 7, pubkey: web.pubkey, content: '👍' });
    expect((await entry()).reactions.map((r) => [r.content, r.count])).toEqual([['👍', 1]]);
    // The web's own view (channelView with its pubkey) lists it as its own: toggling it publishes a kind 5 of it.
    const mine = channelView([msg, react!], { groupId: G, me: web.pubkey }).messages[0]!;
    const [undo] = await publishToChannel(web, reactionToggle(G, mine, '👍'));
    expect(undo).toMatchObject({ kind: 5, tags: [['h', G], ['e', react!.id], ['k', '7']] });
    expect((await entry()).reactions).toEqual([]);
  });

  it('FR015-04: replies land in the parent’s thread, also nested; a wrong root is refused as Buzz does', async () => {
    const { evt: top } = await post(bob, { kind: 9, content: 'primer tema', tags: [['h', G]] });
    const [reply] = await publishToChannel(web, [replyMessage(G, 'respuesta desde la web', top)]);
    const { evt: nested, res } = await post(bob, replyMessage(G, 'respuesta a la web', reply!));
    expect(res.ok).toBe(true);
    const v = await seen();
    const threadOf = (e: NostrEvent) => v.messages.find((m) => m.event.id === e.id)?.thread;
    expect([threadOf(reply!), threadOf(nested)]).toEqual([
      { root: top.id, parent: top.id },
      { root: top.id, parent: reply!.id },
    ]);
    expect(reply!.tags).toContainEqual(['q', top.id, '', getPublicKey(bobSk)]);
    // A NIP-10 client that puts the answered reply as root does not match Buzz's thread: refused.
    const { res: wrong } = await post(bob, { kind: 9, content: 'mal enhebrada', tags: [['h', G], ['e', reply!.id, '', 'root'], ['e', nested.id, '', 'reply']] });
    expect(wrong).toMatchObject({ ok: false, message: 'invalid: root tag does not match thread ancestry' });
  });

  it('FR015-04: the author deletes its message (9005); others cannot, a channel admin can', async () => {
    const [own] = await publishToChannel(web, [{ kind: 9, content: 'me equivoqué', tags: [['h', G]] }]);
    const { evt: bobs } = await post(bob, { kind: 9, content: 'mensaje de bob', tags: [['h', G]] });
    const admins = groupAdmins(await reader.query([relay.url], [{ kinds: [39000, 39001], '#d': [G] }], 3000), G);
    expect([canDelete(own!, web.pubkey, admins), canDelete(bobs, web.pubkey, admins), canDelete(bobs, getPublicKey(adminSk), admins)]).toEqual([true, false, true]);

    await publishToChannel(web, [deleteEvent(G, own!.id)]);
    // The relay no longer serves it and the channel view hides it.
    expect(relay.query([{ ids: [own!.id] }])).toEqual([]);
    expect((await seen()).messages.map((m) => m.event.id)).not.toContain(own!.id);

    // The web is no admin: the relay refuses its deletion of bob's message and says why.
    await expect(publishToChannel(web, [deleteEvent(G, bobs.id)])).rejects.toThrow(/must be event author or channel owner\/admin/);
    expect((await seen()).messages.map((m) => m.event.id)).toContain(bobs.id);
    // The admin can.
    expect((await post(admin, deleteEvent(G, bobs.id))).res.ok).toBe(true);
    expect((await seen()).messages.map((m) => m.event.id)).not.toContain(bobs.id);
  });

  it('FR015-04: a deletion that a permissive relay would keep hides nothing unless its author or an admin signed it', async () => {
    const { evt: msg } = await post(admin, { kind: 9, content: 'aviso del admin', tags: [['h', G]] });
    const forged = await bob.signEvent(deleteEvent(G, msg.id));
    const view = channelView([msg, forged], { groupId: G, me: web.pubkey, admins: new Set([getPublicKey(adminSk)]) });
    expect(view.messages.map((m) => m.event.content)).toEqual(['aviso del admin']);
  });
});
