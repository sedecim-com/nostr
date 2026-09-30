/**
 * FR015-04: collaboration in NIP-29 channels: reactions (kind 7), replies in threads (NIP-10 markers read as Buzz reads
 * them, plus the NIP-C7 `q` tag) and deletions (kind 5 of one's own events, kind 9005 by the author or a channel admin).
 */
import { describe, expect, it } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned, type NostrEvent } from '@sedecim/nostr-core';
import { channelFilters, channelView, chatMessage, deleteEvent, deletion, groupAdmins, reaction, replyMessage, threadOf } from '../src/index';

let clock = 1_800_000_000;
const sign = (sk: Uint8Array, kind: number, content: string, tags: string[][]) => finalizeEvent(toUnsigned({ kind, content, tags, created_at: ++clock }, getPublicKey(sk)), sk);
const signTemplate = (sk: Uint8Array, t: { kind: number; content: string; tags?: string[][] }) => sign(sk, t.kind, t.content, t.tags ?? []);
const [relaySk, adminSk, bobSk, carolSk] = [generateSecretKey(), generateSecretKey(), generateSecretKey(), generateSecretKey()];
const [admin, bob, carol] = [adminSk, bobSk, carolSk].map(getPublicKey) as [string, string, string];
const id = (c: string) => c.repeat(64);

/** Every order of a small list (the view must not depend on arrival order). */
function* orders<T>(items: T[]): Generator<T[]> {
  if (items.length <= 1) return yield items;
  for (let i = 0; i < items.length; i++) for (const rest of orders([...items.slice(0, i), ...items.slice(i + 1)])) yield [items[i]!, ...rest];
}

describe('threads in NIP-29 channels', () => {
  it('FR015-04: reads NIP-10 markers as Buzz does: a lone root is top-level, a lone reply answers the root', () => {
    expect(threadOf({ tags: [['e', id('a'), '', 'root'], ['e', id('b'), '', 'reply']] })).toEqual({ root: id('a'), parent: id('b') });
    expect(threadOf({ tags: [['e', id('a'), '', 'reply']] })).toEqual({ root: id('a'), parent: id('a') });
    expect(threadOf({ tags: [['e', id('a'), '', 'root']] })).toBeUndefined();
    expect(threadOf({ tags: [['e', id('a')]] })).toBeUndefined();
    // Malformed ids are not thread links; the last valid marker of each kind wins.
    expect(threadOf({ tags: [['e', 'nope', '', 'reply']] })).toBeUndefined();
    expect(threadOf({ tags: [['e', id('a'), '', 'reply'], ['e', id('c'), '', 'reply']] })).toEqual({ root: id('c'), parent: id('c') });
  });

  it('FR015-04: a reply names the root of its parent’s thread, both markers and the parent in `q`', () => {
    const top = sign(bobSk, 9, 'arranca el hilo', [['h', 'g']]);
    const direct = replyMessage('g', 'respuesta', top);
    expect(direct).toEqual({ kind: 9, content: 'respuesta', tags: [['h', 'g'], ['e', top.id, '', 'root'], ['e', top.id, '', 'reply'], ['q', top.id, '', bob]] });
    const reply = signTemplate(carolSk, direct);
    expect(threadOf(reply)).toEqual({ root: top.id, parent: top.id });
    // Nested: the root stays the thread's, the parent is the reply answered.
    const nested = signTemplate(adminSk, replyMessage('g', 'y otra', reply));
    expect(threadOf(nested)).toEqual({ root: top.id, parent: reply.id });
    // A reply written by a Buzz client (only a `reply` marker) belongs to its target's thread.
    const buzzReply = sign(bobSk, 9, 'desde Buzz', [['h', 'g'], ['e', top.id, '', 'reply']]);
    expect(threadOf(signTemplate(carolSk, replyMessage('g', 'sigo', buzzReply)))).toEqual({ root: top.id, parent: buzzReply.id });
    // A message with a lone root is top-level for Buzz, so it roots its own thread.
    const loneRoot = sign(bobSk, 9, 'NIP-10 con root solo', [['h', 'g'], ['e', top.id, '', 'root']]);
    expect(threadOf(signTemplate(carolSk, replyMessage('g', 'a esta', loneRoot)))).toEqual({ root: loneRoot.id, parent: loneRoot.id });
    // Without replyTo nothing changes.
    expect(chatMessage('g', 'hola').tags).toEqual([['h', 'g']]);
  });
});

describe('reactions and deletions', () => {
  it('FR015-04: builds the events Buzz accepts: one target per deletion, h on everything', () => {
    const msg = sign(bobSk, 9, 'hola', [['h', 'g']]);
    const r = reaction('g', msg, '🎉');
    expect(r).toEqual({ kind: 7, content: '🎉', tags: [['h', 'g'], ['e', msg.id], ['p', bob], ['k', '9']] });
    const own = signTemplate(carolSk, r);
    expect(deletion('g', own)).toEqual({ kind: 5, content: '', tags: [['h', 'g'], ['e', own.id], ['k', '7']] });
    expect(deleteEvent('g', msg.id)).toEqual({ kind: 9005, content: '', tags: [['h', 'g'], ['e', msg.id]] });
    // The subscription limits messages and the activity around them apart.
    expect(channelFilters('g')).toEqual([
      { kinds: [9], '#h': ['g'], limit: 100 },
      { kinds: [7, 5, 9005], '#h': ['g'], limit: 500 },
    ]);
  });

  it('FR015-04: the admins are the ones of the 39001 signed by the key that signs the 39000', () => {
    const meta = sign(relaySk, 39000, '', [['d', 'g'], ['name', 'General']]);
    const list = sign(relaySk, 39001, '', [['d', 'g'], ['p', admin, 'admin']]);
    const forged = sign(bobSk, 39001, '', [['d', 'g'], ['p', bob, 'admin']]);
    const other = sign(relaySk, 39001, '', [['d', 'otro'], ['p', carol, 'admin']]);
    expect([...groupAdmins([meta, list, forged, other], 'g')]).toEqual([admin]);
    expect([...groupAdmins([list], 'g')]).toEqual([]);
    // The newest list wins.
    expect([...groupAdmins([meta, list, sign(relaySk, 39001, '', [['d', 'g'], ['p', carol, 'owner']])], 'g')]).toEqual([carol]);
  });

  it('FR015-04: counts each author once per content, lists one’s own reactions and drops those deleted with kind 5', () => {
    const msg = sign(bobSk, 9, 'hola', [['h', 'g']]);
    const r1 = signTemplate(carolSk, reaction('g', msg, '👍'));
    const r2 = signTemplate(carolSk, reaction('g', msg, '👍'));
    const r3 = signTemplate(adminSk, reaction('g', msg, '👍'));
    const r4 = signTemplate(adminSk, reaction('g', msg, '❤️'));
    // A Buzz client reacts with only an `e` tag and no content ('+').
    const r5 = sign(bobSk, 7, '', [['e', msg.id]]);
    let v = channelView([msg, r1, r2, r3, r4, r5], { groupId: 'g', me: carol });
    expect(v.messages[0]!.reactions.map((r) => [r.content, r.count, r.mine.length])).toEqual([
      ['👍', 2, 2],
      ['+', 1, 0],
      ['❤️', 1, 0],
    ]);
    // Removing carol's 👍 deletes both of her reactions; a deletion by someone else removes nothing.
    const undo = [r1, r2].map((r) => signTemplate(carolSk, deletion('g', r)));
    const notYours = signTemplate(bobSk, deletion('g', r4));
    v = channelView([msg, r1, r2, r3, r4, r5, ...undo, notYours], { groupId: 'g', me: carol });
    expect(v.messages[0]!.reactions.map((r) => [r.content, r.count, r.mine.length])).toEqual([
      ['+', 1, 0],
      ['❤️', 1, 0],
      ['👍', 1, 0],
    ]);
    // A reaction to a message the view does not have is not shown anywhere.
    expect(channelView([sign(carolSk, 7, '+', [['h', 'g'], ['e', id('d')]])], { groupId: 'g', me: carol }).messages).toEqual([]);
  });

  it('FR015-04: hides what the author deletes (5 or 9005) or a channel admin deletes (9005 in the same channel), in any order', () => {
    const a = sign(bobSk, 9, 'uno', [['h', 'g']]);
    const b = sign(bobSk, 9, 'dos', [['h', 'g']]);
    const c = sign(bobSk, 9, 'tres', [['h', 'g']]);
    const d = sign(carolSk, 9, 'cuatro', [['h', 'g']]);
    const e = sign(carolSk, 9, 'cinco', [['h', 'g']]);
    const f = sign(bobSk, 9, 'seis', [['h', 'otro']]);
    const events = [
      signTemplate(bobSk, deleteEvent('g', a.id)), // its author, 9005
      signTemplate(bobSk, deletion('g', b)), // its author, kind 5
      signTemplate(adminSk, deleteEvent('g', c.id)), // a channel admin
      signTemplate(bobSk, deleteEvent('g', d.id)), // neither: ignored
      signTemplate(adminSk, deletion('g', e)), // kind 5 by someone else: ignored
      signTemplate(adminSk, deleteEvent('otro', f.id)), // f is in another channel than the view
    ];
    // Deletions before or after their targets (720 orders).
    for (const order of orders([a, b, c, ...events.slice(0, 3)])) {
      const v = channelView([d, e, ...order, ...events.slice(3)], { groupId: 'g', me: carol, admins: new Set([admin]) });
      expect(v.messages.map((m) => m.event.content)).toEqual(['cuatro', 'cinco']);
    }
    // 9005 needs the target in the channel it names: an admin cannot reach another channel's message from here.
    const cross = signTemplate(adminSk, { kind: 9005, content: '', tags: [['h', 'g'], ['e', f.id]] });
    expect(channelView([f, cross], { groupId: 'otro', me: carol, admins: new Set([admin]) }).messages.map((m) => m.event.content)).toEqual(['seis']);
    // A deleted message takes its reactions with it, and the reply still shows whom it answered.
    const reply = signTemplate(carolSk, replyMessage('g', 'respuesta a uno', a));
    const v = channelView([a, reply, events[0]!, signTemplate(carolSk, reaction('g', a, '👍'))], { groupId: 'g', me: carol });
    expect(v.messages.map((m) => [m.event.content, m.thread?.parent, m.reactions.length])).toEqual([['respuesta a uno', a.id, 0]]);
    expect(v.deleted.has(a.id) && v.byId.get(a.id)?.content).toBe('uno');
  });

  it('FR015-04: the view keeps only the channel’s messages, oldest first', () => {
    const late = sign(bobSk, 9, 'después', [['h', 'g']]);
    const early = finalizeEvent(toUnsigned({ kind: 9, content: 'antes', tags: [['h', 'g']], created_at: late.created_at - 50 }, bob), bobSk);
    const elsewhere = sign(bobSk, 9, 'otro canal', [['h', 'x']]);
    const note: NostrEvent = sign(bobSk, 1, 'nota', []);
    expect(channelView([late, elsewhere, note, early], { groupId: 'g', me: bob }).messages.map((m) => m.event.content)).toEqual(['antes', 'después']);
  });
});
