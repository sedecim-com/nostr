/**
 * FR015-04: TestRelay's `groupModeration` refuses, with Buzz's messages, the replies, reactions and deletions the pinned
 * Buzz refuses, and hides what an accepted 9005 deletes.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned, type NostrEvent } from '@sedecim/nostr-core';
import { TestRelay } from '../src/index';

const [relaySk, adminSk, bobSk, carolSk] = [generateSecretKey(), generateSecretKey(), generateSecretKey(), generateSecretKey()];
const sign = (sk: Uint8Array, kind: number, tags: string[][], content = '') => finalizeEvent(toUnsigned({ kind, content, tags }, getPublicKey(sk)), sk);

async function publish(url: string, evt: NostrEvent): Promise<{ ok: boolean; message: string }> {
  const ws = new WebSocket(url);
  await new Promise((r) => ws.once('open', r));
  const res = new Promise<{ ok: boolean; message: string }>((resolve) =>
    ws.on('message', (m) => {
      const msg = JSON.parse(m.toString()) as unknown[];
      if (msg[0] === 'OK' && msg[1] === evt.id) resolve({ ok: msg[2] as boolean, message: msg[3] as string });
    }),
  );
  ws.send(JSON.stringify(['EVENT', evt]));
  const out = await res;
  ws.close();
  return out;
}

describe('TestRelay groupModeration (Buzz rules for channel collaboration)', () => {
  const relay = new TestRelay({ self: getPublicKey(relaySk), groupModeration: true });
  beforeAll(async () => {
    await relay.start();
    relay.inject(sign(relaySk, 39001, [['d', 'g'], ['p', getPublicKey(adminSk), 'admin']]));
    // A list for bob that the relay did not sign names nobody.
    relay.inject(sign(bobSk, 39001, [['d', 'g'], ['p', getPublicKey(bobSk), 'admin']]));
  });
  afterAll(() => relay.stop());

  it('FR015-04: refuses what Buzz refuses and says why', async () => {
    const top = sign(bobSk, 9, [['h', 'g']], 'tema');
    const elsewhere = sign(bobSk, 9, [['h', 'otro']], 'en otro canal');
    for (const e of [top, elsewhere]) expect((await publish(relay.url, e)).ok).toBe(true);
    const cases: Array<[NostrEvent, string]> = [
      [sign(carolSk, 9, [['h', 'g'], ['e', 'f'.repeat(64), '', 'reply']]), 'invalid: reply parent not found'],
      [sign(carolSk, 9, [['h', 'g'], ['e', elsewhere.id, '', 'reply']]), 'invalid: parent event belongs to a different channel'],
      [sign(carolSk, 7, [['h', 'g'], ['e', 'f'.repeat(64)]], '+'), 'invalid: reaction target event not found'],
      [sign(carolSk, 7, [['h', 'g']], '+'), 'invalid: reaction must reference a target event via e tag'],
      [sign(bobSk, 5, [['e', top.id], ['e', elsewhere.id]]), 'invalid: deletion events must reference exactly one target via e or a tag'],
      [sign(carolSk, 5, [['e', top.id]]), 'invalid: must be event author'],
      [sign(carolSk, 9005, [['h', 'g'], ['e', top.id]]), 'invalid: must be event author or channel owner/admin'],
      [sign(adminSk, 9005, [['e', top.id]]), 'invalid: channel-scoped events must include an h tag'],
      [sign(adminSk, 9005, [['h', 'g'], ['e', elsewhere.id]]), 'invalid: target event belongs to a different channel'],
    ];
    for (const [evt, message] of cases) expect(await publish(relay.url, evt), message).toEqual({ ok: false, message });
    expect(relay.query([{ kinds: [9] }]).map((e) => e.content).sort()).toEqual(['en otro canal', 'tema']);
  });

  it('FR015-04: an accepted 9005 (author or admin) hides its target', async () => {
    const [a, b] = [sign(bobSk, 9, [['h', 'g']], 'uno'), sign(carolSk, 9, [['h', 'g']], 'dos')];
    for (const e of [a, b]) await publish(relay.url, e);
    expect((await publish(relay.url, sign(bobSk, 9005, [['h', 'g'], ['e', a.id]]))).ok).toBe(true);
    expect((await publish(relay.url, sign(adminSk, 9005, [['h', 'g'], ['e', b.id]]))).ok).toBe(true);
    expect(relay.query([{ ids: [a.id, b.id] }])).toEqual([]);
    // Reacting to a deleted message is refused like reacting to one that does not exist.
    expect(await publish(relay.url, sign(carolSk, 7, [['h', 'g'], ['e', a.id]], '+'))).toEqual({ ok: false, message: 'invalid: reaction target event not found' });
  });
});
