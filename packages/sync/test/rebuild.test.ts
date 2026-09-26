import { describe, expect, it } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned } from '@sedecim/nostr-core';
import { GROUP_LIST_KIND, discoverChannels, ownActivityFilter, seenLookup } from '../src/index';

describe('rebuild helpers (FR013-03)', () => {
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);
  const ev = (kind: number, tags: string[][], t: number) => finalizeEvent(toUnsigned({ kind, content: '', tags, created_at: 1_700_000_000 + t }, pk), sk);

  it('discovers channels from h tags and the kind 10009 list, dropping channels left afterwards', () => {
    const own = [
      ev(9021, [['h', 'general']], 1),
      ev(9, [['h', 'general']], 2),
      ev(9, [['h', 'viejo']], 3),
      ev(9022, [['h', 'viejo']], 4),
      ev(9022, [['h', 'vuelta']], 5),
      ev(9021, [['h', 'vuelta']], 6),
      ev(GROUP_LIST_KIND, [['group', 'lista', 'wss://r.example']], 7),
    ];
    expect(discoverChannels(own)).toEqual(['general', 'lista', 'vuelta']);
  });

  it('never asks for unscoped kinds (relays p-gate kind 1059)', () => {
    expect(ownActivityFilter(pk, 5).kinds).not.toContain(1059);
    expect(ownActivityFilter(pk, 5)).toMatchObject({ authors: [pk], since: 5 });
  });

  it('exposes sync evidence as an outbox lookup with normalised relay URLs', async () => {
    const lookup = seenLookup(new Map([['e1', new Set(['wss://r.example'])]]));
    expect(await lookup.has('wss://R.example/', 'e1')).toBe(true);
    expect(await lookup.has('wss://other.example', 'e1')).toBe(false);
  });
});
