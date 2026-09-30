import { describe, expect, it } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned, type Filter, type NostrEvent } from '@sedecim/nostr-core';
import { buildProfile, cleanProfileText, parseProfile, PROFILE_LIMITS, ProfileCache } from '../src/index';

const sk = generateSecretKey();
const pk = getPublicKey(sk);
const kind0 = (content: unknown, createdAt: number, key = sk) => finalizeEvent(toUnsigned({ kind: 0, content: typeof content === 'string' ? content : JSON.stringify(content), tags: [] }, getPublicKey(key), createdAt), key);

/** A relay query that records what it is asked and answers from a fixed set of events. */
function fakePool(events: NostrEvent[], opts: { fail?: boolean } = {}) {
  const asked: Filter[][] = [];
  return {
    asked,
    query: async (_urls: string[], filters: Filter[]) => {
      asked.push(filters);
      if (opts.fail) throw new Error('offline');
      return events;
    },
  };
}

describe('public profile of a persona (kind 0, FR006-04)', () => {
  it('builds the kind 0 of what the user typed: cleaned, capped, and only http(s) avatars (FR006-04)', () => {
    const t = buildProfile({ name: '  Ana‮ ‏Pérez  ', about: 'x'.repeat(400), picture: 'https://blossom.example/' + 'ab'.repeat(32) + '.png' });
    expect(t.kind).toBe(0);
    const content = JSON.parse(t.content) as Record<string, string>;
    expect(content).toMatchObject({ name: 'Ana Pérez', display_name: 'Ana Pérez', picture: 'https://blossom.example/' + 'ab'.repeat(32) + '.png' });
    expect([...content.about!]).toHaveLength(PROFILE_LIMITS.about);
    expect(() => buildProfile({ name: 'x', picture: 'javascript:alert(1)' })).toThrow(/http\(s\)/);
    expect(() => buildProfile({ picture: 'data:image/png;base64,AAAA' })).toThrow(/http\(s\)/);
    // An empty profile replaces, and so withdraws, the previous one.
    expect(buildProfile({})).toEqual({ kind: 0, content: '{}', tags: [] });
    expect(cleanProfileText('a\u0000b⁦c', 10)).toBe('a b c');
  });

  it('reads what others publish defensively: display_name first, no unsafe characters, no non-http avatars (FR006-04)', () => {
    expect(parseProfile(kind0({ name: 'ana', display_name: 'Ana', about: 'hola', picture: 'https://x.example/a.png' }, 10))).toMatchObject({ pubkey: pk, name: 'Ana', about: 'hola', picture: 'https://x.example/a.png', createdAt: 10 });
    expect(parseProfile(kind0({ name: 'Bob‮evil', picture: 'file:///etc/passwd' }, 10))).toMatchObject({ name: 'Bob evil' });
    expect(parseProfile(kind0({ name: 'Bob', picture: 'file:///etc/passwd' }, 10))!.picture).toBeUndefined();
    expect(parseProfile(kind0({ name: 'x'.repeat(200) }, 10))!.name).toHaveLength(PROFILE_LIMITS.name);
    for (const bad of ['no es json', '[1,2]', 'null', '"texto"']) expect(parseProfile(kind0(bad, 10))).toBeUndefined();
    expect(parseProfile({ ...kind0({ name: 'Ana' }, 10), kind: 1 })).toBeUndefined();
  });

  it('caches per persona: one request for many keys, the newest profile wins, and a key is not asked again within the TTL (FR006-04)', async () => {
    const other = generateSecretKey();
    const stranger = generateSecretKey();
    const pool = fakePool([kind0({ name: 'Vieja' }, 10), kind0({ name: 'Nueva' }, 20), kind0({ name: 'Otra' }, 5, other), kind0({ name: 'No pedida' }, 5, stranger)]);
    let now = 1_000;
    const cache = new ProfileCache(pool, { ttlMs: 60_000, now: () => now });
    let changes = 0;
    const off = cache.onChange(() => changes++);
    await cache.lookup(['wss://relay.example'], [pk, getPublicKey(other), 'no-es-hex']);
    expect(pool.asked).toEqual([[{ kinds: [0], authors: [pk, getPublicKey(other)] }]]);
    expect(cache.get(pk)?.name).toBe('Nueva');
    expect(cache.get(getPublicKey(other))?.name).toBe('Otra');
    // Only the keys asked for are kept, whatever the relay sends.
    expect(cache.get(getPublicKey(stranger))).toBeUndefined();
    expect(changes).toBeGreaterThan(0);

    await cache.lookup(['wss://relay.example'], [pk]);
    expect(pool.asked).toHaveLength(1);
    now += 60_000;
    await cache.lookup(['wss://relay.example'], [pk]);
    expect(pool.asked).toHaveLength(2);
    // An older event never replaces a newer one (e.g. the one this persona just published).
    cache.put(kind0({ name: 'Más vieja' }, 1));
    expect(cache.get(pk)?.name).toBe('Nueva');
    off();
  });

  it('a failed lookup is not remembered, and lookups at once share one request (FR006-04)', async () => {
    const offline = fakePool([], { fail: true });
    const cache = new ProfileCache(offline);
    await cache.lookup(['wss://relay.example'], [pk]);
    await cache.lookup(['wss://relay.example'], [pk]);
    expect(offline.asked).toHaveLength(2);

    const pool = fakePool([kind0({ name: 'Ana' }, 10)]);
    const shared = new ProfileCache(pool);
    await Promise.all([shared.lookup(['wss://r'], [pk]), shared.lookup(['wss://r'], [pk])]);
    expect(pool.asked).toHaveLength(1);
    expect(shared.get(pk)?.name).toBe('Ana');
    // Without relays nothing is asked.
    await new ProfileCache(pool).lookup([], [pk]);
    expect(pool.asked).toHaveLength(1);
  });
});
