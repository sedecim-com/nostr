import { describe, expect, it } from 'vitest';
import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EncryptedStore, FileBackend, MemoryBackend, WrongPassphraseError } from '@sedecim/encrypted-store';
import { finalizeEvent, generateSecretKey, getPublicKey, randomBytes, toUnsigned, type NostrEvent } from '@sedecim/nostr-core';
import { EventCache, filterKey } from '../src/index';

const alice = generateSecretKey();
const bob = generateSecretKey();
const base = 1_750_000_000;
const sign = (sk: Uint8Array, kind: number, created_at: number, content = '', tags: string[][] = []) => finalizeEvent(toUnsigned({ kind, content, tags, created_at }, getPublicKey(sk)), sk);
const chat = (sk: Uint8Array, t: number, text: string, channel = 'general') => sign(sk, 9, base + t, text, [['h', channel]]);
const memoryStore = () => EncryptedStore.withKey(new MemoryBackend(), randomBytes(32));

describe('encrypted event cache (FR013-05)', () => {
  it('keeps events sealed at rest: no id, key, channel or text in clear on disk, and another key reads nothing (FR013-05)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'evcache-'));
    const store = await EncryptedStore.open(new FileBackend(dir), 'frase de paso', { logN: 4 });
    const cache = await EventCache.open(store);
    const events = Array.from({ length: 40 }, (_, i) => chat(i % 2 ? alice : bob, i, `contenido sensible ${i}`, 'redaccion-secreta'));
    const wrap = sign(generateSecretKey(), 1059, base + 50, 'ciphertext-nip44', [['p', getPublicKey(alice)]]);
    await cache.put([...events, wrap], { relay: 'wss://relay.example' });

    const files = (await readdir(dir)).filter((f) => f !== 'meta__kdf');
    // 64 buckets at most plus the metadata record: the disk does not say how many events there are.
    expect(files.length).toBeLessThanOrEqual(65);
    const disk = (await Promise.all(files.map((f) => readFile(join(dir, f))))).map((b) => b.toString('latin1')).join('\n') + files.join('\n');
    for (const secret of ['redaccion-secreta', 'contenido sensible', 'ciphertext-nip44', 'relay.example', getPublicKey(alice), getPublicKey(bob), ...[...events, wrap].map((e) => e.id)]) {
      expect(disk).not.toContain(secret);
    }

    const reopened = await EventCache.open(await EncryptedStore.open(new FileBackend(dir), 'frase de paso', { logN: 4 }));
    expect(reopened.query({ kinds: [9], '#h': ['redaccion-secreta'] }).map((e) => e.id).sort()).toEqual(events.map((e) => e.id).sort());
    expect(reopened.get(wrap.id)).toEqual(wrap);

    await expect(EncryptedStore.open(new FileBackend(dir), 'otra frase', { logN: 4 })).rejects.toBeInstanceOf(WrongPassphraseError);
    const before = await Promise.all(files.map((f) => readFile(join(dir, f))));
    await expect(EventCache.open(EncryptedStore.withKey(new FileBackend(dir), randomBytes(32)))).rejects.toThrow();
    // Failing to open deletes or rewrites nothing.
    expect((await readdir(dir)).filter((f) => f !== 'meta__kdf').sort()).toEqual([...files].sort());
    expect(await Promise.all(files.map((f) => readFile(join(dir, f))))).toEqual(before);
  });

  it('stores each event once, whatever batch or relay brings it, and remembers which relays served it (FR013-05)', async () => {
    const store = memoryStore();
    const cache = await EventCache.open(store);
    const events = Array.from({ length: 10 }, (_, i) => chat(alice, i, `m${i}`));
    expect(await cache.put(events, { relay: 'wss://a.example' })).toMatchObject({ added: 10, refused: 0 });
    expect(await cache.put([...events, ...events.slice(0, 3)], { relay: 'wss://b.example/' })).toMatchObject({ added: 0 });
    expect(await cache.put(events.slice(0, 5))).toMatchObject({ added: 0 });
    expect(cache.size).toBe(10);
    const filter = { kinds: [9], '#h': ['general'] };
    expect(cache.localSet(filter, 'wss://A.example').map((x) => x.id).sort()).toEqual(events.map((e) => e.id).sort());
    expect(cache.localSet(filter, 'wss://b.example').map((x) => x.id).sort()).toEqual(events.map((e) => e.id).sort());
    expect(cache.localSet(filter, 'wss://c.example')).toEqual([]);
    const reopened = await EventCache.open(store);
    expect(reopened.size).toBe(10);
    expect(reopened.localSet(filter, 'wss://b.example')).toHaveLength(10);
    expect(reopened.localSet(filter)).toHaveLength(10);
  });

  it('answers filters by kind, author, tag and time from memory, a limit keeping the newest (FR013-05)', async () => {
    const cache = await EventCache.open(memoryStore());
    const a = Array.from({ length: 6 }, (_, i) => chat(alice, i, `a${i}`, 'uno'));
    const b = Array.from({ length: 6 }, (_, i) => chat(bob, 10 + i, `b${i}`, 'dos'));
    const note = sign(alice, 1, base + 20, 'nota');
    await cache.put([...a, ...b, note]);
    expect(cache.query({ kinds: [9], authors: [getPublicKey(alice)] }).map((e) => e.content)).toEqual(['a0', 'a1', 'a2', 'a3', 'a4', 'a5']);
    expect(cache.query({ '#h': ['dos'], since: base + 12, until: base + 14 }).map((e) => e.content)).toEqual(['b2', 'b3', 'b4']);
    expect(cache.query({ kinds: [9], limit: 3 }).map((e) => e.content)).toEqual(['b3', 'b4', 'b5']);
    expect(cache.query([{ kinds: [1] }, { ids: [a[0]!.id, a[0]!.id] }]).map((e) => e.content)).toEqual(['a0', 'nota']);
    expect(cache.query({ authors: [getPublicKey(bob)], kinds: [1] })).toEqual([]);
  });

  it('drops the oldest events past the count, byte or age limit and raises the floor (FR013-05)', async () => {
    const store = memoryStore();
    const cache = await EventCache.open(store, { maxEvents: 10 });
    const events = Array.from({ length: 15 }, (_, i) => chat(alice, i * 10, `m${i}`));
    expect(await cache.put(events)).toMatchObject({ added: 15, evicted: 5 });
    expect(cache.query({ kinds: [9] }).map((e) => e.content)).toEqual(events.slice(5).map((e) => e.content));
    expect(cache.floor).toBe(base + 40 + 1);
    // A lower limit applies when the cache is opened again.
    const smaller = await EventCache.open(store, { maxEvents: 4 });
    expect(smaller.query({ kinds: [9] }).map((e) => e.content)).toEqual(['m11', 'm12', 'm13', 'm14']);
    expect(smaller.floor).toBe(base + 100 + 1);

    const size = JSON.stringify(events[0]).length;
    const bytes = await EventCache.open(memoryStore(), { maxBytes: size * 3 + 10 });
    await bytes.put(events);
    expect(bytes.size).toBe(3);
    expect(bytes.stats().bytes).toBeLessThanOrEqual(size * 3 + 10);

    let now = base + 200;
    const aged = await EventCache.open(memoryStore(), { maxAgeSeconds: 100, now: () => now });
    expect(await aged.put(events)).toMatchObject({ added: 5, evicted: 10 });
    expect(aged.query({}).map((e) => e.content)).toEqual(['m10', 'm11', 'm12', 'm13', 'm14']);
    expect(aged.floor).toBe(base + 100);
    now += 30;
    await aged.put([]);
    expect(aged.query({}).map((e) => e.content)).toEqual(['m13', 'm14']);
  });

  it('honours NIP-40 expiration, NIP-09 and NIP-29 deletions (also of events that come later) and replaceable heads (FR013-05)', async () => {
    let now = base + 1000;
    const cache = await EventCache.open(memoryStore(), { now: () => now });
    const expired = sign(alice, 9, base + 1, 'caducado', [['h', 'general'], ['expiration', String(base + 999)]]);
    const expiring = sign(alice, 9, base + 2, 'caduca pronto', [['h', 'general'], ['expiration', String(base + 1100)]]);
    const ephemeral = sign(alice, 20001, base + 3, 'efímero');
    expect(await cache.put([expired, expiring, ephemeral])).toMatchObject({ added: 1, refused: 2 });
    expect(cache.admits(expired)).toBe(false);
    now = base + 1100;
    expect(cache.query({ kinds: [9] })).toEqual([]);
    await cache.put([]);
    expect(cache.has(expiring.id)).toBe(false);

    const mine = chat(alice, 10, 'lo borro yo');
    const theirs = chat(bob, 11, 'no es tuyo');
    const later = chat(alice, 12, 'llega después del borrado');
    await cache.put([mine, theirs]);
    const deletion = sign(alice, 5, base + 20, '', [['h', 'general'], ['e', mine.id], ['e', theirs.id], ['e', later.id]]);
    await cache.put([deletion]);
    expect(cache.has(mine.id)).toBe(false);
    expect(cache.has(theirs.id)).toBe(true); // a kind 5 only deletes its author's own events
    expect(await cache.put([later, mine])).toMatchObject({ added: 0, refused: 2 });
    expect(cache.admits(theirs)).toBe(true);

    // NIP-29 9005, accepted by the group's relay: removes its channel's events, not another channel's.
    const moderated = chat(bob, 30, 'moderado', 'general');
    const elsewhere = chat(bob, 31, 'otro canal', 'otro');
    await cache.put([moderated, elsewhere]);
    await cache.put([sign(alice, 9005, base + 40, '', [['h', 'general'], ['e', moderated.id], ['e', elsewhere.id]])]);
    expect(cache.has(moderated.id)).toBe(false);
    expect(cache.has(elsewhere.id)).toBe(true);

    const v1 = sign(alice, 10009, base + 50, '', [['group', 'general']]);
    const v2 = sign(alice, 10009, base + 60, '', [['group', 'general'], ['group', 'otro']]);
    await cache.put([v2]);
    expect(await cache.put([v1])).toMatchObject({ refused: 1 });
    expect(cache.admits(v1)).toBe(false);
    const v3 = sign(alice, 10009, base + 70, '', []);
    await cache.put([v3]);
    expect(cache.query({ kinds: [10009] }).map((e) => e.id)).toEqual([v3.id]);
  });

  it('keeps one cursor per relay and filter that never moves back, and clear() forgets everything (FR013-05)', async () => {
    const store = memoryStore();
    await store.collection<string>('outbox').put('op', 'otra colección');
    const cache = await EventCache.open(store);
    const filter = { kinds: [1059, 9], '#p': ['x'] };
    expect(await cache.advanceCursor('wss://a.example', filter, base + 100)).toBe(base + 100);
    expect(await cache.advanceCursor('wss://a.example', { ...filter, since: 5 }, base + 50)).toBe(base + 100);
    expect(cache.cursor('wss://A.example/', { '#p': ['x'], kinds: [9, 1059], since: 7, limit: 3 })).toBe(base + 100);
    expect(cache.cursor('wss://b.example', filter)).toBeUndefined();
    expect(filterKey({ kinds: [9, 1059], until: 3 })).toBe(filterKey({ kinds: [1059, 9, 9] }));

    const events: NostrEvent[] = Array.from({ length: 70 }, (_, i) => chat(alice, i, `m${i}`));
    await cache.put(events, { relay: 'wss://a.example' });
    await cache.clear();
    expect(cache.size).toBe(0);
    expect(cache.cursor('wss://a.example', filter)).toBeUndefined();
    expect(await store.raw.keys('evcache:')).toEqual([]);
    expect(await store.raw.keys('evcache-meta:')).toEqual([]);
    expect(await store.collection<string>('outbox').get('op')).toBe('otra colección');
    const reopened = await EventCache.open(store);
    expect(reopened.size).toBe(0);
    expect(reopened.cursors()).toEqual([]);
  });
});
