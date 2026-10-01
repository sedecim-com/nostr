import { describe, expect, it } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey, npubEncode, toUnsigned, type Filter, type NostrEvent } from '@sedecim/nostr-core';
import {
  buildStatus,
  buildStatusClear,
  parseStatus,
  ProfileCache,
  STATUS_CLEAR_TTL_SECONDS,
  STATUS_MAX_CHARS,
  STATUS_MAX_TTL_SECONDS,
  StatusCache,
  statusFilter,
  statusTemplateProblem,
  statusText,
  StatusTextError,
  statusVisible,
  USER_STATUS_KIND,
} from '../src/index';

const sk = generateSecretKey();
const pk = getPublicKey(sk);
const NOW = 1_800_000_000;
const status = (content: string, createdAt: number, tags: string[][] = [['d', 'general'], ['expiration', String(createdAt + 3600)]], key = sk) =>
  finalizeEvent(toUnsigned({ kind: USER_STATUS_KIND, content, tags }, getPublicKey(key), createdAt), key);
const problem = (f: () => unknown) => {
  try {
    f();
  } catch (e) {
    return e instanceof StatusTextError ? e.problem : (e as Error).message;
  }
  return undefined;
};

describe('NIP-38 status this client publishes (FR015-05)', () => {
  it('FR015-05: a status is the general slot and a bounded NIP-40 expiration, nothing else, with the text as the user confirms it', () => {
    const t = buildStatus('  En una\nreunión‮  ', 4 * 3600, NOW);
    expect(t).toEqual({ kind: 30315, content: 'En una reunión', tags: [['d', 'general'], ['expiration', String(NOW + 4 * 3600)]], created_at: NOW });
    expect(statusTemplateProblem(t)).toBeUndefined();
    // The longest lifetime is a day; shorter than a minute or longer than a day is refused, never capped in silence.
    expect(buildStatus('x', STATUS_MAX_TTL_SECONDS, NOW).tags![1]).toEqual(['expiration', String(NOW + 24 * 3600)]);
    expect(() => buildStatus('x', STATUS_MAX_TTL_SECONDS + 1, NOW)).toThrow(RangeError);
    expect(() => buildStatus('x', 59, NOW)).toThrow(RangeError);
    expect(() => buildStatus('x', 3600.5, NOW)).toThrow(RangeError);
  });

  it('FR015-05: the text has at most 100 characters and no links or mentions; it is refused, never cut', () => {
    expect(statusText('a'.repeat(STATUS_MAX_CHARS))).toHaveLength(STATUS_MAX_CHARS);
    expect(problem(() => statusText('a'.repeat(STATUS_MAX_CHARS + 1)))).toBe('too-long');
    // Characters, not UTF-16 units: 100 emoji fit.
    expect([...statusText('🌙'.repeat(STATUS_MAX_CHARS))]).toHaveLength(STATUS_MAX_CHARS);
    for (const linked of ['mira https://example.com', 'en www.example.org', 'ipfs://bafy', 'nostr:npub1qqqqqqqqqqqqqqqq', `con ${npubEncode(pk)}`, 'mailto:ana@example.com', 'geo:19.43,-99.13', 'lightning:lnbc1']) {
      expect(problem(() => statusText(linked)), linked).toBe('link');
    }
    // Times, ratios and plain words are not links.
    for (const plain of ['Reunión de 10:30 a 11:00', 'Ratio 1:2', 'Leyendo el informe v2.pdf', 'Hora: tarde']) expect(statusText(plain)).toBe(plain);
    expect(problem(() => buildStatus(' \n\t ', 3600, NOW))).toBe('empty');
  });

  it('FR015-05: clearing is an empty status that expires an hour later', () => {
    const t = buildStatusClear(NOW);
    expect(t).toEqual({ kind: 30315, content: '', tags: [['d', 'general'], ['expiration', String(NOW + STATUS_CLEAR_TTL_SECONDS)]], created_at: NOW });
    expect(STATUS_CLEAR_TTL_SECONDS).toBe(3600);
    expect(statusTemplateProblem(t)).toBeUndefined();
  });

  it('FR015-05: the validator refuses tags that point to people or places, a missing or far expiration and unsanitized text', () => {
    const ok = buildStatus('Comiendo', 3600, NOW);
    const tags = ok.tags!;
    const withTag = (tag: string[]) => ({ ...ok, tags: [...tags, tag] });
    for (const tag of [['p', pk], ['e', 'ab'.repeat(32)], ['a', `30023:${pk}:x`], ['r', 'https://example.com'], ['d', 'music']]) expect(statusTemplateProblem(withTag(tag)), tag[0]).toMatch(/only tags/);
    expect(statusTemplateProblem({ ...ok, tags: [['d', 'general']] })).toMatch(/only tags/);
    expect(statusTemplateProblem({ ...ok, tags: [['d', 'music'], tags[1]!] })).toMatch(/only tags/);
    expect(statusTemplateProblem({ ...ok, tags: [['d', 'general'], ['expiration', String(NOW + STATUS_MAX_TTL_SECONDS + 1)]] })).toMatch(/must expire/);
    expect(statusTemplateProblem({ ...ok, tags: [['d', 'general'], ['expiration', String(NOW)]] })).toMatch(/must expire/);
    expect(statusTemplateProblem({ ...ok, tags: [['d', 'general'], ['expiration', 'mañana']] })).toMatch(/only tags/);
    const { created_at: _dropped, ...undated } = ok;
    expect(statusTemplateProblem(undated)).toMatch(/created_at/);
    expect(statusTemplateProblem({ ...ok, content: 'dos\nlíneas' })).toMatch(/not sanitized/);
    expect(statusTemplateProblem({ ...ok, content: 'https://example.com' })).toMatch(/refused: link/);
    expect(statusTemplateProblem({ ...ok, kind: 0 })).toMatch(/not a status/);
  });
});

describe('NIP-38 statuses read from others (FR015-05)', () => {
  it('FR015-05: reads the general slot defensively: sanitized and capped text, no other slot, a malformed expiration ignored', () => {
    expect(parseStatus(status('Viajando', NOW))).toMatchObject({ pubkey: pk, text: 'Viajando', createdAt: NOW, expiresAt: NOW + 3600 });
    expect(parseStatus(status('Canción', NOW, [['d', 'music'], ['expiration', String(NOW + 60)]]))).toBeUndefined();
    expect(parseStatus(status('Sin slot', NOW, []))).toBeUndefined();
    expect(parseStatus(status('a\u0000b⁦\nc', NOW))!.text).toBe('a b c');
    expect([...parseStatus(status('x'.repeat(400), NOW))!.text]).toHaveLength(STATUS_MAX_CHARS);
    expect(parseStatus(status('Sin caducidad', NOW, [['d', 'general'], ['expiration', 'pronto']]))!.expiresAt).toBeUndefined();
    // Tags another client added are kept out of what is shown.
    expect(Object.keys(parseStatus(status('Con enlaces', NOW, [['d', 'general'], ['r', 'https://example.com'], ['p', pk]]))!).sort()).toEqual(['createdAt', 'eventId', 'pubkey', 'text']);
    expect(parseStatus({ ...status('x', NOW), kind: 0 })).toBeUndefined();
  });

  it('FR015-05: a status is shown until it expires, never more than a day after it was published, nor when dated ahead or cleared', () => {
    const s = parseStatus(status('Aquí', NOW))!;
    expect(statusVisible(s, NOW + 3599)).toBe(true);
    expect(statusVisible(s, NOW + 3600)).toBe(false);
    const noExpiration = parseStatus(status('Desde otro cliente', NOW, [['d', 'general']]))!;
    expect(statusVisible(noExpiration, NOW + STATUS_MAX_TTL_SECONDS - 1)).toBe(true);
    expect(statusVisible(noExpiration, NOW + STATUS_MAX_TTL_SECONDS)).toBe(false);
    const farExpiration = parseStatus(status('Una semana', NOW, [['d', 'general'], ['expiration', String(NOW + 7 * 86400)]]))!;
    expect(statusVisible(farExpiration, NOW + STATUS_MAX_TTL_SECONDS)).toBe(false);
    expect(statusVisible(parseStatus(status('Del futuro', NOW + 3600))!, NOW)).toBe(false);
    expect(statusVisible(parseStatus(status('', NOW))!, NOW)).toBe(false);
  });

  it('FR015-05: the cache keeps the newest status of each key, a clear hides it, and a key without a status in a lookup is forgotten', () => {
    let now = NOW;
    const cache = new StatusCache(() => now);
    let changes = 0;
    const off = cache.onChange(() => changes++);
    const other = generateSecretKey();
    cache.put(status('Primero', NOW));
    cache.put(status('Segundo', NOW + 10));
    cache.put(status('Viejo', NOW + 5));
    expect(cache.get(pk)?.text).toBe('Segundo');
    cache.put(status('', NOW + 20));
    expect(cache.get(pk)).toBeUndefined();
    expect(cache.latest(pk)?.createdAt).toBe(NOW + 20);
    // A lookup answers for the keys it asked: statuses of keys not asked are ignored, absent ones are forgotten.
    cache.receive([status('De otra', NOW, undefined, other), status('Nuevo', NOW + 30)], [pk]);
    expect(cache.get(pk)?.text).toBe('Nuevo');
    expect(cache.get(getPublicKey(other))).toBeUndefined();
    cache.receive([], [pk]);
    expect(cache.latest(pk)).toBeUndefined();
    expect(changes).toBe(5);
    cache.put(status('Hasta luego', NOW));
    now = NOW + 3600;
    expect(cache.visible()).toEqual([]);
    off();
  });

  it('FR015-05: statuses ride on the profile request, for the same keys; without a companion the request is the profile one', async () => {
    const asked: Filter[][] = [];
    const events: NostrEvent[] = [status('En el tren', Math.floor(Date.now() / 1000))];
    const pool = {
      query: async (_urls: string[], filters: Filter[]) => {
        asked.push(filters);
        return events;
      },
    };
    await new ProfileCache(pool).lookup(['wss://relay.example'], [pk]);
    expect(asked.pop()).toEqual([{ kinds: [0], authors: [pk] }]);

    const statuses = new StatusCache();
    let on = false;
    const profiles = new ProfileCache(pool, { companion: () => (on ? statuses : undefined) });
    await profiles.lookup(['wss://relay.example'], [pk]);
    expect(asked.pop()).toEqual([{ kinds: [0], authors: [pk] }]);
    expect(statuses.get(pk)).toBeUndefined();
    on = true;
    const other = getPublicKey(generateSecretKey());
    await new ProfileCache(pool, { companion: () => (on ? statuses : undefined) }).lookup(['wss://relay.example'], [pk, other]);
    // One request: the profiles and the statuses of exactly the same keys.
    expect(asked).toEqual([[{ kinds: [0], authors: [pk, other] }, statusFilter([pk, other])]]);
    expect(statusFilter([pk])).toEqual({ kinds: [30315], authors: [pk], '#d': ['general'] });
    expect(statuses.get(pk)?.text).toBe('En el tren');
  });
});
