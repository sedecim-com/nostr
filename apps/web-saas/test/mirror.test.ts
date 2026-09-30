/**
 * FR014-04: the web asks the operator's mirror (services/indexer) for unread counts and search, signed by the persona
 * (NIP-98), only where its profile allows it. Where each channel was read up to stays sealed in this browser's vault:
 * the mirror never receives, nor keeps, that cursor.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { createIndexerApi, GroupAuthorities, MemoryEventRepository, type IndexerPolicy } from '@sedecim/indexer';
import { CHANNEL_MIRROR_TEXTS, preset } from '@sedecim/profiles';
import { LocalSigner } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import { ChannelReadState, countUnread, MirrorClient, MirrorError, mirrorAvailability, refreshesInBackground, unreadLabel } from '../src/lib/mirror';

const silent = createLogger({ write: () => {} });
const t0 = Math.floor(Date.now() / 1000);
const relaySk = generateSecretKey();
const [meSk, otherSk] = [generateSecretKey(), generateSecretKey()];
const me = getPublicKey(meSk);
const sign = (sk: Uint8Array, kind: number, content: string, tags: string[][], created_at: number) => finalizeEvent(toUnsigned({ kind, content, tags, created_at }, getPublicKey(sk)), sk);
const members = (h: string, who: Uint8Array[]) => sign(relaySk, 39002, '', [['d', h], ...who.map((sk) => ['p', getPublicKey(sk), '', 'member'])], t0 - 1000);
const newStore = () => EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(7));

/** fetch that records what reaches the mirror. */
function recorder() {
  const seen: Array<{ url: string; authorization: string }> = [];
  const doFetch: typeof fetch = async (input, init) => {
    seen.push({ url: String(input), authorization: String((init?.headers as Record<string, string> | undefined)?.authorization ?? '') });
    return fetch(input, init);
  };
  return { seen, doFetch };
}
const authEvent = (authorization: string) => JSON.parse(Buffer.from(authorization.slice('Nostr '.length), 'base64').toString('utf8')) as NostrEvent;

describe('channels through the mirror in the web (FR014-04)', () => {
  const repo = new MemoryEventRepository();
  const groups = new GroupAuthorities([getPublicKey(relaySk)]);
  // As deployed: NIP-98 on every read.
  const api = createIndexerApi(repo, { name: 'mirror-web', groups, requireAuth: true, logger: silent });
  let base: string;
  const put = (...events: NostrEvent[]) => Promise.all(events.map((e) => repo.upsert(e, 'ws://relay')));

  beforeAll(async () => {
    base = await api.listen();
    // The persona is in 'general' but not in 'ops' (relay-signed NIP-29 lists).
    await put(members('general', [meSk, otherSk]), members('ops', [otherSk]));
    await put(sign(otherSk, 9, 'hola a todos', [['h', 'general']], t0 - 100), sign(otherSk, 9, 'segundo aviso', [['h', 'general']], t0 - 50), sign(meSk, 9, 'hola, soy yo', [['h', 'general']], t0 - 40), sign(otherSk, 9, 'hola en ops', [['h', 'ops']], t0 - 30));
  });
  afterAll(() => api.close());

  it('FR014-04: only where the deployment has a mirror and the profile allows it, and it says why not', () => {
    expect(mirrorAvailability(undefined, preset('convenience'))).toEqual({ state: 'hidden' });
    expect(mirrorAvailability(base, preset('convenience'))).toEqual({ state: 'available' });
    expect(mirrorAvailability(base, preset('institutional'))).toEqual({ state: 'available' });
    for (const p of ['private-resilient', 'sovereign'] as const) expect(mirrorAvailability(base, preset(p))).toEqual({ state: 'disabled', reason: CHANNEL_MIRROR_TEXTS.pseudonymous });
    expect(mirrorAvailability(base, { ...preset('convenience'), network: 'tor-only' })).toEqual({ state: 'disabled', reason: CHANNEL_MIRROR_TEXTS.torOnly });
    // A signer that may ask to approve every signature is never used in the background.
    expect([refreshesInBackground('local'), refreshesInBackground('managed'), refreshesInBackground('nip07'), refreshesInBackground('nip46')]).toEqual([true, true, false, false]);
  });

  it('FR014-04: unread counts via NIP-98 against a cursor that stays sealed in the vault', async () => {
    const { seen, doFetch } = recorder();
    const client = new MirrorClient(base, new LocalSigner(meSk), doFetch);
    const state = new ChannelReadState(newStore(), 'a1');

    // Only the channel the persona is in, without its own message. An id the indexer would refuse is not asked.
    let recent = await client.recent(['general', 'ops', 'x'.repeat(300), 'a,b'], { kinds: [9] });
    expect([...recent]).toEqual([['general', [t0 - 50, t0 - 100]]]);
    // Never counted in this browser: the channel starts read.
    expect(countUnread(recent, await state.cursors([...recent.keys()], t0)).get('general')).toEqual({ count: 0, more: false });

    await put(sign(otherSk, 9, 'nuevo uno', [['h', 'general']], t0 + 10), sign(otherSk, 9, 'nuevo dos', [['h', 'general']], t0 + 20));
    recent = await client.recent(['general', 'ops'], { kinds: [9] });
    expect(countUnread(recent, await state.cursors(['general'], t0 + 30)).get('general')).toEqual({ count: 2, more: false });
    // Reading the channel moves the cursor here only.
    expect(await state.markRead('general', t0 + 20, t0 + 30)).toBe(t0 + 20);
    expect(countUnread(recent, await state.cursors(['general'])).get('general')).toEqual({ count: 0, more: false });

    // What reached the mirror: channel ids, kinds and limit, signed by the persona for that exact URL; never a cursor.
    expect(seen.length).toBe(2);
    for (const r of seen) {
      const u = new URL(r.url);
      expect(u.pathname).toBe('/v1/unread/recent');
      expect(Object.fromEntries(u.searchParams)).toEqual({ h: 'general,ops', kinds: '9', limit: '100' });
      expect(authEvent(r.authorization)).toMatchObject({ kind: 27235, pubkey: me, tags: expect.arrayContaining([['u', r.url], ['method', 'GET']]) });
    }
    // The mirror keeps no cursor of the persona (its read_cursors, FR014-03, stay empty).
    expect(await repo.readCursors(me, ['general'])).toEqual({ general: 0 });
  });

  it('FR014-04: a channel with more unread messages than the mirror lists shows «N+»', async () => {
    const client = new MirrorClient(base, new LocalSigner(meSk));
    const recent = await client.recent(['general'], { kinds: [9], limit: 2 });
    const counts = countUnread(recent, new Map([['general', t0 - 200]]), 2);
    expect(counts.get('general')).toEqual({ count: 2, more: true });
    expect(unreadLabel(counts.get('general')!)).toBe('2+');
    expect(unreadLabel({ count: 3, more: false })).toBe('3');
  });

  it('FR014-04: the cursor never moves back nor past now, is per persona and is sealed at rest', async () => {
    const backend = new MemoryBackend();
    const store = EncryptedStore.withKey(backend, new Uint8Array(32).fill(8));
    const a = new ChannelReadState(store, 'a1');
    const b = new ChannelReadState(store, 'b2');
    expect(await a.markRead('general', 500, 1000)).toBe(500);
    expect(await a.markRead('general', 400, 1000)).toBe(500);
    // A message dated in the future cannot mark as read what arrives before that date.
    expect(await a.markRead('general', 5000, 1000)).toBe(1000);
    // Updates at once still end at the newest.
    await Promise.all([a.markRead('dev', 10, 100), a.markRead('dev', 30, 100), a.markRead('dev', 20, 100)]);
    expect((await a.cursors(['dev'], 100)).get('dev')).toBe(30);
    // Another persona of the same vault has its own.
    expect((await b.cursors(['general'], 2000)).get('general')).toBe(2000);
    const raw = [...backend.data].map(([k, v]) => k + Buffer.from(v).toString('latin1')).join('\n');
    for (const clear of ['general', 'dev', '1000']) expect(raw).not.toContain(clear);
  });

  it('FR014-04: search via NIP-98 only returns verified messages of the channels the persona may read', async () => {
    const { seen, doFetch } = recorder();
    const client = new MirrorClient(base, new LocalSigner(meSk), doFetch);
    const hits = await client.search('hola', { kinds: [9] });
    expect(hits.map((h) => [h.channel, h.event.content])).toEqual([
      ['general', 'hola, soy yo'],
      ['general', 'hola a todos'],
    ]);
    // The text searched does reach the operator, as the disclosure says.
    expect(new URL(seen[0]!.url).searchParams.get('q')).toBe('hola');

    // The mirror is a copy of signed events: an altered one, or one outside a channel, is dropped.
    const valid = hits[0]!.event;
    const note = sign(otherSk, 9, 'hola sin canal', [], t0);
    const lying = new MirrorClient(base, new LocalSigner(meSk), async () => new Response(JSON.stringify({ events: [{ ...valid, content: 'hola alterado' }, note, valid] })));
    expect((await lying.search('hola')).map((h) => h.event.id)).toEqual([valid.id]);
  });

  it('FR014-04: in an organization the policy decides too: a denied channel gets no count', async () => {
    const policy: IndexerPolicy = { evaluate: async (i) => ({ allow: i.resourceId !== 'general', reasons: [] }) };
    const institutional = createIndexerApi(repo, { name: 'mirror-web-policy', groups, policy, logger: silent });
    const url = await institutional.listen();
    try {
      const client = new MirrorClient(url, new LocalSigner(meSk));
      expect([...(await client.recent(['general', 'ops'], { kinds: [9] })).keys()]).toEqual([]);
      expect(await client.search('hola')).toEqual([]);
    } finally {
      await institutional.close();
    }
  });

  it('FR014-04: says why the mirror did not answer', async () => {
    // A device clock an hour behind: the mirror refuses the NIP-98 signature as stale.
    const inner = new LocalSigner(meSk);
    const skewed: Signer = { custody: 'local', getPublicKey: () => inner.getPublicKey(), signEvent: (t) => inner.signEvent({ ...t, created_at: t0 - 3600 }), nip44Encrypt: (p, x) => inner.nip44Encrypt(p, x), nip44Decrypt: (p, x) => inner.nip44Decrypt(p, x) };
    const err = await new MirrorClient(base, skewed).recent(['general']).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MirrorError);
    expect(err).toMatchObject({ status: 401, message: expect.stringMatching(/rechazó la firma NIP-98/) });
    const down = await new MirrorClient(base, new LocalSigner(meSk), async () => Promise.reject(new TypeError('fetch failed'))).search('hola').catch((e: unknown) => e);
    expect(down).toMatchObject({ status: 0, message: 'No se pudo contactar con el mirror.' });
  });
});
