/**
 * FR015-05: presence (NIP-38) in the web, checked at the relay, which records every EVENT and every REQ it receives.
 * With presence off, in every profile the web opens, nothing of kind 30315 is published or asked for. Once the user
 * turns it on where the profile allows it, the statuses of others ride on the profile lookups (same request, same keys)
 * and a status goes out only when the user publishes one, signed by the persona, on its own relays and connection.
 * Where the profile does not allow it, a configuration that has it on anyway publishes and asks nothing.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EncryptedStore, MemoryBackend, type Vault } from '@sedecim/encrypted-store';
import { DEFAULT_MIRROR_KINDS } from '@sedecim/indexer';
import { STATUS_CLEAR_TTL_SECONDS, USER_STATUS_KIND } from '@sedecim/messaging';
import { bytesToHex, finalizeEvent, generateSecretKey, getPublicKey, getTagValue, toUnsigned, type Filter } from '@sedecim/nostr-core';
import { PRESENCE_TEXTS, preset, type SovereigntyConfig } from '@sedecim/profiles';
import { TestRelay } from '@sedecim/test-relay';
import { clearStatus, loadOwnStatus, PresenceDisabledError, publishStatus } from '../src/lib/presence';
import { lookupChannelAuthors, lookupDmCorrespondents, lookupGroupMembers } from '../src/lib/profiles';
import { createPersona, openPersona, personaConfig } from '../src/lib/session';
import { PersonaBook, type PersonaRecord } from '../src/lib/vault';

const newBook = () => new PersonaBook({ store: EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(7)) } as unknown as Vault);
const asksForStatuses = (filters: Filter[]) => filters.some((f) => f.kinds?.includes(USER_STATUS_KIND));

describe('web: presence per profile (FR015-05)', () => {
  const relay = new TestRelay({ requireAuth: true });
  const second = new TestRelay({ requireAuth: true });
  // Someone else's profile and status on the relays: what a persona with presence on reads along with the profile.
  const other = generateSecretKey();
  const otherPk = getPublicKey(other);
  beforeAll(async () => {
    await relay.start();
    await second.start();
    const now = Math.floor(Date.now() / 1000);
    for (const r of [relay, second]) {
      r.inject(finalizeEvent(toUnsigned({ kind: 0, content: JSON.stringify({ name: 'Lucía' }), tags: [] }, otherPk, now), other));
      r.inject(finalizeEvent(toUnsigned({ kind: USER_STATUS_KIND, content: 'De viaje', tags: [['d', 'general'], ['expiration', String(now + 3600)]] }, otherPk, now), other));
    }
  });
  afterAll(async () => {
    await relay.stop();
    await second.stop();
  });

  it('FR015-05: with presence off, in every profile the web opens, nothing of kind 30315 is published or asked for', async () => {
    const from = { relay: relay.requests.length, second: second.requests.length };
    for (const name of ['convenience', 'private-resilient', 'institutional', 'sovereign'] as const) {
      const book = newBook();
      const p = await createPersona(book, { kind: 'create' }, { label: name, relays: preset(name).quorum > 1 ? [relay.url, second.url] : [relay.url], preset: name });
      const config = personaConfig(p);
      expect(config.presence, name).toBe('off');
      const s = await openPersona(book, p);
      try {
        // Everything of the web that could touch presence: the profile lookups of each view, the status card's own read,
        // and publishing or clearing a status.
        await s.profiles.lookup(s.persona.relays, [s.pubkey]);
        await lookupChannelAuthors(s, [otherPk]);
        await lookupDmCorrespondents(s, [otherPk]);
        await lookupGroupMembers(s, [getPublicKey(generateSecretKey())]);
        expect(await loadOwnStatus(s, config)).toBeUndefined();
        await expect(publishStatus(s, config, 'En una reunión', 3600)).rejects.toBeInstanceOf(PresenceDisabledError);
        await expect(clearStatus(s, config)).rejects.toBeInstanceOf(PresenceDisabledError);
        expect(s.statuses.visible()).toEqual([]);
        expect(s.profiles.get(otherPk)?.name).toBe('Lucía');
      } finally {
        s.close();
      }
    }
    expect([...relay.received, ...second.received].filter((e) => e.kind === USER_STATUS_KIND)).toEqual([]);
    const requests = [...relay.requests.slice(from.relay), ...second.requests.slice(from.second)];
    // The lookups did reach the relays, so the check below is not vacuous.
    expect(requests.length).toBeGreaterThan(0);
    expect(requests.filter(asksForStatuses)).toEqual([]);
  });

  it('FR015-05: once turned on where the profile allows it, statuses ride on the profile request and only the status the user writes goes out', async () => {
    const book = newBook();
    const p = await createPersona(book, { kind: 'create' }, { label: 'Con estado', relays: [relay.url], preset: 'convenience' });
    let config: SovereigntyConfig = { ...personaConfig(p), presence: 'status' };
    const s = await openPersona(book, p, {}, { config: () => config });
    try {
      // The card's own read asks for this persona's own status only.
      const own = relay.requests.length;
      expect(await loadOwnStatus(s, config)).toBeUndefined();
      expect(relay.requests.slice(own).filter(asksForStatuses).every((fs) => fs.every((f) => JSON.stringify(f.authors) === JSON.stringify([p.pubkey])))).toBe(true);
      // One request carries the profiles and the statuses of exactly the same keys: no request of its own, no other key.
      const from = relay.requests.length;
      await lookupChannelAuthors(s, [otherPk]);
      expect(relay.requests.slice(from)).toEqual([[{ kinds: [0], authors: [otherPk] }, { kinds: [USER_STATUS_KIND], authors: [otherPk], '#d': ['general'] }]]);
      expect(s.statuses.get(otherPk)?.text).toBe('De viaje');
      // Opening, reading and looking up published nothing: a status only goes out when the user publishes one.
      expect(relay.received.filter((e) => e.kind === USER_STATUS_KIND && e.pubkey === p.pubkey)).toEqual([]);

      const rec = await publishStatus(s, config, '  En una\nreunión ', 3600);
      expect(rec.state).toBe('REPLICATED');
      const [published, ...more] = relay.query([{ kinds: [USER_STATUS_KIND], authors: [p.pubkey] }]);
      expect(more).toEqual([]);
      expect(published).toMatchObject({ pubkey: p.pubkey, content: 'En una reunión' });
      expect(published!.tags).toEqual([['d', 'general'], ['expiration', String(published!.created_at + 3600)]]);
      expect((await loadOwnStatus(s, config))?.text).toBe('En una reunión');
      await expect(publishStatus(s, config, 'mira https://example.com', 3600)).rejects.toThrow(/link/);

      // Clearing replaces it with an empty status that expires an hour later, dated after it even within the same second.
      await clearStatus(s, config);
      const [cleared, ...rest] = relay.query([{ kinds: [USER_STATUS_KIND], authors: [p.pubkey] }]);
      expect(rest).toEqual([]);
      expect(cleared!.content).toBe('');
      expect(cleared!.created_at).toBeGreaterThan(published!.created_at);
      expect(getTagValue(cleared!, 'expiration')).toBe(String(cleared!.created_at + STATUS_CLEAR_TTL_SECONDS));
      expect(s.statuses.get(p.pubkey)).toBeUndefined();

      // Turned off again in the panel: the next lookups carry no status filter, and nothing more is published.
      config = { ...config, presence: 'off' };
      const again = relay.requests.length;
      await lookupGroupMembers(s, [getPublicKey(generateSecretKey())]);
      expect(relay.requests.length).toBeGreaterThan(again);
      expect(relay.requests.slice(again).filter(asksForStatuses)).toEqual([]);
      await expect(publishStatus(s, config, 'Otra vez', 3600)).rejects.toThrow(PRESENCE_TEXTS.off);
      expect(relay.query([{ kinds: [USER_STATUS_KIND], authors: [p.pubkey] }])).toEqual([cleared]);
    } finally {
      s.close();
    }
  });

  it("FR015-05: a status goes out on its persona's own relays and connection, never through another persona of the browser", async () => {
    const book = newBook();
    const a = await createPersona(book, { kind: 'create' }, { label: 'A', relays: [relay.url], preset: 'convenience' });
    const b = await createPersona(book, { kind: 'create' }, { label: 'B', relays: [second.url], preset: 'convenience' });
    const on = (p: PersonaRecord): SovereigntyConfig => ({ ...personaConfig(p), presence: 'status' });
    const sa = await openPersona(book, a, {}, { config: () => on(a) });
    const sb = await openPersona(book, b, {}, { config: () => on(b) });
    try {
      // Both are open and connected to their relays.
      await sb.profiles.lookup(sb.persona.relays, [sb.pubkey]);
      await publishStatus(sa, on(a), 'Solo A', 3600);
      expect(relay.query([{ kinds: [USER_STATUS_KIND], authors: [a.pubkey] }]).map((e) => e.content)).toEqual(['Solo A']);
      expect(second.received.filter((e) => e.kind === USER_STATUS_KIND)).toEqual([]);
      // Each relay only ever saw its own persona authenticate (NIP-42): the status did not travel over B's connection.
      expect(relay.authedPubkeys).toContain(a.pubkey);
      expect(relay.authedPubkeys).not.toContain(b.pubkey);
      expect(second.authedPubkeys).toContain(b.pubkey);
      expect(second.authedPubkeys).not.toContain(a.pubkey);
    } finally {
      sa.close();
      sb.close();
    }
  });

  it('FR015-05: where the profile does not allow presence (an organization, Tor-only), a configuration that has it on publishes and asks nothing', async () => {
    const book = newBook();
    const p = await createPersona(book, { kind: 'create' }, { label: 'Organización', relays: [relay.url], preset: 'institutional' });
    const config: SovereigntyConfig = { ...personaConfig(p), presence: 'status' };
    const s = await openPersona(book, p, {}, { config: () => config });
    const from = { received: relay.received.length, requests: relay.requests.length };
    try {
      await s.profiles.lookup(s.persona.relays, [s.pubkey, otherPk]);
      expect(await loadOwnStatus(s, config)).toBeUndefined();
      await expect(publishStatus(s, config, 'En el despacho', 3600)).rejects.toThrow(PRESENCE_TEXTS.organization);
      await expect(clearStatus(s, config)).rejects.toBeInstanceOf(PresenceDisabledError);
      expect(relay.requests.length).toBeGreaterThan(from.requests);
      expect(relay.requests.slice(from.requests).filter(asksForStatuses)).toEqual([]);
      expect(relay.received.slice(from.received).filter((e) => e.kind === USER_STATUS_KIND)).toEqual([]);
    } finally {
      s.close();
    }

    // Tor-only: refused before anything, and the browser opens no relay connection for it anyway.
    const sk = generateSecretKey();
    const tor: PersonaRecord = { id: 'tor', label: 'Tor', pubkey: getPublicKey(sk), custody: 'local', secretHex: bytesToHex(sk), relays: [relay.url], preset: 'custom', config: { ...preset('sovereign-tor'), presence: 'status' }, createdAt: 0 };
    const st = await openPersona(book, tor);
    try {
      await expect(publishStatus(st, personaConfig(tor), 'Desde Tor', 3600)).rejects.toThrow(PRESENCE_TEXTS.torOnly);
      expect(await loadOwnStatus(st, personaConfig(tor))).toBeUndefined();
      expect(relay.authedPubkeys).not.toContain(tor.pubkey);
    } finally {
      st.close();
    }
  });

  it('FR015-05: the operator mirror does not copy statuses: kind 30315 is not among the kinds it mirrors by default', () => {
    expect(DEFAULT_MIRROR_KINDS).not.toContain(USER_STATUS_KIND);
  });
});
