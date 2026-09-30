/**
 * FR006-04: the web publishes a persona's public profile (kind 0) with the persona's own signer, and a pseudonymous
 * persona only by its explicit choice; profiles are shown next to the npub, looked up only where that tells the relays
 * nothing new; avatars never tell a third-party server who is looking. The views are exercised by the browser E2E.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EncryptedStore, MemoryBackend, type Vault } from '@sedecim/encrypted-store';
import { createManagedSignerApi, ManagedSigner, MemoryVault } from '@sedecim/managed-signer';
import { ProfileCache } from '@sedecim/messaging';
import { bytesToHex, finalizeEvent, generateSecretKey, getPublicKey, toUnsigned, type Filter } from '@sedecim/nostr-core';
import { createTestCognito } from '@sedecim/service-kit';
import { LocalSigner } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import { heicWithGps, TestBlossomServer, TestRelay, tinyPng } from '@sedecim/test-relay';
import { authorLabel, loadAvatar, lookupChannelAuthors, lookupDmCorrespondents, lookupGroupMembers, ProfileConsentError, publishProfile, uploadAvatar } from '../src/lib/profiles';
import { createPersona, openPersona, personaConfig, shortNpub, type PersonaSession } from '../src/lib/session';
import { PersonaBook } from '../src/lib/vault';

const newBook = () => new PersonaBook({ store: EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(7)) } as unknown as Vault);
const sha256 = async (b: Uint8Array) => bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', b.slice())));

describe('web: public profile of a persona (FR006-04)', () => {
  const relay = new TestRelay({ requireAuth: true });
  const media = new TestBlossomServer();
  beforeAll(async () => {
    await relay.start();
    await media.start();
  });
  afterAll(async () => {
    await relay.stop();
    await media.stop();
  });
  const profilesOn = (pubkey: string) => relay.query([{ kinds: [0], authors: [pubkey] }]);

  it('a pseudonymous persona publishes nothing without its explicit choice; with it, its own key signs the kind 0 (FR006-04)', async () => {
    const book = newBook();
    const p = await createPersona(book, { kind: 'create' }, { label: 'Seudónima', relays: [relay.url], preset: 'sovereign' });
    const s = await openPersona(book, p);
    try {
      const config = personaConfig(p);
      expect(config.identity).toBe('pseudonymous');
      await expect(publishProfile(s, config, { name: 'Lechuza' })).rejects.toBeInstanceOf(ProfileConsentError);
      expect(profilesOn(p.pubkey)).toEqual([]);

      const rec = await publishProfile(s, config, { name: 'Lechuza', about: 'Hola' }, { acknowledged: true });
      expect(rec.state).toBe('REPLICATED');
      const [evt] = profilesOn(p.pubkey);
      expect(evt).toMatchObject({ kind: 0, pubkey: p.pubkey });
      expect(JSON.parse(evt!.content)).toEqual({ name: 'Lechuza', display_name: 'Lechuza', about: 'Hola' });
      expect(authorLabel(s, p.pubkey)).toBe(`Lechuza · ${shortNpub(p.pubkey)}`);

      // Withdrawing publishes an empty profile, which replaces it even within the same second (it is dated later).
      await publishProfile(s, config, {}, { acknowledged: true });
      expect(profilesOn(p.pubkey)[0]!.created_at).toBeGreaterThan(evt!.created_at);
      expect(profilesOn(p.pubkey).map((e) => e.content)).toEqual(['{}']);
      expect(authorLabel(s, p.pubkey)).toBe(shortNpub(p.pubkey));
      // A configuration the browser cannot honour publishes nothing, acknowledged or not.
      await expect(publishProfile(s, { ...config, network: 'tor-only' }, { name: 'x' }, { acknowledged: true })).rejects.toThrow(/Tor-only/);
    } finally {
      s.close();
    }

    // A linked identity (convenience) publishes when the user asks, with no extra step.
    const q = await createPersona(book, { kind: 'create' }, { label: 'Trabajo', relays: [relay.url], preset: 'convenience' });
    const t = await openPersona(book, q);
    try {
      await publishProfile(t, personaConfig(q), { name: 'Ana del trabajo' });
      expect(JSON.parse(profilesOn(q.pubkey)[0]!.content).name).toBe('Ana del trabajo');
    } finally {
      t.close();
    }
  });

  it('a managed persona signs its profile through the managed-signer, with its own key (FR006-04)', async () => {
    const acceso = createTestCognito();
    const core = new ManagedSigner(new MemoryVault(), {});
    const api = createManagedSignerApi(core, { name: 'ms-profile-test', cognito: acceso.verifier(), logger: createLogger({ write: () => {} }) });
    const baseUrl = await api.listen();
    try {
      const token = async () => acceso.token({ sub: 'ana' });
      const book = newBook();
      const p = await createPersona(book, { kind: 'managed', conn: { baseUrl, token }, consentVersion: 'textos test' }, { label: 'Gestionada', relays: [relay.url], preset: 'convenience' });
      const s = await openPersona(book, p, { baseUrl, token });
      try {
        await publishProfile(s, personaConfig(p), { name: 'Ana gestionada' });
        expect(profilesOn(p.pubkey).map((e) => JSON.parse(e.content).name)).toEqual(['Ana gestionada']);
        expect((await core.usageOf(p.managedKeyId!, `${acceso.issuer}#ana`)).some((u) => u.action === 'sign' && u.kind === 0)).toBe(true);
      } finally {
        s.close();
      }
    } finally {
      await api.close();
    }
  });

  it('looks profiles up only where it tells the relays nothing new: channel authors, DM contacts, group members on request (FR006-04)', async () => {
    const asked: string[][] = [];
    const known = generateSecretKey();
    const pool = {
      query: async (_urls: string[], filters: Filter[]) => {
        asked.push([...(filters[0]!.authors ?? [])]);
        return [finalizeEvent(toUnsigned({ kind: 0, content: JSON.stringify({ name: 'Conocida' }), tags: [] }, getPublicKey(known)), known)];
      },
    };
    const me = getPublicKey(generateSecretKey());
    const [contact, stranger, author, member] = [getPublicKey(known), getPublicKey(generateSecretKey()), getPublicKey(generateSecretKey()), getPublicKey(generateSecretKey())];
    const s = { pubkey: me, persona: { relays: ['wss://relay.example'] }, profiles: new ProfileCache(pool), isContact: async (pk: string) => pk === contact } as unknown as PersonaSession;

    await lookupChannelAuthors(s, [author]);
    expect(asked.pop()).toEqual([author]);
    // Someone who wrote without being a contact is not asked for: that would tell the relays who writes to this persona.
    await lookupDmCorrespondents(s, [contact, stranger]);
    expect(asked.pop()).toEqual([me, contact]);
    expect(authorLabel(s, contact)).toBe(`Conocida · ${shortNpub(contact)}`);
    expect(authorLabel(s, stranger)).toBe(shortNpub(stranger));
    // Group members only when the user asks (the groups view's button).
    await lookupGroupMembers(s, [member]);
    expect(asked.pop()).toEqual([member]);
  });

  it('downloads avatars without cookies, referrer or a token for third-party servers; hash-checked images of at most 1 MB (FR006-04)', async () => {
    const png = tinyPng();
    const hash = await sha256(png);
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const serve = (body: Uint8Array, headers: Record<string, string> = {}) =>
      (async (url: string, init: RequestInit) => {
        calls.push({ url, init });
        return new Response(body.slice(), { status: 200, headers });
      }) as unknown as typeof fetch;

    const blob = await loadAvatar(`https://avatars.example/${hash}.png`, { fetch: serve(png) });
    expect(blob.type).toBe('image/png');
    expect(calls[0]!.init).toEqual({ credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', cache: 'force-cache' });
    await expect(loadAvatar(`https://avatars.example/${'00'.repeat(32)}.png`, { fetch: serve(png) })).rejects.toThrow(/hash mismatch/);
    await expect(loadAvatar('https://avatars.example/a.png', { fetch: serve(new TextEncoder().encode('<svg onload=alert(1)>')) })).rejects.toThrow(/not a JPEG, PNG or WebP/);
    await expect(loadAvatar('https://avatars.example/a.png', { fetch: serve(png, { 'content-length': String(2_000_000) }) })).rejects.toThrow(/too large/);
    await expect(loadAvatar('javascript:alert(1)', { fetch: serve(png) })).rejects.toThrow(/http\(s\)/);

    // A server that wants to know who reads (BUD-01): only the deployment's own media server gets a token.
    const signer = new LocalSigner(generateSecretKey());
    const guarded = new TestBlossomServer();
    guarded.requireGetAuth = true;
    await guarded.start();
    try {
      const other = new TestBlossomServer();
      await other.start();
      try {
        const { uploadToServers, prepareBlob } = await import('@sedecim/blossom-client');
        const up = await uploadToServers(prepareBlob(png, { sanitize: false, mimeType: 'image/png' }), [guarded.url], signer);
        await expect(loadAvatar(up.descriptor.url)).rejects.toThrow(/401/);
        await expect(loadAvatar(up.descriptor.url, { operator: { mediaServer: other.url, signer } })).rejects.toThrow(/401/);
        expect((await loadAvatar(up.descriptor.url, { operator: { mediaServer: guarded.url, signer } })).type).toBe('image/png');
      } finally {
        await other.stop();
      }
    } finally {
      await guarded.stop();
    }
  });

  it('uploads the avatar without its metadata, and refuses what cannot be cleaned (FR006-04)', async () => {
    const book = newBook();
    const p = await createPersona(book, { kind: 'create' }, { label: 'Avatar', relays: [relay.url], preset: 'convenience' });
    const s = await openPersona(book, p);
    try {
      const cfg = { mode: 'self-hosted' as const, relays: [relay.url], buzzMedia: media.url };
      const url = await uploadAvatar(s, cfg, tinyPng('tomada en casa de mi madre'), personaConfig(p));
      const stored = media.blobs.get(url.split('/').pop()!)!;
      expect(stored.type).toBe('image/png');
      expect(Buffer.from(stored.data).includes(Buffer.from('casa de mi madre'))).toBe(false);
      await expect(uploadAvatar(s, cfg, heicWithGps(), personaConfig(p))).rejects.toThrow(/JPEG, PNG o WebP/);
      await expect(uploadAvatar(s, cfg, tinyPng(), { ...personaConfig(p), network: 'tor-only' })).rejects.toThrow(/Tor-only/);
    } finally {
      s.close();
    }
  });
});
