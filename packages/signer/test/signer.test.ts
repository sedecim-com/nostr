import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, getPublicKey, verifyEvent } from '@sedecim/nostr-core';
import { NetworkBlockedError, RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { LocalSigner, Nip46Bunker, Nip46Signer, parseBunkerUrl, formatBunkerUrl, createNostrConnect, parseNostrConnect, describePermissions, WEB_NIP46_PERMISSIONS, NOSTR_CONNECT_KIND } from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
const PRIVACY_NETWORK_UNAVAILABLE = 'No enviado: red de privacidad no disponible';

/** A pool whose network policy refuses every connection while `down` is set, as Tor-only does without Tor. */
function policyPool() {
  const state = { down: true };
  const pool = new RelayPool({
    autoReconnect: false,
    webSocketFactory: (url) => {
      if (state.down) throw new NetworkBlockedError(PRIVACY_NETWORK_UNAVAILABLE, url);
      return factory(url);
    },
  });
  return { pool, state };
}

describe('LocalSigner', () => {
  it('signs, encrypts and zeroizes', async () => {
    const a = new LocalSigner(generateSecretKey());
    const b = new LocalSigner(generateSecretKey());
    const evt = await a.signEvent({ kind: 1, content: 'x' });
    expect(verifyEvent(evt)).toBe(true);
    const ct = await a.nip44Encrypt(await b.getPublicKey(), 'hola');
    expect(await b.nip44Decrypt(await a.getPublicKey(), ct)).toBe('hola');
    a.destroy();
    await expect(a.signEvent({ kind: 1, content: 'y' })).rejects.toThrow(/destroyed/);
  });
});

describe('bunker urls', () => {
  it('roundtrips', () => {
    const pk = getPublicKey(generateSecretKey());
    const url = formatBunkerUrl({ remoteSignerPubkey: pk, relays: ['wss://a.example', 'wss://b.example'], secret: 's3' });
    expect(parseBunkerUrl(url)).toEqual({ remoteSignerPubkey: pk, relays: ['wss://a.example', 'wss://b.example'], secret: 's3' });
  });
});

describe('NIP-46 remote signing (FR-004)', () => {
  const relay = new TestRelay();
  let bunkerPool: RelayPool;
  let clientPool: RelayPool;
  const userKey = generateSecretKey();
  const userSigner = new LocalSigner(userKey);
  const log: Array<{ method: string; allowed: boolean; kind?: number }> = [];
  let bunker: Nip46Bunker;

  beforeAll(async () => {
    await relay.start();
    bunkerPool = new RelayPool({ webSocketFactory: factory });
    clientPool = new RelayPool({ webSocketFactory: factory });
    bunker = new Nip46Bunker(userSigner, bunkerPool, [relay.url], { allowedKinds: [1, 14, 13, 22242], onRequest: (i) => log.push(i) });
    await bunker.start();
  });
  afterAll(async () => {
    bunker.stop();
    bunkerPool.close();
    clientPool.close();
    await relay.stop();
  });

  it('signs through the bunker without the client holding the nsec', async () => {
    const remote = new Nip46Signer(await bunker.pointer(), { pool: clientPool, timeoutMs: 5000 });
    await remote.connect();
    expect(await remote.getPublicKey()).toBe(getPublicKey(userKey));
    const evt = await remote.signEvent({ kind: 1, content: 'firmado remotamente' });
    expect(verifyEvent(evt)).toBe(true);
    expect(evt.pubkey).toBe(getPublicKey(userKey));
    const peer = new LocalSigner(generateSecretKey());
    const ct = await remote.nip44Encrypt(await peer.getPublicKey(), 'secreto');
    expect(await peer.nip44Decrypt(evt.pubkey, ct)).toBe('secreto');
    await expect(remote.signEvent({ kind: 0, content: '{}' })).rejects.toThrow(/unauthorized/);
    expect(log.some((l) => l.method === 'sign_event' && l.kind === 0 && !l.allowed)).toBe(true);
    remote.close();
  });

  it('connects from a client-initiated nostrconnect:// offer (FR004-03)', async () => {
    const offer = createNostrConnect({ relays: [relay.url], name: 'Acceso Nostr' });
    const parsed = parseNostrConnect(offer.uri);
    expect(parsed.permissions).toEqual(WEB_NIP46_PERMISSIONS);
    expect(parsed.name).toBe('Acceso Nostr');
    let ready!: () => void;
    const isReady = new Promise<void>((r) => (ready = r));
    const waiting = Nip46Signer.fromNostrConnect(offer, { pool: clientPool, timeoutMs: 5000, onReady: ready });
    await isReady;
    await bunker.acceptNostrConnect(offer.uri);
    const remote = await waiting;
    expect(await remote.getPublicKey()).toBe(getPublicKey(userKey));
    expect(verifyEvent(await remote.signEvent({ kind: 13, content: 'x' }))).toBe(true);
    remote.close();
  });

  it('describes the requested permissions for the user before connecting (FR004-04)', () => {
    const d = describePermissions(['get_public_key', 'sign_event:9', 'sign_event:31337']);
    expect(d.map((x) => x.label)).toEqual(['Conocer tu clave pública', 'Firmar: Mensajes de canal (NIP-29)', 'Firmar: kind 31337']);
    expect(d[1]).toMatchObject({ method: 'sign_event', kind: 9 });
    expect(WEB_NIP46_PERMISSIONS).not.toContain('sign_event');
  });

  it('surfaces auth_url and keeps waiting for the real response (FR004-05)', async () => {
    // A signer that first demands approval in a web page, then answers.
    const transport = new LocalSigner(generateSecretKey());
    const approvalPool = new RelayPool({ webSocketFactory: factory });
    const urls: string[] = [];
    const remote = new Nip46Signer({ remoteSignerPubkey: await transport.getPublicKey(), relays: [relay.url] }, { pool: clientPool, timeoutMs: 1000, onAuthUrl: (u) => urls.push(u) });
    const me = await remote.clientPubkey();
    const sub = approvalPool.subscribe([relay.url], [{ kinds: [NOSTR_CONNECT_KIND], '#p': [await transport.getPublicKey()] }], {
      onevent: async (evt) => {
        const req = JSON.parse(await transport.nip44Decrypt(evt.pubkey, evt.content)) as { id: string };
        const send = async (body: object) =>
          approvalPool.publish(await transport.signEvent({ kind: NOSTR_CONNECT_KIND, content: await transport.nip44Encrypt(me, JSON.stringify({ id: req.id, ...body })), tags: [['p', me]] }), [relay.url]);
        await send({ result: 'auth_url', error: 'https://signer.example/approve/123' });
        await new Promise((r) => setTimeout(r, 1500)); // longer than timeoutMs: the auth window must apply
        await send({ result: getPublicKey(userKey) });
      },
    });
    await new Promise((r) => setTimeout(r, 200));
    expect(await remote.getPublicKey()).toBe(getPublicKey(userKey));
    expect(urls).toEqual(['https://signer.example/approve/123']);
    sub.close();
    remote.close();
    approvalPool.close();
  });

  it('rejects clients with a wrong secret', async () => {
    const p = await bunker.pointer();
    const remote = new Nip46Signer({ ...p, secret: 'wrong' }, { pool: clientPool, timeoutMs: 5000 });
    await expect(remote.connect()).rejects.toThrow(/invalid secret/);
    await expect(remote.getPublicKey()).rejects.toThrow(/unauthorized/);
    remote.close();
  });

  it('drops the sessions of a revoked device and never lets them back (FR024-03)', async () => {
    const pointer = await bunker.pointer();
    const stolen = new Nip46Signer(pointer, { pool: clientPool, timeoutMs: 5000 });
    const other = new Nip46Signer(pointer, { pool: clientPool, timeoutMs: 5000 });
    await stolen.connect();
    await other.connect();
    bunker.bindDevice(await stolen.clientPubkey(), 'dev-phone');
    bunker.bindDevice(await other.clientPubkey(), 'dev-laptop');
    expect(bunker.sessions()).toEqual(expect.arrayContaining([{ clientPubkey: await stolen.clientPubkey(), deviceId: 'dev-phone' }]));
    expect(verifyEvent(await stolen.signEvent({ kind: 1, content: 'antes' }))).toBe(true);

    expect(bunker.revokeDevice('dev-phone')).toEqual([await stolen.clientPubkey()]);
    await expect(stolen.signEvent({ kind: 1, content: 'después' })).rejects.toThrow(/unauthorized/);
    // Neither the old secret nor the new one lets that client key back in.
    await expect(stolen.connect()).rejects.toThrow(/client revoked/);
    expect(bunker.secret).not.toBe(pointer.secret);
    await expect(new Nip46Signer(pointer, { pool: clientPool, timeoutMs: 5000 }).connect()).rejects.toThrow(/invalid secret/);
    const otherPk = await other.clientPubkey();
    expect(() => bunker.bindDevice(otherPk, 'dev-phone')).toThrow(/revoked/);
    // Other devices keep working.
    expect(verifyEvent(await other.signEvent({ kind: 1, content: 'sigue' }))).toBe(true);
    for (const r of [stolen, other]) r.close();
  });

  it('refused by the network policy, a request fails as a block with its reason and listens again once the relays are reachable (FR004-08)', async () => {
    const { pool, state } = policyPool();
    const remote = new Nip46Signer(await bunker.pointer(), { pool, timeoutMs: 5000 });
    try {
      const refused = await remote.connect().then(() => undefined, (e: unknown) => e);
      expect(refused).toBeInstanceOf(NetworkBlockedError);
      expect((refused as Error).message).toBe(PRIVACY_NETWORK_UNAVAILABLE);
      // The privacy network is back: the same signer subscribes again and gets its answers.
      state.down = false;
      await remote.connect();
      expect(await remote.getPublicKey()).toBe(getPublicKey(userKey));
    } finally {
      remote.close();
      pool.close();
    }
  });

  it('concurrent requests share one subscription for the answers (FR004-08)', async () => {
    const pool = new RelayPool({ webSocketFactory: factory });
    let subscriptions = 0;
    const subscribe = pool.subscribe.bind(pool);
    pool.subscribe = (...args) => (subscriptions++, subscribe(...args));
    const remote = new Nip46Signer(await bunker.pointer(), { pool, timeoutMs: 5000 });
    try {
      await Promise.allSettled([remote.connect(), remote.nip44Encrypt(getPublicKey(generateSecretKey()), 'x'), remote.getPublicKey()]);
      expect(subscriptions).toBe(1);
    } finally {
      remote.close();
      pool.close();
    }
  });

  it('a known pubkey is not asked for, and an event signed with another key is refused (FR004-08)', async () => {
    const pointer = await bunker.pointer();
    const known = new Nip46Signer(pointer, { pool: clientPool, timeoutMs: 5000, pubkey: getPublicKey(userKey) });
    const wrong = new Nip46Signer(pointer, { pool: clientPool, timeoutMs: 5000, pubkey: getPublicKey(generateSecretKey()) });
    try {
      await known.connect();
      const asked = log.filter((l) => l.method === 'get_public_key').length;
      expect(await known.getPublicKey()).toBe(getPublicKey(userKey));
      expect(verifyEvent(await known.signEvent({ kind: 1, content: 'como la persona' }))).toBe(true);
      expect(log.filter((l) => l.method === 'get_public_key')).toHaveLength(asked);
      // The signer answers for its own key, which is not the one this persona is: nothing signed by it is used.
      await wrong.connect();
      await expect(wrong.signEvent({ kind: 1, content: 'otra llave' })).rejects.toThrow(/invalid event/);
    } finally {
      known.close();
      wrong.close();
    }
  });

  it('a nostrconnect:// offer no relay can hear the answer to fails at once and is never shown (FR004-08)', async () => {
    const { pool } = policyPool();
    let shown = 0;
    try {
      const blocked = await Nip46Signer.fromNostrConnect(createNostrConnect({ relays: [relay.url] }), { pool, timeoutMs: 5000, onReady: () => shown++ }).then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(blocked).toBeInstanceOf(NetworkBlockedError);
      expect((blocked as Error).message).toBe(PRIVACY_NETWORK_UNAVAILABLE);
    } finally {
      pool.close();
    }
    // A relay that is just unreachable (no policy involved) fails the same way, as a plain error.
    const unreachable = new RelayPool({ webSocketFactory: factory, autoReconnect: false });
    try {
      await expect(Nip46Signer.fromNostrConnect(createNostrConnect({ relays: ['ws://127.0.0.1:1'] }), { pool: unreachable, timeoutMs: 5000, onReady: () => shown++ })).rejects.toThrow(/no relay to hear the signer on/);
    } finally {
      unreachable.close();
    }
    expect(shown).toBe(0);
  });
});
