import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, getPublicKey, verifyEvent } from '@sedecim/nostr-core';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { LocalSigner, Nip46Bunker, Nip46Signer, parseBunkerUrl, formatBunkerUrl, createNostrConnect, parseNostrConnect, describePermissions, WEB_NIP46_PERMISSIONS, NOSTR_CONNECT_KIND } from '../src/index';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;

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
});
