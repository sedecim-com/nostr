import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, getPublicKey, verifyEvent } from '@sedecim/nostr-core';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { LocalSigner, Nip46Bunker, Nip46Signer, parseBunkerUrl, formatBunkerUrl } from '../src/index';

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

  it('rejects clients with a wrong secret', async () => {
    const p = await bunker.pointer();
    const remote = new Nip46Signer({ ...p, secret: 'wrong' }, { pool: clientPool, timeoutMs: 5000 });
    await expect(remote.connect()).rejects.toThrow(/invalid secret/);
    await expect(remote.getPublicKey()).rejects.toThrow(/unauthorized/);
    remote.close();
  });
});
