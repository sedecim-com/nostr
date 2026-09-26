import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { TestRelay } from '@sedecim/test-relay';
import {
  EncryptedGroupStorage,
  GroupCryptoUnavailableError,
  MarmotTsProvider,
  PoolGroupNetwork,
  UnavailableGroupCryptoProvider,
  assertHighSecurity,
  assertRemovalSecrecy,
  decodeValue,
  encodeValue,
  runConformance,
} from '../src/index';

const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;

describe('storage codec', () => {
  it('roundtrips MLS-shaped values', () => {
    const v = { a: new Uint8Array([1, 2]), b: 5n, c: new Map([[1, new Set(['x'])]]), d: [undefined, { e: null }] };
    expect(decodeValue(JSON.parse(JSON.stringify(encodeValue(v))))).toEqual(v);
  });
});

describe('fallback provider', () => {
  it('fails closed without a provider', async () => {
    const p = new UnavailableGroupCryptoProvider();
    await expect(p.openSession()).rejects.toBeInstanceOf(GroupCryptoUnavailableError);
    expect(() => assertHighSecurity(p)).toThrow(/forward secrecy/);
  });
});

describe('Marmot provider (marmot-ts / ts-mls) — FR-025', () => {
  const relay = new TestRelay({ pGatedKinds: [1059] });
  const pools: RelayPool[] = [];
  const backends = new Map<string, MemoryBackend>();

  beforeAll(async () => {
    await relay.start();
  });
  afterAll(async () => {
    pools.forEach((p) => p.close());
    await relay.stop();
  });

  const makeMember = (name: string) => {
    const signer = new LocalSigner(generateSecretKey());
    const pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'auto' });
    pools.push(pool);
    const backend = new MemoryBackend();
    backends.set(name, backend);
    const storage = new EncryptedGroupStorage(EncryptedStore.withKey(backend, new Uint8Array(32).fill(name.charCodeAt(0))));
    return { signer, storage, network: new PoolGroupNetwork(pool, [relay.url]) };
  };

  it('passes the behavioural conformance suite (add, message, remove, PCS rotation)', async () => {
    const provider = new MarmotTsProvider();
    const failures = await runConformance({ provider, makeMember, relays: [relay.url] });
    expect(failures).toEqual([]);
  });

  it('self-test guards against removal-secrecy regressions in the MLS library', async () => {
    await expect(assertRemovalSecrecy()).resolves.toBeUndefined();
  });

  it('relays only ever see ciphertext and MLS secrets are encrypted at rest', async () => {
    const plaintexts = ['hello', 'after removal', 'post rotation'];
    for (const e of relay.events.values()) for (const p of plaintexts) expect(e.content.includes(p)).toBe(false);
    const groupEvents = [...relay.events.values()].filter((e) => e.kind === 445);
    expect(groupEvents.length).toBeGreaterThan(0);
    expect(new Set(groupEvents.map((e) => e.pubkey)).size).toBe(groupEvents.length); // ephemeral signer per message
    for (const backend of backends.values()) {
      expect(backend.data.size).toBeGreaterThan(0);
      for (const [k, v] of backend.data) {
        // entry names are namespace + HMAC(id): group ids / key package refs never appear on disk
        expect(k).toMatch(/^mls-[a-z]+:[0-9a-f]{40}$/);
        expect(Buffer.from(v).toString('utf8')).not.toMatch(/"\$u8"|privatePackage|conformance/);
      }
    }
  });
});
