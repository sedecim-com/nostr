import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { nip77 } from 'nostr-tools';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned, type NostrEvent } from '@sedecim/nostr-core';
import { NegentropyResponder, TestRelay } from '../src/index';

const sk = generateSecretKey();
const pk = getPublicKey(sk);
const mk = (i: number) => finalizeEvent(toUnsigned({ kind: 1, content: `e${i}`, created_at: 1_700_000_000 + i }, pk), sk);

/** Runs a full initiator (nostr-tools) against the responder in memory. */
function reconcile(server: NostrEvent[], client: NostrEvent[]) {
  const storage = new nip77.NegentropyStorageVector();
  for (const e of client) storage.insert(e.created_at, e.id);
  storage.seal();
  const neg = new nip77.Negentropy(storage);
  const responder = new NegentropyResponder(server);
  const need: string[] = [];
  const have: string[] = [];
  let msg: string | null = neg.initiate();
  let rounds = 0;
  while (msg !== null) {
    msg = neg.reconcile(responder.respond(msg), (id) => have.push(id), (id) => need.push(id));
    rounds++;
  }
  return { need: need.sort(), have: have.sort(), rounds };
}

describe('NegentropyResponder (NIP-77 server side)', () => {
  const all = Array.from({ length: 700 }, (_, i) => mk(i));

  it('finds exactly the differences for small and large sets', () => {
    for (const [serverN, skip] of [[0, 1], [5, 2], [40, 3], [700, 7]] as const) {
      const server = all.slice(0, serverN);
      const client = [...server.filter((_, i) => i % skip !== 0), mk(10_000 + serverN)];
      const r = reconcile(server, client);
      expect(r.need).toEqual(server.filter((_, i) => i % skip === 0).map((e) => e.id).sort());
      expect(r.have).toEqual([mk(10_000 + serverN).id]);
    }
  });

  it('answers only the version byte for a different protocol version', () => {
    expect(new NegentropyResponder([]).respond('62')).toBe('61');
  });
});

describe('TestRelay NIP-77 flag', () => {
  const on = new TestRelay({ supportsNegentropy: true, requireAuth: true });
  const off = new TestRelay();

  beforeAll(async () => {
    await on.start();
    await off.start();
  });
  afterAll(async () => {
    await on.stop();
    await off.stop();
  });

  const exchange = (url: string, msg: unknown[]) =>
    new Promise<unknown[]>((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.on('open', () => ws.send(JSON.stringify(msg)));
      ws.on('message', (raw) => {
        const m = JSON.parse(raw.toString()) as unknown[];
        if (m[0] === 'AUTH') return;
        ws.close();
        resolve(m);
      });
      ws.on('error', reject);
    });

  it('is off by default: NEG-OPEN is an unknown verb (NOTICE)', async () => {
    expect(await exchange(off.url, ['NEG-OPEN', 'n1', {}, '6100000200'])).toEqual(['NOTICE', 'unsupported: NEG-OPEN']);
  });

  it('applies the same access rules as REQ (NEG-ERR auth-required)', async () => {
    const m = await exchange(on.url, ['NEG-OPEN', 'n1', { kinds: [1] }, '6100000200']);
    expect(m.slice(0, 2)).toEqual(['NEG-ERR', 'n1']);
    expect(m[2]).toMatch(/^auth-required:/);
  });

  it('advertises 77 in NIP-11 only when enabled', async () => {
    const info = async (r: TestRelay) => (await (await fetch(r.url.replace('ws:', 'http:'), { headers: { accept: 'application/nostr+json' } })).json()) as { supported_nips: number[] };
    expect((await info(on)).supported_nips).toContain(77);
    expect((await info(off)).supported_nips).not.toContain(77);
  });
});
