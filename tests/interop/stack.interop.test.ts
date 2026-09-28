/**
 * Full-stack checks against the Docker Compose deployment (OPS-01, FR-014, FR-018, FR-017).
 *   docker compose up -d && STACK_INDEXER_URL=http://localhost:8081 BUZZ_RELAY_URL=ws://localhost:3000 \
 *     STACK_BLOB_URL=http://localhost:8085 STACK_WEB_URL=http://localhost:8080 npm run test:interop
 */
import { afterAll, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import WebSocket from 'ws';
import { generateSecretKey, getTagValue } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { chatMessage, createGroup, parseGroupMetadata } from '@sedecim/messaging';
import { BlossomClient, prepareBlob } from '@sedecim/blossom-client';
import { nip98Fetch } from '@sedecim/service-kit';

const RELAY = process.env.BUZZ_RELAY_URL;
const INDEXER = process.env.STACK_INDEXER_URL;
const BLOBS = process.env.STACK_BLOB_URL;
const WEB = process.env.STACK_WEB_URL;
const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;

async function eventually<T>(fn: () => Promise<T | undefined>, ms: number): Promise<T | undefined> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = await fn().catch(() => undefined);
    if (v) return v;
    await new Promise((r) => setTimeout(r, 500));
  }
  return undefined;
}

describe.skipIf(!RELAY || !INDEXER)('stack: mirror follows Buzz (FR-014, FR014-05)', () => {
  const sk = generateSecretKey();
  const signer = new LocalSigner(sk);
  const pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'auto', authTimeoutMs: 1500 });
  afterAll(() => pool.close());

  it('a channel message written to Buzz appears in the mirror API without proprietary Buzz APIs', async () => {
    const create = await signer.signEvent(createGroup(`stack-${Date.now()}`, 'open'));
    expect((await pool.publishTo(create, RELAY!)).ok).toBe(true);
    const meta = await eventually(async () => (await pool.query([RELAY!], [{ kinds: [39000], limit: 200 }], 5000)).map(parseGroupMetadata).find((m) => m?.name === getTagValue(create, 'name')), 20_000);
    expect(meta).toBeDefined();
    const msg = await signer.signEvent(chatMessage(meta!.id, 'mensaje espejado por el stack'));
    expect((await pool.publishTo(msg, RELAY!)).ok).toBe(true);
    const found = await eventually(async () => {
      const res = await nip98Fetch(sk, `${INDEXER}/v1/events?kinds=9&h=${meta!.id}`);
      return res.status === 200 && res.json.events.some((e: { id: string }) => e.id === msg.id) ? res.json : undefined;
    }, 90_000);
    expect(found, 'indexer did not mirror the message').toBeDefined();
    expect(found.meta.find((m: { id: string }) => m.id === msg.id).sensitivity).toBe('channel');

    // FR014-05: the mirror follows Buzz's own NIP-29 lists (signed with the key in its NIP-11 `self`): someone
    // outside the channel reads nothing of it, and a deletion (kind 9005) accepted by Buzz hides the message.
    const outsider = await nip98Fetch(generateSecretKey(), `${INDEXER}/v1/events?kinds=9&h=${meta!.id}`);
    expect(outsider.status).toBe(200);
    expect(outsider.json.events).toEqual([]);
    const del = await signer.signEvent({ kind: 9005, content: '', tags: [['h', meta!.id], ['e', msg.id]] });
    expect((await pool.publishTo(del, RELAY!)).ok).toBe(true);
    const gone = await eventually(async () => {
      const res = await nip98Fetch(sk, `${INDEXER}/v1/events?kinds=9&h=${meta!.id}`);
      return res.status === 200 && !res.json.events.some((e: { id: string }) => e.id === msg.id) ? true : undefined;
    }, 60_000);
    expect(gone, 'the mirror still serves a message deleted with kind 9005').toBe(true);
  }, 200_000);

  it('the mirror API requires NIP-98 in the deployed configuration', async () => {
    expect((await fetch(`${INDEXER}/v1/events?kinds=9`)).status).toBe(401);
  });
});

describe.skipIf(!BLOBS)('stack: encrypted attachments via blob-store (FR-018)', () => {
  it('stores and returns a client-encrypted blob verified by hash', async () => {
    const client = new BlossomClient(BLOBS!, new LocalSigner(generateSecretKey()));
    const blob = prepareBlob(new TextEncoder().encode('adjunto cifrado del stack'), { sanitize: false, encrypt: true });
    const d = await client.upload(blob);
    expect(new TextDecoder().decode(await client.download(d.sha256, { decrypt: blob.encryption! }))).toBe('adjunto cifrado del stack');
  });
});

describe.skipIf(!WEB)('stack: web serves the gate flags (FR-017)', () => {
  it('flags.json matches the committed gate result', async () => {
    const served = await (await fetch(`${WEB}/flags.json`)).json();
    const committed = JSON.parse(readFileSync(new URL('../../infra/web/flags.json', import.meta.url), 'utf8'));
    expect(served.nip17).toEqual(committed.nip17);
  });
});
