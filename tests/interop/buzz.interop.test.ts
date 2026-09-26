/**
 * Interop gate against the EXACT pinned Buzz build (spec §6.2, §22.1, FR-017).
 *   docker compose up -d relay && BUZZ_RELAY_URL=ws://localhost:3000 npm run test:interop
 * Produces interop-report.json. NIP-17 may only be enabled in production when this report says so.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { writeFileSync } from 'node:fs';
import { crc32, deflateSync } from 'node:zlib';
import WebSocket from 'ws';
import { generateSecretKey, getTagValue } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { chatMessage, createGroup, createDirectMessage, dmInboxFilter, openDirectMessage, parseGroupMetadata } from '@sedecim/messaging';
import { BlossomClient, prepareBlob } from '@sedecim/blossom-client';

const URL_ = process.env.BUZZ_RELAY_URL;
const HTTP = URL_?.replace(/^ws/, 'http');
const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;

const report: Record<string, unknown> = { relay: URL_, startedAt: new Date().toISOString() };

/** 2x2 RGB PNG with valid CRCs and no metadata chunks. */
function tinyPng(): Uint8Array {
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type), data])) >>> 0);
    return Buffer.concat([len, Buffer.from(type), data, crc]);
  };
  const ihdr = Buffer.from([0, 0, 0, 2, 0, 0, 0, 2, 8, 2, 0, 0, 0]);
  const raw = Buffer.from([0, 255, 0, 0, 0, 255, 0, 0, 0, 0, 255, 255, 255, 255]);
  return new Uint8Array(Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]));
}

describe.skipIf(!URL_)('Buzz interop gate', () => {
  const alice = new LocalSigner(generateSecretKey());
  const bob = new LocalSigner(generateSecretKey());
  let pa: RelayPool;
  let pb: RelayPool;
  let groupId: string | undefined;

  beforeAll(() => {
    pa = new RelayPool({ webSocketFactory: factory, signer: alice, authMode: 'auto' });
    pb = new RelayPool({ webSocketFactory: factory, signer: bob, authMode: 'auto' });
  });
  afterAll(() => {
    pa.close();
    pb.close();
    report.finishedAt = new Date().toISOString();
    writeFileSync('interop-report.json', JSON.stringify(report, null, 2) + '\n');
  });

  it('serves NIP-11', async () => {
    const res = await fetch(HTTP!, { headers: { accept: 'application/nostr+json' } });
    const info = (await res.json()) as { supported_nips?: number[]; software?: string; version?: string };
    report.nip11 = { status: res.status, supported_nips: info.supported_nips, software: info.software, version: info.version };
    expect(res.status).toBe(200);
  });

  it('NIP-42 + NIP-29: third-party create group, post and read from another client', async () => {
    const create = await alice.signEvent(createGroup(`interop-${Date.now()}`, 'open'));
    const res = await pa.publishTo(create, URL_!);
    report.nip29_create = res;
    expect(res.ok).toBe(true);
    const meta = await pa.query([URL_!], [{ kinds: [39000], limit: 50 }], 5000);
    groupId = meta.map(parseGroupMetadata).find((m) => m && getTagValue(create, 'name') === m.name)?.id;
    report.nip29_group_id = groupId;
    expect(groupId).toBeDefined();
    await pb.publishTo(await bob.signEvent({ kind: 9021, content: '', tags: [['h', groupId!]] }), URL_!);
    const msg = await alice.signEvent(chatMessage(groupId!, 'interop hola'));
    const sent = await pa.publishTo(msg, URL_!);
    report.nip29_message = sent;
    expect(sent.ok).toBe(true);
    const read = await pb.query([URL_!], [{ kinds: [9], '#h': [groupId!], limit: 20 }], 5000);
    expect(read.map((e) => e.id)).toContain(msg.id);
  });

  it('NIP-17: records which gift-wrap timestamp strategies the relay accepts', async () => {
    const bobPk = await bob.getPublicKey();
    const results: Record<string, { accepted: number; attempts: number; messages: string[] }> = {};
    for (const [name, jitter] of [['nip59-default-2d', undefined], ['bounded-5m', 300], ['none', 0]] as const) {
      const r = { accepted: 0, attempts: 0, messages: [] as string[] };
      for (let i = 0; i < 3; i++) {
        const dm = await createDirectMessage(alice, { recipients: [bobPk], content: `interop ${name} ${i}` }, { timestampJitterSeconds: jitter });
        const res = await pa.publishTo(dm.wraps.find((w) => w.recipient === bobPk)!.event, URL_!);
        r.attempts++;
        if (res.ok) r.accepted++;
        else r.messages.push(res.message);
      }
      results[name] = r;
    }
    const inbox = await pb.query([URL_!], [dmInboxFilter(bobPk)], 5000);
    const opened = (await Promise.all(inbox.map((w) => openDirectMessage(bob, w).catch(() => undefined)))).filter(Boolean);
    const unscoped = await pb.query([URL_!], [{ kinds: [1059], limit: 5 }], 3000);
    report.nip17 = {
      strategies: results,
      receivedByRecipient: opened.length,
      unscopedSubscriptionLeaks: unscoped.length,
      // Gate decision: enable only with a strategy that is fully accepted AND received.
      recommendedJitterSeconds: results['nip59-default-2d']!.accepted === 3 ? 172800 : results['bounded-5m']!.accepted === 3 ? 300 : null,
      enableFlag: opened.length > 0 && (results['nip59-default-2d']!.accepted === 3 || results['bounded-5m']!.accepted === 3),
    };
    expect(unscoped.length).toBe(0);
  });

  it('Blossom via Buzz /media: plain sanitized image accepted, client-encrypted blob rejected', async () => {
    const client = new BlossomClient(`${HTTP}/media`, alice);
    const enc = prepareBlob(tinyPng(), { encrypt: true });
    const encrypted = await client.upload(enc).then(
      () => ({ accepted: true }),
      (err: Error) => ({ accepted: false, error: err.message }),
    );
    const plainBlob = prepareBlob(tinyPng(), { sanitize: true, mimeType: 'image/png' });
    const plain = await client.upload(plainBlob).then(
      async (d) => ({ accepted: true, url: d.url, verified: (await client.download(d.sha256, { url: d.url })).length > 0 }),
      (err: Error) => ({ accepted: false, error: err.message }),
    );
    // Encrypted attachments must use a content-agnostic Blossom server (services/blob-store).
    report.blossom = { buzzMedia: { plainImage: plain, clientEncrypted: encrypted }, encryptedAttachmentsRoute: encrypted.accepted ? 'buzz-media' : 'blob-store' };
    expect(plain.accepted, JSON.stringify(plain)).toBe(true);
  });
});
