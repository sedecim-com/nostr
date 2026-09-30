/**
 * Interop gate against the EXACT pinned Buzz build (spec §6.2, §22.1, FR-017).
 *   docker compose up -d relay && BUZZ_RELAY_URL=ws://localhost:3000 npm run test:interop
 * Produces interop-report.json. NIP-17 may only be enabled in production when this report says so.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { writeFileSync } from 'node:fs';
import WebSocket from 'ws';
import { generateSecretKey, getTagValue } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { chatMessage, createGroup, createDirectMessage, deleteEvent, deletion, dmInboxFilter, joinRequest, nip17GateDecision, openDirectMessage, parseGroupMetadata, reaction, replyMessage } from '@sedecim/messaging';
import { BlossomClient, prepareBlob } from '@sedecim/blossom-client';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { tinyPng } from '@sedecim/test-relay';
import { EncryptedGroupStorage, MarmotTsProvider, PoolGroupNetwork, runConformance } from '@sedecim/marmot-adapter';

const URL_ = process.env.BUZZ_RELAY_URL;
const HTTP = URL_?.replace(/^ws/, 'http');
const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;

const report: Record<string, unknown> = { relay: URL_, startedAt: new Date().toISOString() };

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

  // FR015-04: the events the web's channels send for replies, reactions and deletions, against the pinned Buzz. What the
  // web relies on is asserted; the removal of a reaction with kind 5 (NIP-09 is not in Buzz's NIP-11) is only recorded.
  it('FR015-04: replies in threads, reactions and deletions (9005) as the web sends them', async () => {
    const create = await alice.signEvent(createGroup(`interop-collab-${Date.now()}`, 'open'));
    expect((await pa.publishTo(create, URL_!)).ok).toBe(true);
    const meta = await pa.query([URL_!], [{ kinds: [39000], limit: 50 }], 5000);
    const g = meta.map(parseGroupMetadata).find((m) => m && getTagValue(create, 'name') === m.name)?.id;
    expect(g).toBeDefined();
    await pb.publishTo(await bob.signEvent(joinRequest(g!)), URL_!);
    const top = await alice.signEvent(chatMessage(g!, 'tema del hilo'));
    expect((await pa.publishTo(top, URL_!)).ok).toBe(true);

    // Replies: Buzz checks that the root is the parent's thread root (a direct reply and a nested one).
    const reply = await bob.signEvent(replyMessage(g!, 'respuesta', top));
    const replyRes = await pb.publishTo(reply, URL_!);
    const nested = await alice.signEvent(replyMessage(g!, 'respuesta anidada', reply));
    const nestedRes = await pa.publishTo(nested, URL_!);

    // A reaction (NIP-25) that the other member reads by #h, then its removal as the web sends it (kind 5).
    const react = await bob.signEvent(reaction(g!, top, '👍'));
    const reactRes = await pb.publishTo(react, URL_!);
    const reactions = async () => (await pa.query([URL_!], [{ kinds: [7], '#h': [g!] }], 5000)).map((e) => e.id);
    const reactionServed = (await reactions()).includes(react.id);
    const unreactRes = await pb.publishTo(await bob.signEvent(deletion(g!, react)), URL_!);
    const reactionServedAfterKind5 = (await reactions()).includes(react.id);

    // Deletions (9005): by the author, by a member on someone else's message, and by the channel's owner (its creator).
    const bobs = await bob.signEvent(chatMessage(g!, 'mensaje de bob'));
    expect((await pb.publishTo(bobs, URL_!)).ok).toBe(true);
    const byAuthor = await pb.publishTo(await bob.signEvent(deleteEvent(g!, reply.id)), URL_!);
    const byMember = await pb.publishTo(await bob.signEvent(deleteEvent(g!, top.id)), URL_!);
    const byOwner = await pa.publishTo(await alice.signEvent(deleteEvent(g!, bobs.id)), URL_!);
    const served = new Set((await pb.query([URL_!], [{ kinds: [9], '#h': [g!] }], 5000)).map((e) => e.id));

    report.nip29Collaboration = {
      reply: replyRes,
      nestedReply: nestedRes,
      reaction: reactRes,
      reactionServed,
      removeReactionKind5: unreactRes,
      reactionServedAfterKind5,
      delete9005ByAuthor: byAuthor,
      delete9005ByMember: byMember,
      delete9005ByOwner: byOwner,
      servedAfterDeletions: { reply: served.has(reply.id), top: served.has(top.id), bobMessage: served.has(bobs.id) },
    };
    expect(replyRes.ok, replyRes.message).toBe(true);
    expect(nestedRes.ok, nestedRes.message).toBe(true);
    expect(reactRes.ok, reactRes.message).toBe(true);
    expect(reactionServed).toBe(true);
    expect(byAuthor.ok, byAuthor.message).toBe(true);
    expect(byOwner.ok, byOwner.message).toBe(true);
    expect(byMember.ok).toBe(false);
    expect([served.has(reply.id), served.has(bobs.id), served.has(top.id)]).toEqual([false, false, true]);
    expect(unreactRes.ok || unreactRes.message.length > 0, 'a rejection says why').toBe(true);
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
      // Gate decision (FR017-05): standard 2-day jitter as soon as Buzz accepts it (#4192), else the
      // bounded adapter; enabled only with a strategy that is fully accepted AND received.
      ...nip17GateDecision(results, opened.length),
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
  it('records which Marmot kinds the relay accepts (30443 key package, 445 group message, 10051 relay list)', async () => {
    const probe: Record<number, { ok: boolean; message: string }> = {};
    for (const kind of [30443, 445, 10051]) {
      const tags = kind === 30443 ? [['d', 'interop-probe']] : kind === 445 ? [['h', 'ab'.repeat(32)]] : [['relay', URL_!]];
      const res = await pa.publishTo(await alice.signEvent({ kind, content: 'probe', tags }), URL_!);
      probe[kind] = { ok: res.ok, message: res.message };
    }
    report.marmotKinds = probe;
    report.marmotRoute = Object.values(probe).every((p) => p.ok) ? 'buzz' : 'secure-relay';
    expect(Object.keys(probe)).toHaveLength(3);
  });
  // OPS-21: without a DM relay list (FR017-06) on its relay, DMs to a persona go to the sender's relays, and the web
  // and the CLI say delivery is uncertain. The tor-profile check relies on what this records.
  it('records whether the relay takes DM relay lists (kind 10050)', async () => {
    const res = await pa.publishTo(await alice.signEvent({ kind: 10050, content: '', tags: [['relay', URL_!]] }), URL_!);
    report.dmRelayList = { ok: res.ok, message: res.message };
    expect(res.ok || res.message.length > 0, 'a rejection says why').toBe(true);
  });
});

const MARMOT_URL = process.env.MARMOT_RELAY_URL;

describe.skipIf(!MARMOT_URL)('Marmot/MLS conformance on the secure relay', () => {
  it('passes add / message / remove / rotate through a real relay', async () => {
    const pools: RelayPool[] = [];
    const makeMember = (name: string) => {
      const signer = new LocalSigner(generateSecretKey());
      const pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'on-demand' });
      pools.push(pool);
      return { signer, storage: new EncryptedGroupStorage(EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(name.charCodeAt(0)))), network: new PoolGroupNetwork(pool, [MARMOT_URL!]) };
    };
    try {
      const failures = await runConformance({ provider: new MarmotTsProvider(), makeMember, relays: [MARMOT_URL!] });
      writeFileSync('interop-marmot-report.json', JSON.stringify({ relay: MARMOT_URL, provider: new MarmotTsProvider().properties, failures, at: new Date().toISOString() }, null, 2) + '\n');
      expect(failures).toEqual([]);
    } finally {
      pools.forEach((p) => p.close());
    }
  }, 60_000);
});
