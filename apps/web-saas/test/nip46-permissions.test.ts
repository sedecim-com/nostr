/**
 * FR004-06: the NIP-46 permissions the web asks a remote signer for are exactly the kinds the web signs with the
 * persona's key. Every signing path the web uses runs here through a signer that records what it is asked to
 * sign: a kind missing from WEB_NIP46_PERMISSIONS would make that action fail with a remote signer, and a kind
 * the web never signs would be a permission it has no use for.
 */
import { describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, getPublicKey, nip98, type EventTemplate, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { buildServerList, prepareBlob, uploadToServers, type HttpClient } from '@sedecim/blossom-client';
import { createPublicLink } from '@sedecim/identity/public-link';
import { MarmotTsProvider, MemoryGroupNetwork, VolatileGroupStorage, type ExtendedGroupSession } from '@sedecim/marmot-adapter';
import { chatMessage, createDirectMessage, createFileMessage, createGroup, createReceipt, deleteEvent, joinRequest, publishDmRelayList, replyMessage } from '@sedecim/messaging';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { LocalSigner, WEB_NIP46_PERMISSIONS } from '@sedecim/signer';
import { TestRelay } from '@sedecim/test-relay';
import { reactionToggle } from '../src/lib/channels';

/** Stands in for a remote (NIP-46) signer and records every kind it is asked to sign. */
class RecordingSigner implements Signer {
  readonly custody = 'external' as const;
  readonly kinds = new Set<number>();
  private readonly inner = new LocalSigner(generateSecretKey());
  getPublicKey() {
    return this.inner.getPublicKey();
  }
  signEvent(t: EventTemplate & { created_at?: number }): Promise<NostrEvent> {
    this.kinds.add(t.kind);
    return this.inner.signEvent(t);
  }
  nip44Encrypt(peer: string, plaintext: string) {
    return this.inner.nip44Encrypt(peer, plaintext);
  }
  nip44Decrypt(peer: string, ciphertext: string) {
    return this.inner.nip44Decrypt(peer, ciphertext);
  }
}

const permitted = new Set(WEB_NIP46_PERMISSIONS.filter((p) => p.startsWith('sign_event:')).map((p) => Number(p.slice('sign_event:'.length))));

describe('NIP-46 permissions of the web (FR004-04, FR004-06)', () => {
  it('covers exactly the kinds the web signs with the persona key', async () => {
    const me = new RecordingSigner();
    const other = new RecordingSigner();
    const peer = getPublicKey(generateSecretKey());

    // Direct messages (NIP-17): text, file and receipt rumors travel in a seal the persona signs.
    await createDirectMessage(me, { recipients: [peer], content: 'hola' });
    await createFileMessage(me, { recipients: [peer], url: 'https://blossom.example/abc', mimeType: 'image/png', sha256: 'ab'.repeat(32), originalSha256: 'cd'.repeat(32), size: 3, encryption: { algorithm: 'aes-gcm', keyHex: '00'.repeat(32), nonceHex: '00'.repeat(12) } });
    await createReceipt(me, peer, 'ef'.repeat(32), 'read');
    await publishDmRelayList(me, ['wss://relay.example']);

    // Channels (NIP-29) and the Blossom server list go through the outbox, which signs their templates.
    for (const t of [chatMessage('g1', 'hola'), createGroup('Redacción', 'open'), joinRequest('g1'), buildServerList(['https://blossom.example'])]) await me.signEvent(t);
    // FR015-04: replies, reactions and their removal, and deletions of channel messages (what the channels view sends).
    const channelMsg = await other.signEvent(chatMessage('g1', 'tema'));
    const channelEntry = { event: channelMsg, reactions: [] };
    const [react] = reactionToggle('g1', channelEntry, '👍');
    const reacted = await me.signEvent(react!);
    for (const t of [replyMessage('g1', 'respuesta', channelMsg), ...reactionToggle('g1', { ...channelEntry, reactions: [{ content: '👍', count: 1, mine: [reacted] }] }, '👍'), deleteEvent('g1', channelMsg.id)]) await me.signEvent(t);
    const http: HttpClient = async (_url, init) => ({ status: 200, headers: {}, body: new TextEncoder().encode(JSON.stringify({ sha256: init.headers!['x-sha-256'], url: 'https://blossom.example/x', size: 3, type: 'application/octet-stream', uploaded: 0 })) });
    await uploadToServers(prepareBlob(new Uint8Array([1, 2, 3]), { encrypt: true }), ['https://blossom.example'], me, { http });

    // HTTP services (NIP-98) and relays that ask for NIP-42.
    await me.signEvent(nip98.buildHttpAuthTemplate('https://id.example/v1/links', 'POST', '{}'));
    const relay = new TestRelay({ requireAuth: true });
    await relay.start();
    const pool = new RelayPool({ webSocketFactory: (u) => new WebSocket(u) as unknown as WebSocketLike, signer: me, authMode: 'on-demand' });
    try {
      await pool.publish(await new LocalSigner(generateSecretKey()).signEvent({ kind: 1, content: 'x' }), [relay.url]);
    } finally {
      pool.close();
      await relay.stop();
    }

    // Public link between two personas of the user (both sign it).
    await createPublicLink(me, other, { confirm: true, acknowledgePermanent: true });

    // Secure groups (Marmot): what the groups view does.
    const network = new MemoryGroupNetwork();
    const provider = new MarmotTsProvider();
    const open = (signer: Signer, deviceId: string) => provider.openSession({ signer, network, storage: new VolatileGroupStorage(), deviceId }) as Promise<ExtendedGroupSession>;
    const [alice, bob, carol] = [await open(me, 'web-alice'), await open(other, 'web-bob'), await open(new RecordingSigner(), 'web-carol')];
    const relays = ['wss://secure.example'];
    await bob.publishKeyPackage(relays);
    await carol.publishKeyPackage(relays);
    const g = await alice.createGroup({ name: 'Redacción', relays });
    for (const s of [bob, carol]) {
      const [kp] = await network.query(relays, [{ kinds: [30443], authors: [s.pubkey], limit: 1 }]);
      await alice.invite(g.groupId, kp!);
    }
    await bob.acceptInvites();
    await carol.acceptInvites();
    await alice.send(g.groupId, 'hola');
    await bob.sync(g.groupId);
    await alice.removeMember(g.groupId, carol.pubkey);
    await bob.sync(g.groupId);
    await bob.leave(g.groupId);
    await alice.publishKeyPackage(relays);

    const signed = new Set([...me.kinds, ...other.kinds]);
    expect([...signed].filter((k) => !permitted.has(k)).sort((a, b) => a - b), 'signed by the web but not in WEB_NIP46_PERMISSIONS').toEqual([]);
    expect([...permitted].filter((k) => !signed.has(k)).sort((a, b) => a - b), 'in WEB_NIP46_PERMISSIONS but never signed by the web').toEqual([]);
  }, 60_000);
});
