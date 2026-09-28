/**
 * FR017-06: the sovereign CLI and the web route NIP-17 DMs the same way. Each side publishes its DM relay list
 * (kind 10050) on its own relay; a DM goes to the recipient's DM relays, never left only on the sender's, and the
 * recipient reads it with its own client. The web code runs here as it does in the browser (lib/session).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EncryptedStore, MemoryBackend, type Vault } from '@sedecim/encrypted-store';
import { BUZZ_PINNED_ADAPTER, DirectMessenger, dmInboxFilter, openDirectMessage } from '@sedecim/messaging';
import { getPublicKey, getTagValue, npubEncode, type NostrEvent } from '@sedecim/nostr-core';
import { SovereignClient } from '@sedecim/sovereign-client';
import { TestRelay } from '@sedecim/test-relay';
import { createPersona, openPersona, publishDmRelays, type PersonaSession } from '../../apps/web-saas/src/lib/session';
import { PersonaBook } from '../../apps/web-saas/src/lib/vault';

const wrapsFor = (relay: TestRelay, pubkey: string) => relay.received.filter((e: NostrEvent) => e.kind === 1059 && getTagValue(e, 'p') === pubkey);

async function replicated(s: PersonaSession, kind: number) {
  for (let i = 0; i < 100; i++) {
    const rec = (await s.engine.list()).find((r) => r.event?.kind === kind);
    if (rec?.state === 'REPLICATED') return rec;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`kind ${kind} was not replicated`);
}

describe('DMs between the web and the sovereign CLI (FR017-06)', () => {
  // Like the reference relays: gift wraps only reach their authenticated recipient.
  const webRelay = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  const cliRelay = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  let cli: SovereignClient;
  let web: PersonaSession;
  let cliPersona: { id: string; pubkey: string };

  beforeAll(async () => {
    await webRelay.start();
    await cliRelay.start();
    // Each side looks the other's lists up on its relays plus the configured discovery relays.
    const book = new PersonaBook({ store: EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(9)) } as unknown as Vault);
    const p = await createPersona(book, { kind: 'create' }, { label: 'Web', relays: [webRelay.url], preset: 'convenience' });
    web = await openPersona(book, p, {}, { discoveryRelays: [cliRelay.url] });
    await publishDmRelays(web);
    await replicated(web, 10050);
    cli = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'web-cli-dm-')), passphrase: 'pass', scryptLogN: 4, discoveryRelays: [webRelay.url], retry: { baseMs: 20, maxMs: 50 } });
    cliPersona = await cli.createPersona({ label: 'CLI', relays: [cliRelay.url] });
    expect((await cli.publishDmRelays(cliPersona.id)).state).toBe('REPLICATED');
  });
  afterAll(async () => {
    web.close();
    cli.close();
    await webRelay.stop();
    await cliRelay.stop();
  });

  it('the CLI writes to the web persona on the web persona DM relays, and the web reads it', async () => {
    const recs = await cli.sendDm(cliPersona.id, npubEncode(web.pubkey), 'hola desde el CLI');
    const toWeb = recs.find((r) => r.meta?.recipient === web.pubkey)!;
    expect(toWeb).toMatchObject({ state: 'REPLICATED', meta: { dmRelaySource: 'dm-relays' } });
    expect(Object.keys(toWeb.relayStatus)).toEqual([webRelay.url]);
    expect(wrapsFor(cliRelay, web.pubkey)).toHaveLength(0);
    // The sender keeps its own copy on its own relays.
    expect(recs.find((r) => r.meta?.recipient === cliPersona.pubkey)).toMatchObject({ state: 'REPLICATED', meta: { dmRelaySource: 'self' } });

    const inbox = await web.pool.query([webRelay.url], [dmInboxFilter(web.pubkey)], 3000);
    const opened = await Promise.all(inbox.map((w) => openDirectMessage(web.signer, w).catch(() => undefined)));
    expect(opened.map((m) => m?.rumor.content)).toContain('hola desde el CLI');
  });

  it('the web writes to the CLI persona on the CLI persona DM relays, and the CLI reads it', async () => {
    const messenger = new DirectMessenger(web.signer, { nip17: true, readReceipts: false }, BUZZ_PINNED_ADAPTER.wrap);
    const { deliveries } = await messenger.send({ recipients: [cliPersona.pubkey], content: 'hola desde la web' }, { pool: web.pool, outbox: web.engine, ownRelays: web.persona.relays, discoveryRelays: web.dmDiscovery, wait: true });
    expect(deliveries.find((d) => d.recipient === cliPersona.pubkey)).toMatchObject({ source: 'dm-relays', relays: [cliRelay.url] });
    expect(wrapsFor(webRelay, cliPersona.pubkey)).toHaveLength(0);
    expect((await cli.inbox(cliPersona.id)).map((m) => m.rumor.content)).toContain('hola desde la web');
  });

  it('a recipient without DM relays gets the wrap on the sender relays, and the record says so', async () => {
    const stranger = getPublicKey(new Uint8Array(32).fill(3));
    const recs = await cli.sendDm(cliPersona.id, stranger, 'sin lista');
    expect(recs.find((r) => r.meta?.recipient === stranger)).toMatchObject({ meta: { dmRelaySource: 'fallback' } });
    expect(wrapsFor(cliRelay, stranger)).toHaveLength(1);
  });
});
