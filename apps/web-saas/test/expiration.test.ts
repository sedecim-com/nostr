/**
 * PANEL-06 (§12.2): in the web, the expiration of DMs per persona and conversation, sealed in the browser vault; at
 * expiry the browser forgets its copies and their Continuity Vault archives; deleting one's own DM says first what
 * it cannot undo, and the contact's client applies it. The test relay does not honour NIP-40, the vault is the
 * repo's in-memory one, and the clock is injected.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ArchiveVaultClient, archiveId, eventLabel } from '@sedecim/continuity';
import { createContinuityVaultApi, MemoryArchiveRepository, MemoryObjectStore } from '@sedecim/continuity-vault';
import { EncryptedStore, MemoryBackend, type Vault } from '@sedecim/encrypted-store';
import { DirectMessenger, NotYourMessageError, unwrappedExpiration, type DirectMessage } from '@sedecim/messaging';
import { eventExpiration, hexToBytes } from '@sedecim/nostr-core';
import { DM_DELETION_TEXTS } from '@sedecim/profiles';
import { createLogger } from '@sedecim/telemetry-policy';
import { TestRelay } from '@sedecim/test-relay';
import { pushVault } from '../src/lib/continuity';
import { conversationExpiration, dmTombstones, expirationFor, planDmDeletion, purgeExpiredDms, setConversationExpiration, shortestExpiration } from '../src/lib/expiration';
import { createPersona, openDmInbox, openPersona, personaConfig, type PersonaSession } from '../src/lib/session';
import { PersonaBook, type PersonaRecord } from '../src/lib/vault';

function newBook() {
  const backend = new MemoryBackend();
  return { backend, book: new PersonaBook({ store: EncryptedStore.withKey(backend, new Uint8Array(32).fill(6)) } as unknown as Vault) };
}

async function until<T>(fn: () => Promise<T | undefined> | T | undefined, what: string, ms = 5000): Promise<T> {
  for (let t = 0; t < ms; t += 25) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`timed out waiting for ${what}`);
}

const route = (s: PersonaSession) => ({ pool: s.pool, outbox: s.engine, operations: s.dmOperations, ownRelays: s.persona.relays, discoveryRelays: s.dmDiscovery, quorum: 1, wait: true });
const vaultHolds = async (url: string, p: PersonaRecord, eventId: string) => {
  const key = hexToBytes(p.archiveKeyHex!);
  return (await new ArchiveVaultClient({ baseUrl: url, auth: { archiveKey: key } }).listAll()).some((a) => a.id === archiveId(key, eventLabel(eventId)));
};

describe('expiration and deletion of DMs in the web (PANEL-06)', () => {
  const relay = new TestRelay();
  const vault = createContinuityVaultApi(new MemoryArchiveRepository(), new MemoryObjectStore(), { name: 'vault-web-expiration', logger: createLogger({ write: () => {} }) });
  let vaultUrl: string;
  const sessions: PersonaSession[] = [];
  beforeAll(async () => {
    await relay.start();
    vaultUrl = await vault.listen();
  });
  afterAll(async () => {
    for (const s of sessions) (s.engine.stop(), s.close());
    await vault.close();
    await relay.stop();
  });
  const persona = async (label: string) => {
    const { book, backend } = newBook();
    const p = await createPersona(book, { kind: 'create' }, { label, relays: [relay.url], preset: 'convenience' });
    // Convenience copies each send to the vault, best-effort.
    const s = await openPersona(book, p, {}, { continuityVault: vaultUrl });
    sessions.push(s);
    return { book, backend, p, s };
  };

  it('PANEL-06: the conversation’s expiration wins over the persona’s, which wins over the profile’s, sealed in the browser vault', async () => {
    const { book, backend, p } = await persona('Ajustes');
    const contact = 'ab'.repeat(32);
    expect(await conversationExpiration(book.store, p, contact)).toEqual({ option: 'off', source: 'persona' });
    const thirty = { ...p, config: { ...p.config, messageExpiration: '30d' as const } };
    expect(await conversationExpiration(book.store, thirty, contact)).toEqual({ option: '30d', source: 'persona' });
    await setConversationExpiration(book.store, thirty, contact, '7d');
    expect(await conversationExpiration(book.store, thirty, contact)).toEqual({ option: '7d', source: 'conversation', conversation: '7d' });
    expect(await shortestExpiration(book.store, thirty)).toBe('7d');
    await setConversationExpiration(book.store, thirty, contact, 'off');
    expect(await conversationExpiration(book.store, thirty, contact)).toEqual({ option: 'off', source: 'conversation', conversation: 'off' });
    await setConversationExpiration(book.store, thirty, contact, undefined);
    expect(await conversationExpiration(book.store, thirty, contact)).toEqual({ option: '30d', source: 'persona' });
    // A persona stored before PANEL-06 (no value, a customized profile) has none.
    const { messageExpiration: _gone, ...older } = p.config;
    const legacy = { ...p, preset: 'custom' as const, config: older as typeof p.config };
    expect(await conversationExpiration(book.store, legacy, contact)).toEqual({ option: 'off', source: 'profile' });
    expect(personaConfig(legacy).messageExpiration).toBe('off');
    // Sealed: the browser storage holds neither the contact nor the choice in clear.
    await setConversationExpiration(book.store, p, contact, '90d');
    const raw = [...backend.data.entries()].map(([k, v]) => k + new TextDecoder().decode(v)).join('\n');
    expect(raw).not.toContain(contact);
    // In clear the choice would be a JSON `{"expiration":"90d"}`; a bare `90d` is no test: it turns up by chance in the
    // hex names of the sealed entries (and failed this check one run in a few dozen).
    expect(raw).not.toContain('"expiration"');
    expect(raw).not.toContain('"90d"');
  });

  it('PANEL-06: a DM of a conversation with an expiration carries it, and at expiry the browser forgets its copies and their vault archives', async () => {
    const alice = await persona('Alice');
    const bob = await persona('Bob');
    await setConversationExpiration(alice.book.store, alice.p, bob.p.pubkey, '1d');
    const option = (await conversationExpiration(alice.book.store, alice.p, bob.p.pubkey)).option;
    const at = expirationFor(option)!;
    expect(at % 86_400).toBe(0);
    const messenger = new DirectMessenger(alice.s.signer, { nip17: true, readReceipts: false });
    const fleeting = await messenger.sendDmOnce('op-fleeting', { recipients: [bob.p.pubkey], content: 'efímero', expiration: at }, route(alice.s));
    const lasting = await messenger.sendDmOnce('op-lasting', { recipients: [bob.p.pubkey], content: 'permanente', expiration: expirationFor('off') }, route(alice.s));
    for (const d of fleeting.deliveries) expect(eventExpiration(d.record.event!)).toBe(at);
    for (const d of lasting.deliveries) expect(eventExpiration(d.record.event!)).toBeUndefined();
    const wraps = fleeting.deliveries.map((d) => d.record.event!.id);
    // The automatic copy put both wraps of each message in the vault.
    for (const id of wraps) expect(await vaultHolds(vaultUrl, alice.p, id)).toBe(true);

    expect(await purgeExpiredDms(alice.book.store, alice.s, vaultUrl, [], (at - 60) * 1000)).toMatchObject({ operations: 0, outbox: 0, vault: 0, next: at });
    const purged = await purgeExpiredDms(alice.book.store, alice.s, vaultUrl, [], at * 1000);
    expect(purged).toMatchObject({ operations: 1, outbox: 2, vault: 2 });
    expect(purged.wrapIds.sort()).toEqual([...wraps].sort());
    for (const id of wraps) expect(await vaultHolds(vaultUrl, alice.p, id)).toBe(false);
    expect(await alice.s.dmOperations.get('op-fleeting')).toBeUndefined();
    expect((await alice.s.engine.list()).filter((r) => r.groupId === fleeting.rumor.id)).toEqual([]);
    // Negative control: years later, the message without expiration is still here, and in the vault.
    expect(await purgeExpiredDms(alice.book.store, alice.s, vaultUrl, [], (at + 3650 * 86_400) * 1000)).toMatchObject({ operations: 0, outbox: 0, vault: 0 });
    expect((await alice.s.dmOperations.get('op-lasting'))!.rumor.content).toBe('permanente');
    for (const d of lasting.deliveries) expect(await vaultHolds(vaultUrl, alice.p, d.record.event!.id)).toBe(true);

    // Bob's browser, with its clock past the expiration, never shows it, though the relay still serves it.
    const inbox = openDmInbox(bob.book, bob.s, { policy: () => ({ delivered: false, read: false }), now: () => at * 1000 });
    expect((await inbox.sync()).map((m) => m.rumor.content)).toEqual(['permanente']);
    inbox.close();
  });

  it('PANEL-06: deleting says first what it cannot undo and sends nothing before confirm; then the contact’s client applies it and the vault forgets it', async () => {
    const alice = await persona('Alice borra');
    const bob = await persona('Bob lee');
    const sent = await new DirectMessenger(alice.s.signer, { nip17: true, readReceipts: false }).sendDmOnce('op-m', { recipients: [bob.p.pubkey], content: 'me arrepiento' }, route(alice.s));
    const bobInbox = openDmInbox(bob.book, bob.s, { policy: () => ({ delivered: false, read: false }) });
    expect((await bobInbox.sync()).map((m) => m.rumor.id)).toContain(sent.rumor.id);
    const aliceInbox = openDmInbox(alice.book, alice.s, { policy: () => ({ delivered: false, read: false }) });
    const own = (await aliceInbox.sync()).find((m) => m.rumor.id === sent.rumor.id)!; // her copy, read back from the relay
    const wraps = sent.deliveries.map((d) => d.record.event!.id);

    const before = relay.received.length;
    const plan = planDmDeletion(alice.book.store, alice.s, own, { inbox: aliceInbox, vaultUrl });
    // The notice is there before anything is sent: what is asked, what this browser does, and the copies it cannot reach.
    expect(plan.notice).toEqual(expect.arrayContaining([DM_DELETION_TEXTS.request, DM_DELETION_TEXTS.local, DM_DELETION_TEXTS.copies]));
    expect(plan.notice.join(' ')).toMatch(/las copias replicadas pueden seguir existiendo/);
    expect(relay.received.length).toBe(before);
    expect(await alice.s.dmOperations.get(`delete:${sent.rumor.id}`)).toBeUndefined();

    const done = await plan.confirm();
    expect(done.forgotten).toMatchObject({ operations: 1, outbox: 2 });
    expect(done.vault).toBe(2);
    expect(aliceInbox.list().map((m) => m.rumor.id)).not.toContain(sent.rumor.id);
    expect((await alice.s.engine.list()).filter((r) => r.groupId === sent.rumor.id)).toEqual([]);
    for (const id of wraps) {
      expect(await dmTombstones(alice.book.store, alice.p.id).get(`wrap:${id}`)).toBe(true);
      expect(await vaultHolds(vaultUrl, alice.p, id)).toBe(false);
    }
    // Bob's client reads the deletion and removes the message.
    await until(async () => (await bobInbox.sync()).every((m) => m.rumor.id !== sent.rumor.id) || undefined, 'the deletion in Bob’s inbox');
    // The next push of Alice's history leaves her copy out, though the relay still serves it.
    await pushVault(vaultUrl, alice.s, alice.book.store);
    for (const id of wraps) expect(await vaultHolds(vaultUrl, alice.p, id)).toBe(false);
    bobInbox.close();
    aliceInbox.close();
  });

  it('PANEL-06: deleting a message someone else wrote is refused, and nothing is sent', async () => {
    const alice = await persona('Alice recibe');
    const bob = await persona('Bob escribe');
    await new DirectMessenger(bob.s.signer, { nip17: true, readReceipts: false }).sendDmOnce('op-b', { recipients: [alice.p.pubkey], content: 'mío, no tuyo' }, route(bob.s));
    const inbox = openDmInbox(alice.book, alice.s, { policy: () => ({ delivered: false, read: false }) });
    const theirs = (await inbox.sync()).find((m) => m.rumor.content === 'mío, no tuyo') as DirectMessage;
    expect(unwrappedExpiration(theirs)).toBeUndefined();
    const before = relay.received.length;
    expect(() => planDmDeletion(alice.book.store, alice.s, theirs, { inbox, vaultUrl })).toThrow(NotYourMessageError);
    expect(relay.received.length).toBe(before);
    inbox.close();
  });
});
