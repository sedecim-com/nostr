/**
 * PANEL-06 (§12.2): what expired (NIP-40) or what its author deleted does not stay in the Continuity Vault through the
 * client: a push leaves it out and deletes its archives, a restore ignores it, and the deletions the client could not
 * make wait in its queue for the next run. The format of the archives does not change.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned, type NostrEvent } from '@sedecim/nostr-core';
import { ArchiveVaultClient, archiveEvent, archiveHistory, archiveId, eventLabel, forgetDueArchives, generateArchiveKey, restoreHistory, scheduleArchiveExpiry, type ArchiveForgetQueue } from '@sedecim/continuity';
import { createContinuityVaultApi, MemoryArchiveRepository, MemoryObjectStore } from '../src/index';

const persona = generateSecretKey();
const pubkey = getPublicKey(persona);
const ev = (sk: Uint8Array, kind: number, content: string, tags: string[][] = []): NostrEvent => finalizeEvent(toUnsigned({ kind, content, tags }, getPublicKey(sk)), sk);
/** A gift wrap for the persona (an ephemeral key signs it), with an NIP-40 expiration when given. */
const wrap = (content: string, expiration?: number) => ev(generateSecretKey(), 1059, content, [['p', pubkey], ...(expiration !== undefined ? [['expiration', String(expiration)]] : [])]);

/** An ArchiveForgetQueue in memory (the clients use a Collection of the persona's encrypted store). */
function memoryQueue(): ArchiveForgetQueue & { entries: Map<string, number> } {
  const entries = new Map<string, number>();
  return { entries, all: async () => [...entries].map(([id, value]) => ({ id, value })), put: async (id, due) => void entries.set(id, due), delete: async (id) => void entries.delete(id) };
}

describe('expired and deleted messages in the Continuity Vault (PANEL-06)', () => {
  const repo = new MemoryArchiveRepository();
  const api = createContinuityVaultApi(repo, new MemoryObjectStore(), { name: 'vault-expiration' });
  let base: string;
  beforeAll(async () => {
    base = await api.listen();
  });
  afterAll(() => api.close());
  const account = () => {
    const key = generateArchiveKey();
    return { key, client: new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: key } }) };
  };
  const T = Math.ceil(Date.now() / 1000 / 86_400) * 86_400 + 86_400;

  it('PANEL-06: a push leaves out the expired and the deleted, deletes their archives, and keeps their operations out of the ledger', async () => {
    const { key, client } = account();
    const fleeting = wrap('efímero', T);
    const deleted = wrap('borrado por su autor');
    const channel = ev(persona, 9, 'mensaje de canal', [['h', 'general']]);
    // The automatic copy of each send put them there when they were sent.
    for (const e of [fleeting, deleted, channel]) await archiveEvent(client, key, e);
    const ledger = [fleeting, deleted, channel].map((event, i) => ({ opId: `op-${i}`, state: 'REPLICATED', event }));

    const pushed = await archiveHistory(client, key, { pubkey, events: [fleeting, deleted, channel], ledger, forget: [deleted.id] }, { now: () => T * 1000 });
    expect(pushed).toMatchObject({ events: { uploaded: 0, kept: 1, expired: 1 }, forgotten: 2, snapshots: ['ledger'] });
    const ids = new Set((await client.listAll()).map((a) => a.id));
    expect(ids.has(archiveId(key, eventLabel(fleeting.id)))).toBe(false);
    expect(ids.has(archiveId(key, eventLabel(deleted.id)))).toBe(false);
    expect(ids.has(archiveId(key, eventLabel(channel.id)))).toBe(true);

    const restored = await restoreHistory(client, key, { pubkey, now: () => T * 1000 });
    expect(restored.events.map((e) => e.id)).toEqual([channel.id]);
    expect((restored.ledger!.outbox as Array<{ opId: string }>).map((r) => r.opId)).toEqual(['op-2']);
    // Negative control: the next push keeps what never expired, and deletes nothing more.
    expect(await archiveHistory(client, key, { pubkey, events: [channel] }, { now: () => (T + 3650 * 86_400) * 1000 })).toMatchObject({ events: { kept: 1, expired: 0 }, forgotten: 0 });
  });

  it('PANEL-06: an event that expired after it was pushed is left out of a restore and of the export it feeds', async () => {
    const { key, client } = account();
    const fleeting = wrap('caduca tras guardarlo', T);
    const lasting = wrap('sin caducidad');
    await archiveHistory(client, key, { pubkey, events: [fleeting, lasting], ledger: [{ opId: 'op-f', event: fleeting }, { opId: 'op-l', event: lasting }] }, { now: () => (T - 60) * 1000 });
    const before = await restoreHistory(client, key, { pubkey, now: () => (T - 60) * 1000 });
    expect(before.events.map((e) => e.id).sort()).toEqual([fleeting.id, lasting.id].sort());
    const after = await restoreHistory(client, key, { pubkey, now: () => T * 1000 });
    expect(after.events.map((e) => e.id)).toEqual([lasting.id]);
    expect((after.ledger!.outbox as Array<{ opId: string }>).map((r) => r.opId)).toEqual(['op-l']);
    expect(after.expired).toBe(2); // the archive and its ledger operation
  });

  it('PANEL-06: the deletions the client cannot make yet wait in its queue, and go once the vault answers', async () => {
    const { key, client } = account();
    const pushedLater = wrap('guardado con su caducidad', T);
    const deletedNow = wrap('borrado sin vault a mano');
    for (const e of [pushedLater, deletedNow]) await archiveEvent(client, key, e);
    const queue = memoryQueue();
    await scheduleArchiveExpiry(queue, [pushedLater, ev(persona, 9, 'sin caducidad, no se encola')]);
    expect([...queue.entries]).toEqual([[pushedLater.id, T]]);

    // No vault in this run: the deletion is queued, due now; the expiring one waits for its time.
    expect(await forgetDueArchives(undefined, queue, [deletedNow.id], T - 60)).toEqual({ deleted: 0, queued: 2, next: T });
    expect(queue.entries.get(deletedNow.id)).toBe(0);
    // A vault that does not answer: everything due stays queued.
    const down = new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: key }, fetch: async () => new Response('caído', { status: 503 }) });
    expect(await forgetDueArchives({ client: down, key }, queue, [], T)).toMatchObject({ deleted: 0, queued: 2, error: expect.stringMatching(/503|caído/) });
    expect((await client.listAll()).length).toBe(2);
    // The vault answers: both archives go and the queue empties.
    expect(await forgetDueArchives({ client, key }, queue, [], T)).toEqual({ deleted: 2, queued: 0 });
    expect(await client.listAll()).toEqual([]);
    expect(queue.entries.size).toBe(0);
    // Deleting what the vault no longer holds is not an error.
    expect(await forgetDueArchives({ client, key }, queue, [deletedNow.id], T)).toEqual({ deleted: 0, queued: 0 });
  });

  it('PANEL-06: an expired message is only tried with the vault at hand: what the device stored was queued then, so the queue does not grow with every expiry', async () => {
    const { key, client } = account();
    const stored = wrap('guardado en el vault', T);
    const neverStored = wrap('nunca llegó al vault', T);
    await archiveEvent(client, key, stored);
    const queue = memoryQueue();
    await scheduleArchiveExpiry(queue, [stored]);

    // No vault in this run, then one that does not answer: only what was queued stays, due now.
    expect(await forgetDueArchives(undefined, queue, [stored.id, neverStored.id], T, { remember: false })).toEqual({ deleted: 0, queued: 1 });
    expect([...queue.entries]).toEqual([[stored.id, 0]]);
    const down = new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: key }, fetch: async () => new Response('caído', { status: 503 }) });
    expect(await forgetDueArchives({ client: down, key }, queue, [neverStored.id], T, { remember: false })).toMatchObject({ deleted: 0, queued: 1 });
    expect([...queue.entries]).toEqual([[stored.id, 0]]);
    // The vault answers: the stored copy goes; the other one is tried and is not there.
    expect(await forgetDueArchives({ client, key }, queue, [neverStored.id], T, { remember: false })).toEqual({ deleted: 1, queued: 0 });
    expect(await client.listAll()).toEqual([]);
    expect(queue.entries.size).toBe(0);
  });
});
