/**
 * FR006-07 (spec §14.1): in the web, before the active persona uses a recipient, an invitee or a file that another
 * persona of this browser already used, the views ask for an explicit confirmation (views/ReuseConfirm.tsx; the
 * browser E2E clicks through it). This is what they ask: the ledger of each persona, in the vault next to its outbox.
 */
import { describe, expect, it } from 'vitest';
import { EncryptedStore, MemoryBackend, type Vault } from '@sedecim/encrypted-store';
import { fileDigest } from '@sedecim/identity/usage';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { recordUse, reuseWarnings } from '../src/lib/compartment';
import { createPersona } from '../src/lib/session';
import { PersonaBook } from '../src/lib/vault';

describe('web: reusing a contact or a file across personas (FR006-07)', () => {
  it('warns the second persona once, naming the first, and keeps only keyed tags in the vault (FR006-07)', async () => {
    const backend = new MemoryBackend();
    const book = new PersonaBook({ store: EncryptedStore.withKey(backend, new Uint8Array(32).fill(6)) } as unknown as Vault);
    const make = (label: string) => createPersona(book, { kind: 'create' }, { label, relays: ['wss://relay.example'], preset: 'convenience' });
    const [work, home] = [await make('Trabajo'), await make('Casa')];
    const contact = getPublicKey(generateSecretKey());
    const fileHash = await fileDigest(new TextEncoder().encode('foto de la reunión'));

    expect(await reuseWarnings(book, work, [{ contact, fileHash }])).toEqual([]);
    await recordUse(book, work, [{ contact, fileHash }]);
    const warnings = await reuseWarnings(book, home, [{ contact, fileHash }]);
    expect(warnings.map((w) => [w.kind, w.label])).toEqual([
      ['contact', 'Trabajo'],
      ['file', 'Trabajo'],
    ]);
    expect(warnings[0]!.message).toMatch(/desde tu persona "Trabajo"/);
    // Several invitees at once: one warning per contact that crosses.
    expect((await reuseWarnings(book, home, [{ contact: getPublicKey(generateSecretKey()) }, { contact }])).map((w) => w.kind)).toEqual(['contact']);

    // Once confirmed and recorded, the same crossing is not asked again; the first persona is never asked.
    await recordUse(book, home, [{ contact, fileHash }]);
    expect(await reuseWarnings(book, home, [{ contact, fileHash }])).toEqual([]);
    expect(await reuseWarnings(book, work, [{ contact, fileHash }])).toEqual([]);

    // A web persona is never high-risk: writing to another persona of this browser is not warned about here (the
    // groups view refuses inviting one).
    expect(await reuseWarnings(book, home, [{ contact: work.pubkey }])).toEqual([]);

    // The vault holds, per persona, a key and one tag per use: never the npub or the file hash.
    const ledger = await book.store.collection<string>(`usage-${work.id}`).all();
    expect(ledger).toHaveLength(3);
    const everything = JSON.stringify([ledger, await book.store.collection<string>(`usage-${home.id}`).all()]) + [...backend.data.values()].map((v) => Buffer.from(v).toString('latin1')).join('');
    expect(everything).not.toContain(contact);
    expect(everything).not.toContain(fileHash);
  });
});
