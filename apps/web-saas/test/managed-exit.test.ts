/**
 * FR026-04: leaving managed custody from the web. The file the migration offers carries its npub, so the restore flows
 * accept it. Cancelling without migrating first downloads a backup checked against the persona (with its archive key),
 * then asks for the end of the npub; the key stops signing and the persona leaves this browser.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EncryptedStore, MemoryBackend, type Vault } from '@sedecim/encrypted-store';
import { openArchiveKeyBackup, openKeyBackup, parseKeyBackup } from '@sedecim/identity/key-backup';
import { createManagedSignerApi, ManagedSigner, MemoryVault } from '@sedecim/managed-signer';
import { bytesToHex, generateSecretKey, getPublicKey, nip19, nip49 } from '@sedecim/nostr-core';
import { preset } from '@sedecim/profiles';
import { createTestCognito } from '@sedecim/service-kit';
import { ManagedSignerClient } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import { cancelManagedCustody, managedCancellationBackup, managedExitBackupJson } from '../src/lib/session';
import { PersonaBook, type PersonaRecord } from '../src/lib/vault';

const newBook = () => new PersonaBook({ store: EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(6)) } as unknown as Vault);
const PASSWORD = 'contraseña del respaldo';

describe('leaving managed custody from the web (FR026-04)', () => {
  const acceso = createTestCognito();
  const core = new ManagedSigner(new MemoryVault(), { retentionDays: 30 });
  const api = createManagedSignerApi(core, { name: 'ms-exit-test', cognito: acceso.verifier(), logger: createLogger({ write: () => {} }) });
  // One connection per request: the export's scrypt keeps this single process busy for seconds, and a pooled socket the
  // test server closes meanwhile (Node's 5 s keep-alive) would reset the next request.
  const fresh: typeof fetch = (input, init) => fetch(input, { ...init, headers: { ...(init?.headers as Record<string, string>), connection: 'close' } });
  const conn = () => ({ baseUrl: base, token: async () => acceso.token({ sub: 'ana' }), fetch: fresh });
  let base: string;
  beforeAll(async () => {
    base = await api.listen();
  });
  afterAll(() => api.close());

  /** A managed persona of this browser, as the web records it, with its archive key. */
  const managedPersona = async (book: PersonaBook): Promise<{ persona: PersonaRecord; client: ManagedSignerClient }> => {
    const key = await ManagedSignerClient.createKey(conn(), { consentVersion: 'textos test' });
    const persona: PersonaRecord = {
      id: `p-${key.keyId}`,
      label: 'Gestionada',
      pubkey: key.pubkey,
      custody: 'managed',
      managedKeyId: key.keyId,
      archiveKeyHex: bytesToHex(generateSecretKey()),
      relays: [],
      preset: 'convenience',
      config: { ...preset('convenience'), custody: 'managed' },
      createdAt: Date.now(),
    };
    await book.save(persona);
    return { persona, client: new ManagedSignerClient({ ...conn(), keyId: key.keyId }) };
  };

  it('the migration file carries its npub, so it restores the same key', async () => {
    const book = newBook();
    const { persona, client } = await managedPersona(book);
    const { ncryptsec } = await client.exportForMigration(PASSWORD);
    const json = await managedExitBackupJson(persona, ncryptsec);
    expect(parseKeyBackup(json)).toMatchObject({ format: 'acceso-nostr-key-backup', version: 1, npub: nip19.npubEncode(persona.pubkey) });
    expect((await openKeyBackup(json, PASSWORD)).pubkey).toBe(persona.pubkey);
  });

  it('cancels only after a backup checked against the persona and the end of its npub; the key stops signing everywhere', async () => {
    const book = newBook();
    const { persona, client } = await managedPersona(book);

    await expect(managedCancellationBackup(persona, client, 'corta')).rejects.toThrow(/al menos 12 caracteres/);
    // A key that is not this persona's never becomes its backup.
    const other = { ...persona, pubkey: getPublicKey(generateSecretKey()) };
    await expect(managedCancellationBackup(other, client, PASSWORD)).rejects.toThrow(/no corresponde a esta persona/);

    const json = await managedCancellationBackup(persona, client, PASSWORD);
    expect(parseKeyBackup(json)).toMatchObject({ version: 2, npub: nip19.npubEncode(persona.pubkey) });
    expect((await openKeyBackup(json, PASSWORD)).pubkey).toBe(persona.pubkey);
    expect(bytesToHex(await openArchiveKeyBackup(json, PASSWORD, persona.pubkey))).toBe(persona.archiveKeyHex);
    expect(json).not.toContain(persona.archiveKeyHex!);
    // Exporting the backup does not cancel anything: the key still signs.
    expect((await client.signEvent({ kind: 1, content: 'todavía' })).pubkey).toBe(persona.pubkey);

    const npub = nip19.npubEncode(persona.pubkey);
    await expect(cancelManagedCustody(book, persona, client, npub.slice(-7))).rejects.toThrow(/últimos 8 caracteres/);
    expect(await book.get(persona.id)).toBeDefined();

    const { destroyAfter } = await cancelManagedCustody(book, persona, client, ` ${npub.slice(-8)} `);
    expect(Date.parse(destroyAfter)).toBeGreaterThan(Date.now() + 29 * 86_400_000);
    expect(await book.get(persona.id)).toBeUndefined();
    await expect(client.signEvent({ kind: 1, content: 'después' })).rejects.toThrow(/404/);
    expect((await ManagedSignerClient.closedKeys(conn())).find((k) => k.keyId === persona.managedKeyId)).toMatchObject({ exit: 'cancelled', destroyAfter: Date.parse(destroyAfter) });
    // The backup still opens the key, now as the user's own.
    expect(nip49.decryptKey(parseKeyBackup(json).ncryptsec!, PASSWORD).secretKey).toHaveLength(32);
  });
});
