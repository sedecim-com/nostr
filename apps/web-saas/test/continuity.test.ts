/**
 * VAULT-02: in the web every persona has an archive key that is not its nsec, its backup file (v2) carries it, a
 * persona whose key lives in a signer backs up the archive key alone, and the delivery ledger is sealed in the
 * browser before it reaches the Continuity Vault.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { archiveOwnerPubkey } from '@sedecim/continuity';
import { createContinuityVaultApi, MemoryArchiveRepository, MemoryObjectStore } from '@sedecim/continuity-vault';
import { EncryptedStore, MemoryBackend, type Vault } from '@sedecim/encrypted-store';
import { openArchiveKeyBackup, openKeyBackup, parseKeyBackup } from '@sedecim/identity/key-backup';
import { bytesToHex, generateSecretKey, getPublicKey, hexToBytes } from '@sedecim/nostr-core';
import { preset } from '@sedecim/profiles';
import { createLogger } from '@sedecim/telemetry-policy';
import { TestRelay } from '@sedecim/test-relay';
import { pushLedger, vaultUsage, verifyVault } from '../src/lib/continuity';
import { backupJson, createPersona, ensureArchiveKey, openPersona, setArchiveKey } from '../src/lib/session';
import { PersonaBook, type PersonaRecord } from '../src/lib/vault';

const newBook = () => new PersonaBook({ store: EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(5)) } as unknown as Vault);

describe('web archive key and Continuity Vault (VAULT-02)', () => {
  const relay = new TestRelay();
  const repo = new MemoryArchiveRepository();
  const objects = new MemoryObjectStore();
  const vault = createContinuityVaultApi(repo, objects, { name: 'vault-web', logger: createLogger({ write: () => {} }) });
  let vaultUrl: string;
  beforeAll(async () => {
    await relay.start();
    vaultUrl = await vault.listen();
  });
  afterAll(async () => {
    await vault.close();
    await relay.stop();
  });

  it('every new persona gets its own archive key, and its backup v2 carries it', async () => {
    const book = newBook();
    const p = await createPersona(book, { kind: 'create' }, { label: 'Web', relays: [relay.url], preset: 'convenience' });
    expect(p.archiveKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(p.archiveKeyHex).not.toBe(p.secretHex);
    const json = await backupJson(p, 'contraseña del backup');
    expect(parseKeyBackup(json)).toMatchObject({ format: 'acceso-nostr-key-backup', version: 2 });
    expect(json).not.toContain(p.archiveKeyHex!);
    const opened = await openKeyBackup(json, 'contraseña del backup');
    expect(bytesToHex(opened.archiveKey!)).toBe(p.archiveKeyHex);

    // Restoring on a new browser keeps the same archive key.
    const other = newBook();
    const restored = await createPersona(other, { kind: 'secret', secretKey: opened.secretKey, archiveKey: opened.archiveKey! }, { label: 'Restaurada', relays: [relay.url], preset: 'convenience' });
    expect(restored.archiveKeyHex).toBe(p.archiveKeyHex);
    // A backup whose archive key is the nsec is refused.
    const sk = generateSecretKey();
    await expect(createPersona(newBook(), { kind: 'secret', secretKey: new Uint8Array(sk), archiveKey: new Uint8Array(sk) }, { label: 'x', relays: [relay.url], preset: 'convenience' })).rejects.toThrow(/must not be the nsec/);
  });

  it('a persona whose key lives in a signer backs up only its archive key, and restores it later', async () => {
    const book = newBook();
    const signerPubkey = getPublicKey(generateSecretKey());
    const legacy: PersonaRecord = { id: 'nip46', label: 'Signer', pubkey: signerPubkey, custody: 'nip46', bunker: `bunker://${'ab'.repeat(32)}?relay=${relay.url}`, relays: [relay.url], preset: 'private-resilient', config: preset('private-resilient'), createdAt: 0 };
    await book.save(legacy);
    // Created before the vault: it gets its key on first use.
    const withKey = await ensureArchiveKey(book, legacy);
    expect(withKey.archiveKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect((await book.get('nip46'))!.archiveKeyHex).toBe(withKey.archiveKeyHex);
    expect(await ensureArchiveKey(book, withKey)).toBe(withKey);

    const json = await backupJson(withKey, 'contraseña del backup');
    const parsed = parseKeyBackup(json);
    expect(parsed.ncryptsec).toBeUndefined();
    const key = await openArchiveKeyBackup(json, 'contraseña del backup', signerPubkey);
    // A new browser opens the persona with its signer (a new archive key) and then restores the backed-up one.
    const fresh = await ensureArchiveKey(book, { ...legacy, id: 'again', archiveKeyHex: undefined });
    expect(fresh.archiveKeyHex).not.toBe(withKey.archiveKeyHex);
    expect((await setArchiveKey(book, fresh, key)).archiveKeyHex).toBe(withKey.archiveKeyHex);
    // A local persona never takes its own nsec as archive key.
    const local = await createPersona(book, { kind: 'create' }, { label: 'Local', relays: [relay.url], preset: 'convenience' });
    await expect(setArchiveKey(book, local, hexToBytes(local.secretHex!))).rejects.toThrow(/must not be the nsec/);
  });

  it('seals the delivery ledger in the browser: the vault keeps no text, and the key opens it again', async () => {
    const book = newBook();
    const p = await createPersona(book, { kind: 'create' }, { label: 'Resiliente', relays: [relay.url], preset: 'convenience' });
    const s = await openPersona(book, p);
    try {
      const rec = await s.engine.submit({ template: { kind: 1, content: 'nota con el número 5512', tags: [] } }, { relays: [relay.url], quorum: 1, wait: true });
      expect(rec.state).toBe('REPLICATED');
      const pushed = await pushLedger(vaultUrl, s);
      expect(pushed.operations).toBe(1);
      expect(await vaultUsage(vaultUrl, p)).toMatchObject({ archives: 1, bytes: pushed.archive.size });
      expect(await verifyVault(vaultUrl, p)).toEqual({ archives: 1, opened: 1 });
      // Another archive key (e.g. a persona that has not restored its key yet) opens nothing.
      expect(await verifyVault(vaultUrl, { ...p, archiveKeyHex: bytesToHex(new Uint8Array(32).fill(1)) })).toEqual({ archives: 0, opened: 0 });

      expect(repo.rows().map((r) => r.owner)).toEqual([`nostr:${archiveOwnerPubkey(hexToBytes(p.archiveKeyHex!))}`]);
      let stored = JSON.stringify(repo.rows());
      for await (const k of objects.list()) stored += new TextDecoder().decode((await objects.get(k))!);
      for (const needle of ['5512', 'nota con', p.pubkey, rec.event!.id, relay.url, 'REPLICATED']) expect(stored, needle).not.toContain(needle);
    } finally {
      s.close();
    }
  });
});
