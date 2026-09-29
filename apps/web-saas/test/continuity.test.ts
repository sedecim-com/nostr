/**
 * VAULT-02: in the web every persona has an archive key that is not its nsec, its backup file (v2) carries it, and a
 * persona whose key lives in a signer backs up the archive key alone. VAULT-03: the persona's history (canonical
 * events, group chat, ledger, MLS state) is sealed in the browser before it reaches the Continuity Vault, and a clean
 * browser with nothing but the backup gets it back with empty relays.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { archiveOwnerPubkey } from '@sedecim/continuity';
import { createContinuityVaultApi, MemoryArchiveRepository, MemoryObjectStore } from '@sedecim/continuity-vault';
import { EncryptedStore, MemoryBackend, type Vault } from '@sedecim/encrypted-store';
import { openArchiveKeyBackup, openKeyBackup, parseKeyBackup } from '@sedecim/identity/key-backup';
import { bytesToHex, generateSecretKey, getPublicKey, hexToBytes } from '@sedecim/nostr-core';
import { preset } from '@sedecim/profiles';
import { createLogger } from '@sedecim/telemetry-policy';
import { LocalSigner } from '@sedecim/signer';
import { TestRelay } from '@sedecim/test-relay';
import { CONTINUITY_HELD } from '@sedecim/delivery-engine';
import { createServer } from 'node:net';
import { createDirectMessage } from '@sedecim/messaging';
import { pushVault, restoreVault, vaultUsage, verifyVault } from '../src/lib/continuity';
import { GroupHistory } from '../src/lib/groups';
import { backupJson, createPersona, ensureArchiveKey, openPersona, publishDmRelays, setArchiveKey } from '../src/lib/session';
import { PersonaBook, type PersonaRecord } from '../src/lib/vault';

const newBook = () => new PersonaBook({ store: EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(5)) } as unknown as Vault);

/** A local port nobody listens on (yet). */
async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', () => r()));
  const { port } = probe.address() as { port: number };
  await new Promise<void>((r) => probe.close(() => r()));
  return port;
}

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
    // VAULT-04: a stale copy of the persona (made before the vault copy of a send made its key) gets that key, not a new one.
    expect((await ensureArchiveKey(book, legacy)).archiveKeyHex).toBe(withKey.archiveKeyHex);

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

  it('seals the history in the browser, and a clean browser restores it with empty relays', async () => {
    const book = newBook();
    const p = await createPersona(book, { kind: 'create' }, { label: 'Resiliente', relays: [relay.url], preset: 'convenience' });
    const s = await openPersona(book, p);
    const empty = new TestRelay();
    await empty.start();
    let s2: Awaited<ReturnType<typeof openPersona>> | undefined;
    try {
      // The fixture: a channel message (ledger + event), a DM received, a group chat line and MLS state.
      const rec = await s.engine.submit({ template: { kind: 9, content: 'nota con el número 5512', tags: [['h', 'general']] } }, { relays: [relay.url], quorum: 1, wait: true });
      expect(rec.state).toBe('REPLICATED');
      await publishDmRelays(s);
      for (let i = 0; i < 40 && !relay.received.some((e) => e.kind === 10050 && e.pubkey === p.pubkey); i++) await new Promise((r) => setTimeout(r, 50));
      const dm = await createDirectMessage(new LocalSigner(generateSecretKey()), { recipients: [p.pubkey], content: 'dm recibido 7781' });
      const wrap = dm.wraps.find((w) => w.recipient === p.pubkey)!.event;
      relay.inject(wrap);
      await new GroupHistory(book.store, p.id).append('g1', [{ id: 'rumor-1', sender: p.pubkey, content: 'mensaje de grupo 4410', createdAt: 1_700_000_000 }]);
      await book.store.collection<unknown>(`mls-${p.id}-groups`).put('g1', { state: 'estado-mls-g1' });
      await book.store.collection<unknown>(`mls-${p.id}-keypackages`).put('kp', 'clave-privada-del-key-package');

      const pushed = await pushVault(vaultUrl, s, book.store);
      expect(pushed).toMatchObject({ events: { kept: 0, invalid: 0 }, groupMessages: { uploaded: 1, kept: 0 }, snapshots: ['ledger', 'mls'] });
      expect(pushed.events.uploaded).toBe(3); // the channel message, the 10050 list and the gift wrap
      expect(pushed.operations).toBe(2);
      const archives = pushed.events.uploaded + pushed.groupMessages.uploaded + 2;
      expect(await vaultUsage(vaultUrl, p)).toMatchObject({ archives });
      expect(await verifyVault(vaultUrl, p)).toEqual({ archives, opened: archives });
      // Another archive key (e.g. a persona that has not restored its key yet) opens nothing.
      expect(await verifyVault(vaultUrl, { ...p, archiveKeyHex: bytesToHex(new Uint8Array(32).fill(1)) })).toEqual({ archives: 0, opened: 0 });

      expect(new Set(repo.rows().map((r) => r.owner))).toEqual(new Set([`nostr:${archiveOwnerPubkey(hexToBytes(p.archiveKeyHex!))}`]));
      let stored = JSON.stringify(repo.rows());
      for await (const k of objects.list()) stored += new TextDecoder().decode((await objects.get(k))!);
      for (const needle of ['5512', 'nota con', '4410', 'estado-mls', 'clave-privada', p.pubkey, rec.event!.id, relay.url, 'REPLICATED', 'general']) expect(stored, needle).not.toContain(needle);

      // A clean browser with the backup only, and relays that lost everything.
      const opened = await openKeyBackup(await backupJson(p, 'contraseña del backup'), 'contraseña del backup');
      const clean = newBook();
      const p2 = await createPersona(clean, { kind: 'secret', secretKey: opened.secretKey, archiveKey: opened.archiveKey! }, { label: 'Restaurada', relays: [empty.url], preset: 'convenience' });
      s2 = await openPersona(clean, p2);
      const restored = await restoreVault(vaultUrl, s2, clean.store);
      expect(restored).toMatchObject({ archives, skipped: 0, events: 3, published: 3, rejected: 0, groupMessages: 1, ledger: 2, mls: 'restored', missing: 0 });
      expect(restored.savedAt).toBeGreaterThan(Date.now() - 60_000);
      expect(new Set(empty.received.map((e) => e.id))).toEqual(new Set([rec.event!.id, wrap.id, ...relay.received.filter((e) => e.kind === 10050 && e.pubkey === p.pubkey).map((e) => e.id)]));
      expect((await s2.engine.list()).map((r) => r.opId)).toContain(rec.opId);
      expect(await new GroupHistory(clean.store, p2.id).list('g1')).toEqual([{ id: 'rumor-1', sender: p.pubkey, content: 'mensaje de grupo 4410', createdAt: 1_700_000_000 }]);
      expect(await clean.store.collection<unknown>(`mls-${p2.id}-groups`).get('g1')).toEqual({ state: 'estado-mls-g1' });
      expect(await clean.store.collection<unknown>(`mls-${p2.id}-keypackages`).all()).toEqual([]);
      expect(await clean.store.collection<unknown>(`mls-${p2.id}-device`).get('owner')).toBe('vault-restore');

      // Restoring again adds nothing twice and keeps this browser's MLS state.
      expect(await restoreVault(vaultUrl, s2, clean.store)).toMatchObject({ skipped: 0, ledger: 0, groupMessages: 1, mls: 'kept' });
      expect(await new GroupHistory(clean.store, p2.id).list('g1')).toHaveLength(1);
    } finally {
      s.close();
      s2?.close();
      await empty.stop();
    }
  });

  it('VAULT-04: each send is copied to the vault as the persona policy says, apart from the relay ACKs', async () => {
    const book = newBook();
    const p = await createPersona(book, { kind: 'create' }, { label: 'Continua', relays: [relay.url], preset: 'convenience' });
    expect(p.config.continuity).toBe('best-effort');
    let config = { ...p.config };
    const s = await openPersona(book, p, {}, { continuityVault: vaultUrl, config: () => config });
    try {
      const rec = await s.engine.submit({ template: { kind: 9, content: 'copia best-effort', tags: [['h', 'general']] } }, { relays: [relay.url], wait: true });
      expect(rec).toMatchObject({ state: 'REPLICATED', continuity: { policy: 'best-effort', state: 'CONTINUITY_BACKED_UP' } });
      expect(await verifyVault(vaultUrl, (await book.get(p.id))!)).toMatchObject({ opened: expect.any(Number) });
      const restored = await restoreVault(vaultUrl, s, book.store);
      expect(restored.events).toBeGreaterThanOrEqual(1);

      // Off: nothing is copied.
      config = { ...config, continuity: 'off' };
      expect((await s.engine.submit({ template: { kind: 9, content: 'sin copia', tags: [['h', 'general']] } }, { relays: [relay.url], wait: true })).continuity).toBeUndefined();
    } finally {
      s.close();
    }

    // Required, with a vault that is not up: the send is held, and relaxing the policy releases it.
    const port = await freePort();
    config = { ...config, continuity: 'required-for-resilient' };
    const held = await openPersona(book, p, {}, { continuityVault: `http://127.0.0.1:${port}`, config: () => config });
    try {
      const text = `retenido ${Date.now()}`;
      const rec = await held.engine.submit({ template: { kind: 9, content: text, tags: [['h', 'general']] } }, { relays: [relay.url], wait: true });
      expect(rec).toMatchObject({ state: 'QUEUED', blockedReason: CONTINUITY_HELD, continuity: { state: 'PENDING' } });
      expect(relay.received.some((e) => e.content === text)).toBe(false);
      config = { ...config, continuity: 'best-effort' };
      await held.engine.resume();
      const sent = (await held.engine.get(rec.opId))!;
      expect(sent).toMatchObject({ state: 'REPLICATED', continuity: { policy: 'best-effort', state: 'PENDING' } });
      expect(relay.received.some((e) => e.content === text)).toBe(true);
    } finally {
      held.close();
    }
  });

  it('VAULT-04: without a vault in the deployment, a profile that requires one copies best-effort instead', async () => {
    const p = await createPersona(newBook(), { kind: 'create' }, { label: 'Sin vault', relays: [relay.url, 'ws://127.0.0.1:1'], preset: 'private-resilient', continuityVault: false });
    expect(p.config.continuity).toBe('best-effort');
    const q = await createPersona(newBook(), { kind: 'create' }, { label: 'Con vault', relays: [relay.url, 'ws://127.0.0.1:1'], preset: 'private-resilient', continuityVault: true });
    expect(q.config.continuity).toBe('required-for-resilient');
  });
});
