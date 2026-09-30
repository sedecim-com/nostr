import { describe, expect, it } from 'vitest';
import { bytesToHex, generateSecretKey, getPublicKey, utf8ToBytes } from '@sedecim/nostr-core';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { fileDigest, IdentityManager, ReuseNotConfirmedError, UsageLedger, type ReuseWarning } from '../src/index';

const LOGN = 4;

function setup() {
  const backends = new Map<string, MemoryBackend>();
  const accountBackend = new MemoryBackend();
  const account = EncryptedStore.withKey(accountBackend, new Uint8Array(32).fill(3));
  const open = async (id: string) => {
    if (!backends.has(id)) backends.set(id, new MemoryBackend());
    return EncryptedStore.withKey(backends.get(id)!, new Uint8Array(32).fill(id.length));
  };
  return { mgr: new IdentityManager(account, open), account, accountBackend, backends, open };
}

const persona = (mgr: IdentityManager, label: string, compartment?: 'high-risk') => mgr.createPersona({ label, relays: [], keyPassphrase: 'pp', scryptLogN: LOGN, ...(compartment ? { compartment } : {}) });
const summary = (ws: ReuseWarning[]) => ws.map((w) => `${w.kind}:${w.label}`).sort();

describe('compartmentation: reusing a contact or a file across personas (FR006-07)', () => {
  it('warns before a persona uses a contact or a file another persona used, once, whatever the compartments (FR006-07)', async () => {
    const { mgr } = setup();
    const [a, b, c] = [await persona(mgr, 'Trabajo'), await persona(mgr, 'Personal'), await persona(mgr, 'Vecinal')];
    const contact = getPublicKey(generateSecretKey());
    const fileHash = await fileDigest(utf8ToBytes('acta de la asamblea'));
    expect(await mgr.reuseCheck(a.id, { contact, fileHash })).toEqual([]);
    await mgr.recordUsage(a.id, { contact, fileHash });

    // Another persona is told which persona already used them, and who could relate the two.
    const warnings = await mgr.reuseCheck(b.id, { contact, fileHash });
    expect(summary(warnings)).toEqual(['contact:Trabajo', 'file:Trabajo']);
    expect(warnings.every((w) => w.personaId === a.id)).toBe(true);
    expect(warnings.find((w) => w.kind === 'contact')!.message).toMatch(/desde tu persona "Trabajo".*el contacto.*puede deducir que ambas personas son la misma/);
    expect(warnings.find((w) => w.kind === 'file')!.message).toMatch(/este mismo archivo desde tu persona "Trabajo".*quien reciba o vea las dos copias/);
    // The persona that used them first is not asked, and neither is the second once it has confirmed and recorded them.
    expect(await mgr.reuseCheck(a.id, { contact, fileHash })).toEqual([]);
    await mgr.recordUsage(b.id, { contact, fileHash });
    expect(await mgr.reuseCheck(b.id, { contact, fileHash })).toEqual([]);
    // A third persona hears about both.
    expect(summary(await mgr.reuseCheck(c.id, { contact, fileHash }))).toEqual(['contact:Personal', 'contact:Trabajo', 'file:Personal', 'file:Trabajo']);
    // Only what crosses: another contact or another file is not warned about.
    expect(await mgr.reuseCheck(c.id, { contact: getPublicKey(generateSecretKey()), fileHash: await fileDigest(utf8ToBytes('otro')) })).toEqual([]);
    expect(summary(await mgr.reuseCheck(c.id, { contact: contact.toUpperCase() }))).toEqual(['contact:Personal', 'contact:Trabajo']);
    expect(await mgr.reuseWarnings(c.id, { fileHash })).toHaveLength(2);
  });

  it('writing to another of your own identities is warned about, every time, when one of them is high-risk (FR006-07)', async () => {
    const { mgr } = setup();
    const [plain, other, risky] = [await persona(mgr, 'Normal'), await persona(mgr, 'Otra'), await persona(mgr, 'Fuente', 'high-risk')];
    expect(await mgr.reuseCheck(plain.id, { contact: other.pubkey })).toEqual([]);
    const own = await mgr.reuseCheck(risky.id, { contact: plain.pubkey });
    expect(own).toEqual([{ kind: 'identity', personaId: plain.id, label: 'Normal', message: expect.stringMatching(/otra de tus identidades \("Normal"\)/) }]);
    await mgr.recordUsage(risky.id, { contact: plain.pubkey });
    expect(summary(await mgr.reuseCheck(risky.id, { contact: plain.pubkey }))).toEqual(['identity:Normal']);
    expect(summary(await mgr.reuseCheck(plain.id, { contact: risky.pubkey }))).toEqual(['identity:Fuente']);
    // The error the clients throw lists what would cross and says that nothing was sent.
    const err = new ReuseNotConfirmedError(own);
    expect(err.message).toMatch(/^compartimentación: El contacto es otra de tus identidades .* No se ha enviado nada: .*confirmación explícita\.$/);
  });

  it('keeps the ledger in each persona store as keyed tags: no npub, no file hash, nothing in the account store (FR006-07)', async () => {
    const { mgr, open, backends, accountBackend } = setup();
    const [a, b] = [await persona(mgr, 'A'), await persona(mgr, 'B')];
    const contact = getPublicKey(generateSecretKey());
    const fileHash = await fileDigest(utf8ToBytes('documento'));
    await mgr.recordUsage(a.id, { contact, fileHash });
    await mgr.recordUsage(b.id, { contact });

    // Nothing about the use is left in the account store.
    expect([...accountBackend.data.keys()].some((k) => k.startsWith('usage:'))).toBe(false);
    // In the persona store: a key and one opaque tag per use; neither the npub nor the hash, sealed or opened.
    const entries = async (id: string) => (await open(id)).collection<string>('usage').all();
    const [ledgerA, ledgerB] = [await entries(a.id), await entries(b.id)];
    expect(ledgerA).toHaveLength(3);
    expect(ledgerB).toHaveLength(2);
    expect(ledgerA.find((e) => e.id === 'key')!.value).toMatch(/^[0-9a-f]{64}$/);
    expect(ledgerA.filter((e) => e.id !== 'key').every((e) => /^[0-9a-f]{64}$/.test(e.id) && e.value === '')).toBe(true);
    const opened = JSON.stringify([ledgerA, ledgerB]);
    for (const secret of [contact, fileHash]) {
      expect(opened).not.toContain(secret);
      for (const backend of backends.values()) for (const raw of backend.data.values()) expect(Buffer.from(raw).toString('latin1')).not.toContain(secret);
    }
    // Each persona has its own key: the same contact gets unrelated tags in two ledgers.
    const tags = (l: typeof ledgerA) => l.filter((e) => e.id !== 'key').map((e) => e.id);
    expect(tags(ledgerA).filter((t) => tags(ledgerB).includes(t))).toEqual([]);
    expect(ledgerA.find((e) => e.id === 'key')!.value).not.toBe(ledgerB.find((e) => e.id === 'key')!.value);
  });

  it('moves the list kept before it (npubs and hashes in clear in the account store) into the persona ledgers (FR006-07)', async () => {
    const { mgr, account, accountBackend, open } = setup();
    const [a, b] = [await persona(mgr, 'Antes'), await persona(mgr, 'Ahora')];
    const contact = getPublicKey(generateSecretKey());
    const fileHash = bytesToHex(new Uint8Array(32).fill(7));
    // A value that is not hex is dropped instead of blocking every later check.
    await account.collection('usage').put(a.id, { personaId: a.id, contacts: [contact, 'npub1basura'], files: [fileHash] });
    await account.collection('usage').put('gone', { personaId: 'gone', contacts: [contact], files: [] });

    expect(summary(await mgr.reuseCheck(b.id, { contact, fileHash }))).toEqual(['contact:Antes', 'file:Antes']);
    expect([...accountBackend.data.keys()].some((k) => k.startsWith('usage:'))).toBe(false);
    // A later run (another manager over the same stores) finds them in the persona's ledger.
    const later = new IdentityManager(account, open);
    expect(summary(await later.reuseCheck(b.id, { contact, fileHash }))).toEqual(['contact:Antes', 'file:Antes']);
  });

  it('one ledger makes one key even when two records race on a fresh persona (FR006-07)', async () => {
    const store = EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(9));
    const ledger = new UsageLedger(store.collection<string>('usage'));
    const [x, y] = [getPublicKey(generateSecretKey()), getPublicKey(generateSecretKey())];
    await Promise.all([ledger.record({ contact: x }), ledger.record({ contact: y })]);
    expect((await store.collection<string>('usage').all()).filter((e) => e.id === 'key')).toHaveLength(1);
    const fresh = new UsageLedger(store.collection<string>('usage'));
    expect(await fresh.has({ contact: x })).toEqual({ contact: true, file: false });
    expect(await fresh.has({ contact: y })).toEqual({ contact: true, file: false });
    await expect(ledger.record({ contact: 'npub1nothex' })).rejects.toThrow(/hex pubkey/);
  });

  it('fileDigest is the sha256 of the bytes as picked (FR006-07)', async () => {
    expect(await fileDigest(utf8ToBytes('abc'))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    const view = utf8ToBytes('xxabcxx').subarray(2, 5);
    expect(await fileDigest(view)).toBe(await fileDigest(utf8ToBytes('abc')));
  });
});
