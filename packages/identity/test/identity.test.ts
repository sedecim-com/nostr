import { describe, expect, it } from 'vitest';
import { generateSecretKey, getPublicKey, nip19, nip49, verifyEvent, bytesToHex } from '@sedecim/nostr-core';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { preset } from '@sedecim/profiles';
import { backupFile, generateKey } from '../../../apps/key-generator/src/generate';
import { ConsentRequiredError, IdentityManager, KeyBackupError, openKeyBackup, parseKeyBackup } from '../src/index';

function setup() {
  const backends = new Map<string, MemoryBackend>();
  const account = EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(3));
  const open = async (id: string) => {
    if (!backends.has(id)) backends.set(id, new MemoryBackend());
    return EncryptedStore.withKey(backends.get(id)!, new Uint8Array(32).fill(id.length));
  };
  return { mgr: new IdentityManager(account, open), backends, open };
}
const LOGN = 4;

describe('IdentityManager', () => {
  it('creates a local identity that signs and verifies (FR-001)', async () => {
    const { mgr } = setup();
    const p = await mgr.createPersona({ label: 'Personal', relays: ['wss://r.example'], keyPassphrase: 'pp', scryptLogN: LOGN });
    const signer = await mgr.unlock(p.id, 'pp');
    const evt = await signer.signEvent({ kind: 1, content: 'test' });
    expect(verifyEvent(evt)).toBe(true);
    expect(evt.pubkey).toBe(p.pubkey);
    await expect(mgr.unlock(p.id, 'wrong')).rejects.toThrow();
  });

  it('imports nsec/ncryptsec and validates correspondence (FR-002)', async () => {
    const { mgr } = setup();
    const sk = generateSecretKey();
    const pk = getPublicKey(sk);
    await expect(mgr.importPersona({ nsec: nip19.nsecEncode(sk), keyPassphrase: 'x', expectedPubkey: '00'.repeat(32) }, { label: 'bad', relays: [], scryptLogN: LOGN })).rejects.toThrow(/does not match/);
    const p = await mgr.importPersona({ ncryptsec: nip49.encryptKey(sk, 'pw', LOGN), password: 'pw', keyPassphrase: 'x', expectedPubkey: pk }, { label: 'ok', relays: [], scryptLogN: LOGN });
    expect(p.pubkey).toBe(pk);
    const ext = await mgr.importPersona({ bunker: `bunker://${'ab'.repeat(32)}?relay=wss://r&secret=zzz`, pubkey: getPublicKey(generateSecretKey()) }, { label: 'signer', relays: [] });
    expect(ext.custody).toBe('external');
    expect(ext.bunker).not.toContain('zzz');
  });

  it('manages >=3 personas with independent stores and relays, unlinked by default (FR-006)', async () => {
    const { mgr, backends } = setup();
    const a = await mgr.createPersona({ label: 'Anónima', relays: ['ws://abc.onion'], compartment: 'high-risk', keyPassphrase: 'a', scryptLogN: LOGN });
    const b = await mgr.createPersona({ label: 'Personal', relays: ['wss://relay.a'], keyPassphrase: 'b', scryptLogN: LOGN });
    const c = await mgr.createPersona({ label: 'Institucional', relays: ['wss://org.relay'], compartment: 'institutional', keyPassphrase: 'c', scryptLogN: LOGN });
    expect(new Set([a.pubkey, b.pubkey, c.pubkey]).size).toBe(3);
    expect(a.network).toBe('tor-only');
    expect(backends.size).toBe(3);
    expect(await mgr.linksOf(a.id)).toEqual([]);
    expect(await mgr.sendingAs(a.id)).toMatch(/^Enviando como Anónima \(npub1.*sin vínculo · Tor-only$/);
  });

  it('requires explicit consent for links and audits them (FR-007)', async () => {
    const { mgr } = setup();
    const a = await mgr.createPersona({ label: 'A', relays: [], keyPassphrase: 'a', scryptLogN: LOGN });
    const b = await mgr.createPersona({ label: 'B', relays: [], keyPassphrase: 'b', scryptLogN: LOGN });
    await expect(mgr.link(a.id, b.id, 'private', { confirm: false })).rejects.toBeInstanceOf(ConsentRequiredError);
    const l = await mgr.link(a.id, b.id, 'selective', { confirm: true, audience: ['ff'.repeat(32)] });
    expect(l.consent).toBe('explicit-user-action');
    expect((await mgr.auditLog()).map((e) => e.action)).toContain('link.created');
    expect(await mgr.sendingAs(a.id)).toContain('vínculo selectivo');
  });

  it('warns about reuse across high-risk compartments', async () => {
    const { mgr } = setup();
    const a = await mgr.createPersona({ label: 'Fuente', relays: [], compartment: 'high-risk', keyPassphrase: 'a', scryptLogN: LOGN });
    const b = await mgr.createPersona({ label: 'Personal', relays: [], keyPassphrase: 'b', scryptLogN: LOGN });
    await mgr.recordUsage(b.id, { contact: 'cc'.repeat(32), fileHash: 'dd'.repeat(32) });
    const w = await mgr.reuseWarnings(a.id, { contact: 'cc'.repeat(32), fileHash: 'dd'.repeat(32) });
    expect(w).toHaveLength(2);
    expect(await mgr.reuseWarnings(a.id, { contact: b.pubkey })).toHaveLength(1);
  });

  it('restores identity and configuration from an encrypted backup on a clean device (FR-027)', async () => {
    const one = setup();
    const p = await one.mgr.createPersona({ label: 'Personal', relays: ['wss://r'], keyPassphrase: 'pp', scryptLogN: LOGN });
    const pkg = await one.mgr.exportBackup(p.id, 'backup-pw', { keyPassphrase: 'pp', scryptLogN: LOGN });
    expect(JSON.stringify(pkg)).not.toMatch(/nsec1/);
    const two = setup();
    const restored = await two.mgr.restoreBackup(JSON.parse(JSON.stringify(pkg)), 'backup-pw', 'new-pp', { scryptLogN: LOGN });
    expect(restored).toEqual(p);
    const signer = await two.mgr.unlock(p.id, 'new-pp');
    expect(await signer.getPublicKey()).toBe(p.pubkey);
    await expect(two.mgr.restoreBackup(pkg, 'wrong', 'x')).rejects.toThrow();
  });

  it('full backup seals relays, panel config and MLS state; restore recovers them (FR027-02)', async () => {
    const one = setup();
    const p = await one.mgr.createPersona({ label: 'Grupos', relays: ['wss://a.example', 'wss://b.example'], keyPassphrase: 'pp', scryptLogN: LOGN });
    const config = { ...preset('sovereign'), network: 'multi-relay' as const, quorum: 2 };
    await one.mgr.saveConfig(p.id, config);
    const store = await one.open(p.id);
    await store.collection('mls-groups').put('g1', { $obj: { epoch: { $bi: '7' }, secret: { $u8: 'AAEC' } } });
    await store.collection('mls-keypackages').put('kp1', 'opaque');
    await store.collection('outbox').put('op1', { opId: 'op1', state: 'QUEUED', relays: ['wss://a.example'] });
    const pkg = await one.mgr.exportBackup(p.id, 'backup-pw', { keyPassphrase: 'pp', scryptLogN: LOGN });
    expect(pkg.version).toBe(2);
    const text = JSON.stringify(pkg);
    for (const leak of ['wss://a.example', 'Grupos', 'multi-relay', 'mls-groups', 'AAEC', 'QUEUED', p.pubkey]) expect(text).not.toContain(leak);
    expect(Object.keys(pkg).sort()).toEqual(['contentKey', 'createdAt', 'format', 'ncryptsec', 'sealed', 'version']);

    const two = setup();
    await expect(two.mgr.restoreBackup(pkg, 'wrong', 'x', { scryptLogN: LOGN })).rejects.toThrow();
    const restored = await two.mgr.restoreBackup(JSON.parse(text), 'backup-pw', 'new-pp', { scryptLogN: LOGN });
    expect(restored).toEqual(p);
    expect(restored.relays).toEqual(['wss://a.example', 'wss://b.example']);
    expect(await two.mgr.getConfig(p.id)).toEqual(config);
    const s2 = await two.open(p.id);
    expect(await s2.collection('mls-groups').get('g1')).toEqual({ $obj: { epoch: { $bi: '7' }, secret: { $u8: 'AAEC' } } });
    expect(await s2.collection('mls-keypackages').get('kp1')).toBe('opaque');
    expect(await s2.collection('outbox').get('op1')).toEqual({ opId: 'op1', state: 'QUEUED', relays: ['wss://a.example'] });
    expect(await (await two.mgr.unlock(p.id, 'new-pp')).getPublicKey()).toBe(p.pubkey);
    expect((await two.mgr.auditLog()).at(-1)).toMatchObject({ action: 'backup.restored', details: { version: '2' } });

    // Tampering with the sealed payload is detected.
    const bad = { ...pkg, sealed: pkg.sealed.slice(0, -4) + (pkg.sealed.endsWith('AAAA') ? 'BBBB' : 'AAAA') };
    await expect(setup().mgr.restoreBackup(bad, 'backup-pw', 'x', { scryptLogN: LOGN })).rejects.toThrow();
  });

  it('still restores legacy v1 backups and external personas without key material (FR-027)', async () => {
    const sk = generateSecretKey();
    const persona = { id: 'aa'.repeat(8), label: 'Legacy', pubkey: getPublicKey(sk), custody: 'local' as const, compartment: 'standard' as const, relays: ['wss://old'], network: 'direct' as const, createdAt: 1 };
    const v1 = { format: 'sedecim-identity-backup' as const, version: 1 as const, persona, ncryptsec: nip49.encryptKey(sk, 'pw', LOGN, 0x01), createdAt: 1 };
    const { mgr } = setup();
    expect(await mgr.restoreBackup(v1, 'pw', 'kp', { scryptLogN: LOGN })).toEqual(persona);
    expect(await (await mgr.unlock(persona.id, 'kp')).getPublicKey()).toBe(persona.pubkey);
    await expect(mgr.restoreBackup({ ...v1, version: 3 } as never, 'pw', 'kp')).rejects.toThrow(/unsupported/);

    const one = setup();
    const ext = await one.mgr.importPersona({ bunker: `bunker://${'ab'.repeat(32)}?relay=wss://r`, pubkey: getPublicKey(generateSecretKey()) }, { label: 'signer', relays: ['wss://r'] });
    const pkg = await one.mgr.exportBackup(ext.id, 'pw', { scryptLogN: LOGN });
    expect(pkg.ncryptsec).toBeUndefined();
    expect(await setup().mgr.restoreBackup(pkg, 'pw', 'x')).toEqual(ext);
  });

  it('parses and opens key-generator and web key backups, validating ncryptsec against npub (FR002-03)', async () => {
    const k = generateKey({ password: 'contraseña larga', logN: LOGN });
    const offline = backupFile(k, LOGN);
    const parsed = parseKeyBackup(JSON.stringify(offline));
    expect(parsed).toEqual({ format: 'sedecim-offline-key', npub: k.npub, pubkey: k.pubkeyHex, ncryptsec: k.ncryptsec });
    const opened = await openKeyBackup(offline, 'contraseña larga');
    expect(opened.pubkey).toBe(k.pubkeyHex);
    expect(getPublicKey(opened.secretKey)).toBe(k.pubkeyHex);
    await expect(openKeyBackup(offline, 'otra')).rejects.toThrow(/wrong passphrase/);

    const sk = generateSecretKey();
    const web = { format: 'acceso-nostr-key-backup', version: 1, npub: nip19.npubEncode(getPublicKey(sk)), ncryptsec: nip49.encryptKey(sk, 'pw', LOGN) };
    expect(parseKeyBackup(web).format).toBe('acceso-nostr-key-backup');
    expect((await openKeyBackup(web, 'pw')).pubkey).toBe(getPublicKey(sk));

    // ncryptsec of another key than the declared npub: rejected.
    const mismatch = { ...web, npub: k.npub };
    await expect(openKeyBackup(mismatch, 'pw')).rejects.toBeInstanceOf(KeyBackupError);
    await expect(openKeyBackup(mismatch, 'pw')).rejects.toThrow(/does not match/);
    for (const bad of [null, '[]', '{', { ...web, format: 'other' }, { ...web, version: 2 }, { ...web, npub: 'npub1xyz' }, { ...web, ncryptsec: 'nsec1abc' }, { ...web, npub: nip19.nsecEncode(sk) }])
      expect(() => parseKeyBackup(bad)).toThrow(KeyBackupError);

    const { mgr } = setup();
    await expect(mgr.importKeyBackup(mismatch, 'pw', 'kp', { label: 'x', relays: [] })).rejects.toThrow(/does not match/);
    expect(await mgr.list()).toEqual([]);
    const p = await mgr.importKeyBackup(offline, 'contraseña larga', 'kp', { label: 'Offline', relays: ['wss://r'], scryptLogN: LOGN });
    expect(p).toMatchObject({ pubkey: k.pubkeyHex, custody: 'local', label: 'Offline' });
    expect(await (await mgr.unlock(p.id, 'kp')).getPublicKey()).toBe(k.pubkeyHex);
    await expect(mgr.importKeyBackup(offline, 'contraseña larga', 'kp', { label: 'dup', relays: [] })).rejects.toThrow(/already exists/);
  });

  it('migrates managed custody to local only with a matching key (FR-026)', async () => {
    const { mgr } = setup();
    const sk = generateSecretKey();
    const p = await mgr.importPersona({ managedKeyId: 'k1', pubkey: getPublicKey(sk) }, { label: 'Managed', relays: [] });
    await expect(mgr.markCustodyMigrated(p.id, 'local', generateSecretKey(), 'x')).rejects.toThrow(/does not match/);
    const next = await mgr.markCustodyMigrated(p.id, 'local', sk, 'x');
    expect(next.custody).toBe('local');
    expect(next.managedKeyId).toBeUndefined();
    expect(bytesToHex(sk)).toHaveLength(64);
  });
});
