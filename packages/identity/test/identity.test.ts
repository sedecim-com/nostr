import { describe, expect, it } from 'vitest';
import { generateSecretKey, getPublicKey, nip19, nip49, verifyEvent, bytesToHex } from '@sedecim/nostr-core';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { ConsentRequiredError, IdentityManager } from '../src/index';

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
