import { describe, expect, it } from 'vitest';
import { MemoryBackend, MemoryKeyring, Vault, WrongPassphraseError } from '../src/index';

const fast = { logN: 10 };

describe('Vault (DEC-05, ADR 0007)', () => {
  it('creates a passphrase vault, stores records and reopens only with the right passphrase', async () => {
    const backend = new MemoryBackend();
    const v = await Vault.create(backend, { kind: 'passphrase', passphrase: 'correcta', ...fast });
    await v.store.collection<string>('key').put('p1', 'secreto');
    expect(await Vault.inspect(backend)).toEqual({ exists: true, kind: 'passphrase' });
    await expect(Vault.unlock(backend, { kind: 'passphrase', passphrase: 'otra' })).rejects.toBeInstanceOf(WrongPassphraseError);
    const again = await Vault.unlock(backend, { kind: 'passphrase', passphrase: 'correcta' });
    expect(await again.store.collection<string>('key').get('p1')).toBe('secreto');
  });

  it('never writes the secret or the master key in clear', async () => {
    const backend = new MemoryBackend();
    const v = await Vault.create(backend, { kind: 'passphrase', passphrase: 'x', ...fast });
    await v.store.collection<string>('key').put('p1', 'nsec1supersecreto');
    const all = [...backend.data.values()].map((b) => new TextDecoder().decode(b)).join('\n');
    expect(all).not.toContain('nsec1supersecreto');
  });

  it('opens with the device keyring without a passphrase', async () => {
    const backend = new MemoryBackend();
    const keyring = new MemoryKeyring();
    const v = await Vault.create(backend, { kind: 'device', keyring });
    await v.store.collection<number>('n').put('a', 7);
    const again = await Vault.unlock(backend, { kind: 'device', keyring });
    expect(await again.store.collection<number>('n').get('a')).toBe(7);
    await expect(Vault.unlock(backend, { kind: 'device', keyring: new MemoryKeyring() })).rejects.toThrow();
    await expect(Vault.unlock(backend, { kind: 'passphrase', passphrase: 'x' })).rejects.toThrow(/protected by device/);
  });

  it('re-wraps device → passphrase without re-encrypting records', async () => {
    const backend = new MemoryBackend();
    const keyring = new MemoryKeyring();
    const v = await Vault.create(backend, { kind: 'device', keyring });
    await v.store.collection<string>('key').put('p1', 'secreto');
    await v.rewrap({ kind: 'passphrase', passphrase: 'nueva', ...fast });
    expect(await Vault.inspect(backend)).toEqual({ exists: true, kind: 'passphrase' });
    await expect(Vault.unlock(backend, { kind: 'device', keyring })).rejects.toThrow();
    const again = await Vault.unlock(backend, { kind: 'passphrase', passphrase: 'nueva' });
    expect(await again.store.collection<string>('key').get('p1')).toBe('secreto');
  });

  it('refuses to create over an existing vault', async () => {
    const backend = new MemoryBackend();
    await Vault.create(backend, { kind: 'device', keyring: new MemoryKeyring() });
    await expect(Vault.create(backend, { kind: 'device', keyring: new MemoryKeyring() })).rejects.toThrow(/already exists/);
  });
});
