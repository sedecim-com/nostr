import { describe, expect, it } from 'vitest';
import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EncryptedStore, FileBackend, MemoryBackend, WrongPassphraseError } from '../src/index';

describe('EncryptedStore', () => {
  it('encrypts values and names at rest', async () => {
    const backend = new MemoryBackend();
    const store = await EncryptedStore.open(backend, 'pass', { logN: 4 });
    const c = store.collection<{ text: string }>('outbox');
    await c.put('event-abc', { text: 'mensaje secreto' });
    expect(await c.get('event-abc')).toEqual({ text: 'mensaje secreto' });
    for (const [k, v] of backend.data) {
      expect(k).not.toContain('event-abc');
      expect(Buffer.from(v).toString('utf8')).not.toContain('mensaje secreto');
    }
    expect((await c.all()).map((e) => e.id)).toEqual(['event-abc']);
  });

  it('rejects the wrong passphrase', async () => {
    const backend = new MemoryBackend();
    await EncryptedStore.open(backend, 'right', { logN: 4 });
    await expect(EncryptedStore.open(backend, 'wrong', { logN: 4 })).rejects.toBeInstanceOf(WrongPassphraseError);
  });

  it('persists atomically on disk and reopens', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'store-'));
    const s1 = await EncryptedStore.open(new FileBackend(dir), 'pw', { logN: 4 });
    await s1.collection<number>('counters').put('a', 42);
    const s2 = await EncryptedStore.open(new FileBackend(dir), 'pw', { logN: 4 });
    expect(await s2.collection<number>('counters').get('a')).toBe(42);
    const files = await readdir(dir);
    expect(files.some((f) => f.endsWith('.tmp'))).toBe(false);
    for (const f of files) expect((await readFile(join(dir, f))).toString()).not.toContain('"value":42');
  });

  it('clears one collection without decrypting it and leaves the others (FR013-05)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'store-'));
    const store = await EncryptedStore.open(new FileBackend(dir), 'pw', { logN: 4 });
    await store.collection<string>('evcache').put('a', 'uno');
    await store.collection<string>('evcache').put('b', 'dos');
    await store.collection<string>('evcache-meta').put('meta', 'cursores');
    await store.collection<string>('outbox').put('op', 'pendiente');
    // An entry sealed with another key does not open, yet clear() removes it too.
    await EncryptedStore.withKey(new FileBackend(dir), new Uint8Array(32).fill(9)).collection<string>('evcache').put('c', 'ajeno');
    await store.collection<string>('evcache').clear();
    expect(await store.raw.keys('evcache:')).toEqual([]);
    expect((await readdir(dir)).filter((f) => f.startsWith('evcache__'))).toEqual([]);
    expect(await store.collection<string>('evcache-meta').get('meta')).toBe('cursores');
    expect(await store.collection<string>('outbox').get('op')).toBe('pendiente');
  });

  it('isolates collections (ciphertext bound to collection name)', async () => {
    const backend = new MemoryBackend();
    const store = EncryptedStore.withKey(backend, new Uint8Array(32).fill(7));
    await store.collection<string>('a').put('x', 'v');
    const [key, val] = [...backend.data.entries()][0]!;
    await backend.put(key.replace(/^a:/, 'b:'), val);
    await expect(store.collection<string>('b').all()).rejects.toThrow();
  });
});
