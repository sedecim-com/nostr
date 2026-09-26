import { mkdir, readdir, readFile, rename, rm, writeFile, open } from 'node:fs/promises';
import { join } from 'node:path';

/** Raw key/value backend. Keys are opaque ASCII strings; values are already-encrypted bytes. */
export interface StorageBackend {
  get(key: string): Promise<Uint8Array | undefined>;
  put(key: string, value: Uint8Array): Promise<void>;
  delete(key: string): Promise<void>;
  keys(prefix: string): Promise<string[]>;
}

export class MemoryBackend implements StorageBackend {
  readonly data = new Map<string, Uint8Array>();
  async get(key: string) {
    const v = this.data.get(key);
    return v ? new Uint8Array(v) : undefined;
  }
  async put(key: string, value: Uint8Array) {
    this.data.set(key, new Uint8Array(value));
  }
  async delete(key: string) {
    this.data.delete(key);
  }
  async keys(prefix: string) {
    return [...this.data.keys()].filter((k) => k.startsWith(prefix));
  }
}

const safeName = (key: string) => {
  if (!/^[A-Za-z0-9._:-]+$/.test(key)) throw new Error(`invalid storage key: ${key}`);
  return key.replace(/:/g, '__');
};

/**
 * File backend: one file per entry, written atomically (tmp + fsync + rename) so that a record that
 * reached LOCAL_PERSISTED survives a controlled crash (NFR-002).
 */
export class FileBackend implements StorageBackend {
  private ready?: Promise<void>;
  constructor(readonly dir: string) {}

  private init() {
    this.ready ??= mkdir(this.dir, { recursive: true, mode: 0o700 }).then(() => undefined);
    return this.ready;
  }

  async get(key: string) {
    await this.init();
    try {
      return new Uint8Array(await readFile(join(this.dir, safeName(key))));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw err;
    }
  }

  async put(key: string, value: Uint8Array) {
    await this.init();
    const final = join(this.dir, safeName(key));
    const tmp = `${final}.${process.pid}.${Date.now()}.tmp`;
    await writeFile(tmp, value, { mode: 0o600 });
    const fh = await open(tmp, 'r');
    try {
      await fh.sync();
    } finally {
      await fh.close();
    }
    await rename(tmp, final);
  }

  async delete(key: string) {
    await this.init();
    await rm(join(this.dir, safeName(key)), { force: true });
  }

  async keys(prefix: string) {
    await this.init();
    const p = safeName(prefix);
    return (await readdir(this.dir)).filter((f) => f.startsWith(p) && !f.endsWith('.tmp')).map((f) => f.replace(/__/g, ':'));
  }
}

export { LocalStorageBackend } from './localstorage';
