import { mkdir, readdir, readFile, rename, rm, open } from 'node:fs/promises';
import { join } from 'node:path';
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js';

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

const TMP_SUFFIX = '.tmp';

/** Temp files are named `<entry>.<pid>.<random>.tmp`: the pid tells whether the writer is still alive. */
const tmpOwnerPid = (file: string) => Number(/\.(\d+)\.[0-9a-f]+\.tmp$/.exec(file)?.[1] ?? NaN);

const processAlive = (pid: number) => {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
};

/** fsync a directory so a rename/unlink in it is durable. Not supported everywhere (e.g. Windows). */
async function syncDir(dir: string) {
  let fh;
  try {
    fh = await open(dir, 'r');
    await fh.sync();
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== 'EISDIR' && code !== 'EINVAL' && code !== 'EPERM' && code !== 'EBADF') throw err;
  } finally {
    await fh?.close();
  }
}

/**
 * File backend: one file per entry, written atomically (temp file + fsync + rename + fsync of the
 * directory), so a crash (even kill -9 in the middle of a write) leaves every entry with either its old
 * or its new value, never a torn one (NFR-002, test/crash.test.ts). Temp files left by a killed writer
 * are never read and are removed the next time the store is opened.
 */
export class FileBackend implements StorageBackend {
  private ready?: Promise<void>;
  constructor(readonly dir: string) {}

  private init() {
    this.ready ??= mkdir(this.dir, { recursive: true, mode: 0o700 }).then(() => this.removeStaleTemps());
    return this.ready;
  }

  /** Temp files of writers that no longer run (kill -9, power loss) are garbage: their rename never happened. */
  private async removeStaleTemps() {
    for (const f of await readdir(this.dir)) {
      if (f.endsWith(TMP_SUFFIX) && !processAlive(tmpOwnerPid(f))) await rm(join(this.dir, f), { force: true });
    }
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
    // Unique per write: concurrent puts of the same key never share a temp file.
    const tmp = `${final}.${process.pid}.${bytesToHex(randomBytes(6))}${TMP_SUFFIX}`;
    const fh = await open(tmp, 'wx', 0o600);
    try {
      await fh.writeFile(value);
      await fh.sync();
    } catch (err) {
      await fh.close();
      await rm(tmp, { force: true });
      throw err;
    }
    await fh.close();
    await rename(tmp, final);
    await syncDir(this.dir);
  }

  async delete(key: string) {
    await this.init();
    await rm(join(this.dir, safeName(key)), { force: true });
    await syncDir(this.dir);
  }

  async keys(prefix: string) {
    await this.init();
    const p = safeName(prefix);
    return (await readdir(this.dir)).filter((f) => f.startsWith(p) && !f.endsWith(TMP_SUFFIX)).map((f) => f.replace(/__/g, ':'));
  }
}

export { LocalStorageBackend } from './localstorage';
