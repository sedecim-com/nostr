import { randomBytes } from 'node:crypto';
import { mkdir, open, readdir, readFile, rename, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';

/**
 * Where the envelopes live (ADR 0011): the database keeps only their metadata. Object keys are random, so
 * neither a path nor a key says whose envelope it is. S3-compatible storage is VAULT-06.
 */
export interface ObjectStore {
  put(key: string, data: Uint8Array): Promise<void>;
  get(key: string): Promise<Uint8Array | undefined>;
  /** Deleting a missing object is not an error. */
  delete(key: string): Promise<void>;
  /** Every stored key (audits, tests, orphan sweeps). */
  list(): AsyncIterable<string>;
}

const KEY = /^[0-9a-f]{32}$/;

export const newObjectKey = (): string => randomBytes(16).toString('hex');

function checkKey(key: string): void {
  if (!KEY.test(key)) throw new Error('invalid object key');
}

export class MemoryObjectStore implements ObjectStore {
  private readonly objects = new Map<string, Uint8Array>();

  async put(key: string, data: Uint8Array) {
    checkKey(key);
    this.objects.set(key, new Uint8Array(data));
  }
  async get(key: string) {
    checkKey(key);
    const d = this.objects.get(key);
    return d ? new Uint8Array(d) : undefined;
  }
  async delete(key: string) {
    checkKey(key);
    this.objects.delete(key);
  }
  async *list() {
    yield* [...this.objects.keys()];
  }
}

/** One file per object under `dir/<first 2 hex>/<key>`, mode 0600, made durable before it is visible. */
export class FileObjectStore implements ObjectStore {
  constructor(private readonly dir: string) {}

  private path(key: string): string {
    checkKey(key);
    return join(this.dir, key.slice(0, 2), key);
  }

  async put(key: string, data: Uint8Array) {
    const path = this.path(key);
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    // Written to a temporary name, synced, then renamed: a crash never leaves a truncated object.
    const tmp = `${path}.${randomBytes(6).toString('hex')}.tmp`;
    const fh = await open(tmp, 'wx', 0o600);
    try {
      await fh.writeFile(data);
      await fh.sync();
    } finally {
      await fh.close();
    }
    await rename(tmp, path);
  }

  async get(key: string) {
    try {
      return new Uint8Array(await readFile(this.path(key)));
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw e;
    }
  }

  async delete(key: string) {
    await rm(this.path(key), { force: true });
  }

  async *list() {
    let shards: string[];
    try {
      shards = await readdir(this.dir);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw e;
    }
    for (const shard of shards.filter((s) => /^[0-9a-f]{2}$/.test(s)).sort()) {
      for (const name of (await readdir(join(this.dir, shard))).sort()) if (KEY.test(name) && name.startsWith(shard)) yield name;
    }
  }
}
