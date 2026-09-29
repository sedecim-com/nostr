import { randomBytes } from 'node:crypto';
import { mkdir, open, readdir, readFile, rename, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { DeleteObjectCommand, GetObjectCommand, HeadBucketCommand, ListObjectsV2Command, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';

/**
 * Where the envelopes live (ADR 0011): the database keeps only their metadata. Object keys are random, so
 * neither a path nor a key says whose envelope it is. Backends: memory (development), a directory, and any
 * S3-compatible store (VAULT-06: SeaweedFS in the compose, AWS S3, MinIO…).
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

export interface S3ObjectStoreOptions {
  bucket: string;
  /** S3-compatible endpoint (e.g. http://seaweedfs:8333). Without it, AWS S3 in `region`. */
  endpoint?: string;
  region?: string;
  /** Static credentials (S3-compatible stores); without them, the AWS default provider chain (IAM role). */
  credentials?: { accessKeyId: string; secretAccessKey: string };
  /** Path-style URLs (`endpoint/bucket/key`), which S3-compatible stores need. Default: on with an endpoint. */
  forcePathStyle?: boolean;
  /** Key prefix, to share a bucket (e.g. `vault/`). */
  prefix?: string;
  /** Keys per listing page (S3 caps it at 1000). */
  pageSize?: number;
}

const notFound = (e: unknown) => {
  const err = e as { name?: string; $metadata?: { httpStatusCode?: number } };
  return err?.name === 'NoSuchKey' || err?.name === 'NotFound' || err?.$metadata?.httpStatusCode === 404;
};

/**
 * VAULT-06: envelopes in an S3-compatible bucket, one object per envelope under `prefix + key`. A PUT is atomic, so
 * an object is either whole or absent, as with the directory backend.
 */
export class S3ObjectStore implements ObjectStore {
  private readonly s3: S3Client;
  private readonly bucket: string;
  private readonly prefix: string;
  private readonly pageSize: number;

  constructor(opts: S3ObjectStoreOptions) {
    if (!opts.bucket) throw new Error('S3 bucket required');
    if (opts.prefix && !/^[A-Za-z0-9._/-]+$/.test(opts.prefix)) throw new Error('S3 prefix: letters, digits and . _ / - only');
    this.bucket = opts.bucket;
    this.prefix = opts.prefix ?? '';
    this.pageSize = Math.min(1000, Math.max(1, opts.pageSize ?? 1000));
    this.s3 = new S3Client({
      region: opts.region || 'us-east-1',
      ...(opts.endpoint ? { endpoint: opts.endpoint } : {}),
      ...(opts.credentials ? { credentials: opts.credentials } : {}),
      forcePathStyle: opts.forcePathStyle ?? !!opts.endpoint,
      // Checksums only where S3 requires them: S3-compatible stores do not all accept the newer defaults.
      requestChecksumCalculation: 'WHEN_REQUIRED',
      responseChecksumValidation: 'WHEN_REQUIRED',
    });
  }

  /** Fails when the bucket is missing or these credentials cannot reach it (checked at start, not on the first upload). */
  async check(): Promise<void> {
    await this.s3.send(new HeadBucketCommand({ Bucket: this.bucket }));
  }

  async put(key: string, data: Uint8Array) {
    checkKey(key);
    await this.s3.send(new PutObjectCommand({ Bucket: this.bucket, Key: this.prefix + key, Body: data, ContentType: 'application/octet-stream' }));
  }

  async get(key: string) {
    checkKey(key);
    try {
      const out = await this.s3.send(new GetObjectCommand({ Bucket: this.bucket, Key: this.prefix + key }));
      return out.Body ? new Uint8Array(await out.Body.transformToByteArray()) : new Uint8Array();
    } catch (e) {
      if (notFound(e)) return undefined;
      throw e;
    }
  }

  async delete(key: string) {
    checkKey(key);
    try {
      await this.s3.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: this.prefix + key }));
    } catch (e) {
      if (!notFound(e)) throw e;
    }
  }

  async *list() {
    let token: string | undefined;
    do {
      const page = await this.s3.send(new ListObjectsV2Command({ Bucket: this.bucket, Prefix: this.prefix || undefined, MaxKeys: this.pageSize, ContinuationToken: token }));
      for (const o of page.Contents ?? []) {
        const name = o.Key?.slice(this.prefix.length);
        if (name && o.Key!.startsWith(this.prefix) && KEY.test(name)) yield name;
      }
      token = page.IsTruncated ? page.NextContinuationToken : undefined;
    } while (token);
  }

  close(): void {
    this.s3.destroy();
  }
}
