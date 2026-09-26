import { gcm } from '@noble/ciphers/aes.js';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, randomBytes, type Signer } from '@sedecim/nostr-core';
import { base64 } from '@scure/base';
import { neutralFileName, sanitizeMetadata } from './sanitize';

export const BLOSSOM_AUTH_KIND = 24242;

/** Raised by prepareBlob({ requireSanitizable }) for formats whose metadata cannot be removed safely. */
export class UnsanitizableFileError extends Error {
  constructor(
    readonly format: string,
    readonly reason?: string,
  ) {
    super(`file format cannot be sanitized (${format}${reason ? `: ${reason}` : ''}); refusing upload in this profile`);
    this.name = 'UnsanitizableFileError';
  }
}

export interface BlobDescriptor {
  url: string;
  sha256: string;
  size: number;
  type?: string;
  uploaded?: number;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

/** Transport indirection so uploads can go through the Tor NetworkGuard. */
export type HttpClient = (url: string, init: { method: string; headers?: Record<string, string>; body?: Uint8Array }) => Promise<HttpResponse>;

export const fetchHttpClient: HttpClient = async (url, init) => {
  const res = await fetch(url, { method: init.method, headers: init.headers, body: init.body as BodyInit | undefined });
  return { status: res.status, headers: Object.fromEntries(res.headers.entries()), body: new Uint8Array(await res.arrayBuffer()) };
};

export interface PrepareOptions {
  /** Strip EXIF & co. before upload (default true in sensitive profiles). */
  sanitize?: boolean;
  /** Encrypt client-side before upload (AES-256-GCM, NIP-17 kind 15 compatible). */
  encrypt?: boolean;
  /** Refuse formats the sanitizer does not understand. */
  requireSanitizable?: boolean;
  fileName?: string;
  mimeType?: string;
}

export interface PreparedBlob {
  data: Uint8Array;
  sha256: string;
  originalSha256: string;
  mimeType: string;
  fileName?: string;
  removedMetadata: string[];
  encryption?: { algorithm: 'aes-gcm'; keyHex: string; nonceHex: string };
}

/** Pipeline §13.1: sanitize -> (optional) encrypt -> SHA-256. */
export function prepareBlob(input: Uint8Array, opts: PrepareOptions = {}): PreparedBlob {
  let data = input;
  let removed: string[] = [];
  if (opts.sanitize ?? true) {
    const s = sanitizeMetadata(input);
    if (s.unsanitized && opts.requireSanitizable) throw new UnsanitizableFileError(s.format, s.reason);
    data = s.data;
    removed = s.removed;
  }
  const originalSha256 = bytesToHex(sha256(data));
  let encryption: PreparedBlob['encryption'];
  if (opts.encrypt) {
    const key = randomBytes(32);
    const nonce = randomBytes(12);
    data = gcm(key, nonce).encrypt(data);
    encryption = { algorithm: 'aes-gcm', keyHex: bytesToHex(key), nonceHex: bytesToHex(nonce) };
  }
  const hash = bytesToHex(sha256(data));
  return {
    data,
    sha256: hash,
    originalSha256,
    mimeType: opts.encrypt ? 'application/octet-stream' : (opts.mimeType ?? 'application/octet-stream'),
    ...(opts.fileName ? { fileName: neutralFileName(opts.fileName, originalSha256) } : {}),
    removedMetadata: removed,
    ...(encryption ? { encryption } : {}),
  };
}

export class BlobIntegrityError extends Error {}

export class BlossomClient {
  constructor(private readonly server: string, private readonly signer: Signer, private readonly http: HttpClient = fetchHttpClient) {}

  private async authHeader(verb: 'upload' | 'get' | 'delete', hash: string, ttlSeconds = 300): Promise<string> {
    const evt = await this.signer.signEvent({
      kind: BLOSSOM_AUTH_KIND,
      content: `${verb} blob`,
      tags: [
        ['t', verb],
        ['x', hash],
        ['expiration', String(Math.floor(Date.now() / 1000) + ttlSeconds)],
      ],
    });
    return 'Nostr ' + base64.encode(new TextEncoder().encode(JSON.stringify(evt)));
  }

  async upload(blob: PreparedBlob): Promise<BlobDescriptor> {
    const res = await this.http(`${this.server.replace(/\/$/, '')}/upload`, {
      method: 'PUT',
      headers: { authorization: await this.authHeader('upload', blob.sha256), 'content-type': blob.mimeType, 'x-sha-256': blob.sha256 },
      body: blob.data,
    });
    if (res.status !== 200) throw new Error(`blossom upload failed: ${res.status} ${res.headers['x-reason'] ?? new TextDecoder().decode(res.body)}`);
    const d = JSON.parse(new TextDecoder().decode(res.body)) as BlobDescriptor;
    if (d.sha256 !== blob.sha256) throw new BlobIntegrityError('server reported a different hash');
    return d;
  }

  /** Downloads and verifies the hash BEFORE decrypting or opening (spec §13.1). */
  async download(sha256Hex: string, opts: { url?: string; decrypt?: { keyHex: string; nonceHex: string } } = {}): Promise<Uint8Array> {
    const url = opts.url ?? `${this.server.replace(/\/$/, '')}/${sha256Hex}`;
    let res = await this.http(url, { method: 'GET' });
    // Servers may require BUD-01 authorization for reads (Buzz /media does): retry once with a `get` token.
    if (res.status === 401) res = await this.http(url, { method: 'GET', headers: { authorization: await this.authHeader('get', sha256Hex) } });
    if (res.status !== 200) throw new Error(`blossom download failed: ${res.status}`);
    if (bytesToHex(sha256(res.body)) !== sha256Hex) throw new BlobIntegrityError('blob hash mismatch: refusing to open');
    if (!opts.decrypt) return res.body;
    return gcm(hexToBytes(opts.decrypt.keyHex), hexToBytes(opts.decrypt.nonceHex)).decrypt(res.body);
  }
}
