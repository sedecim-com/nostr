import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { TestBlossomServer } from '@sedecim/test-relay';
import { BlossomClient, BlobIntegrityError, UnsanitizableFileError, prepareBlob, sanitizeMetadata, neutralFileName } from '../src/index';

function jpegWithExif(): Uint8Array {
  const exif = [0xff, 0xe1, 0x00, 0x11, ...Buffer.from('Exif\0\0GPS:40.4N')];
  const app0 = [0xff, 0xe0, 0x00, 0x10, ...Buffer.from('JFIF\0'), 1, 1, 0, 0, 1, 0, 1, 0, 0];
  const com = [0xff, 0xfe, 0x00, 0x08, ...Buffer.from('author')];
  const sos = [0xff, 0xda, 0x00, 0x08, 1, 1, 0, 0, 0x3f, 0, 0x12, 0x34, 0x56];
  return new Uint8Array([0xff, 0xd8, ...app0, ...exif, ...com, ...sos, 0xff, 0xd9]);
}

describe('metadata sanitizer (FR-019)', () => {
  it('strips EXIF and comments from JPEG and keeps image data', () => {
    const r = sanitizeMetadata(jpegWithExif());
    expect(r.removed).toEqual(['APP1 (EXIF/XMP)', 'COM']);
    expect(Buffer.from(r.data).includes(Buffer.from('GPS'))).toBe(false);
    expect(Buffer.from(r.data).includes(Buffer.from('JFIF'))).toBe(true);
    expect(Buffer.from(r.data).includes(Buffer.from([0x12, 0x34, 0x56]))).toBe(true);
  });

  it('strips PNG text/time chunks', () => {
    const chunk = (type: string, data: Buffer) => {
      const len = Buffer.alloc(4);
      len.writeUInt32BE(data.length);
      return Buffer.concat([len, Buffer.from(type), data, Buffer.alloc(4)]);
    };
    const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', Buffer.alloc(13)), chunk('tEXt', Buffer.from('Author\0Ana')), chunk('IDAT', Buffer.from([1, 2])), chunk('IEND', Buffer.alloc(0))]);
    const r = sanitizeMetadata(new Uint8Array(png));
    expect(r.removed).toEqual(['tEXt']);
    expect(Buffer.from(r.data).includes(Buffer.from('Ana'))).toBe(false);
  });

  const riffChunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4);
    len.writeUInt32LE(data.length);
    return Buffer.concat([Buffer.from(type), len, data, data.length & 1 ? Buffer.alloc(1) : Buffer.alloc(0)]);
  };
  const webp = (...chunks: Buffer[]) => {
    const body = Buffer.concat([Buffer.from('WEBP'), ...chunks]);
    const size = Buffer.alloc(4);
    size.writeUInt32LE(body.length);
    return new Uint8Array(Buffer.concat([Buffer.from('RIFF'), size, body]));
  };
  const vp8x = (flags: number) => riffChunk('VP8X', Buffer.from([flags, 0, 0, 0, 9, 0, 0, 9, 0, 0]));

  it('strips EXIF/XMP/ICC chunks from WebP, clears the VP8X flags and fixes the RIFF size (FR019-02)', () => {
    const image = riffChunk('VP8L', Buffer.from([0x2f, 1, 2, 3, 4])); // odd length: padded
    const input = webp(vp8x(0x20 | 0x10 | 0x08 | 0x04), riffChunk('ICCP', Buffer.from('iccprofile-device')), riffChunk('ALPH', Buffer.from([7, 7])), image, riffChunk('EXIF', Buffer.from('Exif\0\0GPS:40.4N')), riffChunk('XMP ', Buffer.from('<x:xmpmeta>Ana</x:xmpmeta>')));
    const r = sanitizeMetadata(input);
    expect(r.format).toBe('webp');
    expect(r.unsanitized).toBe(false);
    expect(r.removed).toEqual(['ICCP (ICC profile)', 'EXIF', 'XMP']);
    const out = Buffer.from(r.data);
    for (const leak of ['GPS', 'Ana', 'iccprofile']) expect(out.includes(Buffer.from(leak))).toBe(false);
    expect(out.readUInt32LE(4)).toBe(out.length - 8);
    expect(out.subarray(0, 4).toString()).toBe('RIFF');
    expect(out[20]).toBe(0x10); // only the alpha flag remains
    expect(out.includes(Buffer.from([0x2f, 1, 2, 3, 4, 0]))).toBe(true);
    expect(out.includes(Buffer.from('ALPH'))).toBe(true);
    // Idempotent and valid for a second pass.
    expect(Buffer.from(sanitizeMetadata(r.data).data).equals(out)).toBe(true);
  });

  it('strips EXIF appended to a simple (non-VP8X) WebP and rejects malformed RIFF', () => {
    const simple = webp(riffChunk('VP8 ', Buffer.alloc(10, 1)), riffChunk('EXIF', Buffer.from('Exif\0\0Make:Phone')));
    const r = sanitizeMetadata(simple);
    expect(r.removed).toEqual(['EXIF']);
    expect(Buffer.from(r.data).includes(Buffer.from('Phone'))).toBe(false);
    const truncated = simple.slice(0, simple.length - 6);
    expect(() => sanitizeMetadata(truncated)).toThrow(/malformed WebP/);
    const lying = Buffer.from(simple);
    lying.writeUInt32LE(0x7fffffff, 16);
    expect(() => sanitizeMetadata(new Uint8Array(lying))).toThrow(/malformed WebP/);
  });

  it('marks HEIC/HEIF/AVIF as unsanitized so requireSanitizable refuses them explicitly (FR019-02)', () => {
    const ftyp = (major: string, ...compat: string[]) => {
      const body = Buffer.concat([Buffer.from('ftyp'), Buffer.from(major), Buffer.alloc(4), ...compat.map((c) => Buffer.from(c))]);
      const size = Buffer.alloc(4);
      size.writeUInt32BE(body.length + 4);
      return new Uint8Array(Buffer.concat([size, body, Buffer.from('....meta....Exif\0\0GPS')]));
    };
    for (const file of [ftyp('heic', 'mif1', 'heic'), ftyp('mif1', 'heic'), ftyp('avif', 'mif1'), ftyp('isom', 'mif1')]) {
      const r = sanitizeMetadata(file);
      expect(r.format).toBe('heif');
      expect(r.unsanitized).toBe(true);
      expect(r.reason).toMatch(/HEIC/);
      expect(() => prepareBlob(file, { requireSanitizable: true, mimeType: 'image/heic' })).toThrow(/cannot be sanitized \(heif: HEIC\/HEIF\/AVIF.*convert the image to JPEG, PNG or WebP/);
      expect(() => prepareBlob(file, { requireSanitizable: true })).toThrow(UnsanitizableFileError);
      // Without the sensitive-profile requirement the file passes through untouched (and flagged).
      expect(prepareBlob(file, { mimeType: 'image/heic' }).removedMetadata).toEqual([]);
    }
    expect(sanitizeMetadata(ftyp('isom', 'mp41')).format).toBe('unknown');
  });

  it('neutralizes file names', () => {
    expect(neutralFileName('Foto de Juan en Madrid.JPG', 'ab'.repeat(32))).toBe('file-abababababab.jpg');
  });
});

describe('Blossom client (FR-018)', () => {
  const server = new TestBlossomServer();
  const signer = new LocalSigner(generateSecretKey());
  beforeAll(async () => {
    await server.start();
  });
  afterAll(async () => {
    await server.stop();
  });

  it('uploads, references, downloads and verifies an encrypted blob; server never sees plaintext', async () => {
    const client = new BlossomClient(server.url, signer);
    const prepared = prepareBlob(jpegWithExif(), { encrypt: true, fileName: 'x.jpg', mimeType: 'image/jpeg' });
    const desc = await client.upload(prepared);
    expect(desc.sha256).toBe(prepared.sha256);
    const stored = server.blobs.get(prepared.sha256)!;
    expect(Buffer.from(stored.data).includes(Buffer.from('JFIF'))).toBe(false);
    const back = await client.download(desc.sha256, { decrypt: prepared.encryption! });
    expect(Buffer.from(back).includes(Buffer.from('JFIF'))).toBe(true);
    expect(Buffer.from(back).includes(Buffer.from('GPS'))).toBe(false);
  });

  it('refuses to open a blob whose hash does not match', async () => {
    const client = new BlossomClient(server.url, signer);
    const prepared = prepareBlob(new Uint8Array([1, 2, 3, 4]), { sanitize: false });
    await client.upload(prepared);
    server.corruptDownloads = true;
    await expect(client.download(prepared.sha256)).rejects.toBeInstanceOf(BlobIntegrityError);
    server.corruptDownloads = false;
  });

  it('retries downloads with a BUD-01 get authorization when the server requires it', async () => {
    const client = new BlossomClient(server.url, signer);
    const prepared = prepareBlob(new Uint8Array([7, 7, 7]), { sanitize: false });
    await client.upload(prepared);
    server.requireGetAuth = true;
    try {
      expect(Array.from(await client.download(prepared.sha256))).toEqual([7, 7, 7]);
    } finally {
      server.requireGetAuth = false;
    }
  });

  it('can refuse unsanitizable formats in sensitive profiles', () => {
    expect(() => prepareBlob(new Uint8Array([1, 2, 3]), { requireSanitizable: true })).toThrow(/cannot be sanitized/);
  });
});
