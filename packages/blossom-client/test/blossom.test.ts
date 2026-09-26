import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { TestBlossomServer } from '@sedecim/test-relay';
import { BlossomClient, BlobIntegrityError, prepareBlob, sanitizeMetadata, neutralFileName } from '../src/index';

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

  it('can refuse unsanitizable formats in sensitive profiles', () => {
    expect(() => prepareBlob(new Uint8Array([1, 2, 3]), { requireSanitizable: true })).toThrow(/cannot be sanitized/);
  });
});
