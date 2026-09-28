import { crc32, deflateSync } from 'node:zlib';

/** 2x2 RGB PNG with valid CRCs; no metadata chunks unless `comment` adds a tEXt one. */
export function tinyPng(comment?: string): Uint8Array {
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type), data])) >>> 0);
    return Buffer.concat([len, Buffer.from(type), data, crc]);
  };
  const ihdr = Buffer.from([0, 0, 0, 2, 0, 0, 0, 2, 8, 2, 0, 0, 0]);
  const raw = Buffer.from([0, 255, 0, 0, 0, 255, 0, 0, 0, 0, 255, 255, 255, 255]);
  const text = comment === undefined ? [] : [chunk('tEXt', Buffer.from(`Comment\0${comment}`, 'latin1'))];
  return new Uint8Array(Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), ...text, chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]));
}

/** The position inside heicWithGps(), to check that it never leaves the device. */
export const HEIC_GPS = 'GPSLatitude 40.4168 N GPSLongitude 3.7038 W';

/**
 * A minimal HEIC (ISO BMFF, brands heic and mif1) with an Exif item that carries a GPS position: metadata the
 * sanitizer cannot remove, so a profile with stripFileMetadata must refuse the file (FR019-03).
 */
export function heicWithGps(): Uint8Array {
  const box = (type: string, ...parts: Buffer[]) => {
    const body = Buffer.concat(parts);
    const size = Buffer.alloc(4);
    size.writeUInt32BE(8 + body.length);
    return Buffer.concat([size, Buffer.from(type, 'latin1'), body]);
  };
  const latin1 = (s: string) => Buffer.from(s, 'latin1');
  const hdlr = box('hdlr', Buffer.alloc(8), latin1('pict'), Buffer.alloc(13));
  const iinf = box('iinf', Buffer.alloc(4), Buffer.from([0, 1]), box('infe', Buffer.from([2, 0, 0, 0, 0, 1, 0, 0]), latin1('Exif\0')));
  // Exif item: offset to the TIFF header, "Exif\0\0", a big-endian TIFF header, then the GPS data.
  const exif = Buffer.concat([Buffer.from([0, 0, 0, 6]), latin1('Exif\0\0MM\0*\0\0\0\x08'), latin1(HEIC_GPS)]);
  return new Uint8Array(Buffer.concat([box('ftyp', latin1('heic\0\0\0\0mif1heic')), box('meta', Buffer.alloc(4), hdlr, iinf), box('mdat', exif)]));
}
