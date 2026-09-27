/**
 * Internal review 2026-09: the hand-written JPEG/PNG/WebP metadata sanitizer of the Blossom client
 * (spec §13.1). Any file must be sanitized, reported as unsanitized or rejected with an Error (bounded
 * work), and metadata segments of well-formed files must never survive.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { sanitizeMetadata } from '@sedecim/blossom-client';
import { runs, throwsCleanly } from './arbitraries';

const seg = (marker: number, body: Uint8Array) => [0xff, marker, (body.length + 2) >> 8, (body.length + 2) & 0xff, ...body];
const SECRET = [...new TextEncoder().encode('GPS-SECRET-48.8584N')];

/** JPEG with random non-metadata segments, one metadata segment carrying SECRET, then scan data. */
const jpeg = fc
  .tuple(
    fc.array(fc.tuple(fc.constantFrom(0xdb, 0xc0, 0xc4, 0xe0, 0xee), fc.uint8Array({ maxLength: 60 })), { maxLength: 4 }),
    fc.constantFrom(0xe1, 0xed, 0xfe, 0xe2, 0xef),
    fc.uint8Array({ maxLength: 40 }),
  )
  .map(([segs, meta, scan]) => new Uint8Array([0xff, 0xd8, ...segs.flatMap(([m, b]) => seg(m, b)), ...seg(meta, new Uint8Array(SECRET)), 0xff, 0xda, ...scan.map((b) => b & 0x7f), 0xff, 0xd9]));

const containsSecret = (d: Uint8Array) => Buffer.from(d).includes(Buffer.from(SECRET));

describe('media metadata sanitizer (fuzz)', () => {
  it('metadata segments of well-formed JPEGs never survive', () => {
    fc.assert(
      fc.property(jpeg, (d) => {
        const r = sanitizeMetadata(d);
        expect(r.format).toBe('jpeg');
        expect(containsSecret(r.data)).toBe(false);
        expect(r.removed.length).toBeGreaterThan(0);
      }),
      runs(500),
    );
  });

  it('random and mutated files are sanitized, flagged or rejected with an Error (bounded work)', () => {
    const headers = fc.constantFrom([0xff, 0xd8], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], [...new TextEncoder().encode('RIFF'), 0, 0, 0, 0, ...new TextEncoder().encode('WEBP')], []);
    const input = fc.oneof(
      fc.tuple(headers, fc.uint8Array({ maxLength: 300 })).map(([h, b]) => new Uint8Array([...h, ...b])),
      fc.tuple(jpeg, fc.nat(), fc.integer({ min: 1, max: 255 })).map(([d, i, x]) => {
        const b = d.slice();
        b[2 + (i % (b.length - 2))]! ^= x;
        return b;
      }),
    );
    fc.assert(fc.property(input, (d) => void throwsCleanly(() => sanitizeMetadata(d))), runs(2000));
  });
});
