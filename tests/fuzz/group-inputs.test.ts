/**
 * FR025-14: what the web's secure groups take from the user or from another member, as properties. File names and sizes
 * of MIP-04 files (every name the sender accepts reaches the members intact and opens; a size a member states is shown
 * only as a whole number of bytes) and the npubs typed into an invitation or a proposal.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { buildMediaImetaTag, decryptGroupMedia, encryptGroupMedia, isValidMediaFilename, parseMediaImeta } from '@sedecim/marmot-adapter';
import { npubEncode } from '@sedecim/nostr-core';
import { fileSizeLabel, parseMembers } from '../../apps/web-saas/src/lib/groups';
import { hex32, runs, text, throwsCleanly, utf8Len } from './arbitraries';

const URL_OF = (sha: string) => `https://blossom.invalid/${sha}`;
const mediaSecret = () => fc.uint8Array({ minLength: 32, maxLength: 32 });
/** Names built from the characters that matter to the `imeta` parsers (spaces, every line terminator, NUL) and others. */
const trickyName = fc.array(fc.constantFrom('a', 'Z', '.', ' ', '\t', '\n', '\r', '\u0000', '\u2028', '\u2029', '\u0085', 'ñ', '😀', '/', 'filename', 'x '), { maxLength: 40 }).map((parts) => parts.join(''));
const LINE_TERMINATORS = /[\n\r\u2028\u2029]/;

describe('secure group inputs (fuzz)', () => {
  it('every file name the sender accepts reaches the members as it was and opens; the others are refused cleanly (FR025-14)', () => {
    for (const name of ['a b.png', ' lead.png', 'trail.png ', 'tab\tname', 'emoji 😀.png', ' ']) expect(isValidMediaFilename(name)).toBe(true);
    for (const name of ['', 'x\ny', 'x\ry', 'x\u2028y.png', 'x\u2029y', 'nul\u0000', 'á'.repeat(128)]) expect(isValidMediaFilename(name)).toBe(false);
    fc.assert(
      fc.property(fc.oneof(trickyName, text({ maxLength: 300 })), fc.uint8Array({ maxLength: 64 }), mediaSecret(), (name, data, secret) => {
        if (!isValidMediaFilename(name)) {
          expect(throwsCleanly(() => encryptGroupMedia(secret, data, { filename: name, type: 'image/png' }))).toBe(true);
          return;
        }
        expect(utf8Len(name)).toBeLessThanOrEqual(255);
        const { ciphertext, ciphertextSha256, attachment } = encryptGroupMedia(secret, data, { filename: name, type: 'image/png' });
        const received = parseMediaImeta(buildMediaImetaTag({ ...attachment, url: URL_OF(ciphertextSha256) }));
        expect(received?.filename).toBe(name);
        expect(decryptGroupMedia(secret, ciphertext, received!)).toEqual(data);
      }),
      runs(300),
    );
  });

  it('a name with a line terminator would be dropped by the members, which is why the sender refuses it (FR025-14)', () => {
    fc.assert(
      fc.property(trickyName.filter((n) => LINE_TERMINATORS.test(n) && !n.startsWith('\n') && !n.startsWith('\r')), (name) => {
        const attachment = { url: URL_OF('ab'.repeat(32)), sha256: 'cd'.repeat(32), type: 'image/png', filename: name, nonce: '00'.repeat(12), version: 'mip04-v2' };
        expect(parseMediaImeta(buildMediaImetaTag(attachment))?.filename).not.toBe(name);
        expect(isValidMediaFilename(name)).toBe(false);
      }),
      runs(200),
    );
  });

  it('any size goes and comes back: the ciphertext is the file plus its tag, the stated size is its own, and one changed byte is refused (FR025-14)', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 4096 }), mediaSecret(), fc.nat(), (data, secret, at) => {
        const { ciphertext, ciphertextSha256, attachment } = encryptGroupMedia(secret, data, { filename: 'f.bin', type: 'application/octet-stream' });
        expect(ciphertext.length).toBe(data.length + 16);
        const received = parseMediaImeta(buildMediaImetaTag({ ...attachment, url: URL_OF(ciphertextSha256) }))!;
        expect(received.size).toBe(data.length);
        expect(decryptGroupMedia(secret, ciphertext, received)).toEqual(data);
        const tampered = ciphertext.slice();
        tampered[at % tampered.length] ^= 1;
        expect(throwsCleanly(() => decryptGroupMedia(secret, tampered, received))).toBe(true);
      }),
      runs(100),
    );
  });

  it('whatever size a member states, the log shows a whole number of bytes or nothing (FR025-14)', () => {
    const shown = /^$|^\d+ B$|^\d+,\d (KB|MB)$/;
    fc.assert(
      fc.property(fc.oneof(fc.string({ maxLength: 24 }), fc.double().map(String), fc.bigInt().map(String)), (raw) => {
        const tag = ['imeta', `url ${URL_OF('ab'.repeat(32))}`, 'm image/png', `x ${'cd'.repeat(32)}`, 'filename a.png', `n ${'00'.repeat(12)}`, 'v mip04-v2', `size ${raw}`];
        expect(fileSizeLabel(parseMediaImeta(tag)?.size)).toMatch(shown);
      }),
      runs(300),
    );
    fc.assert(
      fc.property(fc.oneof(fc.double(), fc.integer(), fc.constant(undefined)), (size) => {
        expect(fileSizeLabel(size)).toMatch(shown);
      }),
      runs(300),
    );
    expect([fileSizeLabel(0), fileSizeLabel(1023), fileSizeLabel(1536), fileSizeLabel(3 * 1024 * 1024)]).toEqual(['0 B', '1023 B', '1,5 KB', '3,0 MB']);
  });

  it('an invitation or a proposal names each npub once, leaves out the members and never takes another persona of this browser (FR025-14)', () => {
    const entry = fc.record({ key: hex32(), npub: fc.boolean(), sep: fc.constantFrom(' ', ',', '\n', ' , ', '\t') });
    fc.assert(
      fc.property(fc.array(entry, { minLength: 1, maxLength: 8 }), fc.array(fc.nat(), { maxLength: 3 }), fc.array(fc.nat(), { maxLength: 3 }), (entries, ownAt, memberAt) => {
        const keys = entries.map((e) => e.key);
        const own = ownAt.map((i) => keys[i % keys.length]!);
        const members = memberAt.map((i) => keys[i % keys.length]!);
        const typed = entries.map((e) => (e.npub ? npubEncode(e.key) : e.key) + e.sep).join('');
        const wanted = [...new Set(keys.filter((k) => !members.includes(k)))];
        if (wanted.some((k) => own.includes(k))) expect(() => parseMembers(typed, own, members)).toThrow(/compartimentación/);
        else expect(parseMembers(typed, own, members)).toEqual(wanted);
      }),
      runs(300),
    );
    // Anything else typed: pubkeys (64 hex) or a refusal that says which entry, never a crash.
    fc.assert(
      fc.property(fc.string({ maxLength: 200 }), (typed) => {
        let out: string[] = [];
        try {
          out = parseMembers(typed, []);
        } catch (e) {
          expect(e).toBeInstanceOf(Error);
          expect((e as Error).message).toMatch(/no es una npub válida/);
          return;
        }
        for (const k of out) expect(k).toMatch(/^[0-9a-f]{64}$/);
      }),
      runs(300),
    );
  });
});
