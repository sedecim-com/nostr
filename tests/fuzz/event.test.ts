/** SEC-03: NIP-01 events — serialization, id, signature round-trip, tamper detection, differential vs nostr-tools. */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import * as nt from 'nostr-tools/pure';
import { finalizeEvent, getEventHash, getPublicKey, serializeEvent, toUnsigned, validateEventShape, verifyEvent, type NostrEvent } from '@sedecim/nostr-core';
import { runs, secretKey, text } from './arbitraries';

const template = fc.record({
  kind: fc.integer({ min: 0, max: 65535 }),
  created_at: fc.integer({ min: 0, max: 2 ** 32 }),
  content: text({ maxLength: 300 }),
  tags: fc.array(fc.array(text({ maxLength: 40 }), { minLength: 1, maxLength: 4 }), { maxLength: 6 }),
});

describe('NIP-01 events (fuzz)', () => {
  it('sign → verify round-trips and matches nostr-tools (id, serialization, signature check)', () => {
    fc.assert(
      fc.property(secretKey(), template, (sk, t) => {
        const evt = finalizeEvent(toUnsigned(t, getPublicKey(sk)), sk);
        expect(verifyEvent(evt)).toBe(true);
        expect(getEventHash(evt)).toBe(nt.getEventHash(evt));
        expect(JSON.parse(serializeEvent(evt))).toEqual([0, evt.pubkey, evt.created_at, evt.kind, evt.tags, evt.content]);
        expect(nt.verifyEvent({ ...evt })).toBe(true);
        // and the other way round: nostr-tools events verify here
        const theirs = nt.finalizeEvent({ ...t }, sk);
        expect(theirs.id).toBe(getEventHash(theirs));
        expect(verifyEvent({ ...theirs })).toBe(true);
      }),
      runs(40),
    );
  });

  it('any change to a signed field breaks verification', () => {
    const field = fc.constantFrom('content', 'kind', 'created_at', 'tags', 'pubkey', 'id', 'sig');
    fc.assert(
      fc.property(secretKey(), secretKey(), template, field, text({ minLength: 1, maxLength: 20 }), (sk, other, t, f, junk) => {
        const evt = finalizeEvent(toUnsigned(t, getPublicKey(sk)), sk);
        const bad: NostrEvent = { ...evt, tags: evt.tags.map((x) => [...x]) };
        if (f === 'content') bad.content = evt.content + junk;
        if (f === 'kind') bad.kind = (evt.kind + 1) % 65536;
        if (f === 'created_at') bad.created_at = evt.created_at + 1;
        if (f === 'tags') bad.tags = [...bad.tags, [junk]];
        if (f === 'pubkey') bad.pubkey = getPublicKey(other);
        if (f === 'id') bad.id = (evt.id[0] === '0' ? '1' : '0') + evt.id.slice(1);
        if (f === 'sig') bad.sig = evt.sig.slice(0, -1) + (evt.sig.endsWith('0') ? '1' : '0');
        fc.pre(f !== 'pubkey' || bad.pubkey !== evt.pubkey);
        expect(verifyEvent(bad)).toBe(false);
        expect(nt.verifyEvent({ ...bad })).toBe(false);
      }),
      runs(60),
    );
  });

  it('verifyEvent never throws on arbitrary input (returns false)', () => {
    const eventish = fc.record(
      { id: fc.oneof(fc.string(), fc.constant('a'.repeat(64))), pubkey: fc.oneof(fc.string(), fc.constant('b'.repeat(64))), sig: fc.string(), kind: fc.oneof(fc.integer(), fc.double(), fc.string()), created_at: fc.anything(), content: fc.anything(), tags: fc.anything() },
      { requiredKeys: [] },
    );
    fc.assert(
      fc.property(fc.oneof(fc.anything(), eventish), (v) => {
        expect(verifyEvent(v)).toBe(false);
        if (!validateEventShape(v)) expect(verifyEvent(v)).toBe(false);
      }),
      runs(300),
    );
  });
});
