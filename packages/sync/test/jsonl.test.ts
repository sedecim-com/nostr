import { describe, expect, it } from 'vitest';
import { verifyEvent as ntVerifyEvent } from 'nostr-tools';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned } from '@sedecim/nostr-core';
import { exportEventsJsonl, importEventsJsonl } from '../src/index';

describe('JSONL history export/import (NFR008-02)', () => {
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);
  const events = [30, 10, 20, 10].map((t, i) => finalizeEvent(toUnsigned({ kind: 1, content: `línea ${i} "con" \n salto`, created_at: 1_700_000_000 + t, tags: [['t', 'x']] }, pk), sk));

  it('writes one canonical signed event per line, sorted and deduplicated, verifiable by nostr-tools', () => {
    const extra = { ...events[0]!, relay: 'wss://leak.example' } as never; // non-NIP-01 fields are dropped
    const text = exportEventsJsonl([...events, events[1]!, extra]);
    const lines = text.trimEnd().split('\n');
    expect(text.endsWith('\n')).toBe(true);
    expect(lines).toHaveLength(4);
    const parsed = lines.map((l) => JSON.parse(l));
    expect(parsed.map((e) => e.created_at)).toEqual([...parsed.map((e) => e.created_at)].sort((a, b) => a - b));
    const tied = parsed.filter((e) => e.created_at === 1_700_000_010).map((e) => e.id);
    expect(tied).toEqual([...tied].sort());
    for (const e of parsed) {
      expect(Object.keys(e)).toEqual(['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig']);
      expect(ntVerifyEvent(e)).toBe(true);
    }
    expect(text).not.toContain('leak.example');
    expect(exportEventsJsonl([])).toBe('');
  });

  it('imports valid lines, reports invalid ones without throwing, and dedupes', () => {
    const text = exportEventsJsonl(events);
    const tampered = JSON.stringify({ ...events[0]!, content: 'cambiado' });
    const input = `${text}\n${JSON.stringify(events[2])}\r\n{not json\n${tampered}\n\n"string"\n`;
    const r = importEventsJsonl(input);
    expect(r.events.map((e) => e.id).sort()).toEqual(events.map((e) => e.id).sort());
    expect(r.duplicates).toBe(1);
    expect(r.invalid.map((i) => i.reason)).toEqual(['malformed JSON', 'invalid event (id or signature)', 'invalid event (id or signature)']);
    expect(r.invalid.map((i) => i.line)).toEqual([7, 8, 10]);
    expect(exportEventsJsonl(r.events)).toBe(text); // round trip is byte-identical
  });
});
