/**
 * Portable history export (NFR008-02): one canonical NIP-01 signed event per line (JSONL), sorted by
 * created_at then id. Any Nostr client can verify and re-publish the lines; nothing proprietary is added.
 */
import { verifyEvent, type NostrEvent } from '@sedecim/nostr-core';
import { sortEvents } from './index';

/** Only the NIP-01 fields, in the canonical key order. */
export function canonicalEvent(e: NostrEvent): NostrEvent {
  return { id: e.id, pubkey: e.pubkey, created_at: e.created_at, kind: e.kind, tags: e.tags, content: e.content, sig: e.sig };
}

/** Serialises events as JSONL (deduplicated by id, canonical order, trailing newline). */
export function exportEventsJsonl(events: Iterable<NostrEvent>): string {
  const byId = new Map<string, NostrEvent>();
  for (const e of events) byId.set(e.id, canonicalEvent(e));
  const lines = sortEvents([...byId.values()]).map((e) => JSON.stringify(e));
  return lines.length ? lines.join('\n') + '\n' : '';
}

export interface JsonlImportIssue {
  /** 1-based line number */
  line: number;
  reason: string;
}

export interface JsonlImportResult {
  /** valid events, deduplicated, canonical order */
  events: NostrEvent[];
  /** lines that were rejected (never thrown) */
  invalid: JsonlImportIssue[];
  /** valid lines repeating an id already seen */
  duplicates: number;
}

/** Parses JSONL, verifying id and signature of every line. Blank lines are ignored. */
export function importEventsJsonl(text: string): JsonlImportResult {
  const byId = new Map<string, NostrEvent>();
  const invalid: JsonlImportIssue[] = [];
  let duplicates = 0;
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = raw.trim();
    if (!line) return;
    let value: unknown;
    try {
      value = JSON.parse(line);
    } catch {
      invalid.push({ line: i + 1, reason: 'malformed JSON' });
      return;
    }
    if (!verifyEvent(value)) {
      invalid.push({ line: i + 1, reason: 'invalid event (id or signature)' });
      return;
    }
    if (byId.has(value.id)) duplicates++;
    else byId.set(value.id, canonicalEvent(value));
  });
  return { events: sortEvents([...byId.values()]), invalid, duplicates };
}
