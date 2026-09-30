/**
 * FR006-04: the public profile of a key (kind 0, NIP-01 and NIP-24): a name, a short description and the address of an
 * avatar, self-asserted by whoever holds the key. Clients show it next to the npub, never instead of it: anyone can
 * claim any name. Profiles are public, replaceable events: the newest one of each key wins.
 */
import type { EventTemplate, NostrEvent } from '@sedecim/nostr-core';
import type { RelayQuery } from './dm-relays';

export const PROFILE_KIND = 0;
/** Longest name, description and avatar address kept from a profile (characters). */
export const PROFILE_LIMITS = { name: 48, about: 280, picture: 1024 } as const;

export interface ProfileFields {
  name?: string;
  about?: string;
  /** http(s) address of the avatar image. */
  picture?: string;
}

export interface PublicProfile extends ProfileFields {
  pubkey: string;
  createdAt: number;
  eventId: string;
}

// Control characters, zero-width characters and bidirectional overrides and isolates: a name could otherwise hide
// text or reorder what is shown around it (the npub next to it).
const UNSAFE = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;

/** A profile text as shown: unsafe characters removed, whitespace collapsed, at most `max` characters. */
export function cleanProfileText(value: unknown, max: number): string | undefined {
  if (typeof value !== 'string') return undefined;
  const s = value.replace(UNSAFE, ' ').replace(/\s+/g, ' ').trim();
  return s ? [...s].slice(0, max).join('').trim() : undefined;
}

/** An avatar address: an http(s) URL of reasonable length, or nothing. */
export function profilePictureUrl(value: unknown): string | undefined {
  if (typeof value !== 'string' || !value.trim() || value.length > PROFILE_LIMITS.picture) return undefined;
  try {
    const u = new URL(value.trim());
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.toString() : undefined;
  } catch {
    return undefined;
  }
}

/** The kind 0 template of these fields. An empty profile (`{}`) replaces, and so withdraws, the previous one. */
export function buildProfile(fields: ProfileFields): EventTemplate {
  const content: Record<string, string> = {};
  const name = cleanProfileText(fields.name, PROFILE_LIMITS.name);
  const about = cleanProfileText(fields.about, PROFILE_LIMITS.about);
  if (fields.picture?.trim() && !profilePictureUrl(fields.picture)) throw new Error('the avatar must be an http(s) URL');
  const picture = profilePictureUrl(fields.picture);
  if (name) {
    content.name = name;
    content.display_name = name;
  }
  if (about) content.about = about;
  if (picture) content.picture = picture;
  return { kind: PROFILE_KIND, content: JSON.stringify(content), tags: [] };
}

/** The profile in a kind 0 event (NIP-24 `display_name` first), or undefined if it is not one. */
export function parseProfile(evt: NostrEvent): PublicProfile | undefined {
  if (evt.kind !== PROFILE_KIND) return undefined;
  let raw: Record<string, unknown>;
  try {
    const v: unknown = JSON.parse(evt.content);
    if (!v || typeof v !== 'object' || Array.isArray(v)) return undefined;
    raw = v as Record<string, unknown>;
  } catch {
    return undefined;
  }
  const name = cleanProfileText(raw.display_name, PROFILE_LIMITS.name) ?? cleanProfileText(raw.name, PROFILE_LIMITS.name);
  const about = cleanProfileText(raw.about, PROFILE_LIMITS.about);
  const picture = profilePictureUrl(raw.picture);
  return { pubkey: evt.pubkey, createdAt: evt.created_at, eventId: evt.id, ...(name ? { name } : {}), ...(about ? { about } : {}), ...(picture ? { picture } : {}) };
}

/**
 * The profiles one persona looked up, in memory (spec §14.1: each persona keeps its own cache). A key is looked up
 * again once `ttlMs` has passed; a failed lookup is not remembered, so it is tried again next time. Only signed kind 0
 * events of the keys asked for are kept (the pool verifies signatures), the newest of each key.
 */
export class ProfileCache {
  private readonly entries = new Map<string, { profile?: PublicProfile; checkedAt: number }>();
  private readonly pending = new Map<string, Promise<void>>();
  private readonly listeners = new Set<() => void>();
  private readonly ttlMs: number;
  private readonly timeoutMs: number;
  private readonly now: () => number;

  constructor(
    private readonly pool: RelayQuery,
    opts: { ttlMs?: number; timeoutMs?: number; now?: () => number } = {},
  ) {
    this.ttlMs = opts.ttlMs ?? 10 * 60_000;
    this.timeoutMs = opts.timeoutMs ?? 5000;
    this.now = opts.now ?? Date.now;
  }

  get(pubkey: string): PublicProfile | undefined {
    return this.entries.get(pubkey)?.profile;
  }

  /** Called whenever a profile is added or replaced. Returns the unsubscribe function. */
  onChange(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /** Keeps the event if it is a newer profile of its key (e.g. the one this persona just published). */
  put(evt: NostrEvent): void {
    const next = parseProfile(evt);
    if (!next) return;
    const entry = this.entries.get(evt.pubkey);
    const cur = entry?.profile;
    const newer = !cur || next.createdAt > cur.createdAt || (next.createdAt === cur.createdAt && next.eventId < cur.eventId);
    this.entries.set(evt.pubkey, { profile: newer ? next : cur, checkedAt: entry?.checkedAt ?? 0 });
    if (newer) for (const l of this.listeners) l();
  }

  /** Looks up, on `relays`, the keys not looked up within the TTL (one request per 100 keys). */
  async lookup(relays: string[], pubkeys: Iterable<string>): Promise<void> {
    const now = this.now();
    const waits: Promise<void>[] = [];
    const wanted: string[] = [];
    for (const pk of new Set(pubkeys)) {
      if (!/^[0-9a-f]{64}$/.test(pk)) continue;
      const busy = this.pending.get(pk);
      if (busy) waits.push(busy);
      else if (now - (this.entries.get(pk)?.checkedAt ?? -Infinity) >= this.ttlMs) wanted.push(pk);
    }
    if (relays.length) {
      for (let i = 0; i < wanted.length; i += 100) {
        const chunk = wanted.slice(i, i + 100);
        const job = this.pool
          .query(relays, [{ kinds: [PROFILE_KIND], authors: chunk }], this.timeoutMs)
          .then((events) => {
            for (const e of events) if (e.kind === PROFILE_KIND && chunk.includes(e.pubkey)) this.put(e);
            const at = this.now();
            for (const pk of chunk) this.entries.set(pk, { ...this.entries.get(pk), checkedAt: at });
          })
          .catch(() => undefined)
          .finally(() => chunk.forEach((pk) => this.pending.delete(pk)));
        for (const pk of chunk) this.pending.set(pk, job);
        waits.push(job);
      }
    }
    await Promise.all(waits);
  }
}
