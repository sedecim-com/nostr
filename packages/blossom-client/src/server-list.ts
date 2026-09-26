import type { EventTemplate, Filter, NostrEvent, Signer } from '@sedecim/nostr-core';
import { verifyEvent } from '@sedecim/nostr-core';
import { BlobIntegrityError, BlossomClient, fetchHttpClient, type BlobDescriptor, type HttpClient, type PreparedBlob } from './client';

/** BUD-03 user server list: a replaceable event whose `server` tags list the user's Blossom servers, most trusted first. */
export const USER_SERVER_LIST_KIND = 10063;

/** Normalizes a Blossom server URL: http(s) only, no query/fragment/credentials, no trailing slash (a base path such as /media is kept). */
export function normalizeServerUrl(raw: string): string {
  const u = new URL(raw.trim());
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error(`blossom server must be http(s): ${raw}`);
  if (u.username || u.password) throw new Error('blossom server URL must not carry credentials');
  return `${u.origin}${u.pathname.replace(/\/+$/, '')}`;
}

function uniqueServers(servers: readonly string[], onInvalid: 'throw' | 'skip'): string[] {
  const out: string[] = [];
  for (const s of servers) {
    let n: string;
    try {
      n = normalizeServerUrl(s);
    } catch (err) {
      if (onInvalid === 'throw') throw err;
      continue;
    }
    if (!out.includes(n)) out.push(n);
  }
  return out;
}

/** Template of a kind 10063 list. The first server is the primary one (uploads go there first). */
export function buildServerList(servers: readonly string[]): EventTemplate {
  return { kind: USER_SERVER_LIST_KIND, content: '', tags: uniqueServers(servers, 'throw').map((s) => ['server', s]) };
}

/** Signs the user's server list (publish it through the outbox like any other event). */
export function publishServerList(signer: Signer, servers: readonly string[]): Promise<NostrEvent> {
  return signer.signEvent(buildServerList(servers));
}

/** Servers of a kind 10063 event, in order; invalid or non-http(s) entries are ignored. */
export function parseServerList(evt: Pick<NostrEvent, 'kind' | 'tags'>): string[] {
  if (evt.kind !== USER_SERVER_LIST_KIND) throw new Error(`not a user server list (kind ${evt.kind})`);
  return uniqueServers(evt.tags.filter((t) => t[0] === 'server' && typeof t[1] === 'string').map((t) => t[1]!), 'skip');
}

/** Newest valid kind 10063 of `pubkey` among `events` (NIP-01 replaceable rule: highest created_at, then lowest id). */
export function latestServerList(events: readonly NostrEvent[], pubkey: string): NostrEvent | undefined {
  return events
    .filter((e) => e.kind === USER_SERVER_LIST_KIND && e.pubkey === pubkey && verifyEvent(e))
    .sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : 1))[0];
}

export interface EventQuery {
  query(urls: string[], filters: Filter[], timeoutMs?: number): Promise<NostrEvent[]>;
}

/** Fetches a user's current Blossom server list from relays (empty when none is published). */
export async function fetchServerList(pool: EventQuery, relays: string[], pubkey: string, timeoutMs = 5000): Promise<string[]> {
  const evt = latestServerList(await pool.query(relays, [{ kinds: [USER_SERVER_LIST_KIND], authors: [pubkey] }], timeoutMs), pubkey);
  return evt ? parseServerList(evt) : [];
}

export interface UploadRouting {
  /** The user's kind 10063 list, in order. */
  userServers: readonly string[];
  /** The blob is client-encrypted ciphertext. */
  encrypted: boolean;
  /**
   * Servers that only accept sniffed images/video (e.g. Buzz /media, interop report field
   * `encryptedAttachmentsRoute: "blob-store"`). Ciphertext is never routed there.
   */
  contentRestricted?: readonly string[];
  /** Deployment default when the list is empty (or has no eligible server): blob-store for ciphertext, relay media for plain images. */
  fallback?: string;
}

/**
 * Upload targets in order (FR018-05): the user's servers first (primary = first), skipping servers that
 * cannot take ciphertext when the blob is encrypted; then the deployment default. Never empty unless there
 * is neither a list nor a fallback.
 */
export function selectUploadServers(r: UploadRouting): string[] {
  const restricted = new Set(uniqueServers(r.contentRestricted ?? [], 'skip'));
  const eligible = uniqueServers(r.userServers, 'skip').filter((s) => !(r.encrypted && restricted.has(s)));
  const fallback = r.fallback ? uniqueServers([r.fallback], 'skip') : [];
  if (r.encrypted && fallback[0] && restricted.has(fallback[0])) fallback.length = 0;
  return [...new Set([...eligible, ...fallback])];
}

export interface MultiUploadResult {
  descriptor: BlobDescriptor;
  /** server that stored the blob first (the primary, unless it failed) */
  server: string;
  mirrored: string[];
  failed: Array<{ server: string; error: string }>;
}

/**
 * Uploads to the first server that accepts the blob; with `mirror`, also to the remaining ones (best
 * effort, BUD-03 "upload to all" pattern without requiring BUD-04 /mirror support).
 */
export async function uploadToServers(blob: PreparedBlob, servers: readonly string[], signer: Signer, opts: { http?: HttpClient; mirror?: boolean } = {}): Promise<MultiUploadResult> {
  const failed: MultiUploadResult['failed'] = [];
  const http = opts.http ?? fetchHttpClient;
  let primary: { server: string; descriptor: BlobDescriptor } | undefined;
  const mirrored: string[] = [];
  for (const server of servers) {
    if (primary && !opts.mirror) break;
    try {
      const descriptor = await new BlossomClient(server, signer, http).upload(blob);
      if (!primary) primary = { server, descriptor };
      else mirrored.push(server);
    } catch (err) {
      failed.push({ server, error: (err as Error).message });
    }
  }
  if (!primary) throw new Error(`blossom upload failed on every server: ${failed.map((f) => `${f.server}: ${f.error}`).join('; ') || 'no server configured'}`);
  return { ...primary, mirrored, failed };
}

/**
 * Downloads a blob trying, in order, the URL it was shared with and then `${server}/${sha256}` on each
 * of the author's servers (BUD-03). Every candidate is hash-verified before decrypting; a server that
 * serves wrong bytes is skipped, never trusted.
 */
export async function downloadFromServers(sha256Hex: string, candidates: { url?: string; servers: readonly string[] }, signer: Signer, opts: { http?: HttpClient; decrypt?: { keyHex: string; nonceHex: string } } = {}): Promise<{ data: Uint8Array; from: string }> {
  const urls: string[] = [];
  if (candidates.url) urls.push(candidates.url);
  for (const s of uniqueServers(candidates.servers, 'skip')) {
    const u = `${s}/${sha256Hex}`;
    if (!urls.includes(u)) urls.push(u);
  }
  const errors: string[] = [];
  for (const url of urls) {
    try {
      const u = new URL(url);
      const client = new BlossomClient(u.origin, signer, opts.http ?? fetchHttpClient);
      const data = await client.download(sha256Hex, { url, ...(opts.decrypt ? { decrypt: opts.decrypt } : {}) });
      return { data, from: url };
    } catch (err) {
      errors.push(`${url}: ${err instanceof BlobIntegrityError ? 'hash mismatch' : (err as Error).message}`);
    }
  }
  throw new Error(`blob ${sha256Hex.slice(0, 12)}… not available: ${errors.join('; ') || 'no candidate server'}`);
}
