import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, isHex, utf8ToBytes } from './utils';

/** Canonical signed Nostr event (NIP-01). The signed event is the canonical object. */
export interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export interface EventTemplate {
  kind: number;
  tags?: string[][];
  content: string;
  created_at?: number;
}

export interface UnsignedEvent {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}

/** An unsigned event with a computed id (NIP-59 "rumor"). */
export interface Rumor extends UnsignedEvent {
  id: string;
}

/** NIP-01 serialization: [0, pubkey, created_at, kind, tags, content]. */
export function serializeEvent(evt: UnsignedEvent): string {
  return JSON.stringify([0, evt.pubkey, evt.created_at, evt.kind, evt.tags, evt.content]);
}

export function getEventHash(evt: UnsignedEvent): string {
  return bytesToHex(sha256(utf8ToBytes(serializeEvent(evt))));
}

export function toUnsigned(template: EventTemplate, pubkey: string, now = Math.floor(Date.now() / 1000)): UnsignedEvent {
  return {
    pubkey,
    created_at: template.created_at ?? now,
    kind: template.kind,
    tags: template.tags ?? [],
    content: template.content,
  };
}

export function createRumor(template: EventTemplate, pubkey: string): Rumor {
  const unsigned = toUnsigned(template, pubkey);
  return { ...unsigned, id: getEventHash(unsigned) };
}

/** Sign an unsigned event with a raw 32-byte secret key (BIP-340 Schnorr). */
export function finalizeEvent(unsigned: UnsignedEvent, secretKey: Uint8Array): NostrEvent {
  const id = getEventHash(unsigned);
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), secretKey));
  return { ...unsigned, id, sig };
}

/** Structural validation of an event object received from the network. */
export function validateEventShape(evt: unknown): evt is NostrEvent {
  if (typeof evt !== 'object' || evt === null) return false;
  const e = evt as Record<string, unknown>;
  if (!isHex(e.id, 32) || !isHex(e.pubkey, 32) || !isHex(e.sig, 64)) return false;
  if (!Number.isInteger(e.created_at) || !Number.isInteger(e.kind)) return false;
  if ((e.kind as number) < 0 || (e.kind as number) > 65535) return false;
  if (typeof e.content !== 'string' || !Array.isArray(e.tags)) return false;
  return e.tags.every((t) => Array.isArray(t) && t.every((v) => typeof v === 'string'));
}

/** Full verification: shape, id recomputation and Schnorr signature. */
export function verifyEvent(evt: unknown): evt is NostrEvent {
  if (!validateEventShape(evt)) return false;
  if (getEventHash(evt) !== evt.id) return false;
  try {
    return schnorr.verify(hexToBytes(evt.sig), hexToBytes(evt.id), hexToBytes(evt.pubkey));
  } catch {
    return false;
  }
}

export function getTagValue(evt: Pick<NostrEvent, 'tags'>, name: string): string | undefined {
  return evt.tags.find((t) => t[0] === name)?.[1];
}

export function getTagValues(evt: Pick<NostrEvent, 'tags'>, name: string): string[] {
  return evt.tags.filter((t) => t[0] === name && t[1] !== undefined).map((t) => t[1]!);
}
