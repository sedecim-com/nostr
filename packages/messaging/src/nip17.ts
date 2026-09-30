/**
 * NIP-17 private direct messages (draft). Implemented as a swappable module behind a feature flag
 * (spec §10.2, FR-017). NIP-44 has no forward secrecy / post-compromise security.
 */
import { createRumor, getTagValue, getTagValues, type NostrEvent, type Rumor, type Signer } from '@sedecim/nostr-core';
import { GIFT_WRAP_KIND, unwrap, wrapRumor, type Unwrapped, type WrapOptions } from './nip59';

export const DM_KIND = 14;
export const FILE_MESSAGE_KIND = 15;

export interface DirectMessageInput {
  recipients: string[];
  content: string;
  subject?: string;
  replyTo?: string;
  /** relay hints per recipient pubkey for the p tag */
  relayHints?: Record<string, string>;
}

export interface FileMessageInput {
  recipients: string[];
  url: string;
  mimeType: string;
  sha256: string;
  /** hash of the plaintext before encryption */
  originalSha256?: string;
  size?: number;
  encryption?: { algorithm: 'aes-gcm'; keyHex: string; nonceHex: string };
}

export interface WrappedMessage {
  rumor: Rumor;
  /** One wrap per recipient plus one for the sender's own devices (multi-device continuity). */
  wraps: Array<{ recipient: string; event: NostrEvent }>;
}

function pTags(input: { recipients: string[]; relayHints?: Record<string, string> }): string[][] {
  return input.recipients.map((p) => (input.relayHints?.[p] ? ['p', p, input.relayHints[p]!] : ['p', p]));
}

async function wrapForAll(signer: Signer, rumor: Rumor, recipients: string[], opts: WrapOptions): Promise<WrappedMessage> {
  const me = await signer.getPublicKey();
  const targets = [...new Set([...recipients, me])];
  const wraps = [];
  for (const recipient of targets) wraps.push({ recipient, event: await wrapRumor(signer, rumor, recipient, opts) });
  return { rumor, wraps };
}

/** The kind 14 rumor of a direct message, before any seal or wrap. */
export async function directMessageRumor(signer: Signer, input: DirectMessageInput): Promise<Rumor> {
  if (input.recipients.length === 0) throw new Error('at least one recipient required');
  const tags = pTags(input);
  if (input.replyTo) tags.push(['e', input.replyTo]);
  if (input.subject) tags.push(['subject', input.subject]);
  return createRumor({ kind: DM_KIND, content: input.content, tags }, await signer.getPublicKey());
}

/** The kind 15 rumor of a file message, before any seal or wrap. */
export async function fileMessageRumor(signer: Signer, input: FileMessageInput): Promise<Rumor> {
  if (input.recipients.length === 0) throw new Error('at least one recipient required');
  const tags = [...pTags(input), ['file-type', input.mimeType], ['x', input.sha256]];
  if (input.originalSha256) tags.push(['ox', input.originalSha256]);
  if (input.size !== undefined) tags.push(['size', String(input.size)]);
  if (input.encryption) {
    tags.push(['encryption-algorithm', input.encryption.algorithm], ['decryption-key', input.encryption.keyHex], ['decryption-nonce', input.encryption.nonceHex]);
  }
  return createRumor({ kind: FILE_MESSAGE_KIND, content: input.url, tags }, await signer.getPublicKey());
}

export async function createDirectMessage(signer: Signer, input: DirectMessageInput, opts: WrapOptions = {}): Promise<WrappedMessage> {
  return wrapForAll(signer, await directMessageRumor(signer, input), input.recipients, opts);
}

export async function createFileMessage(signer: Signer, input: FileMessageInput, opts: WrapOptions = {}): Promise<WrappedMessage> {
  return wrapForAll(signer, await fileMessageRumor(signer, input), input.recipients, opts);
}

export interface DirectMessage extends Unwrapped {
  kind: number;
  participants: string[];
  subject?: string;
  /** Stable conversation key: sorted set of participants (NIP-17 chat room). */
  roomId: string;
}

/** The message in an authenticated unwrap (a kind 14 or 15 rumor). */
export function directMessageFrom(u: Unwrapped): DirectMessage {
  if (u.rumor.kind !== DM_KIND && u.rumor.kind !== FILE_MESSAGE_KIND) throw new Error(`unexpected rumor kind ${u.rumor.kind}`);
  const participants = [...new Set([u.sender, ...getTagValues(u.rumor, 'p')])].sort();
  return { ...u, kind: u.rumor.kind, participants, subject: getTagValue(u.rumor, 'subject'), roomId: participants.join(',') };
}

export async function openDirectMessage(signer: Signer, wrap: NostrEvent): Promise<DirectMessage> {
  return directMessageFrom(await unwrap(signer, wrap));
}

/**
 * Inbox filter. Buzz (and other relays) require #p to match the authenticated pubkey for kind 1059
 * subscriptions; the filter is always scoped to our own pubkey.
 */
export function dmInboxFilter(pubkey: string, since?: number) {
  // Gift wraps are backdated up to 2 days: widen `since` so recent messages are not missed.
  return { kinds: [GIFT_WRAP_KIND], '#p': [pubkey], ...(since !== undefined ? { since: since - 2 * 24 * 3600 } : {}) };
}
