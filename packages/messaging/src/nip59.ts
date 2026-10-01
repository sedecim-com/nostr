/** NIP-59 Gift Wrap: rumor (unsigned) -> seal (kind 13, signed by author) -> wrap (kind 1059, ephemeral key). */
import {
  createRumor,
  expirationTag,
  finalizeEvent,
  generateSecretKey,
  getPublicKey,
  nip44,
  randomInt,
  toUnsigned,
  verifyEvent,
  wipe,
  getEventHash,
  type EventTemplate,
  type NostrEvent,
  type Rumor,
  type Signer,
} from '@sedecim/nostr-core';

export const SEAL_KIND = 13;
export const GIFT_WRAP_KIND = 1059;
/** NIP-59 recommends randomising created_at up to two days in the past. */
export const DEFAULT_TIMESTAMP_JITTER_SECONDS = 2 * 24 * 60 * 60;

export interface WrapOptions {
  /**
   * Max random backdating of seal/wrap timestamps. Some relays reject skewed timestamps
   * (e.g. Buzz issue #4192); a relay adapter can lower this explicitly — never silently.
   */
  timestampJitterSeconds?: number;
  now?: number;
  /** Extra tags for the wrap (e.g. relay hint on the p tag). */
  wrapTags?: string[][];
  /**
   * PANEL-06: NIP-40 `expiration` (unix seconds) of a disappearing message. NIP-17 sets it on the wrap, where relays
   * read it, and on the seal, in case the seal leaks; each layer keeps its own random `created_at` (NIP-59).
   */
  expiration?: number;
}

function randomizedTimestamp(opts: WrapOptions): number {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const jitter = opts.timestampJitterSeconds ?? DEFAULT_TIMESTAMP_JITTER_SECONDS;
  return jitter > 0 ? now - randomInt(jitter) : now;
}

const expirationTags = (opts: WrapOptions): string[][] => (opts.expiration !== undefined ? [expirationTag(opts.expiration)] : []);

export async function createSeal(signer: Signer, rumor: Rumor, recipientPubkey: string, opts: WrapOptions = {}): Promise<NostrEvent> {
  const content = await signer.nip44Encrypt(recipientPubkey, JSON.stringify(rumor));
  return signer.signEvent({ kind: SEAL_KIND, content, tags: expirationTags(opts), created_at: randomizedTimestamp(opts) });
}

export function createWrap(seal: NostrEvent, recipientPubkey: string, opts: WrapOptions = {}): NostrEvent {
  const ephemeral = generateSecretKey();
  try {
    const ck = nip44.getConversationKey(ephemeral, recipientPubkey);
    const content = nip44.encrypt(JSON.stringify(seal), ck);
    const tags = [...(opts.wrapTags ?? [['p', recipientPubkey]]), ...expirationTags(opts)];
    return finalizeEvent(toUnsigned({ kind: GIFT_WRAP_KIND, content, tags, created_at: randomizedTimestamp(opts) }, getPublicKey(ephemeral)), ephemeral);
  } finally {
    wipe(ephemeral);
  }
}

export async function wrapRumor(signer: Signer, rumor: Rumor, recipientPubkey: string, opts: WrapOptions = {}): Promise<NostrEvent> {
  return createWrap(await createSeal(signer, rumor, recipientPubkey, opts), recipientPubkey, opts);
}

export async function rumorFromTemplate(signer: Signer, template: EventTemplate): Promise<Rumor> {
  return createRumor(template, await signer.getPublicKey());
}

export class UnwrapError extends Error {}

export interface Unwrapped {
  rumor: Rumor;
  seal: NostrEvent;
  wrap: NostrEvent;
  /** Authenticated author: the seal signer (equals rumor.pubkey, checked). */
  sender: string;
}

/** Unwraps and authenticates a gift wrap addressed to the signer's key. */
export async function unwrap(signer: Signer, wrap: NostrEvent): Promise<Unwrapped> {
  if (wrap.kind !== GIFT_WRAP_KIND || !verifyEvent(wrap)) throw new UnwrapError('not a valid gift wrap');
  let seal: unknown;
  try {
    seal = JSON.parse(await signer.nip44Decrypt(wrap.pubkey, wrap.content));
  } catch {
    throw new UnwrapError('cannot decrypt gift wrap');
  }
  if (!verifyEvent(seal) || seal.kind !== SEAL_KIND) throw new UnwrapError('invalid seal');
  let rumor: Rumor;
  try {
    rumor = JSON.parse(await signer.nip44Decrypt(seal.pubkey, seal.content)) as Rumor;
  } catch {
    throw new UnwrapError('cannot decrypt seal');
  }
  if (rumor.pubkey !== seal.pubkey) throw new UnwrapError('rumor author does not match seal signer (impersonation attempt)');
  const { id: _id, ...unsigned } = rumor;
  if (getEventHash(unsigned) !== rumor.id) throw new UnwrapError('rumor id mismatch');
  return { rumor, seal, wrap, sender: seal.pubkey };
}
