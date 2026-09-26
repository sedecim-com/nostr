import { getTagValues, isHex, verifyEvent, type EventTemplate, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import type { SovereigntyConfig } from '@sedecim/profiles';
import { ConsentRequiredError } from './manager';

/**
 * FR007-04: optional public link between two personas as a signed Nostr event (format: docs/public-link.md).
 *
 * Each persona signs the same canonical statement naming both pubkeys (sorted) and an issue time. Persona B's
 * signed "consent half" is embedded in persona A's event, and A's signature covers it, so any third party can
 * check that BOTH keys consented, without trusting the publisher, a relay or the identity service.
 * Kind 30078 (NIP-78, parameterized replaceable) with a namespaced `d` tag: one link per pair and author.
 */
export const PUBLIC_LINK_KIND = 30078;
export const PUBLIC_LINK_D_PREFIX = 'acceso-nostr:persona-link:';
export const PUBLIC_LINK_VERSION = 'acceso-nostr/persona-link/v1';
const ALT = 'Vínculo público entre dos personas Nostr: ambas claves lo firmaron (Acceso Nostr, docs/public-link.md)';

export class PublicLinkRefusedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PublicLinkRefusedError';
  }
}

/** Canonical statement both personas sign. Pubkeys are sorted, so it is the same from either side. */
export function linkStatement(pubkeyA: string, pubkeyB: string, issuedAt: number): string {
  const [low, high] = [pubkeyA.toLowerCase(), pubkeyB.toLowerCase()].sort();
  return `${PUBLIC_LINK_VERSION}\n${low}\n${high}\n${issuedAt}`;
}

/**
 * Sovereign and Sovereign Tor profiles refuse to publish a link: publishing it ties the personas together
 * permanently and publicly, which contradicts offline custody / Tor-only compartmentation.
 */
export function assertPublicLinkAllowed(configs: ReadonlyArray<Pick<SovereigntyConfig, 'network' | 'custody'> | undefined>): void {
  for (const c of configs) {
    if (!c) continue;
    if (c.network === 'tor-only') throw new PublicLinkRefusedError('Tor-only profiles never publish a public link between personas');
    if (c.custody === 'offline') throw new PublicLinkRefusedError('sovereign (offline custody) profiles never publish a public link between personas');
  }
}

function halfTemplate(otherPubkey: string, statement: string, issuedAt: number): EventTemplate {
  return {
    kind: PUBLIC_LINK_KIND,
    created_at: issuedAt,
    content: statement,
    tags: [
      ['d', PUBLIC_LINK_D_PREFIX + otherPubkey],
      ['p', otherPubkey],
      ['issued', String(issuedAt)],
      ['alt', ALT],
    ],
  };
}

/** Step 1 (persona B, possibly on another device/signer): sign consent to be linked with `otherPubkey` (persona A). */
export async function signLinkConsent(signer: Signer, otherPubkey: string, issuedAt: number): Promise<NostrEvent> {
  if (!isHex(otherPubkey, 32)) throw new Error('other persona pubkey must be 64 hex chars');
  const me = await signer.getPublicKey();
  if (me === otherPubkey) throw new Error('a persona cannot link to itself');
  return signer.signEvent(halfTemplate(otherPubkey, linkStatement(me, otherPubkey, issuedAt), issuedAt));
}

/** Step 2 (persona A): wrap B's consent in A's own signed event. The result is the publishable public link. */
export async function finalizePublicLink(signer: Signer, counter: NostrEvent): Promise<NostrEvent> {
  const me = await signer.getPublicKey();
  const issuedAt = Number(getTagValues(counter, 'issued')[0]);
  const v = checkHalf(counter, me, issuedAt);
  if (v) throw new Error(`invalid consent from the other persona: ${v}`);
  const tmpl = halfTemplate(counter.pubkey, linkStatement(me, counter.pubkey, issuedAt), issuedAt);
  tmpl.tags!.push(['counter-signature', JSON.stringify(counter)]);
  const evt = await signer.signEvent(tmpl);
  const check = verifyPublicLink(evt);
  if (!check.ok) throw new Error(`public link failed self-verification: ${check.reason}`);
  return evt;
}

export interface CreatePublicLinkOptions {
  /** Explicit user action (FR-007): never created by default. */
  confirm: boolean;
  /** The user acknowledged it is public and cannot be undone (deleting it later does not un-publish it). */
  acknowledgePermanent: boolean;
  /** Panel configuration of both personas: sovereign / Tor-only refuse. */
  profiles?: ReadonlyArray<Pick<SovereigntyConfig, 'network' | 'custody'> | undefined>;
  now?: () => number;
}

/** Both signers at hand (e.g. two personas of the same vault): consent from `b`, then the final event from `a`. */
export async function createPublicLink(a: Signer, b: Signer, opts: CreatePublicLinkOptions): Promise<NostrEvent> {
  if (opts.confirm !== true) throw new ConsentRequiredError('publishing a public link between personas');
  if (opts.acknowledgePermanent !== true) throw new ConsentRequiredError('acknowledging that a public link is permanent');
  assertPublicLinkAllowed(opts.profiles ?? []);
  const issuedAt = Math.floor((opts.now?.() ?? Date.now()) / 1000);
  const counter = await signLinkConsent(b, await a.getPublicKey(), issuedAt);
  return finalizePublicLink(a, counter);
}

/** Checks one consent half signed by `evt.pubkey` naming `otherPubkey`; returns a reason or undefined. */
function checkHalf(evt: unknown, otherPubkey: string, issuedAt: number): string | undefined {
  if (!verifyEvent(evt)) return 'bad-signature';
  if (evt.kind !== PUBLIC_LINK_KIND) return 'wrong-kind';
  if (!Number.isSafeInteger(issuedAt) || issuedAt <= 0) return 'bad-issued';
  const ps = getTagValues(evt, 'p');
  if (ps.length !== 1 || ps[0] !== otherPubkey || !isHex(otherPubkey, 32)) return 'wrong-p';
  if (evt.pubkey === otherPubkey) return 'self-link';
  const ds = getTagValues(evt, 'd');
  if (ds.length !== 1 || ds[0] !== PUBLIC_LINK_D_PREFIX + otherPubkey) return 'wrong-d';
  const issued = getTagValues(evt, 'issued');
  if (issued.length !== 1 || issued[0] !== String(issuedAt)) return 'issued-mismatch';
  if (evt.content !== linkStatement(evt.pubkey, otherPubkey, issuedAt)) return 'statement-mismatch';
  return undefined;
}

export type PublicLinkVerification = { ok: true; personas: [string, string]; issuedAt: number } | { ok: false; reason: string };

/**
 * Third-party verification: both halves are valid Schnorr signatures over the same statement, each naming
 * the other key. A one-sided event (no embedded consent, or consent from another key) is rejected.
 */
export function verifyPublicLink(evt: unknown): PublicLinkVerification {
  if (!verifyEvent(evt)) return { ok: false, reason: 'bad-signature' };
  const other = getTagValues(evt, 'p')[0] ?? '';
  const issuedAt = Number(getTagValues(evt, 'issued')[0]);
  const outer = checkHalf(evt, other, issuedAt);
  if (outer) return { ok: false, reason: outer };
  const counters = getTagValues(evt, 'counter-signature');
  if (counters.length !== 1) return { ok: false, reason: counters.length ? 'multiple-counter-signatures' : 'missing-counter-signature' };
  let counter: unknown;
  try {
    counter = JSON.parse(counters[0]!);
  } catch {
    return { ok: false, reason: 'malformed-counter-signature' };
  }
  if ((counter as { pubkey?: unknown })?.pubkey !== other) return { ok: false, reason: 'counter-signed-by-wrong-key' };
  const inner = checkHalf(counter, evt.pubkey, issuedAt);
  if (inner) return { ok: false, reason: `counter-${inner}` };
  return { ok: true, personas: [evt.pubkey, other], issuedAt };
}

/** NIP-09 deletion request for a published link. Relays and readers may ignore it: it does not un-publish. */
export function publicLinkDeletion(otherPubkey: string, authorPubkey: string): EventTemplate {
  return {
    kind: 5,
    content: 'vínculo público retirado',
    tags: [
      ['a', `${PUBLIC_LINK_KIND}:${authorPubkey}:${PUBLIC_LINK_D_PREFIX}${otherPubkey}`],
      ['k', String(PUBLIC_LINK_KIND)],
    ],
  };
}
