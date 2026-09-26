import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { TestRelay } from '@sedecim/test-relay';
import { preset } from '@sedecim/profiles';
import { ConsentRequiredError, PUBLIC_LINK_KIND, PublicLinkRefusedError, createPublicLink, finalizePublicLink, linkStatement, publicLinkDeletion, signLinkConsent, verifyPublicLink } from '../src/index';

const skA = generateSecretKey();
const skB = generateSecretKey();
const skC = generateSecretKey();
const a = new LocalSigner(skA);
const b = new LocalSigner(skB);
const c = new LocalSigner(skC);
const pkA = getPublicKey(skA);
const pkB = getPublicKey(skB);
const ok = { confirm: true, acknowledgePermanent: true } as const;

/** Re-signs a modified copy with `sk` (a tamperer who controls that key). */
const resign = (evt: NostrEvent, sk: Uint8Array, patch: Partial<NostrEvent>) => finalizeEvent(toUnsigned({ kind: evt.kind, content: evt.content, tags: evt.tags, created_at: evt.created_at, ...patch }, getPublicKey(sk)), sk);
const counterOf = (evt: NostrEvent) => JSON.parse(evt.tags.find((t) => t[0] === 'counter-signature')![1]!) as NostrEvent;
const withCounter = (evt: NostrEvent, counter: unknown) => evt.tags.map((t) => (t[0] === 'counter-signature' ? ['counter-signature', JSON.stringify(counter)] : t));

describe('public persona link as a signed Nostr event (FR007-04)', () => {
  it('is signed by both personas and verifiable by a third party', async () => {
    const evt = await createPublicLink(a, b, { ...ok, now: () => 1_700_000_000_000 });
    expect(evt.kind).toBe(PUBLIC_LINK_KIND);
    expect(evt.pubkey).toBe(pkA);
    expect(evt.tags).toContainEqual(['p', pkB]);
    expect(evt.content).toBe(linkStatement(pkB, pkA, 1_700_000_000));
    expect(verifyPublicLink(evt)).toEqual({ ok: true, personas: [pkA, pkB], issuedAt: 1_700_000_000 });
    // the statement is order independent: both sides sign the very same text
    expect(counterOf(evt).content).toBe(evt.content);
  });

  it('works across devices: consent signed separately, then finalized by the other persona', async () => {
    const consent = await signLinkConsent(b, pkA, 1_700_000_100);
    const evt = await finalizePublicLink(a, consent);
    expect(verifyPublicLink(evt).ok).toBe(true);
    // consent given to someone else cannot be reused by A
    await expect(finalizePublicLink(a, await signLinkConsent(b, getPublicKey(skC), 1_700_000_100))).rejects.toThrow(/wrong-p/);
  });

  it('rejects one-sided and tampered links', async () => {
    const evt = await createPublicLink(a, b, ok);
    const counter = counterOf(evt);
    // one-sided: A alone claims the link
    expect(verifyPublicLink(resign(evt, skA, { tags: evt.tags.filter((t) => t[0] !== 'counter-signature') }))).toEqual({ ok: false, reason: 'missing-counter-signature' });
    // A embeds a "consent" signed by some other key C
    const byC = resign(counter, skC, {});
    expect(verifyPublicLink(resign(evt, skA, { tags: withCounter(evt, byC) }))).toEqual({ ok: false, reason: 'counter-signed-by-wrong-key' });
    // consent tampered after B signed it
    expect(verifyPublicLink(resign(evt, skA, { tags: withCounter(evt, { ...counter, content: counter.content + 'x' }) }))).toEqual({ ok: false, reason: 'counter-bad-signature' });
    // B consented to a different statement (other issue time)
    const otherTime = await signLinkConsent(b, pkA, 42);
    expect(verifyPublicLink(resign(evt, skA, { tags: withCounter(evt, otherTime) }))).toEqual({ ok: false, reason: 'counter-issued-mismatch' });
    // outer event edited without re-signing
    expect(verifyPublicLink({ ...evt, content: 'otra cosa' })).toEqual({ ok: false, reason: 'bad-signature' });
    // C re-publishes B's consent pretending to be A
    expect(verifyPublicLink(resign(evt, skC, {})).ok).toBe(false);
    // p tag swapped to C while keeping B's consent
    const swapped = resign(evt, skA, { tags: evt.tags.map((t) => (t[0] === 'p' ? ['p', getPublicKey(skC)] : t)) });
    expect(verifyPublicLink(swapped).ok).toBe(false);
    expect(verifyPublicLink(resign(evt, skA, { tags: evt.tags.map((t) => (t[0] === 'counter-signature' ? [t[0], '{'] : t)) }))).toEqual({ ok: false, reason: 'malformed-counter-signature' });
    expect(verifyPublicLink({ foo: 1 })).toEqual({ ok: false, reason: 'bad-signature' });
  });

  it('needs explicit consent and is refused by sovereign and Tor-only profiles', async () => {
    await expect(createPublicLink(a, b, { confirm: false, acknowledgePermanent: true })).rejects.toThrow(ConsentRequiredError);
    await expect(createPublicLink(a, b, { confirm: true, acknowledgePermanent: false })).rejects.toThrow(ConsentRequiredError);
    await expect(createPublicLink(a, b, { ...ok, profiles: [preset('convenience'), preset('sovereign')] })).rejects.toThrow(PublicLinkRefusedError);
    await expect(createPublicLink(a, b, { ...ok, profiles: [preset('sovereign-tor'), undefined] })).rejects.toThrow(PublicLinkRefusedError);
    await expect(createPublicLink(a, a, ok)).rejects.toThrow(/itself/);
    expect(verifyPublicLink(await createPublicLink(a, b, { ...ok, profiles: [preset('convenience'), preset('institutional')] })).ok).toBe(true);
  });

  it('builds a NIP-09 deletion request for the link coordinate', () => {
    expect(publicLinkDeletion(pkB, pkA).tags).toContainEqual(['a', `30078:${pkA}:acceso-nostr:persona-link:${pkB}`]);
  });

  describe('through a relay', () => {
    const relay = new TestRelay();
    let pool: RelayPool;
    beforeAll(async () => {
      await relay.start();
      pool = new RelayPool({ webSocketFactory: (u) => new WebSocket(u) as unknown as WebSocketLike, signer: c });
    });
    afterAll(async () => {
      pool.close();
      await relay.stop();
    });

    it('a third party fetches the link from a relay and verifies both signatures', async () => {
      const evt = await createPublicLink(a, b, ok);
      expect((await pool.publishTo(evt, relay.url)).ok).toBe(true);
      const [got] = await pool.query([relay.url], [{ kinds: [PUBLIC_LINK_KIND], '#p': [pkB] }], 2000);
      expect(verifyPublicLink(got)).toMatchObject({ ok: true, personas: [pkA, pkB] });
    });
  });
});
