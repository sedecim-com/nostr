import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { bytesToHex, hexToBytes, nip44 } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { unwrap } from '../src/nip59';

// SEC-07 (ADR 0004): exportable NIP-59 vectors, built in packages/nostr-core/test/vectors/generate.ts with
// @noble primitives and fixed nonces, not with this package's wrapRumor.
const V = JSON.parse(readFileSync(new URL('../../nostr-core/test/vectors/nip59.vectors.json', import.meta.url), 'utf8'));
const signer = (sec: string) => new LocalSigner(hexToBytes(sec));

describe('NIP-59 vectors', () => {
  it('valid: unwrap returns the rumor, the seal and the authenticated sender', async () => {
    for (const v of V.valid) {
      const u = await unwrap(signer(v.recipient_sec), v.wrap);
      expect({ rumor: u.rumor, seal: u.seal, sender: u.sender }, v.note).toEqual({ rumor: v.rumor, seal: v.seal, sender: v.sender_pub });
      expect(bytesToHex(nip44.getConversationKey(hexToBytes(v.recipient_sec), v.wrap.pubkey))).toBe(v.wrap_conversation_key);
      expect(bytesToHex(nip44.getConversationKey(hexToBytes(v.recipient_sec), v.sender_pub))).toBe(v.seal_conversation_key);
    }
  });

  it('invalid: each wrap is rejected for its own reason', async () => {
    const reasons = [/cannot decrypt gift wrap/, /not a valid gift wrap/, /invalid seal/, /does not match seal signer/, /rumor id mismatch/];
    expect(V.invalid).toHaveLength(reasons.length);
    for (const [i, v] of V.invalid.entries()) await expect(unwrap(signer(v.recipient_sec), v.wrap), v.note).rejects.toThrow(reasons[i]);
  });
});
