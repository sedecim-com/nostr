import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { concatBytes, randomBytes, utf8ToBytes, bytesToUtf8, type NostrEvent } from '@sedecim/nostr-core';

/**
 * Optional at-rest sealing of the mirrored raw event ("encrypted mirror/vault"). Encrypted DMs are
 * already ciphertext (gift wraps); sealing additionally hides public metadata in database backups.
 */
export interface EventCodec {
  sealed: boolean;
  encode(evt: NostrEvent): { raw?: NostrEvent; encrypted?: Uint8Array };
  decode(row: { raw?: NostrEvent | null; encrypted?: Uint8Array | null }): NostrEvent;
}

export const plainCodec: EventCodec = {
  sealed: false,
  encode: (evt) => ({ raw: evt }),
  decode: (row) => {
    if (!row.raw) throw new Error('row is sealed but no key configured');
    return row.raw;
  },
};

export function sealedCodec(key: Uint8Array): EventCodec {
  if (key.length !== 32) throw new Error('mirror key must be 32 bytes');
  return {
    sealed: true,
    encode(evt) {
      const nonce = randomBytes(24);
      return { encrypted: concatBytes(nonce, xchacha20poly1305(key, nonce).encrypt(utf8ToBytes(JSON.stringify(evt)))) };
    },
    decode(row) {
      if (row.raw) return row.raw;
      const data = row.encrypted!;
      return JSON.parse(bytesToUtf8(xchacha20poly1305(key, data.subarray(0, 24)).decrypt(data.subarray(24)))) as NostrEvent;
    },
  };
}
