import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { concatBytes, randomBytes, utf8ToBytes, bytesToUtf8, type NostrEvent } from '@sedecim/nostr-core';

/**
 * Optional at-rest sealing of the mirrored raw event ("encrypted mirror/vault"). Encrypted DMs are
 * already ciphertext (gift wraps); sealing additionally hides public metadata in database backups.
 */
export interface StoredEvent {
  raw?: NostrEvent | null;
  encrypted?: Uint8Array | null;
  /** Null/absent for payloads sealed before IR-2026-09-15 (no AAD); {@link SEAL_VERSION} binds the event id. */
  sealVersion?: number | null;
}

export interface EventCodec {
  sealed: boolean;
  encode(evt: NostrEvent): StoredEvent;
  /** `id` is the row's event id: a payload moved to another row fails to decode instead of answering for it. */
  decode(row: StoredEvent, id: string): NostrEvent;
}

/** IR-2026-09-15: sealed payloads carry the event id as AAD. */
export const SEAL_VERSION = 1;
const aad = (id: string) => utf8ToBytes(`sedecim/indexer-mirror/v${SEAL_VERSION}:${id}`);

function checkId(evt: NostrEvent, id: string): NostrEvent {
  if (evt.id !== id) throw new Error('stored event does not match its row');
  return evt;
}

export const plainCodec: EventCodec = {
  sealed: false,
  encode: (evt) => ({ raw: evt }),
  decode: (row, id) => {
    if (!row.raw) throw new Error('row is sealed but no key configured');
    return checkId(row.raw, id);
  },
};

export function sealedCodec(key: Uint8Array): EventCodec {
  if (key.length !== 32) throw new Error('mirror key must be 32 bytes');
  return {
    sealed: true,
    encode(evt) {
      const nonce = randomBytes(24);
      return { encrypted: concatBytes(nonce, xchacha20poly1305(key, nonce, aad(evt.id)).encrypt(utf8ToBytes(JSON.stringify(evt)))), sealVersion: SEAL_VERSION };
    },
    decode(row, id) {
      if (row.raw) return checkId(row.raw, id);
      const data = row.encrypted!;
      // Legacy rows (no AAD) are still bound by checking the decrypted id; resealLegacy() upgrades them.
      const cipher = row.sealVersion === SEAL_VERSION ? xchacha20poly1305(key, data.subarray(0, 24), aad(id)) : xchacha20poly1305(key, data.subarray(0, 24));
      return checkId(JSON.parse(bytesToUtf8(cipher.decrypt(data.subarray(24)))) as NostrEvent, id);
    },
  };
}
