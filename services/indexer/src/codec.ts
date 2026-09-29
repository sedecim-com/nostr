import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { concatBytes, randomBytes, utf8ToBytes, bytesToUtf8, type NostrEvent } from '@sedecim/nostr-core';

/**
 * Optional at-rest sealing of the mirrored raw event ("encrypted mirror/vault"). Encrypted DMs are
 * already ciphertext (gift wraps); sealing additionally hides public metadata in database backups.
 */
export interface EventCodec {
  sealed: boolean;
  encode(evt: NostrEvent): StoredEvent;
  /** The event a row holds. Throws unless it is the one the row's event_id names (IR-2026-09-15). */
  decode(row: StoredEvent, eventId: string): NostrEvent;
}

/** What a row stores for its event: the event itself, or a sealed payload and the format it was sealed with. */
export interface StoredEvent {
  raw?: NostrEvent | null;
  encrypted?: Uint8Array | null;
  /** Absent (NULL): sealed before SEC-06, without AAD. */
  sealVersion?: number | null;
}

/**
 * SEC-06: the AAD names the row's event id, so a payload moved to another row no longer authenticates.
 * Payloads sealed before it (no version) are still read, and the indexer re-seals them at start.
 */
export const SEAL_VERSION = 2;
const sealAad = (eventId: string) => utf8ToBytes(`acceso-nostr/mirror/v${SEAL_VERSION}/${eventId}`);

/** A row holding another row's event was tampered with or corrupted: it is never served under this id. */
function own(evt: NostrEvent, eventId: string): NostrEvent {
  if (evt.id !== eventId) throw new Error(`mirror row ${eventId} holds another event`);
  return evt;
}

export const plainCodec: EventCodec = {
  sealed: false,
  encode: (evt) => ({ raw: evt }),
  decode: (row, eventId) => {
    if (!row.raw) throw new Error('row is sealed but no key configured');
    return own(row.raw, eventId);
  },
};

export function sealedCodec(key: Uint8Array): EventCodec {
  if (key.length !== 32) throw new Error('mirror key must be 32 bytes');
  return {
    sealed: true,
    encode(evt) {
      const nonce = randomBytes(24);
      const sealed = xchacha20poly1305(key, nonce, sealAad(evt.id)).encrypt(utf8ToBytes(JSON.stringify(evt)));
      return { encrypted: concatBytes(nonce, sealed), sealVersion: SEAL_VERSION };
    },
    decode(row, eventId) {
      if (row.raw) return own(row.raw, eventId);
      if (row.sealVersion != null && row.sealVersion !== SEAL_VERSION) throw new Error(`mirror row ${eventId}: unknown seal version ${row.sealVersion}`);
      const data = row.encrypted!;
      // Without a version there is no AAD: the id check is what keeps a moved payload out until it is re-sealed.
      const aad = row.sealVersion == null ? undefined : sealAad(eventId);
      return own(JSON.parse(bytesToUtf8(xchacha20poly1305(key, data.subarray(0, 24), aad).decrypt(data.subarray(24)))) as NostrEvent, eventId);
    },
  };
}
