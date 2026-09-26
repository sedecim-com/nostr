/**
 * Application-level receipts (spec §11: RECIPIENT_ACKED / READ), format per ADR 0005 (proposed):
 * gift-wrapped rumors so relays cannot tell a receipt from a message. Sending is governed by
 * profiles.receiptPolicy(): delivered receipts per profile, read receipts always opt-in. Incoming receipts
 * drive the outbox: `engine.applyReceipt(parseReceipt(await unwrap(signer, wrap)))` (FR-009).
 */
import { createRumor, getTagValue, type Signer } from '@sedecim/nostr-core';
import { wrapRumor, type Unwrapped, type WrapOptions } from './nip59';

/** Application rumor kind for receipts (ADR 0005); never published unwrapped. */
export const APP_RECEIPT_KIND = 16_914;

export type ReceiptType = 'delivered' | 'read';

export async function createReceipt(signer: Signer, to: string, rumorId: string, type: ReceiptType, opts: WrapOptions = {}) {
  const rumor = createRumor({ kind: APP_RECEIPT_KIND, content: '', tags: [['e', rumorId], ['p', to], ['receipt', type]] }, await signer.getPublicKey());
  return { rumor, event: await wrapRumor(signer, rumor, to, opts) };
}

export function parseReceipt(u: Unwrapped): { rumorId: string; type: ReceiptType; from: string } | undefined {
  if (u.rumor.kind !== APP_RECEIPT_KIND) return undefined;
  const rumorId = getTagValue(u.rumor, 'e');
  const type = getTagValue(u.rumor, 'receipt');
  if (!rumorId || (type !== 'delivered' && type !== 'read')) return undefined;
  return { rumorId, type, from: u.sender };
}
