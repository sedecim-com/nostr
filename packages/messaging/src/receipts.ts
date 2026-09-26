/**
 * Application-level receipts (spec §11: RECIPIENT_ACKED / READ). PROVISIONAL: the receipt format is
 * an open decision (§25.1 #6). Receipts are gift-wrapped rumors so relays never see who read what.
 * Read receipts are opt-in and can be disabled by the privacy profile.
 */
import { createRumor, getTagValue, type Signer } from '@sedecim/nostr-core';
import { wrapRumor, type Unwrapped, type WrapOptions } from './nip59';

/** Provisional rumor kind for receipts; never published unwrapped. */
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
