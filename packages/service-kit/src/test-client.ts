import { finalizeEvent, getPublicKey, nip98, toUnsigned } from '@sedecim/nostr-core';

/** Helper for tests and CLIs: performs a NIP-98-authenticated JSON request. */
export async function nip98Fetch(secretKey: Uint8Array, url: string, method = 'GET', body?: unknown): Promise<{ status: number; json: any }> {
  const raw = body === undefined ? undefined : JSON.stringify(body);
  const evt = finalizeEvent(toUnsigned(nip98.buildHttpAuthTemplate(url, method, raw), getPublicKey(secretKey)), secretKey);
  const res = await fetch(url, { method, headers: { authorization: nip98.encodeAuthHeader(evt), 'content-type': 'application/json' }, body: raw });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : undefined };
}
