import { nip98, type Signer } from '@sedecim/nostr-core';

/** NIP-98 authenticated JSON request signed by the active persona (identity-service, indexer, blob-store). */
export async function nip98Request<T = unknown>(signer: Signer, url: string, method = 'GET', body?: unknown): Promise<{ status: number; json: T }> {
  const raw = body === undefined ? undefined : JSON.stringify(body);
  const evt = await signer.signEvent(nip98.buildHttpAuthTemplate(url, method, raw));
  const res = await fetch(url, { method, headers: { authorization: nip98.encodeAuthHeader(evt), 'content-type': 'application/json' }, ...(raw ? { body: raw } : {}) });
  const text = await res.text();
  return { status: res.status, json: (text ? JSON.parse(text) : undefined) as T };
}

/**
 * Attach the Acceso login to this persona's account (explicit consent, ADR 0008): creates the account
 * if needed, then sends the Cognito ID token, which the service verifies and discards.
 */
export async function linkAccesoLogin(signer: Signer, identityService: string, idToken: string, custody: string): Promise<void> {
  const base = identityService.replace(/\/$/, '');
  const me = await nip98Request(signer, `${base}/v1/accounts/me`);
  if (me.status === 404) {
    const created = await nip98Request(signer, `${base}/v1/accounts`, 'POST', { custody_mode: custody });
    if (created.status !== 201) throw new Error(`identity-service: ${created.status}`);
  }
  const res = await nip98Request<{ error?: string }>(signer, `${base}/v1/accounts/me/external-logins`, 'POST', { provider: 'cognito', token: idToken });
  if (res.status !== 201) throw new Error(res.status === 409 ? 'esa cuenta de Acceso ya está vinculada a otra identidad' : `identity-service: ${res.status} ${res.json?.error ?? ''}`);
}
