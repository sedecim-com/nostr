import { nip98, type Signer } from '@sedecim/nostr-core';
import { BackupVaultClient, BackupVaultError, type BackupVaultAuth } from '@sedecim/identity/backup-vault';

/** NIP-98 authenticated JSON request signed by the active persona (identity-service, indexer, blob-store). */
export async function nip98Request<T = unknown>(signer: Signer, url: string, method = 'GET', body?: unknown): Promise<{ status: number; json: T }> {
  const raw = body === undefined ? undefined : JSON.stringify(body);
  const evt = await signer.signEvent(nip98.buildHttpAuthTemplate(url, method, raw));
  const res = await fetch(url, { method, headers: { authorization: nip98.encodeAuthHeader(evt), 'content-type': 'application/json' }, ...(raw ? { body: raw } : {}) });
  const text = await res.text();
  return { status: res.status, json: (text ? JSON.parse(text) : undefined) as T };
}

/** Creates the persona's account on first use; returns the account id and its registered pubkeys. */
export async function ensureAccount(signer: Signer, base: string, custody: string): Promise<{ accountId: string; pubkeys: string[] }> {
  let me = await nip98Request<{ account_id: string; personas: Array<{ pubkey: string }> }>(signer, `${base}/v1/accounts/me`);
  if (me.status === 404) {
    const created = await nip98Request(signer, `${base}/v1/accounts`, 'POST', { custody_mode: custody });
    if (created.status !== 201) throw new Error(`identity-service: ${created.status}`);
    me = await nip98Request(signer, `${base}/v1/accounts/me`);
  }
  return { accountId: me.json.account_id, pubkeys: me.json.personas.map((p) => p.pubkey) };
}

/**
 * Attach the Acceso login to this persona's account (explicit consent, ADR 0008): creates the account
 * if needed, then sends the Cognito ID token, which the service verifies and discards.
 */
export async function linkAccesoLogin(signer: Signer, identityService: string, idToken: string, custody: string): Promise<void> {
  const base = identityService.replace(/\/$/, '');
  await ensureAccount(signer, base, custody);
  const res = await nip98Request<{ error?: string }>(signer, `${base}/v1/accounts/me/external-logins`, 'POST', { provider: 'cognito', token: idToken });
  if (res.status !== 201) throw new Error(res.status === 409 ? 'esa cuenta de Acceso ya está vinculada a otra identidad' : `identity-service: ${res.status} ${res.json?.error ?? ''}`);
}

export type LinkVisibility = 'private' | 'selective' | 'public';

/**
 * FR-007: links two of the user's personas in the identity service after an explicit confirmation.
 * The second persona proves control of its key (fresh NIP-98-style event bound to the account).
 */
export async function linkPersonas(from: { signer: Signer; custody: string }, to: { signer: Signer; custody: string }, identityService: string, visibility: LinkVisibility, audience: string[] = []): Promise<void> {
  const base = identityService.replace(/\/$/, '');
  const account = await ensureAccount(from.signer, base, from.custody);
  const toPub = await to.signer.getPublicKey();
  if (!account.pubkeys.includes(toPub)) {
    const url = `${base}/v1/accounts/me/personas`;
    const proof = await to.signer.signEvent({ kind: nip98.HTTP_AUTH_KIND, content: '', tags: [['u', url], ['account', account.accountId]] });
    const reg = await nip98Request<{ error?: string }>(from.signer, url, 'POST', { pubkey: toPub, custody_mode: to.custody, proof });
    if (reg.status !== 201) throw new Error(reg.status === 409 ? 'esa persona ya está registrada en otra cuenta' : `identity-service: ${reg.status} ${reg.json?.error ?? ''}`);
  }
  const res = await nip98Request<{ error?: string }>(from.signer, `${base}/v1/links`, 'POST', { from: await from.signer.getPublicKey(), to: toPub, visibility, audience, confirm: true });
  if (res.status !== 201) throw new Error(`identity-service: ${res.status} ${res.json?.error ?? ''}`);
}

/** What each visibility reveals, shown before confirming (FR007-03). */
export const LINK_CONSEQUENCES: Record<LinkVisibility, string> = {
  private: 'Solo el servicio de identidad sabrá que ambas personas son tuyas. Nadie más puede consultarlo, pero el operador sí conoce la relación.',
  selective: 'Las personas que elijas podrán comprobar que ambas identidades son tuyas. Cualquiera de ellas podría compartirlo: la desanonimización no se puede deshacer.',
  public: 'Cualquiera podrá comprobar que ambas identidades son la misma persona. Esto desanonimiza la persona pseudónima de forma permanente, aunque borres el vínculo después.',
};

/**
 * FR027-03: saves the persona's encrypted backup (NIP-49 under the backup password) in the cloud vault.
 * Creates the persona's identity account on first use; the server only receives the ciphertext.
 */
export async function saveCloudBackup(signer: Signer, vault: string, envelope: string, custody: string): Promise<void> {
  await ensureAccount(signer, vault.replace(/\/$/, ''), custody);
  await new BackupVaultClient({ baseUrl: vault, auth: { signer } }).upload(envelope);
}

/**
 * Downloads the newest web key backup from the cloud vault. In SaaS the Acceso token is enough (the
 * login must be linked to the account), so a new device can restore; otherwise an open persona of the
 * same account signs the request.
 */
export async function fetchCloudBackup(vault: string, auth: BackupVaultAuth): Promise<string> {
  const client = new BackupVaultClient({ baseUrl: vault, auth });
  const list = await client.list().catch((e) => {
    if (e instanceof BackupVaultError && e.status === 404) throw new Error('No hay copias en la nube para esta cuenta. Con Acceso, la persona debe estar vinculada a tu cuenta de Acceso.');
    throw e;
  });
  const latest = list.find((b) => b.format === 'acceso-nostr-key-backup');
  if (!latest) throw new Error('No hay copias de llave en la nube para esta cuenta.');
  return (await client.download(latest.id)).envelope;
}
