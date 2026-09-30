import { generateSecretKey, nip19, npubEncode, normalizePubkey, wipe, type Signer } from '@sedecim/nostr-core';
import { RelayPool } from '@sedecim/relay-pool';
import { LocalSigner, Nip07Signer, Nip46Signer, parseBunkerUrl } from '@sedecim/signer';

/** The console only ever signs NIP-98 HTTP auth events (kind 27235). */
export const ADMIN_NIP46_PERMISSIONS = ['get_public_key', 'sign_event:27235'];

export type SignerKind = 'nip07' | 'nip46' | 'local-dev';

export interface AdminSession {
  signer: Signer;
  pubkey: string;
  kind: SignerKind;
  close(): void;
}

/** FR023-11: `admin` false: a key that is not a policy admin, which only sees its own devices. */
export type ConsoleSession = AdminSession & { admin: boolean };

export const hasNip07 = () => typeof window !== 'undefined' && !!(window as { nostr?: unknown }).nostr;

export async function signInNip07(): Promise<AdminSession> {
  const signer = new Nip07Signer();
  return { signer, pubkey: await signer.getPublicKey(), kind: 'nip07', close: () => undefined };
}

export async function signInNip46(bunkerUrl: string, onAuthUrl: (url: string) => void): Promise<AdminSession> {
  const clientKey = generateSecretKey();
  const pool = new RelayPool({ signer: new LocalSigner(clientKey), authMode: 'on-demand' });
  const signer = new Nip46Signer(parseBunkerUrl(bunkerUrl.trim()), { pool, clientSecretKey: clientKey, permissions: ADMIN_NIP46_PERMISSIONS, onAuthUrl });
  wipe(clientKey);
  try {
    await signer.connect();
    const pubkey = await signer.getPublicKey();
    return { signer, pubkey, kind: 'nip46', close: () => (signer.close(), pool.close()) };
  } catch (e) {
    signer.close();
    pool.close();
    throw e;
  }
}

/** Development only: the key lives in this tab's memory and is gone on reload. */
export async function signInLocalDev(nsec: string): Promise<AdminSession> {
  const d = nip19.decode(nsec.trim());
  if (d.type !== 'nsec') throw new Error('se esperaba una nsec');
  const signer = new LocalSigner(d.data);
  wipe(d.data);
  return { signer, pubkey: await signer.getPublicKey(), kind: 'local-dev', close: () => undefined };
}

/** npub or hex → hex; throws a Spanish message on bad input. */
export function parsePubkey(v: string): string {
  try {
    return normalizePubkey(v.trim().toLowerCase());
  } catch {
    throw new Error('clave pública inválida: usa npub… o 64 caracteres hex');
  }
}

export const shortNpub = (hex: string) => {
  try {
    const n = npubEncode(hex);
    return `${n.slice(0, 12)}…${n.slice(-6)}`;
  } catch {
    return hex;
  }
};
