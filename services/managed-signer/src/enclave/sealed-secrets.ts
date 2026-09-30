import { constants, createDecipheriv, privateDecrypt, type KeyObject } from 'node:crypto';
import { checkEnvelopeFreshness, envelopeAad, parseEnvelope, parseEnvelopeContent, type EnvelopePurpose, type ExportSecret, type ImportSecrets } from '@sedecim/signer';

/**
 * FR005-10: the enclave's side of the secrets a client seals to it (format in @sedecim/signer, enclave/envelope.ts).
 * They open only with the enclave's ephemeral RSA key, which never leaves it, and only for the request they were sealed
 * for (purpose, owner tag, pubkey in the AAD) within minutes of the attestation the client verified, by the enclave's
 * clock. The parent that relays them cannot read them. What can be wiped is wiped; the strings (password, ncryptsec)
 * live on the JS heap until the garbage collector takes them, like the ones that arrive in clear.
 */

/** Every way a sealed secret can fail to open gets this same answer, whichever part failed. */
export const SEALED_DOES_NOT_OPEN =
  'sealed secret does not open: it was sealed to another enclave key (after a restart the enclave has a new one: fetch a new attestation and seal again), for another request, or it was altered';

export class SealedSecretError extends Error {}

export function openSealedSecret(privateKey: KeyObject, envelope: unknown, purpose: 'import', ownerTag: string, pubkey: string, nowMs: number): ImportSecrets;
export function openSealedSecret(privateKey: KeyObject, envelope: unknown, purpose: 'export', ownerTag: string, pubkey: string, nowMs: number): ExportSecret;
export function openSealedSecret(privateKey: KeyObject, envelope: unknown, purpose: EnvelopePurpose, ownerTag: string, pubkey: string, nowMs: number): ImportSecrets | ExportSecret;
export function openSealedSecret(privateKey: KeyObject, envelope: unknown, purpose: EnvelopePurpose, ownerTag: string, pubkey: string, nowMs: number): ImportSecrets | ExportSecret {
  let aad: Uint8Array;
  let parts: ReturnType<typeof parseEnvelope>;
  try {
    aad = envelopeAad(purpose, ownerTag, pubkey);
    parts = parseEnvelope(envelope);
  } catch (err) {
    throw new SealedSecretError(`sealed secret: ${(err as Error).message}`);
  }
  let key: Buffer | undefined;
  let head: Buffer | undefined;
  let plain: Buffer;
  try {
    key = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, parts.ek);
    if (key.length !== 32) throw new Error('not an AES-256 key');
    const d = createDecipheriv('aes-256-gcm', key, parts.iv, { authTagLength: 16 });
    d.setAAD(aad);
    d.setAuthTag(parts.ct.subarray(parts.ct.length - 16));
    // GCM hands out plaintext before the tag is checked: wiped in `finally` even when the tag then fails.
    head = d.update(parts.ct.subarray(0, parts.ct.length - 16));
    const tail = d.final();
    plain = Buffer.concat([head, tail]);
    tail.fill(0);
  } catch {
    throw new SealedSecretError(SEALED_DOES_NOT_OPEN);
  } finally {
    key?.fill(0);
    head?.fill(0);
  }
  try {
    const content = parseEnvelopeContent(purpose, plain);
    checkEnvelopeFreshness(content.at, nowMs);
    return content;
  } catch (err) {
    throw new SealedSecretError(`sealed secret: ${(err as Error).message}`);
  } finally {
    plain.fill(0);
  }
}

/** A switch of the environment: `1` on; unset, empty or `0` off; anything else is refused (a typo must not leave it off). */
export function flagFromEnv(env: NodeJS.ProcessEnv, name: string): boolean {
  const v = env[name];
  if (v === undefined || v === '' || v === '0') return false;
  if (v === '1') return true;
  throw new Error(`${name} must be 1 (on) or 0/unset (off), got '${v}'`);
}
