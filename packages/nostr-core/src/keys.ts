import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from './utils';

/** Generate a secp256k1 secret key from the platform CSPRNG. */
export function generateSecretKey(): Uint8Array {
  return secp256k1.utils.randomSecretKey();
}

/** x-only public key (hex) as used by Nostr / BIP-340. */
export function getPublicKey(secretKey: Uint8Array): string {
  return bytesToHex(schnorr.getPublicKey(secretKey));
}

export function isValidSecretKey(secretKey: Uint8Array): boolean {
  return secretKey.length === 32 && secp256k1.utils.isValidSecretKey(secretKey);
}

export function isValidPublicKey(pubkey: string): boolean {
  try {
    schnorr.utils.lift_x(BigInt('0x' + pubkey));
    return /^[0-9a-f]{64}$/.test(pubkey);
  } catch {
    return false;
  }
}

export interface KeySelfTest {
  ok: boolean;
  pubkey: string;
  checks: { derivation: boolean; signature: boolean; tamperRejected: boolean };
}

/**
 * Verifies derivation and a BIP-340 sign/verify roundtrip for a key (key lifecycle step 2).
 * Used by the offline key generator and on import.
 */
export function selfTestKey(secretKey: Uint8Array, expectedPubkey?: string): KeySelfTest {
  const pubkey = getPublicKey(secretKey);
  const derivation = isValidSecretKey(secretKey) && (expectedPubkey === undefined || expectedPubkey === pubkey);
  const msg = sha256(utf8ToBytes(`self-test:${pubkey}`));
  const sig = schnorr.sign(msg, secretKey);
  const signature = schnorr.verify(sig, msg, hexToBytes(pubkey));
  const tampered = new Uint8Array(msg);
  tampered[0] = tampered[0]! ^ 0xff;
  const tamperRejected = !schnorr.verify(sig, tampered, hexToBytes(pubkey));
  return { ok: derivation && signature && tamperRejected, pubkey, checks: { derivation, signature, tamperRejected } };
}

/** Best-effort zeroization of key material held in memory. */
export function wipe(bytes: Uint8Array): void {
  bytes.fill(0);
}
