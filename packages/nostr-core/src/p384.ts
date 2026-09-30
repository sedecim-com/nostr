import { p384 } from '@noble/curves/nist.js';
import { sha256, sha384 } from '@noble/hashes/sha2.js';

export { sha256, sha384 };

/**
 * ECDSA P-384 with SHA-384, the algorithm of the AWS Nitro attestation PKI and of its COSE ES384 signatures, for code
 * that cannot use node:crypto (a browser checking an enclave attestation before sealing a secret to it). `der` is the
 * X.509 form (SEQUENCE {r, s}); `compact` is r || s, 96 bytes, the COSE form. High-S signatures are valid, as in
 * OpenSSL. Anything malformed (signature, key, encoding) is `false`, never an exception.
 */
export function verifyEcdsaP384(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array, format: 'der' | 'compact'): boolean {
  try {
    return p384.verify(signature, message, publicKey, { prehash: true, lowS: false, format });
  } catch {
    return false;
  }
}
