/**
 * NIP-44 v2 encrypted payloads.
 *
 * Security note (spec §2.3 / §10.2): NIP-44 does NOT provide forward secrecy, post-compromise
 * security, deniability guarantees against a key compromise, or IP protection. High-risk group
 * conversations must use a GroupCryptoProvider (Marmot/MLS) instead.
 */
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { chacha20 } from '@noble/ciphers/chacha.js';
import { equalBytes as nobleEqualBytes } from '@noble/ciphers/utils.js';
import { extract as hkdfExtract, expand as hkdfExpand } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64 } from '@scure/base';
import { concatBytes, hexToBytes, randomBytes, utf8ToBytes, bytesToUtf8 } from './utils';

const VERSION = 2;
const MIN_PLAINTEXT = 1;
const MAX_PLAINTEXT = 65535;
const SALT = utf8ToBytes('nip44-v2');

export function getConversationKey(secretKey: Uint8Array, peerPubkeyHex: string): Uint8Array {
  const shared = secp256k1.getSharedSecret(secretKey, hexToBytes('02' + peerPubkeyHex));
  return hkdfExtract(sha256, shared.subarray(1, 33), SALT);
}

/** Exported for the official test vectors (`get_message_keys`). */
export function getMessageKeys(conversationKey: Uint8Array, nonce: Uint8Array) {
  if (conversationKey.length !== 32) throw new Error('invalid conversation key length');
  if (nonce.length !== 32) throw new Error('invalid nonce length');
  const keys = hkdfExpand(sha256, conversationKey, nonce, 76);
  return { chachaKey: keys.subarray(0, 32), chachaNonce: keys.subarray(32, 44), hmacKey: keys.subarray(44, 76) };
}

export function calcPaddedLen(len: number): number {
  if (!Number.isSafeInteger(len) || len < 1) throw new Error('expected positive integer');
  if (len <= 32) return 32;
  const nextPower = 1 << (Math.floor(Math.log2(len - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((len - 1) / chunk) + 1);
}

function pad(plaintext: string): Uint8Array {
  const unpadded = utf8ToBytes(plaintext);
  const len = unpadded.length;
  if (len < MIN_PLAINTEXT || len > MAX_PLAINTEXT) throw new Error('invalid plaintext length: must be between 1b and 64KB');
  const prefix = new Uint8Array([(len >> 8) & 0xff, len & 0xff]);
  const suffix = new Uint8Array(calcPaddedLen(len) - len);
  return concatBytes(prefix, unpadded, suffix);
}

function unpad(padded: Uint8Array): string {
  const len = (padded[0]! << 8) | padded[1]!;
  const unpadded = padded.subarray(2, 2 + len);
  if (len < MIN_PLAINTEXT || len > MAX_PLAINTEXT || unpadded.length !== len || padded.length !== 2 + calcPaddedLen(len)) {
    throw new Error('invalid padding');
  }
  return bytesToUtf8(unpadded);
}

function hmacAad(key: Uint8Array, message: Uint8Array, aad: Uint8Array): Uint8Array {
  if (aad.length !== 32) throw new Error('AAD associated data must be 32 bytes');
  return hmac(sha256, key, concatBytes(aad, message));
}

export function encrypt(plaintext: string, conversationKey: Uint8Array, nonce: Uint8Array = randomBytes(32)): string {
  const { chachaKey, chachaNonce, hmacKey } = getMessageKeys(conversationKey, nonce);
  const ciphertext = chacha20(chachaKey, chachaNonce, pad(plaintext));
  const mac = hmacAad(hmacKey, ciphertext, nonce);
  return base64.encode(concatBytes(new Uint8Array([VERSION]), nonce, ciphertext, mac));
}

function decodePayload(payload: string) {
  if (typeof payload !== 'string') throw new Error('payload must be a string');
  const plen = payload.length;
  if (plen < 132 || plen > 87472) throw new Error('invalid payload length: ' + plen);
  if (payload[0] === '#') throw new Error('unknown encryption version');
  const data = base64.decode(payload);
  const dlen = data.length;
  if (dlen < 99 || dlen > 65603) throw new Error('invalid data length: ' + dlen);
  const vers = data[0];
  if (vers !== VERSION) throw new Error('unknown encryption version ' + vers);
  return { nonce: data.subarray(1, 33), ciphertext: data.subarray(33, -32), mac: data.subarray(-32) };
}

export function decrypt(payload: string, conversationKey: Uint8Array): string {
  const { nonce, ciphertext, mac } = decodePayload(payload);
  const { chachaKey, chachaNonce, hmacKey } = getMessageKeys(conversationKey, nonce);
  const calculated = hmacAad(hmacKey, ciphertext, nonce);
  if (!nobleEqualBytes(calculated, mac)) throw new Error('invalid MAC');
  return unpad(chacha20(chachaKey, chachaNonce, ciphertext));
}

export const nip44 = { getConversationKey, encrypt, decrypt, calcPaddedLen };
