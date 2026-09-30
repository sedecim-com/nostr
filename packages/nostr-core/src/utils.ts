import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';

export { bytesToHex, hexToBytes, randomBytes, utf8ToBytes, concatBytes };

const textDecoder = new TextDecoder();

export function bytesToUtf8(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

export function isHex(value: unknown, byteLength?: number): value is string {
  if (typeof value !== 'string') return false;
  if (byteLength !== undefined && value.length !== byteLength * 2) return false;
  return /^[0-9a-f]*$/.test(value) && value.length % 2 === 0;
}

/** Constant-time comparison for equal-length byte arrays. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** Uniform random integer in [0, max) using a CSPRNG. */
export function randomInt(max: number): number {
  if (!Number.isInteger(max) || max <= 0) throw new RangeError('max must be a positive integer');
  const limit = Math.floor(0x1_0000_0000 / max) * max;
  for (;;) {
    const b = randomBytes(4);
    const n = ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
    if (n < limit) return n % max;
  }
}
