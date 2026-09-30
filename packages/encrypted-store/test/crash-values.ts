import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

/** Keys written by crash-writer.ts. */
export const CRASH_KEYS = ['alpha', 'bravo', 'charlie', 'delta', 'echo'];

export interface CrashValue {
  key: string;
  gen: number;
  /** Deterministic filler (32 KiB to 160 KiB) so a write spans several syscalls and a kill can land mid-write. */
  payload: string;
}

export function crashValue(key: string, gen: number): CrashValue {
  const seed = bytesToHex(sha256(utf8ToBytes(`${key}:${gen}`)));
  const size = 512 + (parseInt(seed.slice(0, 4), 16) % 2048);
  return { key, gen, payload: seed.repeat(size) };
}
