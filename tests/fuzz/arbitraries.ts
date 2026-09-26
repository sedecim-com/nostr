/**
 * Shared fast-check arbitraries and run budget for the SEC-03 property/fuzz suite. Runs are bounded so
 * the whole suite stays fast; raise FUZZ_RUNS locally for a longer campaign
 * (e.g. `FUZZ_RUNS=2000 npx vitest run tests/fuzz --testTimeout=0`).
 */
import fc from 'fast-check';
import { isValidSecretKey } from '@sedecim/nostr-core';

const scale = Number(process.env.FUZZ_RUNS ?? 0);
/** fast-check parameters: `base` runs by default, FUZZ_RUNS (if larger) for long campaigns. */
export const runs = (base: number) => ({ numRuns: Math.max(base, scale) });

export const secretKey = () => fc.uint8Array({ minLength: 32, maxLength: 32 }).filter(isValidSecretKey);
export const hex32 = () => fc.uint8Array({ minLength: 32, maxLength: 32 }).map((b) => Buffer.from(b).toString('hex'));
/** Unicode text that survives a UTF-8 round-trip (no lone surrogates). */
export const text = (o: { minLength?: number; maxLength?: number } = {}) => fc.string({ unit: 'binary', ...o }).filter((s) => Buffer.from(s, 'utf8').toString('utf8') === s);
export const utf8Len = (s: string) => Buffer.byteLength(s, 'utf8');

/** True when `fn` throws an Error; fails the property on a non-Error throw (never a crash or hang). */
export function throwsCleanly(fn: () => unknown): boolean {
  try {
    fn();
    return false;
  } catch (e) {
    if (!(e instanceof Error)) throw new Error(`threw a non-Error: ${String(e)}`);
    return true;
  }
}
