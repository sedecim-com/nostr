import { describe, expect, it } from 'vitest';
import { bech32 } from '@scure/base';
import { generateSecretKey, nip49 } from '@sedecim/nostr-core';
import { MAX_IMPORT_LOG_N, ManagedSigner, ManagedSignerError, MemoryVault } from '@sedecim/managed-signer';

/** Rewrites the logN byte of an ncryptsec (the payload no longer decrypts, which is fine: it must be refused first). */
function withLogN(ncryptsec: string, logN: number): string {
  const { words } = bech32.decode(ncryptsec as `ncryptsec1${string}`, 5000);
  const b = new Uint8Array(bech32.fromWords(words));
  b[1] = logN;
  return bech32.encode('ncryptsec', bech32.toWords(b), 5000);
}

describe('managed-signer import limits (internal review 2026-09)', () => {
  const core = new ManagedSigner(new MemoryVault());
  const valid = nip49.encryptKey(generateSecretKey(), 'contraseña larga 123', 4);

  it('refuses an attacker-chosen scrypt cost before running scrypt', async () => {
    const started = Date.now();
    const err = await core.importEncrypted('o', 'p', withLogN(valid, 20), 'contraseña larga 123').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ManagedSignerError);
    expect((err as ManagedSignerError).status).toBe(400);
    expect((err as Error).message).toMatch(/logN 20/);
    expect(Date.now() - started).toBeLessThan(500);
    expect(MAX_IMPORT_LOG_N).toBe(18);
  });

  it('a wrong password or a malformed payload is a 400, not a 500', async () => {
    for (const [nc, pw] of [
      [valid, 'otra contraseña'],
      ['ncryptsec1qqqq', 'x'],
      [42 as unknown as string, 'x'],
    ] as const) {
      const err = await core.importEncrypted('o', 'p', nc, pw).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ManagedSignerError);
      expect((err as ManagedSignerError).status).toBe(400);
    }
    expect((await core.importEncrypted('o', 'p', valid, 'contraseña larga 123')).state).toBe('active');
  });

  it('nip49.decryptKey honours maxLogN', () => {
    expect(nip49.ncryptsecLogN(valid)).toBe(4);
    expect(() => nip49.decryptKey(valid, 'contraseña larga 123', { maxLogN: 3 })).toThrow(/exceeds/);
    expect(nip49.decryptKey(valid, 'contraseña larga 123', { maxLogN: 4 }).logn).toBe(4);
  });
});
