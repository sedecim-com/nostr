import { describe, expect, it } from 'vitest';
import { generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { UnavailableGroupCryptoProvider, GroupCryptoUnavailableError, assertHighSecurity, runConformance } from '../src/index';

describe('marmot adapter', () => {
  it('fails closed without a provider', async () => {
    const p = new UnavailableGroupCryptoProvider();
    await expect(p.encrypt()).rejects.toBeInstanceOf(GroupCryptoUnavailableError);
    expect(() => assertHighSecurity(p)).toThrow(/forward secrecy/);
    const failures = await runConformance({ provider: p, makeSigner: () => new LocalSigner(generateSecretKey()) });
    expect(failures.length).toBeGreaterThan(0);
  });
});
