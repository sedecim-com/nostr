import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { fileURLToPath } from 'node:url';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned } from '@sedecim/nostr-core';
import { createPgPool, migrate, nip98Fetch, resetScope } from '@sedecim/service-kit';
import { createIdentityApi, MemoryIdentityRepository, PgIdentityRepository, type IdentityRepository } from '../src/index';

function suite(name: string, makeRepo: () => Promise<IdentityRepository>) {
  describe(name, () => {
    let base: string;
    let api: ReturnType<typeof createIdentityApi>;
    const a = generateSecretKey();
    const b = generateSecretKey();
    const viewer = generateSecretKey();

    beforeAll(async () => {
      api = createIdentityApi(await makeRepo(), { name: 'identity-test' });
      base = await api.listen();
    });
    afterAll(() => api.close());

    it('creates an account authenticated by NIP-98 and never accepts secrets', async () => {
      const res = await nip98Fetch(a, `${base}/v1/accounts`, 'POST', { custody_mode: 'local', label: 'Personal' });
      expect(res.status).toBe(201);
      expect((await nip98Fetch(a, `${base}/v1/accounts`, 'POST', {})).status).toBe(409);
      expect((await fetch(`${base}/v1/accounts`, { method: 'POST', body: '{}' })).status).toBe(401);
      const bad = await nip98Fetch(a, `${base}/v1/personas/${getPublicKey(a)}/key-metadata`, 'PUT', { key_id: 'k', provider: 'local', nsec: 'nsec1...' });
      expect(bad.status).toBe(400);
      const ok = await nip98Fetch(a, `${base}/v1/personas/${getPublicKey(a)}/key-metadata`, 'PUT', { key_id: 'k1', provider: 'browser-local', version: 1, recovery_state: 'backup-exported' });
      expect(ok.json.key_metadata[0]).toMatchObject({ keyId: 'k1', provider: 'browser-local', recoveryState: 'backup-exported' });
    });

    it('registers a second persona only with proof of key control', async () => {
      const acct = (await nip98Fetch(a, `${base}/v1/accounts/me`)).json;
      const url = `${base}/v1/accounts/me/personas`;
      const proof = finalizeEvent(toUnsigned({ kind: 27235, content: '', tags: [['u', url], ['account', acct.account_id]] }, getPublicKey(b)), b);
      const forged = finalizeEvent(toUnsigned({ kind: 27235, content: '', tags: [['u', url], ['account', acct.account_id]] }, getPublicKey(viewer)), viewer);
      expect((await nip98Fetch(a, url, 'POST', { pubkey: getPublicKey(b), proof: forged })).status).toBe(400);
      const res = await nip98Fetch(a, url, 'POST', { pubkey: getPublicKey(b), custody_mode: 'external', proof });
      expect(res.status).toBe(201);
      expect((await nip98Fetch(b, `${base}/v1/accounts/me`)).json.personas).toHaveLength(2);
    });

    it('links require confirmation; visibility is enforced on reads (FR-007)', async () => {
      const [pa, pb, pv] = [getPublicKey(a), getPublicKey(b), getPublicKey(viewer)];
      expect((await nip98Fetch(a, `${base}/v1/links`, 'POST', { from: pa, to: pb, visibility: 'selective', audience: [pv] })).status).toBe(400);
      expect((await nip98Fetch(a, `${base}/v1/links`, 'POST', { from: pa, to: pb, visibility: 'selective', audience: [pv], confirm: true })).status).toBe(201);
      expect((await (await fetch(`${base}/v1/links/public/${pa}`)).json()).links).toEqual([]);
      expect((await nip98Fetch(viewer, `${base}/v1/links/visible/${pa}`)).json.links).toEqual([{ from: pa, to: pb, visibility: 'selective' }]);
      expect((await nip98Fetch(generateSecretKey(), `${base}/v1/links/visible/${pa}`)).json.links).toEqual([]);
      const audit = (await nip98Fetch(a, `${base}/v1/accounts/me/audit`)).json.audit.map((x: { action: string }) => x.action);
      expect(audit).toEqual(['account.created', 'key_metadata.updated', 'persona.registered', 'link.created']);
    });
  });
}

suite('identity-service (memory)', async () => new MemoryIdentityRepository());
const PG = process.env.TEST_DATABASE_URL;
if (PG) {
  suite('identity-service (postgres)', async () => {
    const pool = createPgPool(PG);
    await resetScope(pool, 'identity-service', ['identity_audit', 'key_metadata', 'identity_links', 'identity_personas', 'accounts']);
    await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'identity-service');
    return new PgIdentityRepository(pool);
  });
}
