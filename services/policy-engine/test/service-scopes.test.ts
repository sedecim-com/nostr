/**
 * IR-2026-10-01 (SEC-13): a service token only reaches the routes of its principal's scopes. The indexer's token (a
 * service exposed to the Internet) cannot list or close MLS rotations, which would leave a revoked member in its groups,
 * nor read the relays' publish grants; the rotation worker's cannot evaluate access or read the grants.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { createPolicyApi, MemoryPolicyRepository, parseServiceScopes, PolicyEngine } from '../src/index';

const TOKENS = { 'indexer-token-1234': 'indexer', 'worker-token-1234': 'rotation-worker', 'allowlist-token-1234': 'relay-allowlist', 'ops-token-1234': 'ops' };

describe('policy-engine service scopes (IR-2026-10-01)', () => {
  const adminSk = generateSecretKey();
  const engine = new PolicyEngine(new MemoryPolicyRepository());
  const api = createPolicyApi(engine, { name: 'policy-scopes', adminPubkeys: [getPublicKey(adminSk)], bearerTokens: TOKENS });
  let base: string;
  let rotationId: string;
  const call = (token: string, path: string, method = 'GET', body?: unknown) =>
    fetch(`${base}${path}`, { method, headers: { authorization: `Bearer ${token}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }).then((r) => r.status);

  beforeAll(async () => {
    base = await api.listen();
    const owner = getPublicKey(generateSecretKey());
    await engine.upsertSubject('admin', { pubkey: owner, roles: ['member'], attributes: {} });
    await engine.upsertResource('admin', { id: 'grupo', kind: 'group', sensitivity: 'confidential', members: [owner], rules: [] });
    const device = await engine.registerDevice('admin', owner);
    await engine.revokeDevice('admin', device.id);
    rotationId = (await engine.listRotations('pending'))[0]!.id;
  });
  afterAll(() => api.close());

  it('keeps rotations and revocations to the rotation worker', async () => {
    expect(await call('indexer-token-1234', '/v1/rotations?status=pending')).toBe(403);
    expect(await call('indexer-token-1234', `/v1/rotations/${rotationId}/done`, 'POST')).toBe(403);
    expect(await call('allowlist-token-1234', '/v1/revocations')).toBe(403);
    expect((await engine.listRotations('pending')).map((r) => r.id)).toEqual([rotationId]);
    expect(await call('worker-token-1234', '/v1/rotations?status=pending')).toBe(200);
    expect(await call('worker-token-1234', '/v1/revocations')).toBe(200);
    expect(await call('worker-token-1234', `/v1/rotations/${rotationId}/done`, 'POST')).toBe(200);
  });

  it('keeps evaluate and the retention to the indexer, and the allowlist and grants to the relay-allowlist', async () => {
    const evaluate = { pubkey: getPublicKey(generateSecretKey()), resourceId: 'grupo', action: 'read' };
    expect(await call('worker-token-1234', '/v1/evaluate', 'POST', evaluate)).toBe(403);
    expect(await call('indexer-token-1234', '/v1/evaluate', 'POST', evaluate)).toBe(200);
    expect(await call('worker-token-1234', '/v1/retention')).toBe(403);
    expect(await call('indexer-token-1234', '/v1/retention')).toBe(200);
    for (const path of ['/v1/relay/allowlist', '/v1/relay/grants']) {
      expect(await call('indexer-token-1234', path)).toBe(403);
      expect(await call('worker-token-1234', path)).toBe(403);
      expect(await call('allowlist-token-1234', path)).toBe(200);
    }
  });

  it('gives a principal without scopes nothing, and POLICY_SERVICE_SCOPES names what others may call', async () => {
    for (const [path, method] of [['/v1/evaluate', 'POST'], ['/v1/relay/allowlist', 'GET'], ['/v1/rotations', 'GET'], ['/v1/retention', 'GET']] as const) {
      expect(await call('ops-token-1234', path, method, method === 'POST' ? { pubkey: 'x', resourceId: 'r', action: 'read' } : undefined)).toBe(403);
    }
    expect(parseServiceScopes('ops=evaluate+rotations,indexer=')).toMatchObject({ ops: ['evaluate', 'rotations'], indexer: [], 'rotation-worker': ['rotations'] });
    expect(() => parseServiceScopes('ops=todo')).toThrow(/unknown scope todo/);
    expect(() => parseServiceScopes('ops')).not.toThrow();
    expect(parseServiceScopes('ops').ops).toEqual([]);
  });
});
