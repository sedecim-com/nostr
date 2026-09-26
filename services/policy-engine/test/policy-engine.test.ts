import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { nip98Fetch } from '@sedecim/service-kit';
import { createPolicyApi, PolicyEngine } from '../src/index';

describe('policy-engine (FR-023, FR-024)', () => {
  const adminSk = generateSecretKey();
  const aliceSk = generateSecretKey();
  const alice = getPublicKey(aliceSk);
  const bob = getPublicKey(generateSecretKey());
  const engine = new PolicyEngine();
  const api = createPolicyApi(engine, { name: 'policy-test', adminPubkeys: [getPublicKey(adminSk)], bearerTokens: { 'relay-token-1234': 'relay' } });
  let base: string;
  const evaluate = (body: unknown) => fetch(`${base}/v1/evaluate`, { method: 'POST', headers: { authorization: 'Bearer relay-token-1234' }, body: JSON.stringify(body) }).then((r) => r.json());

  beforeAll(async () => {
    base = await api.listen();
  });
  afterAll(() => api.close());

  it('enforces RBAC/ABAC for protected resources', async () => {
    expect((await nip98Fetch(aliceSk, `${base}/v1/subjects/${alice}`, 'PUT', { roles: ['admin'] })).status).toBe(403);
    await nip98Fetch(adminSk, `${base}/v1/subjects/${alice}`, 'PUT', { roles: ['analyst'], attributes: { department: 'legal', clearance: 'confidential' } });
    await nip98Fetch(adminSk, `${base}/v1/subjects/${bob}`, 'PUT', { roles: ['guest'], attributes: {} });
    await nip98Fetch(adminSk, `${base}/v1/resources/legal-room`, 'PUT', {
      kind: 'group',
      sensitivity: 'confidential',
      members: [alice, bob],
      rules: [{ actions: ['read', 'publish'], anyRole: ['analyst'], attributes: { department: 'legal' } }],
    });
    const dev = (await nip98Fetch(adminSk, `${base}/v1/devices`, 'POST', { owner: alice })).json;
    expect((await evaluate({ pubkey: alice, deviceId: dev.id, resourceId: 'legal-room', action: 'publish' })).allow).toBe(true);
    expect((await evaluate({ pubkey: bob, resourceId: 'legal-room', action: 'read' })).allow).toBe(false);
    expect((await fetch(`${base}/v1/relay/allowlist`, { headers: { authorization: 'Bearer relay-token-1234' } }).then((r) => r.json())).pubkeys).toEqual([alice]);
  });

  it('revoking a device blocks sessions, access and triggers group rotation', async () => {
    const dev = (await nip98Fetch(adminSk, `${base}/v1/devices`, 'POST', { owner: alice })).json;
    const session = await nip98Fetch(aliceSk, `${base}/v1/sessions`, 'POST', { device_id: dev.id });
    expect(session.status).toBe(201);
    expect(engine.sessionValid(session.json.token)).toBe(true);
    const rev = await nip98Fetch(adminSk, `${base}/v1/devices/${dev.id}/revoke`, 'POST', { reason: 'lost phone' });
    expect(rev.json.rotations).toEqual([expect.objectContaining({ resourceId: 'legal-room', removedPubkey: alice })]);
    expect(engine.sessionValid(session.json.token)).toBe(false);
    expect((await nip98Fetch(aliceSk, `${base}/v1/sessions`, 'POST', { device_id: dev.id })).status).toBe(403);
    expect((await evaluate({ pubkey: alice, deviceId: dev.id, resourceId: 'legal-room', action: 'read' })).reasons).toEqual(['device revoked']);
    const audit = (await nip98Fetch(adminSk, `${base}/v1/audit`)).json.audit;
    expect(audit.some((a: { action: string }) => a.action === 'device.revoke')).toBe(true);
    expect(JSON.stringify(audit)).not.toMatch(/content|plaintext/);
  });
});
