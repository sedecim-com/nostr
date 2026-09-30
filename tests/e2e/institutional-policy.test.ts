/**
 * FR023-05 / FR023-08 E2E: the indexer in institutional mode asks the real policy-engine (bearer token)
 * for every read, and the retention job reads the engine's policies and purges the mirror.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as nt from 'nostr-tools';
import { generateSecretKey, getPublicKey, type NostrEvent } from '@sedecim/nostr-core';
import { bearer, PolicyEngineClient } from '@sedecim/policy-client';
import { nip98Fetch } from '@sedecim/service-kit';
import { createPolicyApi, PolicyEngine } from '@sedecim/policy-engine';
import { createIndexerApi, enforceRetention, GroupAuthorities, MemoryEventRepository } from '@sedecim/indexer';

describe('institutional mode: policy-engine + indexer', () => {
  const adminSk = generateSecretKey();
  const admin = getPublicKey(adminSk);
  const analystSk = generateSecretKey();
  const analyst = getPublicKey(analystSk);
  const guestSk = generateSecretKey();
  const engine = new PolicyEngine();
  const policyApi = createPolicyApi(engine, { name: 'policy-e2e', adminPubkeys: [admin], bearerTokens: { 'indexer-token-1234': 'indexer' } });
  const repo = new MemoryEventRepository();
  let indexerApi: ReturnType<typeof createIndexerApi>;
  let policyBase: string;
  let indexerBase: string;
  let client: PolicyEngineClient;
  const author = generateSecretKey();
  const now = Math.floor(Date.now() / 1000);
  const msg = (h: string, daysAgo: number) => nt.finalizeEvent({ kind: 9, content: `en ${h}`, tags: [['h', h]], created_at: now - daysAgo * 86_400 }, author) as NostrEvent;
  const ev = { legal: msg('legal', 0), legalOld: msg('legal', 45), lobby: msg('lobby', 0), lobbyOld: msg('lobby', 45) };
  // FR014-05: both are members of both channels (relay-signed kind 39002), so the policy is what tells them apart.
  const relaySk = generateSecretKey();
  const members = (h: string) => nt.finalizeEvent({ kind: 39002, content: '', tags: [['d', h], ['p', analyst, '', 'member'], ['p', getPublicKey(guestSk), '', 'member']], created_at: now }, relaySk) as NostrEvent;

  beforeAll(async () => {
    policyBase = await policyApi.listen();
    client = new PolicyEngineClient(policyBase, bearer('indexer-token-1234'));
    indexerApi = createIndexerApi(repo, { name: 'indexer-e2e', policy: { evaluate: (i) => client.evaluate(i) }, groups: new GroupAuthorities([getPublicKey(relaySk)]) });
    indexerBase = await indexerApi.listen();
    const admin98 = (path: string, method: string, body: unknown) => nip98Fetch(adminSk, `${policyBase}${path}`, method, body);
    await admin98(`/v1/subjects/${analyst}`, 'PUT', { roles: ['analyst'], attributes: {} });
    await admin98(`/v1/subjects/${getPublicKey(guestSk)}`, 'PUT', { roles: ['guest'], attributes: {} });
    await admin98('/v1/resources/legal', 'PUT', { kind: 'channel', sensitivity: 'internal', rules: [{ actions: ['read'], anyRole: ['analyst'] }] });
    await admin98('/v1/resources/lobby', 'PUT', { kind: 'channel', sensitivity: 'public', rules: [{ actions: ['read'], anyRole: ['analyst', 'guest'] }] });
    await admin98('/v1/retention/legal', 'PUT', { days: 30, legalHold: true });
    await admin98('/v1/retention/lobby', 'PUT', { days: 30, legalHold: false });
    for (const e of [...Object.values(ev), members('legal'), members('lobby')]) await repo.upsert(e, 'ws://relay');
  });
  afterAll(async () => {
    await indexerApi.close();
    await policyApi.close();
  });

  it('reads are filtered by the engine decision for each reader', async () => {
    const read = async (sk: Uint8Array) => ((await nip98Fetch(sk, `${indexerBase}/v1/events?kinds=9`)).json.events as NostrEvent[]).map((e) => e.id).sort();
    expect(await read(analystSk)).toEqual(Object.values(ev).map((e) => e.id).sort());
    expect(await read(guestSk)).toEqual([ev.lobby.id, ev.lobbyOld.id].sort());
    expect(await read(generateSecretKey())).toEqual([]);
    expect((await nip98Fetch(guestSk, `${indexerBase}/v1/channels/legal/summary`)).status).toBe(403);
    // Decisions are logged by the engine (no content), in the access log with its own retention (FR023-12).
    const access = (await nip98Fetch(adminSk, `${policyBase}/v1/access-log?limit=5`)).json.access;
    expect(access[0]).toMatchObject({ action: 'read', allow: expect.any(Boolean) });
    expect(JSON.stringify(access)).not.toContain('en legal');
    expect(((await nip98Fetch(adminSk, `${policyBase}/v1/audit?limit=100`)).json.audit as Array<{ action: string }>).map((a) => a.action)).not.toContain('policy.evaluate');
  });

  it('retention purges expired mirror data except under legal hold, and carries the notice', async () => {
    const { policies, notice } = await client.retention();
    expect(notice).toMatch(/otros relays/);
    expect(await enforceRetention(repo, policies)).toEqual([{ resourceId: 'lobby', deleted: 1 }]);
    expect(await repo.get(ev.lobbyOld.id)).toBeUndefined();
    expect(await repo.get(ev.legalOld.id)).toBeDefined();
  });
});
