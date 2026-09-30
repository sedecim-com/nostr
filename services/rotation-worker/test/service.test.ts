/**
 * FR024-05: the rotation worker as a service. Against a relay that requires NIP-42 and knows itself by a public URL
 * the worker never dials, the real policy-engine (the worker is not one of its admins: it reads with its service
 * token) and the managed-signer:
 * - the worker publishes its key package, joins the group that lists it as admin, and removes a revoked member;
 * - the revocation reaches the managed-signer;
 * - a restart on the same state keeps the groups; another key does not open that state.
 */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, getPublicKey, nsecEncode, bytesToHex, verifyEvent } from '@sedecim/nostr-core';
import { MarmotTsProvider, PoolGroupNetwork, VolatileGroupStorage, type ExtendedGroupSession } from '@sedecim/marmot-adapter';
import { createManagedSignerApi, ManagedSigner, MemoryVault } from '@sedecim/managed-signer';
import { createPolicyApi, PolicyEngine } from '@sedecim/policy-engine';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { createTestCognito } from '@sedecim/service-kit';
import { LocalSigner, ManagedSignerClient } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import { TestRelay } from '@sedecim/test-relay';
import { mappedNetwork, parseConfig, parseRelays, relayMapping, startRotationWorker, type RotationWorkerConfig } from '../src/index';

const PUBLIC = 'wss://secure.example.test';
const POLICY_TOKEN = 'rotation-worker-token-0123456789';
const REVOCATION_TOKEN = 'policy-revocation-token-0123456789';
const silent = createLogger({ write: () => {} });

describe('parseConfig (FR024-05)', () => {
  const base = { ROTATION_WORKER_NSEC: nsecEncode(generateSecretKey()), ROTATION_WORKER_RELAYS: `${PUBLIC}=ws://secure-relay:8080`, POLICY_ENGINE_TOKEN: POLICY_TOKEN, ROTATION_STATE_KEY: 'ab'.repeat(32) };

  it('reads the environment, with defaults', () => {
    const cfg = parseConfig(base);
    expect(cfg.relays).toEqual([{ public: PUBLIC, dial: 'ws://secure-relay:8080' }]);
    expect([cfg.policyUrl, cfg.stateDir, cfg.intervalMs, cfg.port, cfg.managedSigner]).toEqual(['http://policy-engine:8083', '/data', 15_000, 8089, undefined]);
    expect(parseConfig({ ...base, ROTATION_WORKER_NSEC: bytesToHex(cfg.secretKey) }).secretKey).toEqual(cfg.secretKey);
    expect(parseConfig({ ...base, ROTATION_MANAGED_SIGNER_URL: 'http://managed-signer:8084', ROTATION_MANAGED_SIGNER_TOKEN: REVOCATION_TOKEN }).managedSigner).toEqual({ baseUrl: 'http://managed-signer:8084', token: REVOCATION_TOKEN });
  });

  it('names every missing or invalid variable', () => {
    expect(() => parseConfig({})).toThrow(/ROTATION_WORKER_NSEC is required; ROTATION_WORKER_RELAYS is required; POLICY_ENGINE_TOKEN is required; ROTATION_STATE_KEY is required/);
    expect(() => parseConfig({ ...base, ROTATION_WORKER_NSEC: 'npub1nope' })).toThrow(/an nsec or 64 hex/);
    expect(() => parseConfig({ ...base, ROTATION_STATE_KEY: 'corta' })).toThrow(/ROTATION_STATE_KEY must be 64 hex/);
    expect(() => parseConfig({ ...base, ROTATION_WORKER_RELAYS: 'https://no-es-un-relay' })).toThrow(/ROTATION_WORKER_RELAYS: relay url must be ws/);
    expect(() => parseConfig({ ...base, ROTATION_MANAGED_SIGNER_URL: 'http://managed-signer:8084' })).toThrow(/go together/);
    expect(() => parseConfig({ ...base, ROTATION_INTERVAL_MS: '10' })).toThrow(/at least 1000/);
  });

  it('maps public relay URLs to the address the worker dials, and back', () => {
    const m = relayMapping(parseRelays(`${PUBLIC}/=ws://secure-relay:8080, wss://otro.example`));
    expect([m.dialOf(PUBLIC), m.dialOf(`${PUBLIC}/`), m.dialOf('wss://otro.example'), m.dialOf('wss://desconocido.example')]).toEqual(['ws://secure-relay:8080', 'ws://secure-relay:8080', 'wss://otro.example', 'wss://desconocido.example']);
    expect(m.publicOf('ws://secure-relay:8080')).toBe(PUBLIC);
  });
});

describe('rotation worker service (FR024-05)', () => {
  const relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059], publicUrl: PUBLIC });
  const acceso = createTestCognito();
  const engine = new PolicyEngine();
  const adminSk = generateSecretKey();
  const admin = getPublicKey(adminSk);
  const core = new ManagedSigner(new MemoryVault(), {});
  const signerApi = createManagedSignerApi(core, { name: 'ms-fr024-05', cognito: acceso.verifier(), logger: silent, revocationTokens: { [REVOCATION_TOKEN]: 'rotation-worker' } });
  const pools: RelayPool[] = [];
  const closers: Array<() => unknown> = [];
  let policyBase: string;
  let signerBase: string;

  beforeAll(async () => {
    await relay.start();
    // The worker is not a policy-engine admin: it reads rotations and revocations with its service token.
    const policyApi = createPolicyApi(engine, { name: 'policy-fr024-05', adminPubkeys: [admin], bearerTokens: { [POLICY_TOKEN]: 'rotation-worker' }, logger: silent });
    policyBase = await policyApi.listen();
    signerBase = await signerApi.listen();
    closers.push(() => policyApi.close(), () => signerApi.close(), () => relay.stop());
  });
  afterAll(async () => {
    pools.forEach((p) => p.close());
    for (const c of closers.reverse()) await c();
  });

  /** Where the relay really listens; everyone else knows it as PUBLIC (`relay.url`). */
  const dial = () => `ws://127.0.0.1:${relay.port}`;

  /** A member's device: it names the relay by its public URL, like the web does. */
  const member = async (sk: Uint8Array, deviceId: string) => {
    const signer = new LocalSigner(sk);
    const pool = new RelayPool({ webSocketFactory: (u) => new WebSocket(u) as unknown as WebSocketLike, signer, authMode: 'auto', authRelayUrl: () => PUBLIC });
    pools.push(pool);
    const network = mappedNetwork(new PoolGroupNetwork(pool, [dial()]), relayMapping([{ public: PUBLIC, dial: dial() }]).dialOf);
    return (await new MarmotTsProvider().openSession({ signer, network, storage: new VolatileGroupStorage(), deviceId })) as ExtendedGroupSession;
  };

  it('joins the group that lists it as admin, removes a revoked member, propagates the revocation and survives a restart', async () => {
    const workerSk = generateSecretKey();
    const stateDir = mkdtempSync(join(tmpdir(), 'rotation-worker-'));
    const cfg: RotationWorkerConfig = {
      secretKey: workerSk,
      relays: [{ public: PUBLIC, dial: dial() }],
      policyUrl: policyBase,
      policyToken: POLICY_TOKEN,
      stateDir,
      stateKey: new Uint8Array(32).fill(7),
      intervalMs: 1000,
      managedSigner: { baseUrl: signerBase, token: REVOCATION_TOKEN },
      port: 0,
      host: '127.0.0.1',
    };
    let running = await startRotationWorker(cfg, { logger: silent, loop: false });
    const worker = running.pubkey;
    expect(worker).toBe(getPublicKey(workerSk));
    await running.service.runOnce();
    expect(running.service.status).toMatchObject({ ok: true, errors: {}, groupsJoined: 0 });

    // --- An organisation member creates a group with the worker as admin and invites it, bob and carol.
    const [creatorSk, bobSk, carolSk] = [generateSecretKey(), generateSecretKey(), generateSecretKey()];
    const [bob, carol] = [getPublicKey(bobSk), getPublicKey(carolSk)];
    const creator = await member(creatorSk, 'creator-desk');
    const phone = await engine.registerDevice(admin, bob, 'registered');
    const bobPhone = await member(bobSk, phone.id);
    const carolDesk = await member(carolSk, 'carol-desk');
    for (const s of [bobPhone, carolDesk]) await s.publishKeyPackage([PUBLIC]);
    const g = await creator.createGroup({ name: 'sala legal', relays: [PUBLIC], admins: [creator.pubkey, worker] });
    for (const pk of [worker, bob, carol]) await creator.invitePersona(g.groupId, pk, [PUBLIC]);
    for (const s of [bobPhone, carolDesk]) await s.acceptInvites();

    await running.service.runOnce();
    expect(running.service.status).toMatchObject({ ok: true, groupsJoined: 1, groupsWithoutAdmin: 0 });
    expect((await running.session.group(g.groupId)).admins).toContain(worker);

    // --- Policy: bob's phone is revoked; the group is flagged for rotation.
    for (const pk of [bob, carol]) await engine.upsertSubject(admin, { pubkey: pk, roles: ['analyst'], attributes: {} });
    await engine.upsertResource(admin, { id: g.groupId, kind: 'group', sensitivity: 'confidential', rules: [{ actions: ['read', 'publish'], anyRole: ['analyst'] }], members: [bob, carol] });
    const bobToken = () => acceso.token({ sub: 'bob' });
    const key = await ManagedSignerClient.createKey({ baseUrl: signerBase, token: async () => bobToken() }, { consentVersion: 'textos test' });
    const phoneSession = await ManagedSignerClient.openDeviceSession({ baseUrl: signerBase, token: async () => bobToken() }, phone.id);
    const phoneSigner = new ManagedSignerClient({ baseUrl: signerBase, keyId: key.keyId, token: async () => phoneSession.token });
    expect(verifyEvent(await phoneSigner.signEvent({ kind: 1, content: 'antes' }))).toBe(true);
    await engine.revokeDevice(admin, phone.id, 'robado');
    expect(await engine.listRotations('pending')).toHaveLength(1);

    await running.service.runOnce();
    expect(running.service.status).toMatchObject({ ok: true, rotations: { removed: 1 }, revocationsPropagated: 1 });
    expect(await engine.listRotations('pending')).toEqual([]);
    expect((await running.session.group(g.groupId)).members).not.toContain(bob);
    await expect(phoneSigner.signEvent({ kind: 1, content: 'robado' })).rejects.toThrow(/401/);
    // What is sent after the rotation stays out of the revoked phone's reach.
    await creator.sync(g.groupId);
    await creator.send(g.groupId, 'después de la rotación');
    expect((await carolDesk.sync(g.groupId)).map((m) => m.content)).toContain('después de la rotación');
    expect((await bobPhone.sync(g.groupId).catch(() => [])).map((m) => m.content)).not.toContain('después de la rotación');

    // --- Health, then a restart on the same state: still in the group, and it rotates the next revocation.
    const health = (await (await fetch(`${running.url}/health`)).json()) as { ok: boolean; pubkey: string; npub: string };
    expect([health.ok, health.pubkey, health.npub.startsWith('npub1')]).toEqual([true, worker, true]);
    await running.stop();
    await expect(startRotationWorker({ ...cfg, stateKey: new Uint8Array(32).fill(8) }, { logger: silent, loop: false })).rejects.toThrow(/ROTATION_STATE_KEY does not open/);
    running = await startRotationWorker(cfg, { logger: silent, loop: false });
    expect((await running.session.group(g.groupId)).admins).toContain(worker);
    const desk = await engine.registerDevice(admin, carol, 'registered');
    await engine.revokeDevice(admin, desk.id, 'perdido');
    await running.service.runOnce();
    expect(running.service.status).toMatchObject({ ok: true, rotations: { removed: 1 } });
    expect((await running.session.group(g.groupId)).members).not.toContain(carol);
    await running.stop();
  }, 120_000);
});
