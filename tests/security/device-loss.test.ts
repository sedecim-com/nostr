/**
 * SEC-04 E2E: a device is lost/stolen. The organisation revokes it in the policy-engine and, from there:
 *  - the device has no policy session and gets no new one;
 *  - the rotation worker (group admin) removes the owner's leaves from every flagged Marmot group, so the
 *    stolen MLS state cannot read anything sent after the rotation;
 *  - the revocation reaches the managed-signer (device-bound tokens rejected) and the NIP-46 bunker wired
 *    to it (the device's client session dropped).
 * What the device had already decrypted before the revocation stays readable on it: revocation is not erasure.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, verifyEvent } from '@sedecim/nostr-core';
import { MarmotTsProvider, MemoryGroupNetwork, VolatileGroupStorage, type ExtendedGroupSession } from '@sedecim/marmot-adapter';
import { createManagedSignerApi, ManagedSigner, MemoryVault } from '@sedecim/managed-signer';
import { createPolicyApi, PolicyEngine } from '@sedecim/policy-engine';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { HttpPolicySource, managedSignerSink, RevocationPropagator, RotationWorker } from '@sedecim/rotation-worker';
import { createTestCognito } from '@sedecim/service-kit';
import { LocalSigner, ManagedSignerClient, Nip46Bunker, Nip46Signer } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import { TestRelay } from '@sedecim/test-relay';

const RELAYS = ['wss://relay.invalid'];
const REVOCATION_TOKEN = 'policy-revocation-token-0123456789';
const silent = createLogger({ write: () => {} });
const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;

describe('device loss end to end (SEC-04, FR-024)', () => {
  const acceso = createTestCognito();
  const aliceToken = () => acceso.token({ sub: 'alice' });
  const relay = new TestRelay();
  const pools: RelayPool[] = [];
  const closers: Array<() => unknown> = [];

  // The real policy-engine API (in-memory repository): rotations, audit and NIP-98 admin checks.
  const engine = new PolicyEngine();
  const adminSigner = new LocalSigner(generateSecretKey());
  let policyBase: string;

  // Managed signer (custodial) with device-bound sessions.
  const core = new ManagedSigner(new MemoryVault(), {});
  const signerApi = createManagedSignerApi(core, { name: 'ms-sec04', cognito: acceso.verifier(), logger: silent, revocationTokens: { [REVOCATION_TOKEN]: 'policy-engine' } });
  let signerBase: string;

  beforeAll(async () => {
    await relay.start();
    const admin = await adminSigner.getPublicKey();
    const policyApi = createPolicyApi(engine, { name: 'policy-sec04', adminPubkeys: [admin], logger: silent });
    policyBase = await policyApi.listen();
    signerBase = await signerApi.listen();
    closers.push(() => policyApi.close(), () => signerApi.close(), () => relay.stop());
  });
  afterAll(async () => {
    pools.forEach((p) => p.close());
    for (const c of closers.reverse()) await c();
  });

  it('revoke -> no session -> groups rotated -> stolen MLS state reads nothing new -> signer and bunker reject it', async () => {
    const admin = await adminSigner.getPublicKey();
    const aliceKey = new LocalSigner(generateSecretKey());
    const alice = await aliceKey.getPublicKey();
    const bobKey = new LocalSigner(generateSecretKey());
    const bob = await bobKey.getPublicKey();

    // --- Organisation: subjects and devices.
    await engine.upsertSubject(admin, { pubkey: alice, roles: ['analyst'], attributes: {} });
    await engine.upsertSubject(admin, { pubkey: bob, roles: ['analyst'], attributes: {} });
    const phone = await engine.registerDevice(admin, alice, 'registered');
    const laptop = await engine.registerDevice(admin, alice, 'registered');
    const policySession = await engine.openSession(alice, phone.id);
    expect(await engine.sessionValid(policySession)).toBe(true);

    // --- Marmot group: the worker identity is the admin; every device is its own leaf (device id = policy id).
    const network = new MemoryGroupNetwork();
    const provider = new MarmotTsProvider();
    const open = (signer: LocalSigner, deviceId: string) => provider.openSession({ signer, network, storage: new VolatileGroupStorage(), deviceId }) as Promise<ExtendedGroupSession>;
    const workerSession = await open(adminSigner, 'rotation-worker');
    const stolenMls = await open(aliceKey, phone.id);
    const laptopMls = await open(aliceKey, laptop.id);
    const bobMls = await open(bobKey, 'bob-desk');
    for (const s of [stolenMls, laptopMls, bobMls]) await s.publishKeyPackage(RELAYS);
    const group = await workerSession.createGroup({ name: 'sala confidencial', relays: RELAYS });
    await workerSession.invitePersona(group.groupId, alice, RELAYS);
    await workerSession.invitePersona(group.groupId, bob, RELAYS);
    for (const s of [stolenMls, laptopMls, bobMls]) await s.acceptInvites();
    // The policy resource of kind 'group' uses the MLS group id as its id.
    await engine.upsertResource(admin, { id: group.groupId, kind: 'group', sensitivity: 'confidential', rules: [{ actions: ['read', 'publish'], anyRole: ['analyst'] }], members: [alice, bob] });
    await workerSession.send(group.groupId, 'plan antes del robo');
    expect((await stolenMls.sync(group.groupId)).map((m) => m.content)).toContain('plan antes del robo');

    // --- Managed signer: each device has its own session token.
    const key = await ManagedSignerClient.createKey({ baseUrl: signerBase, token: async () => aliceToken() }, { consentVersion: 'textos test' });
    const phoneSession = await ManagedSignerClient.openDeviceSession({ baseUrl: signerBase, token: async () => aliceToken() }, phone.id);
    const laptopSession = await ManagedSignerClient.openDeviceSession({ baseUrl: signerBase, token: async () => aliceToken() }, laptop.id);
    const phoneSigner = new ManagedSignerClient({ baseUrl: signerBase, keyId: key.keyId, token: async () => phoneSession.token });
    const laptopSigner = new ManagedSignerClient({ baseUrl: signerBase, keyId: key.keyId, token: async () => laptopSession.token });
    expect(verifyEvent(await phoneSigner.signEvent({ kind: 1, content: 'antes' }))).toBe(true);

    // --- NIP-46 bunker in front of the managed key; the phone is one of its clients. The bunker operator
    // wires it to the signer's revocations.
    const bunkerPool = new RelayPool({ webSocketFactory: factory });
    const clientPool = new RelayPool({ webSocketFactory: factory });
    pools.push(bunkerPool, clientPool);
    const bunker = new Nip46Bunker(laptopSigner, bunkerPool, [relay.url]);
    await bunker.start();
    closers.push(() => bunker.stop());
    core.onDeviceRevoked((r) => void bunker.revokeDevice(r.deviceId));
    const phoneNip46 = new Nip46Signer(await bunker.pointer(), { pool: clientPool, timeoutMs: 5000 });
    closers.push(() => phoneNip46.close());
    await phoneNip46.connect();
    bunker.bindDevice(await phoneNip46.clientPubkey(), phone.id);
    expect(verifyEvent(await phoneNip46.signEvent({ kind: 1, content: 'vía bunker' }))).toBe(true);

    // ================= The phone is stolen: the organisation revokes it. =================
    const rotations = await engine.revokeDevice(admin, phone.id, 'robado');
    expect(rotations).toEqual([expect.objectContaining({ resourceId: group.groupId, removedPubkey: alice })]);

    // 1. No policy session: the open one is invalid, no new one, access denied for that device.
    expect(await engine.sessionValid(policySession)).toBe(false);
    await expect(Promise.resolve().then(() => engine.openSession(alice, phone.id))).rejects.toThrow(/not usable/);
    expect((await engine.evaluate({ pubkey: alice, deviceId: phone.id, resourceId: group.groupId, action: 'read' })).reasons).toEqual(['device revoked']);

    // 2. Revocation propagated to the managed-signer (and from it to the bunker), even after more than a
    //    page of other audit entries: the default audit page no longer shows it (B2, FR024-04). Access
    //    decisions no longer go to the audit (FR023-12): admin actions fill it here.
    for (let i = 0; i < 150; i++) await engine.putDirectoryEntry(admin, { pubkey: alice, title: `turno ${i}` });
    expect((await engine.listAudit()).some((e) => e.action === 'device.revoke')).toBe(false);
    const policy = new HttpPolicySource({ baseUrl: policyBase, signer: adminSigner });
    const propagator = new RevocationPropagator({ feed: policy, sinks: [managedSignerSink({ baseUrl: signerBase, token: REVOCATION_TOKEN })], logger: silent });
    expect(await propagator.runOnce()).toEqual([phone.id]);
    expect(await propagator.runOnce()).toEqual([]);

    // 3. The worker rotates the group.
    const epochBefore = (await workerSession.group(group.groupId)).epoch;
    const worker = new RotationWorker({ source: policy, session: workerSession, logger: silent });
    const [outcome] = await worker.runOnce();
    expect(outcome).toMatchObject({ result: 'removed' });
    expect(outcome!.epoch).toBeGreaterThan(epochBefore);
    expect(await policy.pending()).toEqual([]);

    // 4. The stolen MLS state cannot read what is sent after the rotation; the remaining members can.
    await workerSession.send(group.groupId, 'plan después del robo');
    expect((await bobMls.sync(group.groupId)).map((m) => m.content)).toContain('plan después del robo');
    const leaked = await stolenMls.sync(group.groupId).catch(() => []);
    expect(leaked.map((m) => m.content)).not.toContain('plan después del robo');
    expect((await stolenMls.group(group.groupId)).epoch).toBeLessThan(outcome!.epoch!);
    // All of alice's leaves left (removeMember): her laptop must be re-invited with a fresh key package.
    expect((await laptopMls.sync(group.groupId).catch(() => [])).map((m) => m.content)).not.toContain('plan después del robo');

    // 5. Managed signer rejects the phone, the laptop keeps working.
    await expect(phoneSigner.signEvent({ kind: 1, content: 'robado' })).rejects.toThrow(/401/);
    await expect(ManagedSignerClient.openDeviceSession({ baseUrl: signerBase, token: async () => aliceToken() }, phone.id)).rejects.toThrow(/403/);
    expect(verifyEvent(await laptopSigner.signEvent({ kind: 1, content: 'portátil' }))).toBe(true);

    // 6. The bunker dropped the phone's NIP-46 session and refuses it for good.
    await expect(phoneNip46.signEvent({ kind: 1, content: 'robado' })).rejects.toThrow(/unauthorized/);
    await expect(phoneNip46.connect()).rejects.toThrow(/client revoked/);
  });
});
