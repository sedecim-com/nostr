import { afterEach, describe, expect, it } from 'vitest';
import { generateSecretKey, type NostrEvent } from '@sedecim/nostr-core';
import { MarmotTsProvider, MemoryGroupNetwork, VolatileGroupStorage, type ExtendedGroupSession, type GroupNetwork } from '@sedecim/marmot-adapter';
import { LocalSigner } from '@sedecim/signer';
import { createLogger, type LogRecord } from '@sedecim/telemetry-policy';
import { HttpPolicySource, PolicyHttpError, RevocationPropagator, RotationWorker, type DeviceRevocation } from '../src/index';
import { StubPolicyApi, type RotationFeedItem } from '../src/testing';

const RELAYS = ['wss://relay.invalid'];

/** GroupNetwork whose kind 445 publishes can be made to fail (relays down / rejecting the commit). */
class FlakyNetwork implements GroupNetwork {
  failGroupMessages = false;
  constructor(private readonly inner: MemoryGroupNetwork) {}
  publish(relays: string[], e: NostrEvent) {
    if (this.failGroupMessages && e.kind === 445) return Promise.resolve(relays.map((relay) => ({ relay, ok: false, message: 'error: down' })));
    return this.inner.publish(relays, e);
  }
  query: GroupNetwork['query'] = (r, f) => this.inner.query(r, f);
  subscribe: GroupNetwork['subscribe'] = (r, f, fn) => this.inner.subscribe(r, f, fn);
  inboxRelays = () => this.inner.inboxRelays();
}

async function world() {
  const network = new MemoryGroupNetwork();
  const flaky = new FlakyNetwork(network);
  const provider = new MarmotTsProvider();
  const open = (signer: LocalSigner, deviceId: string, net: GroupNetwork = network) =>
    provider.openSession({ signer, network: net, storage: new VolatileGroupStorage(), deviceId }) as Promise<ExtendedGroupSession>;
  const adminSigner = new LocalSigner(generateSecretKey());
  const alice = new LocalSigner(generateSecretKey());
  const admin = await open(adminSigner, 'worker-device', flaky);
  const [alicePhone, aliceLaptop, bob] = [await open(alice, 'alice-phone'), await open(alice, 'alice-laptop'), await open(new LocalSigner(generateSecretKey()), 'bob-desk')];
  for (const s of [alicePhone, aliceLaptop, bob]) await s.publishKeyPackage(RELAYS);
  const g = await admin.createGroup({ name: 'sala legal', relays: RELAYS });
  await admin.invitePersona(g.groupId, alicePhone.pubkey, RELAYS);
  await admin.invitePersona(g.groupId, bob.pubkey, RELAYS);
  for (const s of [alicePhone, aliceLaptop, bob]) await s.acceptInvites();
  return { network, flaky, admin, adminSigner, alicePhone, aliceLaptop, bob, groupId: g.groupId };
}

const contents = async (s: ExtendedGroupSession, gid: string) => (await s.sync(gid).catch(() => [])).map((m) => m.content);

describe('rotation worker (FR024-02)', () => {
  const stubs: StubPolicyApi[] = [];
  afterEach(async () => {
    await Promise.all(stubs.splice(0).map((s) => s.close()));
  });

  const policy = async (feed: RotationFeedItem[], adminPubkey: string) => {
    const stub = new StubPolicyApi({ adminPubkeys: [adminPubkey], bearerTokens: { 'worker-bearer-0123456789': 'rotation-worker' }, feed: () => feed });
    stubs.push(stub);
    return { stub, base: await stub.listen() };
  };

  it('revoke -> pending rotation -> Remove commit -> new epoch -> removed member reads nothing new -> done', async () => {
    const w = await world();
    const logs: LogRecord[] = [];
    const feed: RotationFeedItem[] = [];
    const { stub, base } = await policy(feed, w.admin.pubkey);
    let now = 1_000_000;
    const worker = new RotationWorker({
      source: new HttpPolicySource({ baseUrl: base, signer: w.adminSigner, bearer: 'worker-bearer-0123456789' }),
      session: w.admin,
      now: () => now,
      logger: createLogger({ write: (r) => logs.push(r) }),
    });
    await w.admin.send(w.groupId, 'antes de revocar');
    expect(await contents(w.alicePhone, w.groupId)).toContain('antes de revocar');
    expect(await worker.runOnce()).toEqual([]);

    // The policy-engine revokes alice's device and flags the group (resource id = MLS group id).
    feed.push({ at: now, resourceId: w.groupId, reason: 'device dev-phone revoked', removedPubkey: w.alicePhone.pubkey });
    expect(stub.rotations()).toEqual([expect.objectContaining({ id: 'rot-1', status: 'pending' })]);
    const epoch = (await w.admin.group(w.groupId)).epoch;

    const [out] = await worker.runOnce();
    expect(out).toMatchObject({ id: 'rot-1', result: 'removed' });
    expect(out!.epoch).toBeGreaterThan(epoch);
    expect(stub.rotations()[0]!.status).toBe('done');
    const g = await w.admin.group(w.groupId);
    expect(g.members).not.toContain(w.alicePhone.pubkey);
    expect(g.devices!.some((d) => d.pubkey === w.alicePhone.pubkey)).toBe(false);

    await w.admin.send(w.groupId, 'después de revocar');
    expect(await contents(w.bob, w.groupId)).toContain('después de revocar');
    // Every leaf of the revoked pubkey is gone: neither device decrypts what comes after.
    expect(await contents(w.alicePhone, w.groupId)).not.toContain('después de revocar');
    expect(await contents(w.aliceLaptop, w.groupId)).not.toContain('después de revocar');

    now += 1000;
    expect(await worker.runOnce()).toEqual([]);
    expect(JSON.stringify(logs)).not.toMatch(/antes de revocar|después de revocar/);
    expect(logs.find((l) => l.msg === 'rotation done')).toMatchObject({ rotation_id: 'rot-1', result: 'removed' });
  });

  it('is idempotent: a member already gone (or a duplicate rotation) is just marked done', async () => {
    const w = await world();
    const feed: RotationFeedItem[] = [
      { at: 1, resourceId: w.groupId, reason: 'device a revoked', removedPubkey: w.bob.pubkey },
      { at: 1, resourceId: w.groupId, reason: 'device b revoked', removedPubkey: w.bob.pubkey },
    ];
    const { stub, base } = await policy(feed, w.admin.pubkey);
    // Another admin (here: the same identity by hand) removed bob before the worker ran.
    await w.admin.removeMember(w.groupId, w.bob.pubkey);
    const epoch = (await w.admin.group(w.groupId)).epoch;
    const worker = new RotationWorker({ source: new HttpPolicySource({ baseUrl: base, signer: w.adminSigner }), session: w.admin, logger: createLogger({ write: () => {} }) });
    expect((await worker.runOnce()).map((o) => o.result)).toEqual(['already-removed', 'already-removed']);
    expect(stub.rotations().map((r) => r.status)).toEqual(['done', 'done']);
    expect((await w.admin.group(w.groupId)).epoch).toBe(epoch);
  });

  it('never marks done on failure and retries with backoff', async () => {
    const w = await world();
    const feed: RotationFeedItem[] = [
      { at: 1, resourceId: w.groupId, reason: 'device revoked', removedPubkey: w.bob.pubkey },
      { at: 1, resourceId: 'ab'.repeat(16), reason: 'device revoked', removedPubkey: w.bob.pubkey },
    ];
    const { stub, base } = await policy(feed, w.admin.pubkey);
    let now = 0;
    const worker = new RotationWorker({ source: new HttpPolicySource({ baseUrl: base, signer: w.adminSigner }), session: w.admin, now: () => now, backoff: { baseMs: 1000, maxMs: 4000 }, logger: createLogger({ write: () => {} }) });

    // Relays down: the commit waits in the session (FR025-12); nothing is marked done, the member is still there.
    w.flaky.failGroupMessages = true;
    let out = await worker.runOnce();
    expect(out.map((o) => [o.result, o.retryAt])).toEqual([
      ['failed', 1000],
      ['failed', 1000],
    ]);
    expect(out[0]!.error).toMatch(/remove commit pending/);
    expect(out[1]!.error).toMatch(/not held/);
    expect(stub.done.size).toBe(0);
    expect((await w.admin.group(w.groupId)).members).toContain(w.bob.pubkey);
    expect((await worker.runOnce()).map((o) => o.result)).toEqual(['deferred', 'deferred']);

    // Relays back, but the policy-engine fails the `done` call: the commit happened, still not done.
    w.flaky.failGroupMessages = false;
    stub.failDone = 1;
    now = 1000;
    out = await worker.runOnce();
    expect(out.map((o) => o.result)).toEqual(['failed', 'failed']);
    expect(out[1]!.retryAt).toBe(1000 + 2000);
    expect((await w.admin.group(w.groupId)).members).not.toContain(w.bob.pubkey);
    expect(stub.done.size).toBe(0);

    // Next attempt: member already gone -> done. The unknown group keeps failing with a capped backoff.
    now = 3000;
    out = await worker.runOnce();
    expect(out.map((o) => o.result)).toEqual(['already-removed', 'failed']);
    expect(out[1]!.retryAt).toBe(3000 + 4000);
    now = 7000;
    expect((await worker.runOnce())[0]!.retryAt).toBe(7000 + 4000);
    expect([...stub.done]).toEqual(['rot-1']);
  });

  it('refuses to act without admin credentials on the policy-engine', async () => {
    const w = await world();
    const { base } = await policy([], w.admin.pubkey);
    const intruder = new HttpPolicySource({ baseUrl: base, signer: new LocalSigner(generateSecretKey()) });
    await expect(intruder.pending()).rejects.toThrow(PolicyHttpError);
    await expect(new HttpPolicySource({ baseUrl: base, signer: new LocalSigner(generateSecretKey()), bearer: 'wrong-bearer-0123456789' }).markDone('rot-1')).rejects.toThrow(/401/);
  });
});

describe('device revocation propagation (FR024-03, FR024-04)', () => {
  const quiet = createLogger({ write: () => {} });
  const stubs: StubPolicyApi[] = [];
  afterEach(async () => {
    await Promise.all(stubs.splice(0).map((s) => s.close()));
  });
  const revocation = (cursor: number, at = 0, reason?: string): DeviceRevocation => ({ cursor, at, deviceId: `d${cursor}`, ...(reason ? { reason } : {}) });
  /** In-memory feed with the engine's contract: oldest first, `after` exclusive, `latest`, `now`. */
  const memoryFeed = (entries: DeviceRevocation[], clock = { now: 1_000_000 }) => ({
    reads: 0,
    async revocations(after: number, limit: number) {
      this.reads++;
      return { revocations: entries.filter((e) => e.cursor > after).slice(0, limit), latest: entries.at(-1)?.cursor ?? 0, now: clock.now };
    },
  });
  const memoryCursor = () => {
    const box: { value?: number; saves: number } = { saves: 0 };
    return { box, store: { load: async () => box.value, save: async (c: number) => void ((box.value = c), box.saves++) } };
  };

  it('propagates each revocation to every sink, retrying the ones that failed', async () => {
    const calls: string[] = [];
    let failD3 = true;
    const p = new RevocationPropagator({
      feed: memoryFeed([revocation(2, 0, 'lost phone'), revocation(3)]),
      logger: quiet,
      sinks: [
        async (id, reason) => void calls.push(`signer:${id}:${reason ?? ''}`),
        async (id) => {
          if (id === 'd3' && failD3) throw new Error('bunker offline');
          calls.push(`bunker:${id}`);
        },
      ],
    });
    expect(await p.runOnce()).toEqual(['d2']);
    failD3 = false;
    expect(await p.runOnce()).toEqual(['d3']);
    expect(await p.runOnce()).toEqual([]);
    expect(calls).toEqual(['signer:d2:lost phone', 'bunker:d2', 'signer:d3:', 'signer:d3:', 'bunker:d3']);
  });

  it('pages through the feed over HTTP: 250 revocations, none lost, each propagated once (B2)', async () => {
    const admin = new LocalSigner(generateSecretKey());
    const entries = Array.from({ length: 250 }, (_, i) => revocation(3 * i + 7));
    const stub = new StubPolicyApi({ adminPubkeys: [await admin.getPublicKey()], bearerTokens: { 'worker-bearer-0123456789': 'rotation-worker' }, feed: () => [], revocations: () => entries });
    stubs.push(stub);
    const base = await stub.listen();
    const sent: string[] = [];
    const p = new RevocationPropagator({ feed: new HttpPolicySource({ baseUrl: base, signer: admin, bearer: 'worker-bearer-0123456789' }), pageSize: 100, logger: quiet, sinks: [async (id) => void sent.push(id)] });
    expect(await p.runOnce()).toHaveLength(250);
    expect(sent).toEqual(entries.map((e) => e.deviceId));
    expect(stub.revocationReads).toBe(3);
    expect(await p.runOnce()).toEqual([]);
    expect(sent).toHaveLength(250);
    // Admin NIP-98 works too; anyone else is refused.
    expect((await new HttpPolicySource({ baseUrl: base, signer: admin }).revocations(700, 100)).revocations).toEqual(entries.filter((e) => e.cursor > 700));
    await expect(new HttpPolicySource({ baseUrl: base, signer: new LocalSigner(generateSecretKey()) }).revocations(0, 10)).rejects.toThrow(/403/);
  });

  it('keeps the cursor behind a failure and behind unsettled revocations, and resumes from the saved one', async () => {
    const clock = { now: 1_000_000 };
    const entries = [revocation(10), revocation(20), revocation(30), revocation(40, clock.now - 10_000)];
    const feed = memoryFeed(entries, clock);
    const { box, store } = memoryCursor();
    const sent: string[] = [];
    let failD20 = true;
    const sink = async (id: string) => {
      if (id === 'd20' && failD20) throw new Error('managed-signer 503');
      sent.push(id);
    };
    const p = new RevocationPropagator({ feed, cursor: store, logger: quiet, sinks: [sink] });
    // d20 fails: d30 and d40 still go out, and the cursor stops before d20.
    expect(await p.runOnce()).toEqual(['d10', 'd30', 'd40']);
    expect(box.value).toBe(10);
    // Only d20 is retried. d40 was propagated but is younger than 60 s, so the cursor stops at d30.
    failD20 = false;
    expect(await p.runOnce()).toEqual(['d20']);
    expect(box.value).toBe(30);
    // An id below one already seen whose row commits late is still picked up: the cursor had not passed it.
    entries.splice(3, 0, { cursor: 35, at: 0, deviceId: 'late' });
    expect(await p.runOnce()).toEqual(['late']);
    expect(box.value).toBe(35);
    clock.now += 60_000;
    expect(await p.runOnce()).toEqual([]);
    expect(box.value).toBe(40);
    const saves = box.saves;
    expect(await p.runOnce()).toEqual([]);
    expect(box.saves).toBe(saves);
    // A restart resumes from the saved cursor: nothing is sent again, only what is new.
    entries.push(revocation(50));
    const restarted = new RevocationPropagator({ feed, cursor: store, logger: quiet, sinks: [sink] });
    expect(await restarted.runOnce()).toEqual(['d50']);
    expect(sent).toEqual(['d10', 'd30', 'd40', 'd20', 'late', 'd50']);
  });

  it('starts over when its cursor is ahead of the policy-engine (another or a rebuilt database)', async () => {
    const { box, store } = memoryCursor();
    box.value = 900;
    const logs: LogRecord[] = [];
    const sent: string[] = [];
    const p = new RevocationPropagator({ feed: memoryFeed([revocation(1), revocation(2)]), cursor: store, logger: createLogger({ write: (r) => logs.push(r) }), sinks: [async (id) => void sent.push(id)] });
    expect(await p.runOnce()).toEqual(['d1', 'd2']);
    expect(box.value).toBe(2);
    expect(logs.some((l) => l.level === 'warn' && /starting over/.test(l.msg))).toBe(true);
  });

  it('fails the run on a malformed page instead of skipping what it cannot read', async () => {
    const admin = new LocalSigner(generateSecretKey());
    const stub = new StubPolicyApi({ adminPubkeys: [await admin.getPublicKey()], feed: () => [], revocations: () => [{ cursor: 1, at: 0 } as DeviceRevocation] });
    stubs.push(stub);
    const p = new RevocationPropagator({ feed: new HttpPolicySource({ baseUrl: await stub.listen(), signer: admin }), logger: quiet, sinks: [async () => {}] });
    await expect(p.runOnce()).rejects.toThrow(/malformed/);
  });
});
