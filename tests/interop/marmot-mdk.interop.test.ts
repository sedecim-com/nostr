/**
 * FR025-04: mixed Marmot group marmot-ts <-> MDK (Rust Marmot Development Kit), messages both ways and a
 * creator on each side, through a real websocket relay.
 *
 *   (cd interop/mdk-harness && cargo build --release --locked)
 *   npx vitest run tests/interop/marmot-mdk.interop.test.ts
 *
 * The MDK side is interop/mdk-harness (mdk-core + in-memory storage + nostr-sdk), driven over JSON lines.
 * Relay: packages/test-relay (NIP-42, gift wraps #p-gated like the secure relay) unless MDK_RELAY_URL
 * points to another one (e.g. the secure-relay nostr-rs-relay: MDK_RELAY_URL=ws://localhost:7000).
 * Writes interop-mdk-report.json (copied to docs/interop/ when the pinned versions change).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { existsSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';
import { generateSecretKey, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { TestRelay } from '@sedecim/test-relay';
import { EncryptedGroupStorage, MarmotTsProvider, PoolGroupNetwork, type GroupSession } from '@sedecim/marmot-adapter';

const BIN = process.env.MDK_HARNESS_BIN ?? fileURLToPath(new URL('../../interop/mdk-harness/target/release/mdk-harness', import.meta.url));
const HAVE_BIN = existsSync(BIN);
/** Set in CI (job marmot-mdk): a missing binary is a failure there, not a skip. */
const REQUIRED = process.env.MDK_INTEROP_REQUIRED === '1';
if (!HAVE_BIN && !REQUIRED) console.warn(`[marmot-mdk] skipped: MDK harness not built (${BIN}). Build it with: cd interop/mdk-harness && cargo build --release --locked`);

const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;

type Reply = Record<string, any> & { ok?: boolean; error?: string };

/** The MDK peer: one harness process, one Nostr identity, in-memory MDK storage. */
class MdkPeer {
  pubkey = '';
  version = '';
  private readonly proc: ChildProcessWithoutNullStreams;
  private readonly waiting: Array<(r: Reply) => void> = [];
  private readonly stderr: string[] = [];

  constructor(relay: string) {
    this.proc = spawn(BIN, ['--relay', relay], { stdio: ['pipe', 'pipe', 'pipe'] });
    createInterface({ input: this.proc.stdout }).on('line', (line) => this.waiting.shift()?.(JSON.parse(line)));
    this.proc.stderr.on('data', (d) => this.stderr.push(String(d)));
  }

  private next(timeoutMs = 30_000): Promise<Reply> {
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`mdk-harness timed out; stderr: ${this.stderr.join('')}`)), timeoutMs);
      this.waiting.push((r) => {
        clearTimeout(t);
        resolve(r);
      });
    });
  }

  async start() {
    const ready = await this.next();
    if (!ready.ready) throw new Error(`mdk-harness failed to start: ${ready.error}`);
    this.pubkey = ready.pubkey;
    this.version = ready.mdk;
  }

  /** Sends one command; throws with MDK's own error text when the harness reports a failure. */
  async call(op: string, args: Record<string, unknown> = {}): Promise<Reply> {
    const reply = this.next();
    this.proc.stdin.write(JSON.stringify({ op, ...args }) + '\n');
    const r = await reply;
    if (!r.ok) throw new Error(`MDK ${op}: ${r.error}`);
    return r;
  }

  stop() {
    this.proc.stdin.end(JSON.stringify({ op: 'quit' }) + '\n');
    setTimeout(() => this.proc.kill(), 2000).unref();
  }
}

describe.runIf(!HAVE_BIN && REQUIRED)('Marmot interop: MDK harness (FR025-04)', () => {
  it('is built', () => {
    expect.fail(`MDK_INTEROP_REQUIRED=1 but ${BIN} does not exist: cd interop/mdk-harness && cargo build --release --locked`);
  });
});

/** Differences between marmot-ts 0.5.1 and MDK found by this test (details: docs/marmot.md). */
const KNOWN_INCOMPATIBILITIES = [
  {
    id: 'mls_proposals',
    status: 'open (upstream)',
    detail:
      'MDK >= 0.7 rejects kind 30443 key packages without the mls_proposals tag = 0x000a (SelfRemove, MIP-00). ts-mls 2.0.0-rc.16 does not implement SelfRemove, so marmot-ts 0.5.1 neither advertises the capability nor the tag: MDK cannot add a marmot-ts member by its current key package. Legacy kind 443 copies are still accepted by MDK 0.8.0.',
  },
  {
    id: 'key-package-lifetime',
    status: 'mitigated in marmot-adapter',
    detail:
      'marmot-ts sets not_before = current second with no skew margin; OpenMLS (MDK) requires not_before < now, so a Welcome or key package processed within the same second fails with "Lifetime is not acceptable". The adapter waits for the next second before handing them out; a receiver whose clock is behind the creator still rejects them until it catches up.',
  },
  {
    id: 'key-package-d-tag',
    status: 'fixed in marmot-adapter',
    detail: 'MDK requires the kind 30443 d tag to be 64 hex chars (32 random bytes, MIP-00). The adapter used the device id; it now uses a random 32-byte slot per device, persisted with the MLS state.',
  },
];

interface Step {
  step: string;
  ok: boolean;
  detail?: unknown;
}

describe.skipIf(!HAVE_BIN)('Marmot interop: marmot-ts <-> MDK (FR025-04)', () => {
  const external = process.env.MDK_RELAY_URL;
  const relay = new TestRelay({ pGatedKinds: [1059] });
  let url = '';
  const pools: RelayPool[] = [];
  const peers: MdkPeer[] = [];
  const steps: Step[] = [];
  const provider = new MarmotTsProvider();

  const record = (step: string, ok: boolean, detail?: unknown) => steps.push({ step, ok, ...(detail === undefined ? {} : { detail }) });

  const tsMember = async (name: string): Promise<GroupSession & { signer: LocalSigner }> => {
    const signer = new LocalSigner(generateSecretKey());
    const pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'auto', authTimeoutMs: 1500 });
    pools.push(pool);
    const storage = new EncryptedGroupStorage(EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(name.charCodeAt(0))));
    const session = await provider.openSession({ signer, storage, network: new PoolGroupNetwork(pool, [url]), deviceId: `interop-${name}` });
    return Object.assign(session, { signer });
  };

  const mdkPeer = async () => {
    const peer = new MdkPeer(url);
    peers.push(peer);
    await peer.start();
    return peer;
  };

  /** Relays may confirm before the write is visible to queries: poll briefly. */
  async function eventually<T>(fn: () => Promise<T>, done: (v: T) => boolean, ms = 10_000): Promise<T> {
    const end = Date.now() + ms;
    for (;;) {
      const v = await fn();
      if (done(v) || Date.now() > end) return v;
      await new Promise((r) => setTimeout(r, 400));
    }
  }

  beforeAll(async () => {
    if (external) url = external;
    else {
      await relay.start();
      url = relay.url;
    }
  });

  afterAll(async () => {
    peers.forEach((p) => p.stop());
    pools.forEach((p) => p.close());
    if (!external) await relay.stop();
    writeFileSync(
      'interop-mdk-report.json',
      JSON.stringify(
        {
          relay: external ? url : 'packages/test-relay (NIP-42, kind 1059 #p-gated)',
          marmotTs: provider.properties,
          mdk: { implementation: peers[0]?.version ?? 'unknown', ciphersuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001)', transport: 'nostr-sdk 0.44.1' },
          steps,
          failures: steps.filter((s) => !s.ok).map((s) => s.step),
          knownIncompatibilities: KNOWN_INCOMPATIBILITIES,
          at: new Date().toISOString(),
        },
        null,
        2,
      ) + '\n',
    );
  });

  it('marmot-ts creates the group, MDK joins from the Welcome; messages flow both ways', async () => {
    const alice = await tsMember('alice');
    const mdk = await mdkPeer();

    const kp = (await mdk.call('publish_key_package')).event as NostrEvent;
    record('mdk publishes key package (30443)', kp.kind === 30443, { tags: kp.tags.map((t) => t[0]) });
    const found = await eventually(() => alice.findKeyPackage(mdk.pubkey, [url]), Boolean);
    expect(found?.id, 'marmot-ts did not find the MDK key package').toBe(kp.id);

    const group = await alice.createGroup({ name: 'interop ts->mdk', relays: [url] });
    await alice.invite(group.groupId, found!);
    record('marmot-ts adds MDK key package (commit + gift-wrapped Welcome)', true);
    await alice.send(group.groupId, 'hola desde marmot-ts');

    const joined = await eventually(() => mdk.call('accept_welcomes'), (r) => r.groups.length > 0 || r.errors.length > 0);
    record('MDK joins from the marmot-ts Welcome', joined.groups.length === 1, { errors: joined.errors });
    expect(joined.errors).toEqual([]);
    expect(joined.groups).toHaveLength(1);
    const mdkGroup = joined.groups[0];
    expect(mdkGroup.mls_group_id).toBe(group.groupId);
    expect(mdkGroup.nostr_group_id).toBe(group.nostrGroupId);
    expect(mdkGroup.name).toBe('interop ts->mdk');
    expect([...mdkGroup.members].sort()).toEqual([alice.pubkey, mdk.pubkey].sort());

    const synced = await eventually(() => mdk.call('sync', { group: group.groupId }), (r) => r.messages.length > 0);
    const got = synced.messages.map((m: { content: string }) => m.content);
    record('MDK decrypts a marmot-ts application message', got.includes('hola desde marmot-ts'), { results: synced.results });
    expect(synced.messages).toContainEqual(expect.objectContaining({ sender: alice.pubkey, content: 'hola desde marmot-ts', kind: 9 }));

    await mdk.call('send', { group: group.groupId, content: 'respuesta desde MDK' });
    const back = await eventually(() => alice.sync(group.groupId), (m) => m.length > 0);
    record('marmot-ts decrypts the MDK reply', back.some((m) => m.content === 'respuesta desde MDK'));
    expect(back).toContainEqual(expect.objectContaining({ sender: mdk.pubkey, content: 'respuesta desde MDK', kind: 9 }));
    alice.close();
  }, 90_000);

  it('MDK creates the group, marmot-ts joins from the Welcome; messages flow both ways', async () => {
    const bob = await tsMember('bob');
    const mdk = await mdkPeer();

    const kp = await bob.publishKeyPackage([url]);
    // Known incompatibility (docs/marmot.md): MDK >= 0.7 requires `mls_proposals` = 0x000a (SelfRemove) on
    // kind 30443 key packages; marmot-ts 0.5.1 on ts-mls 2.0.0-rc.16 does not implement SelfRemove, so
    // it neither advertises the capability nor the tag. MDK cannot add a marmot-ts member by its
    // current key package.
    const refused = await mdk.call('create_group', { name: 'interop mdk->ts', members: [bob.pubkey], kinds: [30443] }).then(
      () => undefined,
      (e: Error) => e.message,
    );
    record('MDK adds the marmot-ts kind 30443 key package', refused === undefined, { error: refused, keyPackageTags: kp.tags.map((t) => t[0]), knownIncompatibility: 'mls_proposals' });
    expect(refused, 'MDK now accepts marmot-ts 30443 key packages: drop the legacy 443 path below and update docs/marmot.md').toMatch(/Missing required tag: mls_proposals/);

    // Same key package re-published as legacy kind 443 (MDK still accepts it without mls_proposals / d):
    // exercises the rest of the MDK-creator direction (Welcome, messages both ways) at the MLS level.
    const legacy = await bob.signer.signEvent({ kind: 443, content: kp.content, tags: kp.tags.filter((t) => t[0] !== 'd'), created_at: kp.created_at });
    const pub = await pools.at(-1)!.publish(legacy, [url]);
    expect(pub.some((r) => r.ok), JSON.stringify(pub)).toBe(true);
    const created = await eventually(
      () => mdk.call('create_group', { name: 'interop mdk->ts', members: [bob.pubkey], kinds: [443] }).catch((e: Error) => ({ error: e.message }) as Reply),
      (r) => !r.error?.includes('no key package'),
    );
    record('MDK creates a group with the marmot-ts key package (legacy kind 443 copy)', !created.error, created.error ? { error: created.error } : undefined);
    expect(created.error).toBeUndefined();
    const gid = created.group.mls_group_id as string;

    const joined = await eventually(() => bob.acceptInvites(), (g) => g.length > 0);
    record('marmot-ts joins from the MDK Welcome', joined.length === 1);
    expect(joined).toHaveLength(1);
    expect(joined[0]!.groupId).toBe(gid);
    expect(joined[0]!.nostrGroupId).toBe(created.group.nostr_group_id);
    expect(joined[0]!.name).toBe('interop mdk->ts');
    expect([...joined[0]!.members].sort()).toEqual([bob.pubkey, mdk.pubkey].sort());
    expect(joined[0]!.admins).toEqual([mdk.pubkey]);

    await mdk.call('send', { group: gid, content: 'hola desde MDK' });
    const got = await eventually(() => bob.sync(gid), (m) => m.length > 0);
    record('marmot-ts decrypts an MDK application message', got.some((m) => m.content === 'hola desde MDK'));
    expect(got).toContainEqual(expect.objectContaining({ sender: mdk.pubkey, content: 'hola desde MDK', kind: 9 }));

    await bob.send(gid, 'respuesta desde marmot-ts');
    const back = await eventually(() => mdk.call('sync', { group: gid }), (r) => r.messages.length > 0);
    record('MDK decrypts the marmot-ts reply', back.messages.some((m: { content: string }) => m.content === 'respuesta desde marmot-ts'), { results: back.results });
    expect(back.messages).toContainEqual(expect.objectContaining({ sender: bob.pubkey, content: 'respuesta desde marmot-ts', kind: 9 }));
    bob.close();
  }, 90_000);
});
