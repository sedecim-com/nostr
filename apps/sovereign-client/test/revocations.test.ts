import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPolicyApi, MemoryPolicyRepository, PolicyEngine } from '@sedecim/policy-engine';
import { HttpError, Service } from '@sedecim/service-kit';
import { createLogger } from '@sedecim/telemetry-policy';
import { TestRelay } from '@sedecim/test-relay';
import { SovereignClient } from '../src/index';

const TOKEN = 'revocation-token-0123456789';
const silent = createLogger({ write: () => {} });

describe('sovereign rotation-worker: revocation cursor (FR024-04)', () => {
  const relay = new TestRelay();
  const clock = { now: Date.now() };
  const engine = new PolicyEngine(new MemoryPolicyRepository(), () => clock.now);
  const received: string[] = [];
  const signer = new Service({ name: 'managed-signer-stub', logger: silent });
  signer.post('/v1/devices/:id/revoke', (req) => {
    if (req.headers.authorization !== `Bearer ${TOKEN}`) throw new HttpError(401, 'bad token');
    received.push(req.params.id!);
    return { ok: true };
  }, 'none');
  const closers: Array<() => unknown> = [];
  let dir: string;
  let signerUrl: string;

  beforeAll(async () => {
    await relay.start();
    signerUrl = await signer.listen();
    dir = await mkdtemp(join(tmpdir(), 'sovereign-revocations-'));
    closers.push(() => signer.close(), () => relay.stop());
  });
  afterAll(async () => {
    for (const c of closers.reverse()) await c();
  });

  it('keeps the cursor per policy-engine in the encrypted store and resumes from it after a restart', async () => {
    const client = new SovereignClient({ dataDir: dir, passphrase: 'pass', scryptLogN: 4 });
    closers.push(() => client.close());
    const worker = await client.createPersona({ label: 'Worker', relays: [relay.url] });
    const policy = createPolicyApi(engine, { name: 'policy-sovereign', adminPubkeys: [worker.pubkey], logger: silent });
    const policyUrl = await policy.listen();
    closers.push(() => policy.close());
    const owner = 'ab'.repeat(32);
    const revoke = async () => {
      const d = await engine.registerDevice('admin', owner);
      await engine.revokeDevice('admin', d.id, 'lost');
      return d.id;
    };
    const opts = { policyUrl, managedSigner: { url: signerUrl, token: TOKEN } };

    const d1 = await revoke();
    const { propagator } = await client.revocationWorker(worker.id, opts);
    expect(await propagator!.runOnce()).toEqual([d1]);
    clock.now += 61_000;
    expect(await propagator!.runOnce()).toEqual([]);
    client.close();

    // Restart: the saved cursor is past d1, so only the new revocation goes out.
    const d2 = await revoke();
    const restarted = new SovereignClient({ dataDir: dir, passphrase: 'pass', scryptLogN: 4 });
    closers.push(() => restarted.close());
    const again = await restarted.revocationWorker(worker.id, opts);
    expect(await again.propagator!.runOnce()).toEqual([d2]);
    expect(received).toEqual([d1, d2]);

    // The cursor lives in the encrypted store: the policy-engine URL is nowhere on disk in the clear.
    const host = new URL(policyUrl).host;
    for (const f of await readdir(dir, { recursive: true })) {
      const raw = await readFile(join(dir, String(f)), 'utf8').catch(() => '');
      expect(raw).not.toContain(host);
    }
  });
});
