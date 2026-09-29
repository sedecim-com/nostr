/**
 * VAULT-04: in the CLI, each sent event is copied to the Continuity Vault as the persona's policy says. Best-effort
 * never delays a send; required-for-resilient holds it until the copy is in the vault; the copy is a state of its
 * own beside the relay ACKs. A restore puts back the persona's events, not the gift wraps it sent to other people.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CONTINUITY_HELD, CONTINUITY_HELD_NO_VAULT } from '@sedecim/delivery-engine';
import { createContinuityVaultApi, MemoryArchiveRepository, MemoryObjectStore } from '@sedecim/continuity-vault';
import { createLogger } from '@sedecim/telemetry-policy';
import { TestRelay } from '@sedecim/test-relay';
import { SovereignClient } from '../src/index';

const silent = createLogger({ write: () => {} });

/** A local port nobody listens on (yet). */
async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', () => r()));
  const { port } = probe.address() as { port: number };
  await new Promise<void>((r) => probe.close(() => r()));
  return port;
}

describe('the Continuity Vault in the CLI delivery state machine (VAULT-04)', () => {
  const relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  const repo = new MemoryArchiveRepository();
  const objects = new MemoryObjectStore();
  const vault = createContinuityVaultApi(repo, objects, { name: 'vault-continuity', logger: silent });
  let vaultUrl: string;
  const clients: SovereignClient[] = [];
  const vaults: Array<{ close(): Promise<void> }> = [vault];
  const newClient = async (opts: { vaultUrl?: string; dataDir?: string } = {}) => {
    const c = new SovereignClient({ dataDir: opts.dataDir ?? (await mkdtemp(join(tmpdir(), 'vault-continuity-'))), passphrase: 'pass', scryptLogN: 4, retry: { baseMs: 20, maxMs: 50 }, ...(opts.vaultUrl ? { vaultUrl: opts.vaultUrl } : {}) });
    clients.push(c);
    return c;
  };

  beforeAll(async () => {
    await relay.start();
    vaultUrl = await vault.listen();
  });
  afterAll(async () => {
    for (const c of clients) c.close();
    for (const v of vaults) await v.close();
    await relay.stop();
  });

  it('best-effort: the send goes out and its copy lands in the vault, a state apart from the relay ACK', async () => {
    const c = await newClient({ vaultUrl });
    const p = await c.createPersona({ label: 'Resiliente', relays: [relay.url] });
    // The sovereign profiles keep everything on the device until asked.
    expect((await c.profile(p.id)).continuity).toBe('off');
    const off = await c.sendChannel(p.id, 'general', 'sin copia');
    expect(off.continuity).toBeUndefined();

    const config = await c.setContinuity(p.id, 'best-effort');
    expect(config).toMatchObject({ continuity: 'best-effort', cloudBackup: 'ciphertext-user-key' });
    expect((await c.disclosures(p.id)).find((d) => d.control === 'continuity')!.statement).toMatch(/Si el vault no responde, el envío sale igual/);
    const rec = await c.sendChannel(p.id, 'general', 'con copia en el vault');
    expect(rec.state).toBe('REPLICATED');
    expect(rec.continuity).toMatchObject({ policy: 'best-effort', state: 'CONTINUITY_BACKED_UP', attemptCount: 1 });
    // The vault holds that event (and only sealed bytes).
    expect(await c.vaultVerify(p.id, vaultUrl)).toEqual({ archives: 1, opened: 1 });
    let held = '';
    for await (const k of objects.list()) held += new TextDecoder().decode((await objects.get(k))!);
    expect(held).not.toContain('con copia en el vault');
    expect(held).not.toContain(rec.event!.id);
  });

  it('required-for-resilient: nothing reaches the relay until the copy is in the vault', async () => {
    // A vault that is not up yet.
    const port = await freePort();
    const laterUrl = `http://127.0.0.1:${port}`;
    const c = await newClient({ vaultUrl: laterUrl });
    const p = await c.createPersona({ label: 'Exigente', relays: [relay.url] });
    await c.setContinuity(p.id, 'required-for-resilient');
    const text = `retenido hasta la copia ${Date.now()}`;
    const held = await c.sendChannel(p.id, 'general', text);
    expect(held).toMatchObject({ state: 'QUEUED', blockedReason: CONTINUITY_HELD, continuity: { policy: 'required-for-resilient', state: 'PENDING' } });
    expect(held.continuity!.lastError).toBeTruthy();
    expect(relay.received.some((e) => e.content === text)).toBe(false);

    // The vault comes up: the copy lands first, then the event goes to the relay.
    const later = createContinuityVaultApi(new MemoryArchiveRepository(), new MemoryObjectStore(), { name: 'vault-later', logger: silent });
    vaults.push(later);
    await later.listen(port);
    await c.resume(p.id);
    const sent = (await c.outbox(p.id)).find((r) => r.opId === held.opId)!;
    expect(sent.state).toBe('REPLICATED');
    expect(sent.continuity!.state).toBe('CONTINUITY_BACKED_UP');
    expect(sent.blockedReason).toBeUndefined();
    expect(sent.continuity!.backedUpAt!).toBeLessThanOrEqual(Math.min(...Object.values(sent.relayStatus).map((s) => s.acceptedAt!)));
    expect(relay.received.some((e) => e.content === text)).toBe(true);
  });

  it('refuses to require a copy without a vault, and a held send goes out once the policy is relaxed', async () => {
    const dataDir = await mkdtemp(join(tmpdir(), 'vault-continuity-'));
    const withVault = await newClient({ vaultUrl, dataDir });
    const p = await withVault.createPersona({ label: 'Sin vault luego', relays: [relay.url] });
    await withVault.setContinuity(p.id, 'required-for-resilient');
    withVault.close();

    // The same persona in a run without --vault: its sends are held, and requiring the copy is refused here.
    const noVault = await newClient({ dataDir });
    await expect(noVault.setContinuity(p.id, 'required-for-resilient')).rejects.toThrow(/no hay vault configurado/);
    const text = `sin vault ${Date.now()}`;
    const held = await noVault.sendChannel(p.id, 'general', text);
    expect(held).toMatchObject({ state: 'QUEUED', blockedReason: CONTINUITY_HELD_NO_VAULT });
    expect(relay.received.some((e) => e.content === text)).toBe(false);
    await noVault.setContinuity(p.id, 'off');
    await noVault.resume(p.id);
    const sent = (await noVault.outbox(p.id)).find((r) => r.opId === held.opId)!;
    expect(sent.state).toBe('REPLICATED');
    expect(sent.continuity).toBeUndefined();
    expect(relay.received.some((e) => e.content === text)).toBe(true);
  });

  it('a restore republishes the persona’s events and keeps the gift wraps it sent to others in the vault', async () => {
    const c = await newClient({ vaultUrl });
    const alice = await c.createPersona({ label: 'Alice', relays: [relay.url] });
    const bob = await c.createPersona({ label: 'Bob', relays: [relay.url] });
    await c.publishDmRelays(bob.id);
    await c.setContinuity(alice.id, 'best-effort');
    const [toBob, selfCopy] = await c.sendDm(alice.id, bob.pubkey, 'dm con copia en el vault');
    expect([toBob!.continuity!.state, selfCopy!.continuity!.state]).toEqual(['CONTINUITY_BACKED_UP', 'CONTINUITY_BACKED_UP']);

    const restored = await c.vaultRestore(alice.id, vaultUrl, { republish: true });
    expect(restored.othersWraps).toBe(1);
    expect(restored.published + restored.rejected + restored.othersWraps).toBe(restored.events);
    expect(restored.rejected).toBe(0);
  });
});
