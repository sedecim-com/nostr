/**
 * FR006-06: each Tor persona authenticates to the SOCKS port with its own credentials (IsolateSOCKSAuth).
 * FR021-03: onion-only personas, one held failure when the privacy network cannot carry a message, and no relay IP
 * in what the CLI logs. FR007-05: the CLI shows who is sending (identity, custody, network, link level) before a send.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSecretKey } from '@sedecim/nostr-core';
import { publishDmRelayList } from '@sedecim/messaging';
import { LocalSigner } from '@sedecim/signer';
import { TestRelay, TestSocksServer } from '@sedecim/test-relay';
import { PRIVACY_NETWORK_UNAVAILABLE } from '@sedecim/tor-network';
import { SovereignClient } from '../src/index';

const ONION = 'hardenedrelay' + 'c'.repeat(43) + '.onion';
const MISSING_ONION = 'missingrelay' + 'd'.repeat(44) + '.onion';
const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

function run(args: string[], env: NodeJS.ProcessEnv): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--import', 'tsx', CLI, ...args], { env });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

describe('Sovereign Tor hardening (FR006-06, FR021-03)', () => {
  const onionRelay = new TestRelay({ publicUrl: `ws://${ONION}` });
  const clearnet = new TestRelay();
  let socks: TestSocksServer;
  let client: SovereignClient;

  beforeAll(async () => {
    await onionRelay.start();
    await clearnet.start();
    // Like Tor with IsolateSOCKSAuth on a port that requires credentials.
    socks = new TestSocksServer({ [ONION]: { host: '127.0.0.1', port: onionRelay.port } }, { requireAuth: true });
    await socks.start();
    client = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'tor-hardening-')), passphrase: 'pass', scryptLogN: 4, socksPort: socks.port, retry: { baseMs: 20_000, maxMs: 20_000 } });
  });
  afterAll(async () => {
    client.close();
    await socks.stop();
    await onionRelay.stop();
    await clearnet.stop();
  });

  it('each Tor persona reaches the relay with its own SOCKS credentials, so Tor keeps their circuits apart', async () => {
    const a = await client.createPersona({ label: 'Fuente A', relays: [`ws://${ONION}`], tor: true });
    const b = await client.createPersona({ label: 'Fuente B', relays: [`ws://${ONION}`], tor: true });
    const before = socks.requests.length;
    expect((await client.sendChannel(a.id, 'sala', 'desde A')).state).toBe('REPLICATED');
    expect((await client.sendChannel(b.id, 'sala', 'desde B')).state).toBe('REPLICATED');
    const used = socks.requests.slice(before);
    expect(new Set(used.map((r) => r.username))).toEqual(new Set([a.id, b.id]));
    expect(used.every((r) => r.host === ONION && r.addressType === 'domain')).toBe(true);
  });

  it('an onion-only persona takes only .onion relays and never writes to a clearnet DM relay', async () => {
    await expect(client.createPersona({ label: 'x', relays: [clearnet.url], onionOnly: true })).rejects.toThrow('onion-only: every relay must be a .onion address (1 of 1 are not)');
    const p = await client.createPersona({ label: 'Solo onion', relays: [`ws://${ONION}`], onionOnly: true });
    expect(p).toMatchObject({ network: 'tor-only', onionOnly: true });
    expect(await (await client.identities()).sendingAs(p.id)).toContain(' · Tor-only, solo .onion · ');
    // A recipient whose DM relays are clearnet: routed there, then refused by the guard. Nothing reaches it.
    const bob = new LocalSigner(generateSecretKey());
    const bobPk = await bob.getPublicKey();
    onionRelay.inject(await publishDmRelayList(bob, [clearnet.url]));
    const before = socks.requests.length;
    const recs = await client.sendDm(p.id, bobPk, 'solo por onion');
    const toBob = recs.find((r) => r.meta?.recipient === bobPk)!;
    expect(toBob).toMatchObject({ state: 'QUEUED', meta: { dmRelaySource: 'dm-relays' } });
    expect(toBob.blockedReason).toMatch(/onion-only/);
    expect(clearnet.received).toHaveLength(0);
    expect(socks.requests.slice(before).every((r) => r.host === ONION)).toBe(true);
  });

  it('any SOCKS-level failure is the same held failure: «No enviado: red de privacidad no disponible»', async () => {
    const p = await client.createPersona({ label: 'Onion caído', relays: [`ws://${MISSING_ONION}`], tor: true });
    const rec = await client.sendChannel(p.id, 'sala', 'no llega');
    expect(rec).toMatchObject({ state: 'QUEUED', blockedReason: PRIVACY_NETWORK_UNAVAILABLE });
    expect(Object.values(rec.relayStatus)[0]!.lastError).toBe(`error: ${PRIVACY_NETWORK_UNAVAILABLE}`);
  });
});

describe('what the sovereign CLI logs (FR021-03, FR007-05)', () => {
  const relay = new TestRelay();
  let env: NodeJS.ProcessEnv;
  beforeAll(async () => {
    await relay.start();
    env = { ...process.env, SOVEREIGN_DATA_DIR: await mkdtemp(join(tmpdir(), 'cli-logs-')), SOVEREIGN_PASSPHRASE: 'cli-logs' };
  });
  afterAll(async () => {
    await relay.stop();
  });

  it('lists the maturity of each profile and function without opening any store (PANEL-07)', async () => {
    const { SOVEREIGN_PASSPHRASE: _unused, ...noPassphrase } = env;
    const r = await run(['maturity'], noPassphrase);
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toMatch(/^Experimental +sovereign-tor: /m);
    expect(r.stdout).toMatch(/^Beta +Grupos Marmot\/MLS: /m);
    expect(r.stdout).toMatch(/^Preview +Custodia en Nitro Enclave: /m);
  });

  it('shows who is sending before each send, and names no relay IP in its diagnostics', async () => {
    expect(relay.url).toMatch(/^ws:\/\/127\.0\.0\.1:/);
    const created = await run(['persona', 'create', '--label', 'Cli', '--relay', relay.url], env);
    expect(created.status, created.stderr).toBe(0);
    const id = (JSON.parse(created.stdout) as { id: string }).id;

    const sent = await run(['channel', 'send', '--persona', id, '--group', 'sala', 'hola'], env);
    expect(sent.status, sent.stderr).toBe(0);
    expect(sent.stderr).toMatch(/^Enviando como Cli \(npub1.*\) · llave cifrada en este dispositivo · red directa · sin vínculo$/m);
    expect(sent.stdout).toMatch(/^REPLICATED/);
    const whoami = await run(['whoami', '--persona', id], env);
    expect(whoami.stdout).toMatch(/· red directa · sin vínculo/);
    // PANEL-07: then the maturity of its configuration (sovereign preset, no Tor).
    expect(whoami.stdout).toMatch(/^madurez: Early release \(sovereign \(self-hosted\): /m);

    // The relay goes away: the send waits, and neither its delivery state nor the sync results name the IP.
    await relay.stop();
    const logs = [
      await run(['channel', 'send', '--persona', id, '--group', 'sala', 'sin relay'], env),
      await run(['outbox', '--persona', id], env),
      await run(['history', 'sync', '--persona', id], env),
    ];
    const outbox = logs[1]!.stdout;
    expect(outbox).toMatch(/ws:\/\/ip-[0-9a-f]{8}:\d+ attempts=1 ACK/);
    expect(outbox).toMatch(/ws:\/\/ip-[0-9a-f]{8}:\d+ attempts=\d+ error: /);
    for (const l of logs) expect(l.stdout + l.stderr).not.toContain('127.0.0.1');
    await relay.start();
  }, 60_000);

  it('says what the relay answered when it does not take the DM relay list, as Buzz does (OPS-21)', async () => {
    const buzzLike = new TestRelay();
    await buzzLike.start();
    buzzLike.faults.rejectReason = 'restricted: unknown event kind';
    try {
      const created = await run(['persona', 'create', '--label', 'Buzz', '--relay', buzzLike.url], env);
      expect(created.status, created.stderr).toBe(0);
      expect(created.stderr).toMatch(/^relays de DM \(kind 10050\): FAILED — quorum 1 unreachable: ws:\/\/ip-[0-9a-f]{8}:\d+: restricted: unknown event kind$/m);
      expect(created.stderr).not.toContain('127.0.0.1');
    } finally {
      await buzzLike.stop();
    }
  }, 30_000);
});
