/**
 * The sovereign client's encrypted event cache: history sync fills it and resumes from it, reads work without network
 * (--offline, also in a real CLI process), nothing is in clear on disk and `cache clear` deletes it.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { PersonaConfig } from '@sedecim/identity';
import { BUZZ_PINNED_ADAPTER } from '@sedecim/messaging';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { DEFAULT_RESUME_OVERLAP_SECONDS } from '@sedecim/sync';
import { TestRelay, TestSocksServer } from '@sedecim/test-relay';
import { SovereignClient } from '../src/index';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const PASS = 'cache-pass';
const opts = (dataDir: string, extra: Record<string, unknown> = {}) => ({ dataDir, passphrase: PASS, scryptLogN: 4, retry: { baseMs: 60_000, maxMs: 60_000 }, relayAdapter: { ...BUZZ_PINNED_ADAPTER, wrap: {} }, ...extra });

/** A real CLI process (not blocking this one, so the test relays keep answering if it ever connected). */
function cli(dataDir: string, args: string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--import', 'tsx', CLI, ...args], { env: { ...process.env, SOVEREIGN_DATA_DIR: dataDir, SOVEREIGN_PASSPHRASE: PASS, SOVEREIGN_FLAGS: '/nonexistent' } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

describe('sovereign client event cache (FR013-05)', () => {
  // Buzz-like relays (NIP-42, p-gated gift wraps); only the first one speaks NIP-77.
  const r1 = new TestRelay({ requireAuth: true, pGatedKinds: [1059], supportsNegentropy: true });
  const r2 = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  let dir: string;
  let bobDir: string;
  let device: SovereignClient;
  let bobDevice: SovereignClient;
  let alice: PersonaConfig;
  const network = () => ({ connections: r1.connectionAttempts + r2.connectionAttempts, info: r1.infoRequests + r2.infoRequests });

  beforeAll(async () => {
    await Promise.all([r1.start(), r2.start()]);
    dir = await mkdtemp(join(tmpdir(), 'sovereign-cache-'));
    device = new SovereignClient(opts(dir));
    bobDir = await mkdtemp(join(tmpdir(), 'sovereign-cache-bob-'));
    bobDevice = new SovereignClient(opts(bobDir));
    alice = await device.createPersona({ label: 'Alice', relays: [r1.url, r2.url] });
    const bob = await bobDevice.createPersona({ label: 'Bob', relays: [r1.url, r2.url] });
    await device.joinChannel(alice.id, 'general');
    await device.sendChannel(alice.id, 'general', 'hola general');
    await bobDevice.sendChannel(bob.id, 'general', 'hola Alice, soy Bob');
    await device.sendDm(alice.id, bob.pubkey, 'DM para Bob');
    await bobDevice.sendDm(bob.id, alice.pubkey, 'DM para Alice');
  });
  afterAll(async () => {
    device.close();
    bobDevice.close();
    await Promise.all([r1.stop(), r2.stop()]);
  });

  it('history sync fills the cache and the next one resumes: NIP-77 brings nothing again, REQ asks from the cursor (FR013-05)', async () => {
    const first = await device.syncHistory(alice.id);
    expect(first.strategies).toEqual({ [r1.url]: 'nip77-negentropy', [r2.url]: 'req-window' });
    expect(first.channels['general']!.map((e) => e.content).sort()).toEqual(['hola Alice, soy Bob', 'hola general']);
    expect(first.dms.map((m) => m.rumor.content).sort()).toEqual(['DM para Alice', 'DM para Bob']);
    expect(first.cache!.events).toBeGreaterThanOrEqual(5);

    const cursor = (await device.cacheStatus(alice.id)).cursors.find((c) => c.relay === r2.url && c.filter.includes('"#h":["general"]'))!.at;
    const sent = r1.sentEvents;
    const reqs = r2.reqFilters.length;
    const second = await device.syncHistory(alice.id);
    expect(r1.sentEvents - sent).toBe(0);
    const asked = r2.reqFilters.slice(reqs).flat();
    const channelReqs = asked.filter((f) => f['#h']?.includes('general'));
    expect(Math.min(...channelReqs.map((f) => f.since ?? 0))).toBe(cursor - DEFAULT_RESUME_OVERLAP_SECONDS);
    // The persona's own activity (where its channels come from) is always asked in full.
    const ownReqs = asked.filter((f) => f.authors?.includes(alice.pubkey));
    expect(ownReqs.length).toBeGreaterThan(0);
    expect(Math.min(...ownReqs.map((f) => f.since ?? 0))).toBe(0);
    expect(second.channels['general']!.map((e) => e.id).sort()).toEqual(first.channels['general']!.map((e) => e.id).sort());
    expect(second.dms.map((m) => m.rumor.id).sort()).toEqual(first.dms.map((m) => m.rumor.id).sort());
  });

  it('reads a channel and the DMs offline from another client instance without any connection (FR013-05)', async () => {
    const online = (await device.readChannel(alice.id, 'general')).map((e) => e.id).sort();
    const before = network();
    const offline = new SovereignClient(opts(dir));
    try {
      const started = Date.now();
      const channel = await offline.readChannel(alice.id, 'general', 50, { offline: true });
      const dms = await offline.inbox(alice.id, {}, { offline: true });
      expect(Date.now() - started).toBeLessThan(5_000);
      expect(channel.map((e) => e.id).sort()).toEqual(online);
      expect(channel.map((e) => e.content)).toEqual(expect.arrayContaining(['hola general', 'hola Alice, soy Bob']));
      expect(dms.map((m) => m.rumor.content).sort()).toEqual(['DM para Alice', 'DM para Bob']);
      await offline.settle();
    } finally {
      offline.close();
    }
    expect(network()).toEqual(before);
  });

  it('the CLI answers channel read --offline and dm inbox --offline from the cache without connecting (FR013-05)', async () => {
    const before = network();
    const channel = await cli(dir, ['channel', 'read', '--persona', alice.id, '--group', 'general', '--offline']);
    expect(channel.status, channel.stderr).toBe(0);
    expect(channel.stdout).toContain('hola Alice, soy Bob');
    expect(channel.stderr).toContain('sin conexión: leído de la caché local');
    const inbox = await cli(dir, ['dm', 'inbox', '--persona', alice.id, '--offline']);
    expect(inbox.status, inbox.stderr).toBe(0);
    expect(inbox.stdout).toContain('DM para Alice');
    expect(network()).toEqual(before);
  }, 60_000);

  it('an online dm inbox keeps the gift wraps it reads, which dm inbox --offline opens later (FR013-05)', async () => {
    const [bob] = await (await bobDevice.identities()).list();
    expect((await bobDevice.inbox(bob!.id)).map((m) => m.rumor.content)).toContain('DM para Bob');
    const offline = new SovereignClient(opts(bobDir));
    try {
      expect((await offline.inbox(bob!.id, {}, { offline: true })).map((m) => m.rumor.content).sort()).toEqual(['DM para Alice', 'DM para Bob']);
    } finally {
      offline.close();
    }
  });

  it('a Tor persona reads its cache offline without a single SOCKS request (FR013-05)', async () => {
    const onion = 'cacherelayabcdefghijklmnopqrstuvwxyz234567abcdefghijklmnop.onion';
    const onionRelay = new TestRelay({ publicUrl: `ws://${onion}` });
    await onionRelay.start();
    const socks = new TestSocksServer({ [onion]: { host: '127.0.0.1', port: onionRelay.port } });
    await socks.start();
    const torDir = await mkdtemp(join(tmpdir(), 'sovereign-cache-tor-'));
    const tor = new SovereignClient(opts(torDir, { socksPort: socks.port }));
    try {
      const p = await tor.createPersona({ label: 'Fuente', relays: [`ws://${onion}`], highRisk: true });
      await tor.sendChannel(p.id, 'drop', 'vía tor, guardado');
      expect((await tor.readChannel(p.id, 'drop')).map((e) => e.content)).toContain('vía tor, guardado');
      const requests = socks.requests.length;
      const offline = new SovereignClient(opts(torDir, { socksPort: socks.port }));
      try {
        expect((await offline.readChannel(p.id, 'drop', 50, { offline: true })).map((e) => e.content)).toEqual(['vía tor, guardado']);
        await offline.settle();
      } finally {
        offline.close();
      }
      expect(socks.requests.length).toBe(requests);
    } finally {
      tor.close();
      await socks.stop();
      await onionRelay.stop();
    }
  });

  it('dm inbox --offline refuses a persona whose key lives in a NIP-46 signer (FR013-05)', async () => {
    const remote = await (await device.identities()).importPersona({ bunker: `bunker://${getPublicKey(generateSecretKey())}?relay=wss://signer.invalid`, pubkey: getPublicKey(generateSecretKey()) }, { label: 'Remota', relays: [r1.url] });
    await expect(device.inbox(remote.id, {}, { offline: true })).rejects.toThrow(/signer NIP-46/);
  });

  it('keeps nothing in clear on disk, and cache clear deletes events and cursors but not the persona (FR013-05)', async () => {
    const personaDir = join(dir, 'personas', alice.id);
    const history = await device.syncHistory(alice.id);
    const ids = [...history.history.wraps, ...history.channels['general']!].map((e) => e.id);
    const files = await readdir(personaDir);
    const disk = (await Promise.all(files.map((f) => readFile(join(personaDir, f))))).map((b) => b.toString('latin1')).join('\n') + files.join('\n');
    for (const secret of ['hola general', 'hola Alice, soy Bob', '"#h"', ...ids]) expect(disk).not.toContain(secret);
    expect(files.some((f) => f.startsWith('evcache__'))).toBe(true);
    // Nor does the cache travel in the persona's backup (Bob's message is in no collection of Alice but the cache).
    const bobsMessage = history.channels['general']!.find((e) => e.content === 'hola Alice, soy Bob')!;
    const mgr = await device.identities();
    const backup = await mgr.readBackup(await device.exportBackup(alice.id, 'contraseña del backup', { scryptLogN: 4 }), 'contraseña del backup');
    expect(JSON.stringify(backup)).not.toContain(bobsMessage.id);

    const outbox = (await device.outbox(alice.id)).length;
    await device.clearCache(alice.id);
    expect((await readdir(personaDir)).filter((f) => f.startsWith('evcache'))).toEqual([]);
    expect((await device.cacheStatus(alice.id)).stats.events).toBe(0);
    expect((await device.cacheStatus(alice.id)).cursors).toEqual([]);
    expect(await device.readChannel(alice.id, 'general', 50, { offline: true })).toEqual([]);
    expect((await device.outbox(alice.id)).length).toBe(outbox);

    // Without cursors the next sync starts again from the beginning.
    const reqs = r2.reqFilters.length;
    await device.syncHistory(alice.id);
    const asked = r2.reqFilters.slice(reqs).flat().filter((f) => f['#h']?.includes('general'));
    expect(Math.min(...asked.map((f) => f.since ?? 0))).toBe(0);
  });

  it('history export asks the relays for everything, whatever the cache limits keep (FR013-05)', async () => {
    const small = new SovereignClient(opts(await mkdtemp(join(tmpdir(), 'sovereign-smallcache-')), { eventCache: { maxEvents: 2 } }));
    try {
      const p = await small.createPersona({ label: 'Pequeña', relays: [r2.url] });
      for (const text of ['uno', 'dos', 'tres', 'cuatro']) await small.sendChannel(p.id, 'general', text);
      const lines = (await small.exportHistory(p.id)).trimEnd().split('\n').map((l) => JSON.parse(l) as { content: string });
      expect(lines.map((e) => e.content)).toEqual(expect.arrayContaining(['uno', 'dos', 'tres', 'cuatro']));
      expect((await small.cacheStatus(p.id)).stats.events).toBe(2);
    } finally {
      small.close();
    }
  });

  it('with the cache off nothing is kept and history sync rebuilds as before (FR013-05)', async () => {
    const off = new SovereignClient(opts(await mkdtemp(join(tmpdir(), 'sovereign-nocache-')), { eventCache: false }));
    try {
      const p = await off.createPersona({ label: 'Sin caché', relays: [r2.url] });
      await off.sendChannel(p.id, 'general', 'sin caché');
      const r = await off.syncHistory(p.id);
      expect(r.cache).toBeUndefined();
      expect(r.channels['general']!.map((e) => e.content)).toContain('sin caché');
      await expect(off.readChannel(p.id, 'general', 50, { offline: true })).rejects.toThrow(/desactivada/);
    } finally {
      off.close();
    }
  });
});
