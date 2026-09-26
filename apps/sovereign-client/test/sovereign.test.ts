import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TestRelay, TestSocksServer } from '@sedecim/test-relay';
import { SovereignClient } from '../src/index';

const ONION = 'sovereignrelayabcdefghijklmnopqrstuvwxyz234567abcdefghijk.onion';

describe('sovereign client E2E', () => {
  const relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  const onionRelay = new TestRelay({ publicUrl: `ws://${ONION}` });
  let socks: TestSocksServer;
  let dir: string;
  let client: SovereignClient;

  beforeAll(async () => {
    await relay.start();
    await onionRelay.start();
    socks = new TestSocksServer({ [ONION]: { host: '127.0.0.1', port: onionRelay.port } });
    await socks.start();
    dir = await mkdtemp(join(tmpdir(), 'sovereign-'));
    client = new SovereignClient({ dataDir: dir, passphrase: 'pass', scryptLogN: 4, socksPort: socks.port, retry: { baseMs: 20, maxMs: 50 } });
  });
  afterAll(async () => {
    client.close();
    await socks.stop();
    await relay.stop();
    await onionRelay.stop();
  });

  it('two personas exchange channel messages and DMs through an authenticated relay', async () => {
    const alice = await client.createPersona({ label: 'Alice', relays: [relay.url] });
    const bob = await client.createPersona({ label: 'Bob', relays: [relay.url] });
    const sent = await client.sendChannel(alice.id, 'general', 'hola canal');
    expect(sent.state).toBe('REPLICATED');
    expect((await client.readChannel(bob.id, 'general')).map((e) => e.content)).toContain('hola canal');
    const dms = await client.sendDm(alice.id, bob.pubkey, 'hola Bob');
    expect(dms.every((r) => r.state === 'REPLICATED')).toBe(true);
    const inbox = await client.inbox(bob.id);
    expect(inbox.map((m) => m.rumor.content)).toContain('hola Bob');
    expect(await (await client.identities()).sendingAs(alice.id)).toContain('sin vínculo');
  });

  it('Tor persona reaches an onion relay only via SOCKS (FR-021) and fails closed without Tor (FR-020)', async () => {
    const anon = await client.createPersona({ label: 'Fuente', relays: [`ws://${ONION}`], highRisk: true });
    expect(anon.network).toBe('tor-only');
    const ok = await client.sendChannel(anon.id, 'drop', 'vía tor');
    expect(ok.state).toBe('REPLICATED');
    expect(socks.requests.every((r) => r.addressType === 'domain' && r.host === ONION)).toBe(true);
    expect(client.telemetry.emitted).toHaveLength(0);

    const offline = new SovereignClient({ dataDir: dir, passphrase: 'pass', scryptLogN: 4, socksPort: 1, retry: { baseMs: 10_000, maxMs: 10_000 } });
    try {
      const held = await offline.sendChannel(anon.id, 'drop', 'sin tor');
      expect(held.state).toBe('QUEUED');
      expect(held.blockedReason).toBe('No enviado: red de privacidad no disponible');
      expect(onionRelay.received.some((e) => e.content === 'sin tor')).toBe(false);
    } finally {
      offline.close();
    }
    // Tor is back: the held message is published with the same event id
    const [resumed] = (await client.resume(anon.id)).filter((r) => r.event?.content === 'sin tor');
    expect(resumed!.state).toBe('REPLICATED');
    expect(onionRelay.events.has(resumed!.event!.id)).toBe(true);
  });

  it('refuses a direct connection to a relay not configured for the persona', async () => {
    const p = await client.createPersona({ label: 'Otra', relays: [relay.url] });
    const s = await client.session(p.id);
    await expect(s.guard.assertRoute('wss://tracker.example')).rejects.toThrow(/allowlist/);
  });

  it('re-drives the outbox when a relay connection comes back (FR-011)', async () => {
    const r = new TestRelay();
    await r.start();
    const port = r.port;
    const url = r.url;
    const slow = new SovereignClient({ dataDir: dir, passphrase: 'pass', scryptLogN: 4, retry: { baseMs: 30_000, maxMs: 30_000 } });
    let back: TestRelay | undefined;
    try {
      const p = await slow.createPersona({ label: 'Red', relays: [url] });
      await r.stop();
      const held = await slow.sendChannel(p.id, 'general', 'retenido');
      expect(held.state).toBe('QUEUED');
      back = new TestRelay({ port });
      await back.start();
      // any new traffic reconnects the pool; the reconnect resumes the held message without waiting for its backoff
      expect((await slow.sendChannel(p.id, 'general', 'nuevo')).state).toBe('REPLICATED');
      const end = Date.now() + 3000;
      while (!back.received.some((e) => e.content === 'retenido') && Date.now() < end) await new Promise((res) => setTimeout(res, 20));
      expect(back.received.some((e) => e.content === 'retenido')).toBe(true);
    } finally {
      slow.close();
      await back?.stop();
    }
  });
});
