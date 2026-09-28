import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import dns from 'node:dns';
import { generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, NetworkBlockedError } from '@sedecim/relay-pool';
import { TestRelay, TestSocksServer } from '@sedecim/test-relay';
import { NetworkGuard, PRIVACY_NETWORK_UNAVAILABLE } from '../src/index';

const ONION = 'relayabcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstu.onion';

describe('NetworkGuard policy', () => {
  it('blocks .onion in direct mode and clearnet in onion-only mode', () => {
    const direct = new NetworkGuard({ mode: 'direct' });
    expect(() => direct.checkDestination(`ws://${ONION}`)).toThrow(NetworkBlockedError);
    expect(direct.checkDestination('wss://relay.example').hostname).toBe('relay.example');
    const strict = new NetworkGuard({ mode: 'tor-only', onionOnly: true });
    expect(() => strict.checkDestination('wss://relay.example')).toThrow(/onion-only/);
    const allow = new NetworkGuard({ mode: 'direct', allowedHosts: ['relay.example'] });
    expect(() => allow.checkDestination('https://analytics.example/collect')).toThrow(/allowlist/);
  });

  it('widens an allowlist only with the hosts an explicit action names, and keeps the onion rules (FR017-06)', () => {
    const allow = new NetworkGuard({ mode: 'direct', allowedHosts: ['relay.example'] });
    allow.allowHosts(['dm.recipient.example']);
    expect(allow.checkDestination('wss://dm.recipient.example').hostname).toBe('dm.recipient.example');
    expect(() => allow.checkDestination('wss://other.example')).toThrow(/allowlist/);
    allow.allowHosts([ONION]);
    expect(() => allow.checkDestination(`ws://${ONION}`)).toThrow(/require Tor/);
    const strict = new NetworkGuard({ mode: 'tor-only', onionOnly: true, allowedHosts: [ONION] });
    strict.allowHosts(['dm.recipient.example']);
    expect(() => strict.checkDestination('wss://dm.recipient.example')).toThrow(/onion-only/);
    // Without an allowlist there is nothing to widen.
    const open = new NetworkGuard({ mode: 'direct' });
    open.allowHosts(['x.example']);
    expect(open.config.allowedHosts).toBeUndefined();
  });
});

describe('Tor-only mode (FR-020, FR-021)', () => {
  const relay = new TestRelay({ publicUrl: `ws://${ONION}` });
  let socks: TestSocksServer;

  beforeAll(async () => {
    await relay.start();
    socks = new TestSocksServer({ [ONION]: { host: '127.0.0.1', port: relay.port } });
    await socks.start();
  });
  afterAll(async () => {
    await socks.stop();
    await relay.stop();
  });

  it('fails closed when Tor is down: nothing leaves, message reported as not sent', async () => {
    const guard = new NetworkGuard({ mode: 'tor-only', socksPort: 1, probeTimeoutMs: 500 });
    const pool = new RelayPool({ webSocketFactory: guard.webSocketFactory(), autoReconnect: false });
    const signer = new LocalSigner(generateSecretKey());
    const res = await pool.publishTo(await signer.signEvent({ kind: 1, content: 'x' }), 'wss://relay.example');
    expect(res).toMatchObject({ ok: false, blocked: true });
    expect(res.message).toContain(PRIVACY_NETWORK_UNAVAILABLE);
    expect(guard.egress.every((e) => !e.allowed)).toBe(true);
    pool.close();
  });

  it('reaches an onion relay through SOCKS with remote DNS and no local lookups', async () => {
    const lookup = vi.spyOn(dns, 'lookup');
    const guard = new NetworkGuard({ mode: 'tor-only', socksPort: socks.port, onionOnly: true, isolationKey: 'persona-a' });
    const signer = new LocalSigner(generateSecretKey());
    const pool = new RelayPool({ webSocketFactory: guard.webSocketFactory(), signer });
    const evt = await signer.signEvent({ kind: 1, content: 'via tor' });
    const res = await pool.publishTo(evt, `ws://${ONION}`);
    expect(res.ok).toBe(true);
    expect(relay.events.has(evt.id)).toBe(true);
    expect(socks.requests.at(-1)).toMatchObject({ host: ONION, addressType: 'domain' });
    expect(lookup).not.toHaveBeenCalledWith(ONION, expect.anything(), expect.anything());
    expect(lookup.mock.calls.some((c) => String(c[0]).endsWith('.onion'))).toBe(false);
    lookup.mockRestore();
    pool.close();
  });
  it('fetchApi (NIP-11 and other HTTP of libraries) goes through SOCKS by name, never the local resolver', async () => {
    const lookup = vi.spyOn(dns, 'lookup');
    const guard = new NetworkGuard({ mode: 'tor-only', socksPort: socks.port, allowedHosts: [ONION] });
    const before = socks.requests.length;
    const res = await guard.fetchApi()(`http://${ONION}/`, { headers: { accept: 'application/nostr+json' }, signal: AbortSignal.timeout(5000) });
    expect(res.status).toBe(200);
    expect(Array.isArray(((await res.json()) as { supported_nips?: unknown }).supported_nips)).toBe(true);
    expect(socks.requests.slice(before)).toEqual([{ host: ONION, port: 80, addressType: 'domain' }]);
    expect(lookup.mock.calls.some((c) => String(c[0]).endsWith('.onion'))).toBe(false);
    lookup.mockRestore();
    await expect(guard.fetchApi()('http://analytics.example/collect')).rejects.toThrow(/allowlist/);
  });
});

describe('per-persona circuits and one failure through Tor (FR006-06, FR021-03)', () => {
  const relay = new TestRelay({ publicUrl: `ws://${ONION}` });
  // Like Tor with IsolateSOCKSAuth: username/password is required, and the credentials pick the circuit.
  let socks: TestSocksServer;
  beforeAll(async () => {
    await relay.start();
    socks = new TestSocksServer({ [ONION]: { host: '127.0.0.1', port: relay.port } }, { requireAuth: true });
    await socks.start();
  });
  afterAll(async () => {
    await socks.stop();
    await relay.stop();
  });
  const publish = async (guard: NetworkGuard, url = `ws://${ONION}`) => {
    const signer = new LocalSigner(generateSecretKey());
    const pool = new RelayPool({ webSocketFactory: guard.webSocketFactory(), signer, autoReconnect: false });
    try {
      return await pool.publishTo(await signer.signEvent({ kind: 1, content: 'aislado' }), url);
    } finally {
      pool.close();
    }
  };

  it('each persona authenticates to the SOCKS port with its own credentials, so Tor builds separate circuits', async () => {
    const before = socks.requests.length;
    for (const key of ['persona-a', 'persona-b', 'persona-a']) expect((await publish(new NetworkGuard({ mode: 'tor-only', socksPort: socks.port, isolationKey: key }))).ok).toBe(true);
    const fetched = await new NetworkGuard({ mode: 'tor-only', socksPort: socks.port, isolationKey: 'persona-b' }).fetch(`http://${ONION}/`, { headers: { accept: 'application/nostr+json' } });
    expect(fetched.status).toBe(200);
    expect(socks.requests.slice(before).map((r) => [r.host, r.username])).toEqual([
      [ONION, 'persona-a'],
      [ONION, 'persona-b'],
      [ONION, 'persona-a'],
      [ONION, 'persona-b'],
    ]);
  });

  it('a SOCKS-level failure is one held failure that names no address: no credentials, an unreachable onion, no proxy', async () => {
    const failures = [
      new NetworkGuard({ mode: 'tor-only', socksPort: socks.port }), // refused: no isolation credentials
      new NetworkGuard({ mode: 'tor-only', socksPort: socks.port, isolationKey: 'persona-a' }), // host unreachable
    ];
    const urls = [`ws://${ONION}`, 'ws://unknownrelayabcdefghijklmnopqrstuvwxyz234567abcdefghijklm.onion'];
    for (const [i, guard] of failures.entries()) {
      const res = await publish(guard, urls[i]);
      expect(res).toMatchObject({ ok: false, blocked: true, message: `error: ${PRIVACY_NETWORK_UNAVAILABLE}` });
    }
    await expect(failures[1]!.fetch(`http://unknownrelayabcdefghijklmnopqrstuvwxyz234567abcdefghijklm.onion/`)).rejects.toThrow(PRIVACY_NETWORK_UNAVAILABLE);
    // Tor down: the same message (the probe fails before any SOCKS request).
    expect(await publish(new NetworkGuard({ mode: 'tor-only', socksPort: 1, probeTimeoutMs: 500, isolationKey: 'persona-a' }))).toMatchObject({ blocked: true, message: `error: ${PRIVACY_NETWORK_UNAVAILABLE}` });
  });
});
