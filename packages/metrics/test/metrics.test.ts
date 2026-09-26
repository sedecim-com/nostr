import { afterEach, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { DeliveryEngine, classifyFailure, type OutboxRecord } from '@sedecim/delivery-engine';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { TestRelay } from '@sedecim/test-relay';
import { preset } from '@sedecim/profiles';
import { TelemetryBlockedError, TelemetryPolicy } from '@sedecim/telemetry-policy';
import { Histogram, NostrMetricsExporter, parseRegionMap, regionFor, relayLabel, startAckProbe } from '../src/index';
import { startMetricsServer, type MetricsServer } from '../src/server';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
const signer = new LocalSigner(generateSecretKey());
const memStore = () => EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(3)).collection<OutboxRecord>('outbox');

/** Parses the exposition into {series -> value}. */
function samples(text: string): Map<string, number> {
  const out = new Map<string, number>();
  for (const line of text.split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const i = line.lastIndexOf(' ');
    out.set(line.slice(0, i), Number(line.slice(i + 1)));
  }
  return out;
}

describe('relay labels (NFR004-01)', () => {
  it('keeps only the host: never paths, queries, credentials or schemes', () => {
    expect(relayLabel('wss://relay.example/npub1abcdefghjk?token=secret')).toBe('relay.example');
    expect(relayLabel('wss://user:pw@relay.example:4443/inbox')).toBe('relay.example:4443');
    expect(relayLabel('ws://127.0.0.1:3000')).toBe('127.0.0.1:3000');
  });

  it('hashes onion relays and identifier-looking hosts with a stable label', () => {
    const onion = 'ws://abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz23.onion/path';
    const l = relayLabel(onion);
    expect(l).toMatch(/^onion-[0-9a-f]{12}$/);
    expect(relayLabel(onion.replace('/path', '/other'))).toBe(l);
    expect(relayLabel(onion, { salt: 's' })).not.toBe(l);
    expect(relayLabel(`wss://${'ab'.repeat(32)}.relay.example`)).toMatch(/^relay-[0-9a-f]{12}$/);
    expect(relayLabel('wss://relay.example', { pseudonymize: true })).toMatch(/^relay-[0-9a-f]{12}$/);
  });

  it('maps relays to regions by URL, host or hostname', () => {
    const map = parseRegionMap('relay.example=eu-west-1, ws://127.0.0.1:3000=us-east-1,bad');
    expect(regionFor('wss://relay.example/x', map)).toBe('eu-west-1');
    expect(regionFor('ws://127.0.0.1:3000', map)).toBe('us-east-1');
    expect(regionFor('wss://other.example', map, 'global')).toBe('global');
    expect(regionFor('wss://x', () => 'not a slug!')).toBe('unknown');
  });
});

describe('Prometheus histogram', () => {
  it('renders cumulative buckets usable by histogram_quantile', () => {
    const h = new Histogram('t_seconds', 'test', ['relay'], [0.1, 1]);
    for (const v of [0.05, 0.5, 0.7, 3]) h.observe({ relay: 'a"b' }, v);
    const s = samples(h.render());
    expect(s.get('t_seconds_bucket{relay="a\\"b",le="0.1"}')).toBe(1);
    expect(s.get('t_seconds_bucket{relay="a\\"b",le="1"}')).toBe(3);
    expect(s.get('t_seconds_bucket{relay="a\\"b",le="+Inf"}')).toBe(4);
    expect(s.get('t_seconds_count{relay="a\\"b"}')).toBe(4);
    expect(s.get('t_seconds_sum{relay="a\\"b"}')).toBeCloseTo(4.25);
  });
});

describe('metrics exporter respects the telemetry profile (FR-022)', () => {
  it('refuses to start where the profile forbids telemetry (sovereign, sovereign-tor)', () => {
    for (const p of ['sovereign', 'sovereign-tor'] as const) {
      expect(() => new NostrMetricsExporter({ telemetry: preset(p).telemetry })).toThrow(TelemetryBlockedError);
      expect(NostrMetricsExporter.forProfile(preset(p))).toBeUndefined();
    }
    expect(() => new NostrMetricsExporter({ telemetry: new TelemetryPolicy({ level: 'none' }) })).toThrow(TelemetryBlockedError);
    expect(NostrMetricsExporter.forProfile(preset('institutional'))?.level).toBe('standard');
    expect(NostrMetricsExporter.forProfile(preset('convenience'))?.level).toBe('minimal');
  });
});

describe('ACK latency and outbox metrics against the test relay (NFR004-01, FR011-03)', () => {
  const relays: TestRelay[] = [];
  let pool: RelayPool | undefined;
  let engine: DeliveryEngine | undefined;
  let server: MetricsServer | undefined;
  afterEach(async () => {
    engine?.stop();
    pool?.close();
    await server?.close();
    server = undefined;
    await Promise.all(relays.splice(0).map((r) => r.stop()));
  });
  const start = async () => {
    const r = new TestRelay();
    await r.start();
    relays.push(r);
    return r;
  };

  it('records per-relay ACK latency with region, publish results and outbox failures, without ids or pubkeys', async () => {
    const fast = await start();
    const slow = await start();
    const bad = await start();
    slow.faults.okDelayMs = 300;
    bad.faults.rejectReason = 'blocked: not allowed';
    const exporter = new NostrMetricsExporter({ telemetry: 'standard', regions: { [new URL(fast.url).host]: 'eu-west-1', [slow.url]: 'us-east-1' } });
    pool = new RelayPool({ webSocketFactory: factory, signer });
    exporter.attachPool(pool);
    engine = new DeliveryEngine({ store: memStore(), publisher: pool, signer, retry: { baseMs: 20, maxMs: 40 } });
    exporter.attachEngine(engine);

    const rec = await engine.submit({ template: { kind: 1, content: 'métricas' } }, { relays: [fast.url, slow.url, `${bad.url}/npub1secretpath?x=1`], quorum: 2, wait: true });
    expect(rec.state).toBe('REPLICATED');

    server = await startMetricsServer(exporter);
    const res = await fetch(server.url);
    expect(res.headers.get('content-type')).toMatch(/^text\/plain; version=0\.0\.4/);
    const text = await res.text();
    const s = samples(text);
    const fastHost = new URL(fast.url).host;
    const slowHost = new URL(slow.url).host;
    const badHost = new URL(bad.url).host;
    expect(s.get(`nostr_relay_ack_latency_seconds_count{relay="${fastHost}",region="eu-west-1"}`)).toBe(1);
    expect(s.get(`nostr_relay_ack_latency_seconds_count{relay="${slowHost}",region="us-east-1"}`)).toBe(1);
    // 300 ms OK delay: not in the <= 0.25 s bucket, in the <= 0.5 s one.
    expect(s.get(`nostr_relay_ack_latency_seconds_bucket{relay="${slowHost}",region="us-east-1",le="0.25"}`)).toBe(0);
    expect(s.get(`nostr_relay_ack_latency_seconds_bucket{relay="${slowHost}",region="us-east-1",le="0.5"}`)).toBe(1);
    expect(s.get(`nostr_relay_publish_total{relay="${badHost}",region="unknown",result="rejected"}`)).toBe(1);
    expect(s.get(`nostr_outbox_relay_failures_total{relay="${badHost}",region="unknown",reason="rejected"}`)).toBe(1);
    expect(s.get('nostr_outbox_depth')).toBe(0);
    expect(s.get('nostr_metrics_info{telemetry_level="standard"}')).toBe(1);
    // Nothing identifying: no pubkey, event id, op id, relay path or relay message text.
    for (const leak of [await signer.getPublicKey(), rec.event!.id, rec.opId, 'npub1secretpath', 'not allowed', 'ws://']) expect(text).not.toContain(leak);
    expect((await fetch(server.url.replace('/metrics', '/other'))).status).toBe(404);
  });

  it('reports outbox depth and oldest pending age while a relay is down, and pseudonymizes relays at level minimal', async () => {
    const r = await start();
    r.faults.offline = true;
    let now = 1_000_000;
    const exporter = new NostrMetricsExporter({ telemetry: 'minimal' });
    pool = new RelayPool({ webSocketFactory: factory, signer, connectTimeoutMs: 500, autoReconnect: false });
    exporter.attachPool(pool);
    engine = new DeliveryEngine({ store: memStore(), publisher: pool, signer, retry: { baseMs: 60_000, maxMs: 60_000 }, now: () => now });
    exporter.attachEngine(engine);
    await engine.submit({ template: { kind: 1, content: 'pendiente' } }, { relays: [r.url], wait: true });
    now += 90_000;
    const text = await exporter.render();
    const s = samples(text);
    expect(s.get('nostr_outbox_depth')).toBe(1);
    expect(s.get('nostr_outbox_oldest_pending_age_seconds')).toBe(90);
    expect(text).not.toContain(new URL(r.url).host);
    const failures = [...s].filter(([k]) => k.startsWith('nostr_outbox_relay_failures_total'));
    expect(failures).toHaveLength(1);
    expect(failures[0]![0]).toMatch(/relay="relay-[0-9a-f]{12}",region="unknown",reason="(connection|timeout)"/);
  });

  it('a service-side ACK probe measures latency with empty ephemeral events', async () => {
    const r = await start();
    const exporter = new NostrMetricsExporter({ telemetry: 'standard', defaultRegion: 'stage' });
    pool = new RelayPool({ webSocketFactory: factory, signer });
    exporter.attachPool(pool);
    const stop = startAckProbe({ pool, signer, relays: [r.url], intervalMs: 50 });
    const host = new URL(r.url).host;
    const deadline = Date.now() + 4000;
    while (exporter.ackLatency.count({ relay: host, region: 'stage' }) < 3 && Date.now() < deadline) await new Promise((res) => setTimeout(res, 20));
    stop();
    expect(exporter.ackLatency.count({ relay: host, region: 'stage' })).toBeGreaterThanOrEqual(3);
    // ephemeral: acknowledged but not stored
    expect(await pool.query([r.url], [{ kinds: [20001] }], 1000)).toEqual([]);
  });

  it('classifies publish failures into coarse reason classes', () => {
    expect(classifyFailure('error: timeout waiting for OK')).toBe('timeout');
    expect(classifyFailure('error: connection failed: ws://x')).toBe('connection');
    expect(classifyFailure('error: not connected')).toBe('connection');
    expect(classifyFailure('auth-required: nope')).toBe('auth');
    expect(classifyFailure('rate-limited: slow down')).toBe('rate-limited');
    expect(classifyFailure('invalid: bad sig')).toBe('rejected');
    expect(classifyFailure('error: tor required', true)).toBe('blocked-policy');
    expect(classifyFailure('weird')).toBe('other');
  });
});
