import { describe, expect, it } from 'vitest';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import fc from 'fast-check';
import {
  activeSpan,
  createLogger,
  createTracer,
  inChildSpan,
  isRouteTemplate,
  logSpanExporter,
  NOOP_TRACER,
  OtlpHttpExporter,
  safeSpanName,
  SPAN_ATTRIBUTE_KEYS,
  TelemetryBlockedError,
  TelemetryPolicy,
  type FinishedSpan,
  type LogRecord,
  type SpanExporter,
  type TelemetryLevel,
  type TracerOptions,
} from '../src/index';

/** Deterministic draws (mulberry32) for the sampling tests. */
function seeded(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function tracerWith(rate: number, extra: Partial<TracerOptions> = {}, level: TelemetryLevel = 'standard') {
  const spans: FinishedSpan[] = [];
  const memory: SpanExporter = { export: (s) => void spans.push(s) };
  const tracer = createTracer({ ...extra, policy: new TelemetryPolicy({ level, traceSampleRate: rate }), exporters: [memory, ...(extra.exporters ?? [])] });
  return { tracer, spans };
}

const BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const bech32Like = (hrp: string, n: number) => `${hrp}1${Array.from(randomBytes(n), (b) => BECH32[b % 32]).join('')}`;
const b64u = (v: string) => Buffer.from(v).toString('base64url');

/** One of each kind of data that must never reach a trace, made at run time (none is a real credential). */
function samples() {
  const pubkey = randomBytes(32).toString('hex');
  return {
    pubkey,
    npub: bech32Like('npub', 58),
    nsec: bech32Like('nsec', 58),
    ncryptsec: bech32Like('ncryptsec', 152),
    ipv4: '203.0.113.47',
    ipv6: '2001:db8:85a3::8a2e:370:7334',
    bearer: randomBytes(24).toString('base64url'),
    jwt: [b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT' })), b64u(JSON.stringify({ sub: pubkey.slice(0, 16) })), randomBytes(32).toString('base64url')].join('.'),
    email: 'fuente.reservada@example.org',
    query: `?token=${randomBytes(12).toString('hex')}&persona=${pubkey.slice(0, 20)}`,
  };
}

/** Stand-in for an OTLP collector: records every request; `mode` decides the answer. */
async function collector(mode: 'ok' | 'hang' | 'fail' | { redirect: string } = 'ok') {
  const requests: Array<{ method: string; path: string; contentType: string | undefined; body: any }> = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      requests.push({ method: req.method!, path: req.url!, contentType: req.headers['content-type'], body: JSON.parse(Buffer.concat(chunks).toString('utf8') || 'null') });
      if (mode === 'hang') return;
      if (mode === 'fail') return void res.writeHead(500).end();
      if (typeof mode === 'object') return void res.writeHead(307, { location: mode.redirect }).end();
      res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1/traces`;
  const close = () =>
    new Promise<void>((r) => {
      server.closeAllConnections();
      server.close(() => r());
    });
  return { url, requests, close };
}

const finished = (n: number): FinishedSpan[] =>
  Array.from({ length: n }, (_, i) => ({ traceId: `${'a'.repeat(31)}${i % 10}`, spanId: `${'b'.repeat(15)}${i % 10}`, name: 'db.query', kind: 'client' as const, startMs: 1_000, endMs: 1_002, status: 'unset' as const, attributes: {} }));

describe('trace sampling, decided once at the root (NFR007-02)', () => {
  it('rate 0 records nothing and draws neither samples nor ids', () => {
    let draws = 0;
    let ids = 0;
    const { tracer, spans } = tracerWith(0, { random: () => (draws++, 0), randomId: (n) => (ids++, '1'.repeat(n * 2)) });
    expect(tracer).toBe(NOOP_TRACER);
    expect(tracer.enabled).toBe(false);
    for (let i = 0; i < 1000; i++) tracer.withSpan('job.run', () => tracer.startSpan('db.query').end());
    expect(spans).toEqual([]);
    expect([draws, ids]).toEqual([0, 0]);
  });

  it('rate 1 records every trace, each with its own id', () => {
    const { tracer, spans } = tracerWith(1);
    for (let i = 0; i < 1000; i++) tracer.withSpan('job.run', () => tracer.startSpan('db.query').end());
    expect(spans).toHaveLength(2000);
    expect(new Set(spans.map((s) => s.traceId)).size).toBe(1000);
  });

  it.each([0.2, 0.5, 0.9])('rate %s records that fraction of traces, within tolerance, with one draw per trace', (rate) => {
    let draws = 0;
    const next = seeded(Math.round(rate * 1000));
    const { tracer, spans } = tracerWith(rate, { random: () => (draws++, next()) });
    const roots = 20_000;
    for (let i = 0; i < roots; i++) tracer.withSpan('job.run', () => inChildSpan('db.query', () => undefined));
    const traces = new Set(spans.map((s) => s.traceId)).size;
    expect(draws).toBe(roots); // children never draw
    expect(Math.abs(traces / roots - rate)).toBeLessThan(0.015);
    expect(spans).toHaveLength(traces * 2); // a sampled trace keeps all its spans
  });

  it('children inherit the decision of their root, across awaits and timers, and never draw again', async () => {
    const seq = [0.1, 0.9]; // at rate 0.5: sampled, then not sampled
    let draws = 0;
    const { tracer, spans } = tracerWith(0.5, { random: () => seq[draws++ % 2]! });
    await tracer.withSpan('job.sampled', async (root) => {
      expect(root.recording).toBe(true);
      await new Promise((r) => setTimeout(r, 1));
      tracer.startSpan('job.child').end();
      await tracer.withSpan('job.nested', async () => {
        await Promise.resolve();
        inChildSpan('db.query', (s) => expect(s.recording).toBe(true));
      });
    });
    await tracer.withSpan('job.unsampled', async (root) => {
      expect(root.recording).toBe(false);
      expect([root.traceId, root.spanId]).toEqual([undefined, undefined]);
      await new Promise((r) => setTimeout(r, 1));
      const child = tracer.startSpan('job.child'); // not a new root
      expect(child.recording).toBe(false);
      child.end();
      tracer.withSpan('job.nested', (s) => expect(s.recording).toBe(false));
      inChildSpan('db.query', (s) => expect(s.recording).toBe(false));
      expect(activeSpan()).toBeUndefined();
    });
    expect(draws).toBe(2);
    const by = Object.fromEntries(spans.map((s) => [s.name, s]));
    expect(Object.keys(by).sort()).toEqual(['db.query', 'job.child', 'job.nested', 'job.sampled']);
    expect(new Set(spans.map((s) => s.traceId)).size).toBe(1);
    expect(by['job.sampled']!.parentSpanId).toBeUndefined();
    expect(by['job.child']!.parentSpanId).toBe(by['job.sampled']!.spanId);
    expect(by['job.nested']!.parentSpanId).toBe(by['job.sampled']!.spanId);
    expect(by['db.query']!.parentSpanId).toBe(by['job.nested']!.spanId);
  });

  it('keeps concurrent traces apart (AsyncLocalStorage)', async () => {
    const { tracer, spans } = tracerWith(1);
    const run = (name: string, delay: number) =>
      tracer.withSpan(name, async (root) => {
        for (let i = 0; i < 3; i++) {
          await new Promise((r) => setTimeout(r, delay));
          inChildSpan('db.query', (c) => expect(c.traceId).toBe(root.traceId));
        }
        return root.traceId;
      });
    const [a, b] = await Promise.all([run('job.a', 1), run('job.b', 2)]);
    expect(a).not.toBe(b);
    for (const s of spans.filter((x) => x.name === 'db.query')) expect([a, b]).toContain(s.traceId);
    expect(spans.filter((s) => s.traceId === a)).toHaveLength(4);
  });

  it('draws ids from the CSPRNG: 32 and 16 hex characters, unique, never all zeros', () => {
    const { tracer, spans } = tracerWith(1);
    for (let i = 0; i < 500; i++) tracer.withSpan('job.run', () => tracer.startSpan('db.query').end());
    for (const s of spans) {
      expect(s.traceId).toMatch(/^[0-9a-f]{32}$/);
      expect(s.spanId).toMatch(/^[0-9a-f]{16}$/);
    }
    expect(new Set(spans.map((s) => s.spanId)).size).toBe(spans.length);
    const ids = ['0'.repeat(32), 'c'.repeat(32), '0'.repeat(16), 'd'.repeat(16)];
    const zeros = tracerWith(1, { randomId: () => ids.shift()! });
    zeros.tracer.startSpan('job.run').end();
    expect(zeros.spans[0]).toMatchObject({ traceId: 'c'.repeat(32), spanId: 'd'.repeat(16) });
  });

  it('a span that already ended adopts nothing: later work is not attached to it', async () => {
    let draws = 0;
    const { tracer, spans } = tracerWith(1, { random: () => (draws++, 0) });
    let late!: Promise<void>;
    tracer.withSpan('http.server', () => {
      late = new Promise<void>((r) =>
        setTimeout(() => {
          expect(activeSpan()).toBeUndefined();
          inChildSpan('db.query', (s) => expect(s.recording).toBe(false));
          tracer.startSpan('job.run').end(); // a root of its own: sampled again
          r();
        }, 5),
      );
    });
    await late;
    expect(draws).toBe(2);
    expect(spans.map((s) => [s.name, s.parentSpanId])).toEqual([
      ['http.server', undefined],
      ['job.run', undefined],
    ]);
  });
});

describe('redaction by construction (NFR007-02)', () => {
  it('lets no sensitive value through attributes, span names or errors, in any output', async () => {
    const s = samples();
    const logs: LogRecord[] = [];
    const otlp = await collector();
    const policy = new TelemetryPolicy({ level: 'standard', traceSampleRate: 1, endpoints: [otlp.url] });
    const exporter = new OtlpHttpExporter({ url: otlp.url, policy, serviceName: 'redaction-test' });
    const { tracer, spans } = tracerWith(1, { exporters: [logSpanExporter(createLogger({ write: (r) => logs.push(r) })), exporter] });
    try {
      // Unknown keys, and allowlisted keys with values that are not theirs.
      tracer.withSpan(`GET /v1/directory/${s.pubkey}`, (span) => {
        span.setAttributes({ 'enduser.id': s.npub, 'client.address': s.ipv4, 'network.peer.address': s.ipv6, 'url.full': `https://api.example/v1/x${s.query}`, 'http.request.header.authorization': `Bearer ${s.bearer}`, 'user.email': s.email, secret: s.nsec } as never);
        span.setAttributes({
          'http.route': `/v1/directory/${s.pubkey}`,
          'http.request.method': `Bearer ${s.bearer}`,
          'error.type': s.jwt,
          'db.operation.name': `SELECT * FROM personas WHERE email = '${s.email}'`,
          'db.system': s.ipv6,
          'http.response.status_code': s.ipv4 as never,
        });
      });
      for (const route of [`/v1/keys/${s.npub}`, `/v1/x${s.query}`, `/v1/users/${s.email}`, `/v1/ip/${s.ipv4}`, `/v1/ip/x${s.ipv4}`, `/v1/${s.ipv6}`, `/v1/sessions/${s.bearer}`, `/v1/t/${s.jwt}`, `/v1/keys/${s.ncryptsec}`]) {
        tracer.withSpan(`GET ${route}`, (span) => span.setAttribute('http.route', route));
      }
      // Names.
      for (const name of Object.values(s)) tracer.startSpan(name).end();
      tracer.withSpan('job.run', (span) => span.updateName(`login ${s.email}`));
      // Errors: the message never, the class only when it is a plain class name.
      class LeakyError extends Error {}
      Object.defineProperty(LeakyError, 'name', { value: s.nsec });
      tracer.withSpan('job.run', (span) => span.recordError(new Error(`token ${s.bearer} of ${s.npub} from ${s.ipv4} (${s.email})`)));
      tracer.withSpan('job.run', (span) => span.recordError(new LeakyError(s.jwt)));
      tracer.withSpan('job.run', (span) => span.recordError(s.jwt));
      await expect(
        tracer.withSpan('job.run', async () => {
          throw new Error(`${s.ncryptsec} ${s.query}`);
        }),
      ).rejects.toThrow();
      // What is allowed still gets through.
      tracer.withSpan('GET /v1/keys/:id', (span) => span.setAttributes({ 'http.request.method': 'GET', 'http.route': '/v1/keys/:id', 'http.response.status_code': 404 }));
      await tracer.flush();

      const outputs = JSON.stringify({ spans, logs, otlp: otlp.requests.map((r) => r.body) });
      for (const [kind, value] of Object.entries(s)) expect(outputs, kind).not.toContain(value);
      expect(logs.filter((l) => l.msg === 'span')).toHaveLength(spans.length);
      expect(exporter.stats).toMatchObject({ exported: spans.length, failed: 0, dropped: 0 });
      for (const span of spans) {
        for (const key of Object.keys(span.attributes)) expect(SPAN_ATTRIBUTE_KEYS).toContain(key);
        expect(['span', 'job.run', 'GET /v1/keys/:id']).toContain(span.name);
      }
      expect(spans[0]!.attributes).toEqual({ 'http.request.method': '_OTHER', 'error.type': '_OTHER', 'db.operation.name': '_OTHER' });
      expect(spans.filter((x) => x.status === 'error').map((x) => x.attributes['error.type'])).toEqual(['Error', '_OTHER', '_OTHER', 'Error']);
      expect(spans.at(-1)).toMatchObject({ name: 'GET /v1/keys/:id', attributes: { 'http.request.method': 'GET', 'http.route': '/v1/keys/:id', 'http.response.status_code': 404 } });
      expect(logs.at(-1)).toMatchObject({ msg: 'span', span_name: 'GET /v1/keys/:id', 'http.route': '/v1/keys/:id', 'http.response.status_code': 404 });
    } finally {
      await exporter.shutdown();
      await otlp.close();
    }
  });

  it('accepts the route templates of the services and refuses paths that carry values', () => {
    for (const t of ['/', '/health', '/v1/keys/:id/nip44/encrypt', '/v1/accounts/me/external-logins', '/v1/retention/:resourceId', '/v1/channels/:h/summary', '/v1/keys/import/']) expect(isRouteTemplate(t), t).toBe(true);
    const s = samples();
    for (const p of [`/v1/directory/${s.pubkey}`, `/v1/keys/${s.npub}`, '/v1/x?token=abc', `/v1/users/${s.email}`, '/v1/ip/203.0.113.47', '/v1/ip/x203.0.113.47', `/v1/${s.ipv6}`, '/v1/keys/12345', '/v1/keys/deadbeef00', `/v1/sessions/${s.bearer}`, `/v1/t/${s.jwt}`, 'v1/keys', '//v1', '/v1/%20', '/v1/Keys']) {
      expect(isRouteTemplate(p), p).toBe(false);
    }
  });

  it('property: whatever the keys, values and names, a span keeps only the allowlist and its grammar (fuzz)', () => {
    const key = fc.oneof(fc.constantFrom(...SPAN_ATTRIBUTE_KEYS), fc.string());
    const value = fc.oneof(fc.string(), fc.integer({ min: -1000, max: 1000 }), fc.anything());
    fc.assert(
      fc.property(key, value, fc.string(), (k, v, name) => {
        const { tracer, spans } = tracerWith(1);
        tracer.withSpan(name, (span) => {
          span.setAttribute(k as never, v as never);
          span.setAttributes({ [k]: v } as never);
          span.updateName(`GET ${name}`);
        });
        const out = spans[0]!;
        expect(out.name).toBe(safeSpanName(`GET ${name}`));
        expect(out.name === 'span' || /^[A-Z]{3,7}( \/\S*)?$/.test(out.name)).toBe(true);
        const rules: Record<string, (x: unknown) => boolean> = {
          'http.request.method': (x) => ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', '_OTHER'].includes(x as string),
          'http.route': (x) => isRouteTemplate(x),
          'http.response.status_code': (x) => Number.isInteger(x) && (x as number) >= 100 && (x as number) <= 599,
          'error.type': (x) => /^(?:[1-5]\d\d|(?:[A-Z][a-z]{1,14})+|_OTHER)$/.test(x as string),
          'db.system': (x) => x === 'postgresql',
          'db.operation.name': (x) => /^(?:[A-Z]+|_OTHER)$/.test(x as string),
        };
        for (const [ak, av] of Object.entries(out.attributes)) {
          expect(SPAN_ATTRIBUTE_KEYS).toContain(ak);
          expect(rules[ak]!(av), `${ak}=${String(av)}`).toBe(true);
        }
      }),
      { numRuns: 400 },
    );
  });

  it('property: a value that embeds sensitive data never survives, as attribute, name or error (fuzz)', () => {
    const s = samples();
    fc.assert(
      fc.property(fc.string(), fc.constantFrom(...Object.values(s)), fc.string(), fc.constantFrom(...SPAN_ATTRIBUTE_KEYS), (a, secret, b, k) => {
        const v = a + secret + b;
        const { tracer, spans } = tracerWith(1);
        class Named extends Error {}
        Object.defineProperty(Named, 'name', { value: v });
        tracer.withSpan(v, (span) => span.setAttribute(k, v as never).recordError(new Named(v)));
        tracer.withSpan(`GET /${v}`, (span) => span.setAttribute('http.route', `/${v}`).setAttribute(k, `/${v}` as never));
        tracer.withSpan('job.run', (span) => span.updateName(`${a}.${secret}`).setAttribute('error.type', `${a}${secret}Error`));
        expect(JSON.stringify(spans)).not.toContain(secret);
      }),
      { numRuns: 400 },
    );
  });
});

describe('off at telemetry levels none and minimal (NFR007-02)', () => {
  it('at none: no span, no id, no context and no export, whatever the sample rate and endpoints say', async () => {
    const exported: FinishedSpan[] = [];
    let draws = 0;
    let ids = 0;
    const url = 'http://127.0.0.1:9/v1/traces';
    const policy = new TelemetryPolicy({ level: 'none', traceSampleRate: 1, endpoints: [url] });
    const tracer = createTracer({ policy, exporters: [{ export: (s) => void exported.push(s) }], random: () => (draws++, 0), randomId: (n) => (ids++, 'ab'.repeat(n)) });
    expect(tracer).toBe(NOOP_TRACER);
    const span = tracer.startSpan('GET /v1/keys/:id', { attributes: { 'http.route': '/v1/keys/:id' } });
    expect([span.recording, span.traceId, span.spanId]).toEqual([false, undefined, undefined]);
    span.setAttribute('http.response.status_code', 200).recordError(new Error('x')).end();
    await tracer.withSpan('http.server', async () => {
      expect(activeSpan()).toBeUndefined();
      inChildSpan('db.query', (c) => expect(c.recording).toBe(false));
    });
    await tracer.flush();
    expect(exported).toEqual([]);
    expect([draws, ids]).toEqual([0, 0]);
    expect(policy.tracingEnabled()).toBe(false);
    expect(policy.shouldTrace(() => 0)).toBe(false);
    expect(() => new OtlpHttpExporter({ url, policy, serviceName: 'tor-service' })).toThrow(TelemetryBlockedError);
  });

  it('at minimal no trace either; at standard the default rate is 0', () => {
    expect(tracerWith(1, {}, 'minimal').tracer).toBe(NOOP_TRACER);
    expect(new TelemetryPolicy({ level: 'standard' }).shouldTrace(() => 0)).toBe(false);
    expect(createTracer({ policy: new TelemetryPolicy({ level: 'standard' }) })).toBe(NOOP_TRACER);
    expect(() => tracerWith(1.5)).toThrow(RangeError);
    expect(() => tracerWith(Number.NaN)).toThrow(RangeError);
  });

  it('the OTLP exporter only goes to the endpoint the operator listed, over http(s), without credentials', () => {
    const url = 'http://otel-collector:4318/v1/traces';
    const policy = new TelemetryPolicy({ level: 'standard', traceSampleRate: 1, endpoints: [url] });
    expect(() => new OtlpHttpExporter({ url, policy, serviceName: 'x' })).not.toThrow();
    expect(() => new OtlpHttpExporter({ url: 'http://telemetry.example/v1/traces', policy, serviceName: 'x' })).toThrow(TelemetryBlockedError);
    expect(() => new OtlpHttpExporter({ url: 'http://otel-collector.example:4318/v1/traces', policy, serviceName: 'x' })).toThrow(TelemetryBlockedError);
    expect(() => new OtlpHttpExporter({ url: 'http://otel-collector:4318/v1/traces-elsewhere', policy, serviceName: 'x' })).toThrow(TelemetryBlockedError);
    const odd = new TelemetryPolicy({ level: 'standard', traceSampleRate: 1, endpoints: ['ftp://c/v1/traces', 'http://u:p@c/v1/traces'] });
    expect(() => new OtlpHttpExporter({ url: 'ftp://c/v1/traces', policy: odd, serviceName: 'x' })).toThrow(/http or https/);
    expect(() => new OtlpHttpExporter({ url: 'http://u:p@c/v1/traces', policy: odd, serviceName: 'x' })).toThrow(/credentials/);
  });
});

describe('OTLP/HTTP JSON exporter (NFR007-02)', () => {
  it('posts an ExportTraceServiceRequest: resource, ids, kinds, times in nanoseconds, typed attributes and status', async () => {
    const otlp = await collector();
    const policy = new TelemetryPolicy({ level: 'standard', traceSampleRate: 1, endpoints: [otlp.url] });
    const exporter = new OtlpHttpExporter({ url: otlp.url, policy, serviceName: 'identity-service' });
    let t = 1_700_000_000_000;
    const ids = ['1'.repeat(32), '2'.repeat(16), '3'.repeat(16)];
    const { tracer } = tracerWith(1, { exporters: [exporter], now: () => (t += 1.5), randomId: () => ids.shift()! });
    await tracer.withSpan('GET /v1/keys/:id', async (span) => {
      span.setAttributes({ 'http.request.method': 'GET', 'http.route': '/v1/keys/:id', 'http.response.status_code': 503 }).recordError(new TypeError('boom'));
      await inChildSpan('db.query', async () => undefined, { kind: 'client', attributes: { 'db.system': 'postgresql', 'db.operation.name': 'SELECT' } });
    }, { kind: 'server' });
    await exporter.flush();
    await otlp.close();
    expect(otlp.requests).toHaveLength(1);
    const [req] = otlp.requests;
    expect(req).toMatchObject({ method: 'POST', path: '/v1/traces', contentType: 'application/json' });
    const [rs] = req!.body.resourceSpans;
    expect(rs.resource.attributes).toEqual([{ key: 'service.name', value: { stringValue: 'identity-service' } }]);
    const [child, root] = rs.scopeSpans[0].spans;
    expect(root).toEqual({
      traceId: '1'.repeat(32),
      spanId: '2'.repeat(16),
      name: 'GET /v1/keys/:id',
      kind: 2,
      startTimeUnixNano: '1700000000001500000',
      endTimeUnixNano: '1700000000006000000',
      attributes: [
        { key: 'http.request.method', value: { stringValue: 'GET' } },
        { key: 'http.route', value: { stringValue: '/v1/keys/:id' } },
        { key: 'http.response.status_code', value: { intValue: '503' } },
        { key: 'error.type', value: { stringValue: 'TypeError' } },
      ],
      status: { code: 2 },
    });
    expect(child).toMatchObject({ traceId: '1'.repeat(32), spanId: '3'.repeat(16), parentSpanId: '2'.repeat(16), name: 'db.query', kind: 3, status: { code: 0 } });
    expect(exporter.stats).toEqual({ exported: 2, dropped: 0, failed: 0 });
  });

  it('keeps at most maxQueueSize spans waiting and counts the ones it drops', async () => {
    const otlp = await collector();
    const drops: Array<[string, number]> = [];
    const policy = new TelemetryPolicy({ level: 'standard', traceSampleRate: 1, endpoints: [otlp.url] });
    const exporter = new OtlpHttpExporter({ url: otlp.url, policy, serviceName: 'queue-test', maxQueueSize: 3, maxBatchSize: 100, flushIntervalMs: 60_000, onDrop: (r, n) => drops.push([r, n]) });
    for (const s of finished(5)) exporter.export(s);
    expect(exporter.stats.dropped).toBe(2);
    await exporter.flush();
    await otlp.close();
    expect(otlp.requests.map((r) => r.body.resourceSpans[0].scopeSpans[0].spans.length)).toEqual([3]);
    expect(exporter.stats).toEqual({ exported: 3, dropped: 2, failed: 0 });
    expect(drops).toEqual([['queue-full', 2]]);
  });

  it('gives up on a request after its timeout, drops the batch and never retries it', async () => {
    const otlp = await collector('hang');
    const drops: Array<[string, number]> = [];
    const policy = new TelemetryPolicy({ level: 'standard', traceSampleRate: 1, endpoints: [otlp.url] });
    const exporter = new OtlpHttpExporter({ url: otlp.url, policy, serviceName: 'timeout-test', timeoutMs: 200, onDrop: (r, n) => drops.push([r, n]) });
    for (const s of finished(2)) exporter.export(s);
    const t0 = Date.now();
    await exporter.flush();
    const elapsed = Date.now() - t0;
    await new Promise((r) => setTimeout(r, 300));
    await otlp.close();
    expect(elapsed).toBeGreaterThanOrEqual(150);
    expect(elapsed).toBeLessThan(3000);
    expect(otlp.requests).toHaveLength(1);
    expect(exporter.stats).toEqual({ exported: 0, dropped: 0, failed: 2 });
    expect(drops).toEqual([['send-failed', 2]]);
  });

  it('a collector that is down or answers an error costs the batch: no exception, no retry', async () => {
    const down = await collector();
    await down.close();
    const failing = await collector('fail');
    for (const url of [down.url, failing.url]) {
      const policy = new TelemetryPolicy({ level: 'standard', traceSampleRate: 1, endpoints: [url] });
      // Even a reporter that throws cannot turn the background send into a rejection.
      const onDrop = () => {
        throw new Error('reporter failed');
      };
      const exporter = new OtlpHttpExporter({ url, policy, serviceName: 'down-test', timeoutMs: 1000, onDrop });
      exporter.export(finished(1)[0]!);
      await expect(exporter.flush()).resolves.toBeUndefined();
      expect(exporter.stats).toEqual({ exported: 0, dropped: 0, failed: 1 });
    }
    await new Promise((r) => setTimeout(r, 100));
    await failing.close();
    expect(failing.requests).toHaveLength(1);
  });

  it('does not follow a redirect away from the listed endpoint', async () => {
    const elsewhere = await collector();
    const redirector = await collector({ redirect: elsewhere.url });
    const policy = new TelemetryPolicy({ level: 'standard', traceSampleRate: 1, endpoints: [redirector.url] });
    const exporter = new OtlpHttpExporter({ url: redirector.url, policy, serviceName: 'redirect-test', timeoutMs: 1000 });
    exporter.export(finished(1)[0]!);
    await exporter.flush();
    await Promise.all([elsewhere.close(), redirector.close()]);
    expect(redirector.requests).toHaveLength(1);
    expect(elsewhere.requests).toHaveLength(0);
    expect(exporter.stats.failed).toBe(1);
  });
});

describe('clients never trace (NFR007-02)', () => {
  it('no client source builds a tracer, an OTLP exporter or trace context', () => {
    const root = new URL('../../..', import.meta.url).pathname;
    const sources = (dir: string): string[] =>
      readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? sources(join(dir, e.name)) : /\.(tsx?|mjs|js|html)$/.test(e.name) ? [join(dir, e.name)] : []));
    const apps = readdirSync(join(root, 'apps')).filter((a) => a !== 'node_modules');
    expect(apps).toEqual(expect.arrayContaining(['web-saas', 'sovereign-client', 'admin-console', 'key-generator']));
    const offenders = apps
      .flatMap((a) => sources(join(root, 'apps', a, 'src')))
      .filter((f) => /createTracer|OtlpHttpExporter|logSpanExporter|withSpan|inChildSpan|traceparent|\/v1\/traces|TRACE_(SAMPLE_RATE|EXPORT_URL)/.test(readFileSync(f, 'utf8')));
    expect(offenders).toEqual([]);
    // The CLI's telemetry policy is 'none': nothing it could build would trace.
    expect(readFileSync(join(root, 'apps/sovereign-client/src/app.ts'), 'utf8')).toContain("new TelemetryPolicy({ level: 'none' })");
  });
});
