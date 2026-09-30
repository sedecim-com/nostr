import { describe, expect, it } from 'vitest';
import { createServer, request } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { generateSecretKey, getPublicKey, nip49, npubEncode, nsecEncode } from '@sedecim/nostr-core';
import { createLogger, type LogRecord } from '@sedecim/telemetry-policy';
import { createPgPool, HttpError, isOnionHost, Service, tracingFromEnv, type ServiceTracingOptions } from '../src/index';

const b64u = (v: string) => Buffer.from(v).toString('base64url');

/** One of each kind of data that must never reach a trace, made at run time. */
function samples() {
  const sk = generateSecretKey();
  const pubkey = getPublicKey(sk);
  return {
    pubkey,
    npub: npubEncode(pubkey),
    nsec: nsecEncode(sk),
    ncryptsec: nip49.encryptKey(sk, 'una contraseña de prueba', 1),
    ipv4: '198.51.100.23',
    ipv6: '2001:db8::1234:5678',
    bearer: randomBytes(24).toString('base64url'),
    jwt: [b64u(JSON.stringify({ alg: 'RS256', kid: 'k1' })), b64u(JSON.stringify({ sub: pubkey.slice(0, 16), email: 'x' })), randomBytes(32).toString('base64url')].join('.'),
    email: 'periodista@example.net',
    query: `token=${randomBytes(12).toString('hex')}&persona=${pubkey.slice(0, 24)}`,
  };
}

/** Stand-in for the operator's OTLP collector. */
async function collector(mode: 'ok' | 'hang' = 'ok') {
  const bodies: any[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      bodies.push(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      if (mode === 'ok') res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1/traces`;
  const close = () =>
    new Promise<void>((r) => {
      server.closeAllConnections();
      server.close(() => r());
    });
  return { url, bodies, close };
}

/** Raw HTTP so the Host header and any other header can be set. */
function send(base: string, method: string, path: string, headers: Record<string, string> = {}, body?: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const r = request(base + path, { method, headers }, (res) => (res.resume(), res.on('end', () => resolve(res.statusCode!))));
    r.on('error', reject);
    r.end(body);
  });
}

function service(tracing: ServiceTracingOptions | undefined, logs: LogRecord[], secret = '') {
  // Like the service's default logger, with its name on every line.
  const svc = new Service({ name: 'traced-test', logger: createLogger({ base: { service: 'traced-test' }, minimizeIp: true, write: (r) => logs.push(r) }), ...(tracing ? { tracing } : {}) });
  svc.get('/v1/directory/:pubkey', (req) => ({ length: req.params.pubkey!.length }));
  svc.post('/v1/items/:id/fail', () => {
    throw new Error(`failure while handling ${secret}`);
  });
  svc.get('/v1/busy', () => {
    throw new HttpError(503, `busy, try later ${secret}`);
  });
  return svc;
}

const spansOf = (logs: LogRecord[]) => logs.filter((l) => l.msg === 'span');
const otlpSpans = (bodies: any[]) => bodies.flatMap((b) => b.resourceSpans.flatMap((rs: any) => rs.scopeSpans.flatMap((ss: any) => ss.spans)));

describe('a span per request in service-kit (NFR007-02)', () => {
  it('a sampled request gives one server span with the route template, method, status and duration, and nothing sensitive', async () => {
    const s = samples();
    const logs: LogRecord[] = [];
    const otlp = await collector();
    const svc = service({ telemetry: 'standard', sampleRate: 1, exportUrl: otlp.url }, logs, `${s.email} ${s.nsec}`);
    const base = await svc.listen();
    try {
      const headers = { authorization: `Bearer ${s.bearer}`, 'x-forwarded-for': s.ipv4, 'x-real-ip': s.ipv6, cookie: `session=${s.jwt}`, 'user-agent': `client (${s.email})`, 'x-persona': s.npub };
      expect(await send(base, 'GET', `/v1/directory/${s.pubkey}?${s.query}`, headers)).toBe(200);
      expect(await send(base, 'POST', `/v1/items/${s.npub}/fail`, { 'content-type': 'application/json' }, JSON.stringify({ nsec: s.nsec, ncryptsec: s.ncryptsec, email: s.email }))).toBe(500);
      expect(await send(base, 'GET', '/v1/busy')).toBe(503);
      expect(await send(base, 'GET', `/nowhere/${s.pubkey}`)).toBe(404);
      expect(await send(base, 'OPTIONS', `/v1/directory/${s.pubkey}`, { origin: 'https://elsewhere.example' })).toBe(403);
      await svc.tracer.flush();

      const spans = spansOf(logs);
      expect(spans.map((x) => [x.span_name, x['http.route'], x['http.request.method'], x['http.response.status_code'], x.span_status, x['error.type']])).toEqual([
        ['GET /v1/directory/:pubkey', '/v1/directory/:pubkey', 'GET', 200, 'unset', undefined],
        ['POST /v1/items/:id/fail', '/v1/items/:id/fail', 'POST', 500, 'error', 'Error'],
        ['GET /v1/busy', '/v1/busy', 'GET', 503, 'error', 'HttpError'],
        ['GET', undefined, 'GET', 404, 'unset', undefined],
        ['OPTIONS', undefined, 'OPTIONS', 403, 'unset', undefined],
      ]);
      for (const x of spans) {
        expect(x).toMatchObject({ level: 'info', service: 'traced-test', span_kind: 'server', trace_id: expect.stringMatching(/^[0-9a-f]{32}$/), span_id: expect.stringMatching(/^[0-9a-f]{16}$/) });
        expect(x.duration_ms).toBeGreaterThanOrEqual(0);
        expect(x.parent_span_id).toBeUndefined();
      }
      const exported = otlpSpans(otlp.bodies);
      expect(exported.map((x) => x.name)).toEqual(spans.map((x) => x.span_name));
      expect(otlp.bodies[0].resourceSpans[0].resource.attributes).toEqual([{ key: 'service.name', value: { stringValue: 'traced-test' } }]);
      const outputs = JSON.stringify({ spans, otlp: otlp.bodies });
      for (const [kind, value] of Object.entries(s)) expect(outputs, kind).not.toContain(value);
    } finally {
      await svc.close();
      await otlp.close();
    }
  });

  it('traces nothing at a sample rate of 0, nor without tracing options', async () => {
    const otlp = await collector();
    for (const tracing of [{ telemetry: 'standard' as const, sampleRate: 0, exportUrl: otlp.url }, undefined]) {
      const logs: LogRecord[] = [];
      const svc = service(tracing, logs);
      const base = await svc.listen();
      for (let i = 0; i < 20; i++) expect(await send(base, 'GET', `/v1/directory/p${i}`)).toBe(200);
      await svc.close();
      expect(svc.tracer.enabled).toBe(false);
      expect(spansOf(logs)).toEqual([]);
    }
    await otlp.close();
    expect(otlp.bodies).toEqual([]);
  });

  it('never traces a request addressed to a .onion host, even at a sample rate of 1', async () => {
    const logs: LogRecord[] = [];
    const svc = service({ telemetry: 'standard', sampleRate: 1 }, logs);
    const base = await svc.listen();
    const onion = `${'a2z'.repeat(18)}ab.onion`;
    try {
      expect(await send(base, 'GET', '/v1/directory/x', { host: onion })).toBe(200);
      expect(await send(base, 'GET', '/v1/directory/x', { host: `${onion}:8088` })).toBe(200);
      expect(spansOf(logs)).toEqual([]);
      expect(await send(base, 'GET', '/v1/directory/x', { host: 'vault.example.org' })).toBe(200);
      expect(spansOf(logs)).toHaveLength(1);
    } finally {
      await svc.close();
    }
    expect([isOnionHost(onion), isOnionHost('ABC.ONION.'), isOnionHost('abc.onion:80')]).toEqual([true, true, true]);
    expect([isOnionHost('onion.example.org'), isOnionHost('example.org'), isOnionHost(undefined)]).toEqual([false, false, false]);
  });

  it('the request is never held back by the collector, down or hanging, and the drop is logged without its address', async () => {
    const down = await collector();
    await down.close();
    const logs: LogRecord[] = [];
    const svc = service({ telemetry: 'standard', sampleRate: 1, exportUrl: down.url }, logs);
    const base = await svc.listen();
    expect(await send(base, 'GET', '/v1/directory/x')).toBe(200);
    await svc.close(); // flushes
    expect(spansOf(logs)).toHaveLength(1);
    const warned = logs.filter((l) => l.msg === 'trace export dropped spans');
    expect(warned).toEqual([expect.objectContaining({ level: 'warn', reason: 'send-failed', spans: 1 })]);
    expect(JSON.stringify(warned)).not.toMatch(/127\.0\.0\.1|v1\/traces|http/);

    const hanging = await collector('hang');
    const logs2: LogRecord[] = [];
    const svc2 = service({ telemetry: 'standard', sampleRate: 1, exportUrl: hanging.url }, logs2);
    const base2 = await svc2.listen();
    expect(await send(base2, 'GET', '/v1/directory/first')).toBe(200);
    const sending = svc2.tracer.flush(); // a request to the collector that will not be answered
    await new Promise((r) => setTimeout(r, 50));
    expect(hanging.bodies).toHaveLength(1);
    const t0 = Date.now();
    for (let i = 0; i < 20; i++) expect(await send(base2, 'GET', `/v1/directory/p${i}`)).toBe(200);
    expect(Date.now() - t0).toBeLessThan(2000);
    await hanging.close(); // the pending export fails now
    await sending;
    await svc2.close();
    expect(spansOf(logs2)).toHaveLength(21);
  });
});

describe('tracing configuration from the environment (NFR007-02)', () => {
  it('at TELEMETRY_LEVEL=none no variable turns tracing on, and the service traces nothing', async () => {
    const otlp = await collector();
    const env = { TELEMETRY_LEVEL: 'none', TRACE_SAMPLE_RATE: '1', TRACE_EXPORT_URL: otlp.url };
    expect(tracingFromEnv(env)).toEqual({ telemetry: 'none', sampleRate: 0 });
    expect(tracingFromEnv({ TELEMETRY_LEVEL: 'none', TRACE_SAMPLE_RATE: 'x', TRACE_EXPORT_URL: 'ftp://nowhere' })).toEqual({ telemetry: 'none', sampleRate: 0 });
    // Nor the raw values handed to the service: the policy refuses them.
    for (const tracing of [tracingFromEnv(env), { telemetry: 'none' as const, sampleRate: 1, exportUrl: otlp.url }]) {
      const logs: LogRecord[] = [];
      const svc = service(tracing, logs);
      const base = await svc.listen();
      for (let i = 0; i < 10; i++) expect(await send(base, 'GET', `/v1/directory/p${i}`)).toBe(200);
      await svc.close();
      expect(svc.tracer.enabled).toBe(false);
      expect(spansOf(logs)).toEqual([]);
    }
    await otlp.close();
    expect(otlp.bodies).toEqual([]);
  });

  it('reads TELEMETRY_LEVEL, TRACE_SAMPLE_RATE and TRACE_EXPORT_URL with safe defaults and refuses bad values', () => {
    expect(tracingFromEnv({})).toEqual({ telemetry: 'standard', sampleRate: 0 });
    expect(tracingFromEnv({ TRACE_SAMPLE_RATE: '0.25', TRACE_EXPORT_URL: 'http://otel-collector:4318/v1/traces' })).toEqual({ telemetry: 'standard', sampleRate: 0.25, exportUrl: 'http://otel-collector:4318/v1/traces' });
    const minimal = tracingFromEnv({ TELEMETRY_LEVEL: 'minimal', TRACE_SAMPLE_RATE: '1' });
    expect(minimal).toEqual({ telemetry: 'minimal', sampleRate: 1 });
    expect(new Service({ name: 'minimal-test', tracing: minimal }).tracer.enabled).toBe(false);
    for (const TRACE_SAMPLE_RATE of ['2', '-0.1', 'abc', 'NaN']) expect(() => tracingFromEnv({ TRACE_SAMPLE_RATE })).toThrow(/TRACE_SAMPLE_RATE/);
    expect(() => tracingFromEnv({ TELEMETRY_LEVEL: 'loud' })).toThrow(/TELEMETRY_LEVEL/);
    for (const TRACE_EXPORT_URL of ['ftp://otel/v1/traces', 'not a url', 'http://user:pw@otel/v1/traces']) expect(() => tracingFromEnv({ TRACE_SAMPLE_RATE: '1', TRACE_EXPORT_URL })).toThrow(/TRACE_EXPORT_URL/);
  });
});

describe.skipIf(!process.env.TEST_DATABASE_URL)('database queries as child spans (NFR007-02)', () => {
  it('a query inside a sampled request is a child span that only names the operation; outside a trace nothing changes', async () => {
    const s = samples();
    const pool = createPgPool(process.env.TEST_DATABASE_URL!);
    const logs: LogRecord[] = [];
    const svc = new Service({ name: 'db-traced', logger: createLogger({ write: (r) => logs.push(r) }), tracing: { telemetry: 'standard', sampleRate: 1 } });
    svc.get('/v1/lookup/:pubkey', async (req) => {
      const { rows } = await pool.query<{ v: string }>('SELECT $1::text AS v', [req.params.pubkey]);
      await pool.query({ text: `with t as (select $1::text as e) select e from t`, values: [s.email] });
      return { same: rows[0]!.v === req.params.pubkey };
    });
    const base = await svc.listen();
    try {
      expect(await send(base, 'GET', `/v1/lookup/${s.pubkey}`)).toBe(200);
      const [q1, q2, server] = spansOf(logs);
      expect(server).toMatchObject({ span_name: 'GET /v1/lookup/:pubkey', span_kind: 'server' });
      for (const [q, op] of [
        [q1, 'SELECT'],
        [q2, 'WITH'],
      ] as const) {
        expect(q).toMatchObject({ span_name: 'db.query', span_kind: 'client', trace_id: server!.trace_id, parent_span_id: server!.span_id, 'db.system': 'postgresql', 'db.operation.name': op });
      }
      expect(JSON.stringify(logs)).not.toContain(s.pubkey);
      expect(JSON.stringify(logs)).not.toContain(s.email);
      // Outside a trace: the same pool, promise and callback styles, no span.
      expect((await pool.query<{ two: number }>('SELECT 2 AS two')).rows[0]!.two).toBe(2);
      const three = await new Promise<number>((resolve, reject) => pool.query<{ three: number }>('SELECT 3 AS three', (err, res) => (err ? reject(err) : resolve(res.rows[0]!.three))));
      expect(three).toBe(3);
      expect(spansOf(logs)).toHaveLength(3);
    } finally {
      await svc.close();
      await pool.end();
    }
  });
});
