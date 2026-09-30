import { describe, expect, it } from 'vitest';
import { mkdtemp } from 'node:fs/promises';
import { request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSecretKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { createLogger, type LogRecord } from '@sedecim/telemetry-policy';
import type { ServiceTracingOptions } from '@sedecim/service-kit';
import { BlobStore } from '../src/index';

function send(base: string, method: string, path: string, headers: Record<string, string> = {}, body?: Uint8Array): Promise<number> {
  return new Promise((resolve, reject) => {
    const r = request(base + path, { method, headers }, (res) => (res.resume(), res.on('end', () => resolve(res.statusCode!))));
    r.on('error', reject);
    r.end(body);
  });
}

async function store(tracing: ServiceTracingOptions, logs: LogRecord[]) {
  const s = new BlobStore({ dir: await mkdtemp(join(tmpdir(), 'blobs-')), logger: createLogger({ base: { service: 'blob-store' }, minimizeIp: true, write: (r) => logs.push(r) }), tracing });
  await s.listen();
  return s;
}

describe('blob-store traces (NFR007-02)', () => {
  it('a sampled request gives a span with the route template, never the hash, the pubkey or the token', async () => {
    const logs: LogRecord[] = [];
    const s = await store({ telemetry: 'standard', sampleRate: 1 }, logs);
    const alice = new LocalSigner(generateSecretKey());
    const data = new TextEncoder().encode('adjunto cifrado en el cliente');
    const hash = Buffer.from(await crypto.subtle.digest('SHA-256', data)).toString('hex');
    const now = Math.floor(Date.now() / 1000);
    const evt = await alice.signEvent({ kind: 24242, content: 'upload', created_at: now, tags: [['t', 'upload'], ['x', hash], ['expiration', String(now + 60)]] });
    const authorization = `Nostr ${Buffer.from(JSON.stringify(evt)).toString('base64')}`;
    try {
      expect(await send(s.url, 'PUT', '/upload', { authorization, 'content-type': 'application/octet-stream' }, data)).toBe(200);
      expect(await send(s.url, 'GET', `/${hash}`)).toBe(200);
      expect(await send(s.url, 'HEAD', `/${hash}.bin`)).toBe(200);
      expect(await send(s.url, 'GET', `/${'0'.repeat(64)}`)).toBe(404);
      expect(await send(s.url, 'GET', '/health')).toBe(200);
      expect(await send(s.url, 'GET', `/nowhere/${evt.pubkey}`)).toBe(404);
      // A request to its onion service is never traced.
      expect(await send(s.url, 'GET', `/${hash}`, { host: `${'b7'.repeat(28)}.onion` })).toBe(200);
    } finally {
      await s.close();
    }
    const spans = logs.filter((l) => l.msg === 'span');
    expect(spans.map((x) => [x.span_name, x['http.route'], x['http.response.status_code']])).toEqual([
      ['PUT /upload', '/upload', 200],
      ['GET /:sha256', '/:sha256', 200],
      ['HEAD /:sha256', '/:sha256', 200],
      ['GET /:sha256', '/:sha256', 404],
      ['GET /health', '/health', 200],
      ['GET', undefined, 404],
    ]);
    const out = JSON.stringify(spans);
    for (const value of [hash, evt.pubkey, evt.id, evt.sig, authorization.slice(6, 60)]) expect(out).not.toContain(value);
  });

  it('traces nothing at telemetry level none, whatever the sample rate', async () => {
    const logs: LogRecord[] = [];
    const s = await store({ telemetry: 'none', sampleRate: 1 }, logs);
    try {
      expect(s.tracer.enabled).toBe(false);
      for (let i = 0; i < 5; i++) expect(await send(s.url, 'GET', '/health')).toBe(200);
    } finally {
      await s.close();
    }
    expect(logs.filter((l) => l.msg === 'span')).toEqual([]);
  });
});
