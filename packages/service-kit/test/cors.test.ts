import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { HttpError, Service } from '../src/index';

describe('Service CORS allowlist', () => {
  const svc = new Service({ name: 'cors-test', corsOrigins: ['http://app.example'] });
  svc.get('/ok', () => ({ ok: true }));
  svc.get('/fail', () => {
    throw new HttpError(409, 'conflict');
  });
  let base: string;
  beforeAll(async () => (base = await svc.listen()));
  afterAll(() => svc.close());

  it('answers preflight and echoes only allowed origins', async () => {
    const pre = await fetch(`${base}/ok`, { method: 'OPTIONS', headers: { origin: 'http://app.example', 'access-control-request-headers': 'authorization' } });
    expect(pre.status).toBe(204);
    expect(pre.headers.get('access-control-allow-origin')).toBe('http://app.example');
    expect(pre.headers.get('access-control-allow-headers')).toContain('authorization');
    expect((await fetch(`${base}/ok`, { method: 'OPTIONS', headers: { origin: 'http://evil.example' } })).status).toBe(403);
    const other = await fetch(`${base}/ok`, { headers: { origin: 'http://evil.example' } });
    expect(other.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('adds the headers to errors so the browser can read them', async () => {
    const res = await fetch(`${base}/fail`, { headers: { origin: 'http://app.example' } });
    expect(res.status).toBe(409);
    expect(res.headers.get('access-control-allow-origin')).toBe('http://app.example');
  });
});
