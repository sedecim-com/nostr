import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { request } from 'node:http';
import { lookupToken, safeEqual, Service } from '../src/index';

/** Raw request so header values can carry latin1 bytes that fetch() would refuse. */
function raw(base: string, path: string, headers: Record<string, string>): Promise<number> {
  return new Promise((resolve, reject) => {
    const r = request(base + path, { headers }, (res) => (res.resume(), resolve(res.statusCode!)));
    r.on('error', reject);
    r.end();
  });
}

describe('service-kit hardening (internal review 2026-09)', () => {
  const svc = new Service({ name: 'hardening-test', bearerTokens: { 'abcdefgh': 'svc' } });
  svc.get('/svc', (req) => ({ principal: req.principal }), 'bearer');
  svc.get('/items/:id', (req) => ({ id: req.params.id }));
  let base: string;
  beforeAll(async () => (base = await svc.listen()));
  afterAll(() => svc.close());

  it('safeEqual/lookupToken compare bytes, not UTF-16 lengths', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    // Same string length, different UTF-8 length: used to make timingSafeEqual throw (500).
    expect(safeEqual('abcdefgh', 'abcdefgé')).toBe(false);
    expect(lookupToken({ t1: 'a', t2: 'b' }, 't2')).toBe('b');
    expect(lookupToken({ '': 'empty' }, 'x')).toBeUndefined();
    expect(lookupToken(undefined, 'x')).toBeUndefined();
  });

  it('a bearer token with non-ASCII bytes is a 401, not a 500', async () => {
    expect(await raw(base, '/svc', { authorization: 'Bearer abcdefgé' })).toBe(401);
    expect(await raw(base, '/svc', { authorization: 'Bearer ' })).toBe(401);
    expect(await raw(base, '/svc', { authorization: 'Bearer abcdefgh' })).toBe(200);
  });

  it('a malformed percent-encoded path parameter is a 400, not a 500', async () => {
    expect((await fetch(`${base}/items/%E0%A4%A`)).status).toBe(400);
    expect(await (await fetch(`${base}/items/a%20b`)).json()).toEqual({ id: 'a b' });
  });
});
