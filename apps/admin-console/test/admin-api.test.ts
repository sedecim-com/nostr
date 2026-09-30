import { describe, expect, it } from 'vitest';
import { generateSecretKey, getPublicKey, nip98, npubEncode } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { ApiError, PolicyAdminApi } from '../src/api';
import { formatAttributes, parseAttributes, parseMembers, parseRules } from '../src/forms';
import { b64urlToBytes, bytesToB64url, creationOptionsFromJSON } from '../src/webauthn';

/** fetch double that verifies the NIP-98 header like service-kit does and records the call. */
function fakeFetch(status = 200, body: unknown = {}) {
  const calls: Array<{ url: string; method: string; body?: string; pubkey: string }> = [];
  const f = (async (url: string, init: RequestInit) => {
    const evt = nip98.verifyAuthHeader((init.headers as Record<string, string>).authorization, { url, method: init.method!, body: (init.body as string) ?? '' });
    calls.push({ url, method: init.method!, ...(init.body ? { body: init.body as string } : {}), pubkey: evt.pubkey });
    return new Response(JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
  return { f, calls };
}

describe('PolicyAdminApi', () => {
  const sk = generateSecretKey();
  const signer = new LocalSigner(sk);

  it('signs every request with NIP-98 for the exact URL (query included), method and body', async () => {
    const { f, calls } = fakeFetch(200, { audit: [] });
    const api = new PolicyAdminApi('http://policy.test/', signer, f);
    await api.audit({ limit: 20, before: 123 });
    await api.putRetention('grupo-a', { days: null, legalHold: true });
    await api.deleteDirectory('ab'.repeat(32));
    await api.accessLog({ limit: 20, before: 7, resource: 'canal general' });
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      'GET http://policy.test/v1/audit?limit=20&before=123',
      'PUT http://policy.test/v1/retention/grupo-a',
      `DELETE http://policy.test/v1/directory/${'ab'.repeat(32)}`,
      'GET http://policy.test/v1/access-log?limit=20&before=7&resource=canal+general',
    ]);
    expect(calls[1]!.body).toBe('{"days":null,"legalHold":true}');
    expect(calls.every((c) => c.pubkey === getPublicKey(sk))).toBe(true);
  });

  it('omits members when absent and surfaces API errors', async () => {
    const ok = fakeFetch();
    await new PolicyAdminApi('http://p', signer, ok.f).putResource('r', { kind: 'channel', sensitivity: 'internal', rules: [] });
    expect(JSON.parse(ok.calls[0]!.body!)).toEqual({ kind: 'channel', sensitivity: 'internal', rules: [] });
    const denied = fakeFetch(403, { error: 'admin only' });
    await expect(new PolicyAdminApi('http://p', signer, denied.f).listSubjects()).rejects.toEqual(new ApiError(403, 'admin only'));
  });
});

describe('forms', () => {
  it('parses and formats attributes, including multi-valued ones', () => {
    const a = parseAttributes('clearance=secret\n unit = ops | legal \n');
    expect(a).toEqual({ clearance: 'secret', unit: ['ops', 'legal'] });
    expect(parseAttributes(formatAttributes(a))).toEqual(a);
    expect(() => parseAttributes('sin-igual')).toThrow(/clave=valor/);
  });

  it('validates rules and members', () => {
    expect(parseRules('[{"actions":["read"],"anyRole":["staff"],"minDeviceTrust":"attested"}]')).toHaveLength(1);
    expect(parseRules('')).toEqual([]);
    expect(() => parseRules('{')).toThrow(/JSON/);
    expect(() => parseRules('[{"actions":["fly"]}]')).toThrow(/regla 0/);
    expect(() => parseRules('[{"actions":["read"],"minDeviceTrust":"x"}]')).toThrow(/minDeviceTrust/);
    const pk = getPublicKey(generateSecretKey());
    expect(parseMembers(`${npubEncode(pk)}\n`)).toEqual([pk]);
    expect(parseMembers('  ')).toBeUndefined();
    expect(() => parseMembers('npub1nope')).toThrow(/inválida/);
  });
});

describe('webauthn JSON helpers', () => {
  it('round-trips base64url and decodes the binary option fields', () => {
    const bytes = new Uint8Array([0, 250, 251, 252, 253, 254, 255]);
    expect(b64urlToBytes(bytesToB64url(bytes))).toEqual(bytes);
    expect(bytesToB64url(bytes)).not.toMatch(/[+/=]/);
    const o = creationOptionsFromJSON({ challenge: 'AQID', rp: { name: 'x', id: 'localhost' }, user: { id: 'BAU', name: 'd', displayName: 'D' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], excludeCredentials: [{ type: 'public-key', id: 'Bg' }] });
    expect(new Uint8Array(o.challenge as ArrayBuffer)).toEqual(new Uint8Array([1, 2, 3]));
    expect(new Uint8Array(o.user.id as ArrayBuffer)).toEqual(new Uint8Array([4, 5]));
    expect(new Uint8Array(o.excludeCredentials![0]!.id as ArrayBuffer)).toEqual(new Uint8Array([6]));
  });
});
