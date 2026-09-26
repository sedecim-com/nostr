import { describe, expect, it } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned } from '@sedecim/nostr-core';
import { ManagedSignerClient, ManagedSignerHttpError } from '../src/index';

describe('ManagedSignerClient (FR005-04)', () => {
  const sk = generateSecretKey();
  const pubkey = getPublicKey(sk);

  /** Fake managed-signer: records requests and signs with a local key. */
  function server(status = 200) {
    const seen: Array<{ url: string; method: string; headers: Record<string, string>; body?: unknown }> = [];
    const f = (async (url: string, init?: RequestInit) => {
      const headers = init?.headers as Record<string, string>;
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      seen.push({ url, method: init?.method ?? 'GET', headers, body });
      if (status !== 200) return new Response(JSON.stringify({ error: 'key belongs to another owner' }), { status });
      if (url.endsWith('/sign')) return Response.json({ event: finalizeEvent(toUnsigned(body.template, pubkey), sk) });
      if (url.endsWith('/v1/keys')) return Response.json(init?.method === 'POST' ? { keyId: 'k2', pubkey } : { keys: [{ keyId: 'k1', pubkey }] });
      return Response.json({ keyId: 'k1', pubkey, custodial: true });
    }) as typeof fetch;
    return { seen, f };
  }

  it('sends a fresh Acceso bearer token on every call and nothing else identifying the account', async () => {
    const { seen, f } = server();
    let n = 0;
    const client = new ManagedSignerClient({ baseUrl: 'https://signer.example/', keyId: 'k1', token: async () => `tok-${++n}`, fetch: f });
    const evt = await client.signEvent({ kind: 1, content: 'hola' });
    expect(evt.pubkey).toBe(pubkey);
    expect(seen.map((s) => `${s.method} ${s.url}`)).toEqual(['POST https://signer.example/v1/keys/k1/sign', 'GET https://signer.example/v1/keys/k1']);
    expect(seen.map((s) => s.headers.authorization)).toEqual(['Bearer tok-1', 'Bearer tok-2']);
    expect(seen.every((s) => !('x-account-id' in s.headers))).toBe(true);
    expect(seen[1]!.headers['content-type']).toBeUndefined();

    const conn = { baseUrl: 'https://signer.example', token: async () => 'tok', fetch: f };
    expect((await ManagedSignerClient.listKeys(conn)).map((k) => k.keyId)).toEqual(['k1']);
    expect((await ManagedSignerClient.createKey(conn, { allowedKinds: [1] })).keyId).toBe('k2');
    expect(seen.at(-1)!.body).toEqual({ allowed_kinds: [1] });
  });

  it('surfaces HTTP errors with their status and refuses to call without a session', async () => {
    const { f } = server(403);
    const client = new ManagedSignerClient({ baseUrl: 'https://signer.example', keyId: 'k1', token: async () => 'tok', fetch: f });
    const err = await client.getPublicKey().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ManagedSignerHttpError);
    expect((err as ManagedSignerHttpError).status).toBe(403);
    expect((err as Error).message).toMatch(/another owner/);
    const noSession = new ManagedSignerClient({ baseUrl: 'https://signer.example', keyId: 'k1', token: async () => '', fetch: f });
    await expect(noSession.getPublicKey()).rejects.toThrow(/no Acceso session/);
  });
});
