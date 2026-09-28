import { describe, expect, it } from 'vitest';
import { generateSecretKey, getPublicKey, nip98 } from '@sedecim/nostr-core';
import { preset } from '@sedecim/profiles';
import { LocalSigner } from '@sedecim/signer';
import { disablePush, enablePush, pushAvailability, pushScope, watchableRelays, type PushEnv } from '../src/lib/push';

const GW = 'https://push.example.org';
const VAPID = Buffer.from(Uint8Array.from({ length: 65 }, (_, i) => (i === 0 ? 4 : i))).toString('base64url');

function fakeEnv() {
  const registrations = new Map<string, { scope: string; subscribed?: { endpoint: string; key: Uint8Array }; unregistered: boolean }>();
  const env: PushEnv = {
    hasPushManager: true,
    hasNotification: true,
    serviceWorker: {
      async register(script: string | URL, opts?: RegistrationOptions) {
        expect(String(script)).toBe('./sw.js');
        const scope = opts!.scope!;
        const r = registrations.get(scope) ?? { scope, unregistered: false };
        registrations.set(scope, r);
        const sub = () =>
          r.subscribed && {
            endpoint: r.subscribed.endpoint,
            toJSON: () => ({ endpoint: r.subscribed!.endpoint, keys: { p256dh: 'p', auth: 'a' } }),
            unsubscribe: async () => ((r.subscribed = undefined), true),
          };
        return {
          pushManager: {
            getSubscription: async () => sub() ?? null,
            subscribe: async (o: PushSubscriptionOptionsInit) => {
              expect(o.userVisibleOnly).toBe(true);
              r.subscribed = { endpoint: `https://fcm.googleapis.com/fcm/send/${encodeURIComponent(scope)}`, key: o.applicationServerKey as Uint8Array };
              return sub();
            },
          },
          unregister: async () => ((r.unregistered = true), true),
        } as unknown as ServiceWorkerRegistration;
      },
      async getRegistration(scope?: string) {
        return registrations.has(scope!) ? this.register('./sw.js', { scope: scope! }) : undefined;
      },
    } as PushEnv['serviceWorker'],
  };
  return { env, registrations };
}

function fakeFetch(status = 201) {
  const calls: Array<{ url: string; method: string; headers: Record<string, string>; body?: string }> = [];
  const f = (async (url: string, init?: RequestInit) => {
    calls.push({ url, method: init?.method ?? 'GET', headers: (init?.headers ?? {}) as Record<string, string>, ...(init?.body ? { body: String(init.body) } : {}) });
    if (url.endsWith('/v1/vapid')) return new Response(JSON.stringify({ publicKey: VAPID }));
    return new Response(JSON.stringify(status === 201 ? { mode: 'push', relays: [] } : { error: 'push is disabled for this profile (ADR 0010)' }), { status });
  }) as unknown as typeof fetch;
  return { f, calls };
}

describe('Notificaciones control availability (ADR 0010)', () => {
  const env = fakeEnv().env;
  it('is hidden without a gateway in config.json', () => {
    expect(pushAvailability(undefined, preset('convenience'), env)).toEqual({ state: 'hidden' });
  });
  it('is disabled with an explanation for sovereign and Tor personas', () => {
    const sov = pushAvailability(GW, preset('sovereign'), env);
    const tor = pushAvailability(GW, preset('sovereign-tor'), env);
    const torLike = pushAvailability(GW, { ...preset('convenience'), network: 'tor-only' }, env);
    expect(sov.state).toBe('disabled');
    expect(tor.state).toBe('disabled');
    expect(torLike.state).toBe('disabled');
    expect(tor.state === 'disabled' && tor.reason).toMatch(/Tor/);
  });
  it('reports browsers without Push API and offers the profile mode otherwise', () => {
    expect(pushAvailability(GW, preset('convenience'), { hasPushManager: false, hasNotification: true }).state).toBe('unsupported');
    const a = pushAvailability(GW, preset('private-resilient'), env);
    expect(a.state === 'available' && a.policy.mode).toBe('privacy-push');
  });
});

describe('push registration', () => {
  const sk = generateSecretKey();
  const signer = new LocalSigner(sk);
  const persona = { id: 'p1', preset: 'convenience' as const, relays: ['wss://relay.example.org'], config: preset('convenience') };

  it('subscribes with the VAPID key under a per-persona scope and registers with NIP-98', async () => {
    const { env, registrations } = fakeEnv();
    const { f, calls } = fakeFetch();
    expect(await enablePush(GW, persona, { env, signer, fetch: f })).toMatchObject({ mode: 'push' });
    const reg = registrations.get(pushScope('p1'))!;
    expect(Buffer.from(reg.subscribed!.key).toString('base64url')).toBe(VAPID);
    const post = calls.find((c) => c.method === 'POST')!;
    expect(post.url).toBe(`${GW}/v1/subscriptions`);
    const evt = nip98.verifyAuthHeader(post.headers.authorization, { url: post.url, method: 'POST', body: post.body });
    expect(evt.pubkey).toBe(getPublicKey(sk));
    expect(JSON.parse(post.body!)).toEqual({ subscription: { endpoint: reg.subscribed!.endpoint, keys: { p256dh: 'p', auth: 'a' } }, profile: 'convenience', mode: 'push', network: 'direct', relays: ['wss://relay.example.org'] });

    // a second persona gets its own scope, hence its own endpoint (the gateway cannot link them)
    await enablePush(GW, { ...persona, id: 'p2' }, { env, signer: new LocalSigner(generateSecretKey()), fetch: f });
    expect(registrations.get(pushScope('p2'))!.subscribed!.endpoint).not.toBe(reg.subscribed!.endpoint);
  });

  it('refuses sovereign personas before touching the browser or the gateway', async () => {
    const { env, registrations } = fakeEnv();
    const { f, calls } = fakeFetch();
    await expect(enablePush(GW, { ...persona, preset: 'sovereign', config: preset('sovereign') }, { env, signer, fetch: f })).rejects.toThrow(/no usa notificaciones push/);
    expect(calls).toHaveLength(0);
    expect(registrations.size).toBe(0);
  });

  it('drops the browser subscription when the gateway refuses, and unsubscribes on disable', async () => {
    const { env, registrations } = fakeEnv();
    await expect(enablePush(GW, persona, { env, signer, fetch: fakeFetch(403).f })).rejects.toThrow(/403/);
    expect(registrations.get(pushScope('p1'))!.subscribed).toBeUndefined();

    const ok = fakeFetch();
    await enablePush(GW, persona, { env, signer, fetch: ok.f });
    const endpoint = registrations.get(pushScope('p1'))!.subscribed!.endpoint;
    await disablePush(GW, persona, { env, signer, fetch: ok.f });
    const del = ok.calls.find((c) => c.method === 'DELETE')!;
    expect(JSON.parse(del.body!)).toEqual({ endpoint });
    expect(registrations.get(pushScope('p1'))).toMatchObject({ subscribed: undefined, unregistered: true });
  });
});

describe('relays the gateway can watch (OPS-06)', () => {
  it('splits the persona relays by what the gateway found with its canary, matching normalized URLs', async () => {
    const calls: string[] = [];
    const f = (async (url: string) => {
      calls.push(url);
      return new Response(
        JSON.stringify({
          relays: [
            { relay: 'wss://open.example.org', observable: true, checkedAt: 1 },
            { relay: 'wss://gated.example.org', observable: false, checkedAt: 1 },
            { relay: 'wss://new.example.org', observable: false, checkedAt: 0 },
          ],
        }),
      );
    }) as unknown as typeof fetch;
    expect(await watchableRelays(GW, ['wss://Open.example.org/', 'wss://gated.example.org', 'wss://new.example.org', 'wss://elsewhere.example.org', 'not a relay'], f)).toEqual({
      watchable: ['wss://Open.example.org/'],
      pending: ['wss://new.example.org'],
      unobservable: ['wss://gated.example.org'],
      unserved: ['wss://elsewhere.example.org', 'not a relay'],
    });
    // A GET without credentials: asking says nothing about who is asking.
    expect(calls).toEqual([`${GW}/v1/relays`]);
  });

  it('fails when the gateway does not answer, so the control does not claim anything', async () => {
    await expect(watchableRelays(GW, ['wss://open.example.org'], (async () => new Response('', { status: 502 })) as unknown as typeof fetch)).rejects.toThrow(/502/);
  });
});
