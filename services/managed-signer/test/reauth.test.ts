/**
 * IR-2026-10-03: letting a managed key out (export, confirming the migration) or destroying it (delete, cancel) takes a
 * recent sign-in with the Acceso password: never a device session, never an older login that a stolen browser keeps
 * refreshing (a refreshed token keeps its `auth_time`). The refusal is an RFC 9470 step-up: 401 with
 * `WWW-Authenticate: Bearer error="insufficient_user_authentication"`.
 * IR-2026-10-11: closing the other sessions (which takes that recent sign-in too) cuts off the logins signed in before,
 * except the one that closed them, and no session lasts longer than the configured lifetime.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { finalizeEvent, getPublicKey, nip19, nip49, toUnsigned } from '@sedecim/nostr-core';
import { createTestCognito } from '@sedecim/service-kit';
import { ManagedSignerClient, ManagedSignerReauthError } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import { createManagedSignerApi, ManagedSigner, MemoryDeviceStore, MemoryKeyRegistry, MemoryVault } from '../src/index';

const acceso = createTestCognito();
const silent = createLogger({ write: () => {} });
const nowS = () => Math.floor(Date.now() / 1000);
const PASSWORD = 'una contraseña larga';
const proofFor = (secretKey: Uint8Array, challenge: string) => finalizeEvent(toUnsigned({ kind: 27235, content: '', tags: [['challenge', challenge]] }, getPublicKey(secretKey)), secretKey);

async function start(opts: { reauthMaxAgeSeconds?: number } = {}) {
  const core = new ManagedSigner(new MemoryVault(), { registry: new MemoryKeyRegistry(), retentionDays: 30 });
  const svc = createManagedSignerApi(core, { name: 'ms-reauth', cognito: acceso.verifier(), logger: silent, ...opts });
  const base = await svc.listen();
  const call = (path: string, method: string, body: unknown, token: string) =>
    fetch(`${base}${path}`, { method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }).then(async (r) => ({
      status: r.status,
      headers: r.headers,
      json: await r.json(),
    }));
  return { base, call, close: () => svc.close() };
}

describe('managed-signer: a recent Acceso sign-in to let a key out or destroy it (IR-2026-10-03)', () => {
  let t: Awaited<ReturnType<typeof start>>;
  /** The owner signed in 20 minutes ago in the browser that gets stolen: every refresh keeps that auth_time. */
  const stale = () => acceso.token({ sub: 'vic', auth_time: nowS() - 1200 });
  /** The owner signing in again with the password. */
  const fresh = () => acceso.token({ sub: 'vic', origin_jti: 'vic-again' });
  beforeAll(async () => {
    t = await start();
  });
  afterAll(() => t.close());

  it('a stolen browser (its device session or its refreshed login) still signs, but cannot export, migrate, delete or cancel', async () => {
    const { json: k } = await t.call('/v1/keys', 'POST', { consent_version: 'textos test' }, stale());
    const session = (await t.call('/v1/device-sessions', 'POST', { device_id: 'vic-laptop' }, stale())).json.token as string;
    // What the thief keeps until the owner closes that session: signing.
    expect((await t.call(`/v1/keys/${k.keyId}/sign`, 'POST', { template: { kind: 1, content: 'x' } }, session)).status).toBe(200);
    const noAuthTime = acceso.token({ sub: 'vic', auth_time: undefined });
    const future = acceso.token({ sub: 'vic', auth_time: nowS() + 600 });
    for (const token of [session, stale(), noAuthTime, future]) {
      for (const [path, method, body] of [
        [`/v1/keys/${k.keyId}/export`, 'POST', { password: PASSWORD }],
        [`/v1/keys/${k.keyId}/confirm-migration`, 'POST', { proof: {} }],
        [`/v1/keys/${k.keyId}`, 'DELETE', undefined],
        [`/v1/keys/${k.keyId}/cancel`, 'POST', { confirm: nip19.npubEncode(k.pubkey) }],
        ['/v1/device-sessions', 'DELETE', undefined],
      ] as const) {
        const r = await t.call(path, method, body, token);
        expect(r.status, `${method} ${path}`).toBe(401);
        expect(r.headers.get('www-authenticate')).toMatch(/^Bearer error="insufficient_user_authentication", error_description="[^"]+", max_age=300$/);
        expect(r.json).toMatchObject({ error_code: 'insufficient_user_authentication', max_age: 300 });
      }
    }
    // Nothing was exported, deleted or closed: the key is live and its session still signs.
    expect((await t.call(`/v1/keys/${k.keyId}`, 'GET', undefined, stale())).json.state).toBe('active');
    expect((await t.call(`/v1/keys/${k.keyId}/usage`, 'GET', undefined, stale())).json.usage.map((u: { action: string }) => u.action)).toEqual(['created', 'sign']);
    expect((await t.call(`/v1/keys/${k.keyId}/sign`, 'POST', { template: { kind: 1, content: 'y' } }, session)).status).toBe(200);
  });

  it('its owner, signing in again, exports, migrates and deletes, and still sees the log after the deletion', async () => {
    const login = { baseUrl: t.base, token: async () => fresh() };
    const key = await ManagedSignerClient.createKey(login, { consentVersion: 'textos test' });
    const client = new ManagedSignerClient({ ...login, keyId: key.keyId });
    const { ncryptsec, challenge } = await client.exportForMigration(PASSWORD);
    await client.confirmMigration(proofFor(nip49.decryptKey(ncryptsec, PASSWORD).secretKey, challenge));
    await client.deleteKey();
    // The log stays visible to its owner after the deletion (it answered 404): whoever lost the key sees what happened.
    expect((await client.usage()).map((u) => u.action)).toEqual(['created', 'export', 'migration-confirmed', 'deleted']);
    expect((await t.call(`/v1/keys/${key.keyId}/usage`, 'GET', undefined, acceso.token({ sub: 'otra' }))).status).toBe(403);
  });

  it('the SDK reports the step-up as such and does not renew the session for it', async () => {
    const key = await ManagedSignerClient.createKey({ baseUrl: t.base, token: async () => fresh() }, { consentVersion: 'textos test' });
    let renewals = 0;
    const stolen = new ManagedSignerClient({ baseUrl: t.base, token: async () => stale(), renew: async () => void renewals++, keyId: key.keyId });
    const err = await stolen.exportForMigration(PASSWORD).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ManagedSignerReauthError);
    expect(err).toMatchObject({ status: 401, maxAgeSeconds: 300 });
    await expect(stolen.cancelCustody(nip19.npubEncode(key.pubkey))).rejects.toBeInstanceOf(ManagedSignerReauthError);
    expect(renewals).toBe(0);
  });

  it('the age limit is configurable (MANAGED_SIGNER_REAUTH_MAX_AGE_S)', async () => {
    const strict = await start({ reauthMaxAgeSeconds: 60 });
    try {
      const { json: k } = await strict.call('/v1/keys', 'POST', { consent_version: 'textos test' }, acceso.token({ sub: 'eva' }));
      const late = await strict.call(`/v1/keys/${k.keyId}/export`, 'POST', { password: PASSWORD }, acceso.token({ sub: 'eva', auth_time: nowS() - 120 }));
      expect(late.status).toBe(401);
      expect(late.headers.get('www-authenticate')).toMatch(/max_age=60$/);
      expect((await strict.call(`/v1/keys/${k.keyId}/export`, 'POST', { password: PASSWORD }, acceso.token({ sub: 'eva', auth_time: nowS() - 30 }))).status).toBe(200);
    } finally {
      await strict.close();
    }
  });
});

describe('managed-signer: closing the other sessions cuts off the other logins (IR-2026-10-11)', () => {
  let t: Awaited<ReturnType<typeof start>>;
  // Two browsers of the same user, each with its own sign-in (origin_jti). The phone is lost.
  const phone = () => acceso.token({ sub: 'ana', origin_jti: 'phone-login', auth_time: nowS() - 3600 });
  const laptop = () => acceso.token({ sub: 'ana', origin_jti: 'laptop-login' });
  const as = (token: () => string) => ({ baseUrl: t.base, token: async () => token() });
  beforeAll(async () => {
    t = await start();
  });
  afterAll(() => t.close());

  it('the lost phone cannot open another session with its login, even refreshed; the laptop that closed them keeps working', async () => {
    const key = await ManagedSignerClient.createKey(as(laptop), { consentVersion: 'textos test' });
    const phoneSession = await ManagedSignerClient.openDeviceSession(as(phone), 'ana-phone');
    const laptopSession = await ManagedSignerClient.openDeviceSession(as(laptop), 'ana-laptop');
    const fromLaptop = { baseUrl: t.base, token: async () => laptopSession.token };
    const current = (await ManagedSignerClient.listDeviceSessions(fromLaptop)).find((s) => s.current)!;
    expect(await ManagedSignerClient.closeDeviceSessions(as(laptop), { except: current.id })).toBe(1);

    // The phone's session is closed, and its login, refreshed or not, opens no other one and signs nothing by itself.
    await expect(new ManagedSignerClient({ baseUrl: t.base, token: async () => phoneSession.token, keyId: key.keyId }).signEvent({ kind: 1, content: 'x' })).rejects.toMatchObject({ status: 401 });
    for (const attempt of [
      () => ManagedSignerClient.openDeviceSession(as(phone), 'ana-phone'),
      () => ManagedSignerClient.listKeys(as(phone)),
      () => new ManagedSignerClient({ ...as(phone), keyId: key.keyId }).signEvent({ kind: 1, content: 'x' }),
    ]) {
      await expect(attempt()).rejects.toBeInstanceOf(ManagedSignerReauthError);
    }
    // The laptop keeps its session and its login.
    expect((await new ManagedSignerClient({ ...fromLaptop, keyId: key.keyId }).signEvent({ kind: 1, content: 'sigo' })).pubkey).toBe(key.pubkey);
    expect((await ManagedSignerClient.openDeviceSession(as(laptop), 'ana-laptop-2')).token).toMatch(/^sds_/);
    // Whoever signs in again with the password (a sign-in after the cut) opens sessions again.
    expect((await ManagedSignerClient.openDeviceSession(as(() => acceso.token({ sub: 'ana', origin_jti: 'phone-login-2' })), 'ana-phone')).token).toMatch(/^sds_/);
    // Another user is not affected.
    expect((await ManagedSignerClient.openDeviceSession(as(() => acceso.token({ sub: 'bea', auth_time: nowS() - 3600 })), 'bea-phone')).token).toMatch(/^sds_/);
  });

  it('closing all of them does the same; a login without a sign-in id is not kept either', async () => {
    const early = () => acceso.token({ sub: 'carla', origin_jti: undefined, auth_time: nowS() - 600 });
    await ManagedSignerClient.openDeviceSession(as(early), 'carla-1');
    const closer = () => acceso.token({ sub: 'carla', origin_jti: undefined });
    expect(await ManagedSignerClient.closeDeviceSessions(as(closer))).toBe(1);
    await expect(ManagedSignerClient.openDeviceSession(as(early), 'carla-1')).rejects.toBeInstanceOf(ManagedSignerReauthError);
    // Signed in the same second as the cut or later: not cut off.
    expect((await ManagedSignerClient.openDeviceSession(as(closer), 'carla-1')).token).toMatch(/^sds_/);
  });

  it('no session lasts longer than the configured lifetime, whatever the client asks', async () => {
    const long = await ManagedSignerClient.openDeviceSession(as(laptop), 'ana-long', { ttlSeconds: 400 * 86_400 });
    const left = Date.parse(long.expiresAt) - Date.now();
    expect(left).toBeLessThanOrEqual(12 * 3_600_000);
    expect(left).toBeGreaterThan(12 * 3_600_000 - 60_000);
    const short = await ManagedSignerClient.openDeviceSession(as(laptop), 'ana-short', { ttlSeconds: 600 });
    expect(Date.parse(short.expiresAt) - Date.now()).toBeLessThanOrEqual(600_000);
  });

  it('keeps each cutoff as long as the usage log (DEC-09: 12 months)', async () => {
    let now = Date.UTC(2026, 0, 1);
    const devices = new MemoryDeviceStore();
    const core = new ManagedSigner(new MemoryVault(), { devices, now: () => now });
    await core.closeDeviceSessions('o', {}, 'kept-login');
    expect(await devices.loginCutoff('o')).toEqual({ owner: 'o', at: now, keep: 'kept-login' });
    await expect(core.assertLoginCurrent('o', Math.floor(now / 1000) - 1, 'other-login')).rejects.toBeInstanceOf(Error);
    await core.assertLoginCurrent('o', Math.floor(now / 1000) - 1, 'kept-login');
    await core.assertLoginCurrent('o', Math.floor(now / 1000), 'other-login');
    now = Date.UTC(2026, 11, 31);
    expect((await core.runRetention()).loginCutoffsPurged).toBe(0);
    now = Date.UTC(2027, 0, 2);
    expect((await core.runRetention()).loginCutoffsPurged).toBe(1);
    await core.assertLoginCurrent('o', 0, undefined);
  });
});
