/**
 * FR005-11: the owner of a managed key sees its usage log and their own device sessions, and closes them. Closing a
 * session is the user's call about their own login; revoking a device stays the organisation's (FR024-03).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { verifyEvent } from '@sedecim/nostr-core';
import { createTestCognito } from '@sedecim/service-kit';
import { ManagedSignerClient, ManagedSignerHttpError } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import { createManagedSignerApi, ManagedSigner, MemoryKeyRegistry, MemoryVault } from '../src/index';

const acceso = createTestCognito();
const silent = createLogger({ write: () => {} });

describe('managed-signer: the owner lists and closes their own sessions (FR005-11)', () => {
  let base = '';
  let close = () => {};
  const ana = () => acceso.token({ sub: 'ana' });
  const bea = () => acceso.token({ sub: 'bea' });
  const as = (token: () => string) => ({ baseUrl: base, token: async () => token() });
  const session = async (token: () => string, deviceId: string) => (await ManagedSignerClient.openDeviceSession(as(token), deviceId)).token;

  beforeAll(async () => {
    const core = new ManagedSigner(new MemoryVault(), { registry: new MemoryKeyRegistry() });
    const svc = createManagedSignerApi(core, { name: 'ms-own-sessions', cognito: acceso.verifier(), logger: silent, requireDeviceSession: true });
    base = await svc.listen();
    close = () => svc.close();
  });
  afterAll(() => close());

  it('lists them with the Acceso login or from a session (marked current), never another user’s, never a token', async () => {
    const phone = await session(ana, 'ana-phone');
    const laptop = await session(ana, 'ana-laptop');
    await session(bea, 'bea-phone');
    const withLogin = await ManagedSignerClient.listDeviceSessions(as(ana));
    expect(withLogin.map((s) => s.deviceId)).toEqual(['ana-phone', 'ana-laptop']);
    expect(withLogin.every((s) => /^[0-9a-f]{32}$/.test(s.id) && !s.current && s.expiresAt > s.createdAt)).toBe(true);
    expect(JSON.stringify(withLogin)).not.toContain(phone.slice(4));
    const fromPhone = await ManagedSignerClient.listDeviceSessions(as(() => phone));
    expect(fromPhone.filter((s) => s.current).map((s) => s.deviceId)).toEqual(['ana-phone']);
    expect((await ManagedSignerClient.listDeviceSessions(as(bea))).map((s) => s.deviceId)).toEqual(['bea-phone']);
    await ManagedSignerClient.closeDeviceSessions(as(ana));
    expect(await ManagedSignerClient.listDeviceSessions(as(ana))).toEqual([]);
    void laptop;
  });

  it('a session closes itself but not the others; the Acceso login closes any of them, or all but one', async () => {
    const phone = await session(ana, 'ana-phone');
    const laptop = await session(ana, 'ana-laptop');
    const tablet = await session(ana, 'ana-tablet');
    const ids = Object.fromEntries((await ManagedSignerClient.listDeviceSessions(as(ana))).map((s) => [s.deviceId, s.id]));
    await expect(ManagedSignerClient.closeDeviceSession(as(() => phone), ids['ana-laptop']!)).rejects.toMatchObject({ status: 403 });
    await expect(ManagedSignerClient.closeDeviceSessions(as(() => phone))).rejects.toMatchObject({ status: 403 });
    await ManagedSignerClient.closeDeviceSession(as(() => phone), ids['ana-phone']!);
    await expect(ManagedSignerClient.listDeviceSessions(as(() => phone))).rejects.toMatchObject({ status: 401 });
    // Another user cannot close them, not even knowing their ids.
    await expect(ManagedSignerClient.closeDeviceSession(as(bea), ids['ana-laptop']!)).rejects.toMatchObject({ status: 404 });
    expect(await ManagedSignerClient.closeDeviceSessions(as(ana), { except: ids['ana-tablet']! })).toBe(1);
    expect((await ManagedSignerClient.listDeviceSessions(as(() => tablet))).map((s) => [s.deviceId, !!s.current])).toEqual([['ana-tablet', true]]);
    await expect(ManagedSignerClient.listDeviceSessions(as(() => laptop))).rejects.toBeInstanceOf(ManagedSignerHttpError);
    // Closing a session is not revoking the device: it can open another one with its owner's login.
    expect(await session(ana, 'ana-laptop')).toMatch(/^sds_/);
    await ManagedSignerClient.closeDeviceSessions(as(ana));
  });

  it('a client whose session was closed opens another one and retries; the usage log names the device', async () => {
    const deviceId = 'ana-browser';
    let current = await session(ana, deviceId);
    let renewals = 0;
    const conn = { baseUrl: base, token: async () => current, renew: async () => void ((current = await session(ana, deviceId)), renewals++) };
    const key = await ManagedSignerClient.createKey(conn, { consentVersion: 'textos test' });
    const signer = new ManagedSignerClient({ ...conn, keyId: key.keyId });
    expect(verifyEvent(await signer.signEvent({ kind: 1, content: 'antes' }))).toBe(true);
    // Closed from another browser with the login: the next signature opens a new session and goes through.
    await ManagedSignerClient.closeDeviceSessions(as(ana));
    expect(verifyEvent(await signer.signEvent({ kind: 1, content: 'después' }))).toBe(true);
    expect(renewals).toBe(1);
    const usage = await signer.usage();
    expect(usage.map((u) => [u.action, u.deviceId])).toEqual([
      ['created', undefined],
      ['sign', deviceId],
      ['sign', deviceId],
    ]);
    expect(usage.every((u) => u.keyId === key.keyId && !JSON.stringify(u).includes('después'))).toBe(true);
    // Keys are listed only through a session here (MANAGED_SIGNER_REQUIRE_DEVICE_SESSION): what a new browser does.
    await expect(ManagedSignerClient.listKeys(as(ana))).rejects.toMatchObject({ status: 403 });
    expect((await ManagedSignerClient.listKeys(conn)).map((k) => k.pubkey)).toEqual([key.pubkey]);
  });
});
