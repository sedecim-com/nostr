import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { verifyEvent } from '@sedecim/nostr-core';
import { createManagedSignerApi, ManagedSigner, MemoryVault } from '@sedecim/managed-signer';
import { createTestCognito } from '@sedecim/service-kit';
import { ManagedSignerClient, ManagedSignerReauthError } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import { BrowserManagedSession, DeviceRevokedError, SessionsClosedError } from '../src/lib/managed-session';

describe('the browser session of a managed persona and the organisation’s device (FR024-03)', () => {
  const acceso = createTestCognito();
  const core = new ManagedSigner(new MemoryVault(), {});
  const api = createManagedSignerApi(core, { name: 'ms-web-test', cognito: acceso.verifier(), logger: createLogger({ write: () => {} }) });
  let base: string;
  beforeAll(async () => {
    base = await api.listen();
  });
  afterAll(() => api.close());

  it('binds to the device the organisation registered, closing the old session; once revoked it signs nothing and says why', async () => {
    const store = EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(1));
    const session = new BrowserManagedSession(store as unknown as ConstructorParameters<typeof BrowserManagedSession>[0], base, async () => acceso.token({ sub: 'ana' }));
    const key = await ManagedSignerClient.createKey(session.login(), { consentVersion: 'textos test' });
    const signer = new ManagedSignerClient({ ...session.connection(), keyId: key.keyId });
    const sessions = async () => (await ManagedSignerClient.listDeviceSessions(session.login())).map((x) => x.deviceId);

    // A random id of this browser at first.
    expect(await session.deviceId()).toMatch(/^web-[0-9a-f]{24}$/);
    expect(verifyEvent(await signer.signEvent({ kind: 1, content: 'antes' }))).toBe(true);
    expect(await sessions()).toEqual([await session.deviceId()]);

    await expect(session.bindDevice('no es un id')).rejects.toThrow(/id de dispositivo no válido/);
    await session.bindDevice(' dev-org-1 ');
    expect(await session.deviceId()).toBe('dev-org-1');
    expect(await sessions()).toEqual([]);
    expect(verifyEvent(await signer.signEvent({ kind: 1, content: 'como dispositivo de la organización' }))).toBe(true);
    expect(await sessions()).toEqual(['dev-org-1']);
    // Binding again to the same device changes nothing.
    await session.bindDevice('dev-org-1');
    expect(await sessions()).toEqual(['dev-org-1']);

    // The organisation revokes it (the rotation worker's call): the open session goes, and the login opens no other.
    await core.revokeDevice('dev-org-1', 'rotation-worker', 'perdido');
    const refused = await signer.signEvent({ kind: 1, content: 'después' }).catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(DeviceRevokedError);
    expect((refused as Error).message).toMatch(/Tu organización revocó este dispositivo \(dev-org-1\)/);
    expect(await sessions()).toEqual([]);
  });

  it('once another browser closed the other sessions, this login opens none until the password is typed again (IR-2026-10-11)', async () => {
    const store = EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(2));
    const nowS = Math.floor(Date.now() / 1000);
    // This browser signed in ten minutes ago; every refresh of its login keeps that sign-in.
    let login = acceso.token({ sub: 'eva', origin_jti: 'eva-phone', auth_time: nowS - 600 });
    const session = new BrowserManagedSession(store as unknown as ConstructorParameters<typeof BrowserManagedSession>[0], base, async () => login);
    const key = await ManagedSignerClient.createKey(session.login(), { consentVersion: 'textos test' });
    const signer = new ManagedSignerClient({ ...session.connection(), keyId: key.keyId });
    expect(verifyEvent(await signer.signEvent({ kind: 1, content: 'antes' }))).toBe(true);

    // Eva, in another browser and with her password just typed, closes the other sessions.
    await ManagedSignerClient.closeDeviceSessions({ baseUrl: base, token: async () => acceso.token({ sub: 'eva', origin_jti: 'eva-laptop' }) });
    const refused = await signer.signEvent({ kind: 1, content: 'después' }).catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(SessionsClosedError);
    expect(refused).toBeInstanceOf(ManagedSignerReauthError);
    expect((refused as Error).message).toMatch(/Se cerraron las sesiones de tu llave gestionada desde otro navegador/);

    // Signing in again here (what accesoReauthenticate leaves in place) makes it sign again.
    login = acceso.token({ sub: 'eva', origin_jti: 'eva-phone-2' });
    expect(verifyEvent(await signer.signEvent({ kind: 1, content: 'de vuelta' }))).toBe(true);
  });
});
