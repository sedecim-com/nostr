/**
 * FR023-11: the console's own code (PolicyAdminApi and its WebAuthn helpers) against the real policy-engine, with a test
 * authenticator where the browser's would be: the person registers the passkey on their device with their own key, and
 * every session they open asks that authenticator for an assertion.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { createPolicyApi, MemoryPolicyRepository, PolicyEngine } from '@sedecim/policy-engine';
import { ApiError, PolicyAdminApi } from '../src/api';
import { openSessionWithPasskey, registerPasskey } from '../src/webauthn';
import { TestAuthenticator } from '../../../services/policy-engine/test/webauthn-fixture';

const ORIGIN = 'http://localhost:8080';
const buffer = (b64url: string) => new Uint8Array(Buffer.from(b64url, 'base64url')).buffer;
const b64url = (b: BufferSource) => Buffer.from(ArrayBuffer.isView(b) ? new Uint8Array(b.buffer, b.byteOffset, b.byteLength) : new Uint8Array(b)).toString('base64url');

/**
 * A browser at ORIGIN whose authenticator is `auth`: navigator.credentials hands the page what a browser does (binary
 * fields), and records the options the page asked with. Its counter goes up with each assertion.
 */
function browserWith(auth: TestAuthenticator) {
  const asked = { create: [] as PublicKeyCredentialCreationOptions[], get: [] as PublicKeyCredentialRequestOptions[] };
  let counter = 0;
  const credential = (id: string, response: Record<string, unknown>) => ({ id, rawId: buffer(id), type: 'public-key', authenticatorAttachment: 'platform', response, getClientExtensionResults: () => ({}) });
  const credentials = {
    async create({ publicKey }: { publicKey: PublicKeyCredentialCreationOptions }) {
      asked.create.push(publicKey);
      const c = auth.create({ challenge: b64url(publicKey.challenge), origin: ORIGIN, rpId: publicKey.rp.id! });
      return credential(c.id, { clientDataJSON: buffer(c.response.clientDataJSON), attestationObject: buffer(c.response.attestationObject), getTransports: () => ['internal'] });
    },
    async get({ publicKey }: { publicKey: PublicKeyCredentialRequestOptions }) {
      asked.get.push(publicKey);
      const a = auth.get({ challenge: b64url(publicKey.challenge), origin: ORIGIN, rpId: publicKey.rpId!, counter: ++counter });
      return credential(a.id, { clientDataJSON: buffer(a.response.clientDataJSON), authenticatorData: buffer(a.response.authenticatorData), signature: buffer(a.response.signature), userHandle: null });
    },
  };
  vi.stubGlobal('window', { PublicKeyCredential: class {} });
  vi.stubGlobal('navigator', { credentials });
  return asked;
}

describe('passkey of the person, in every session, from the console (FR023-11)', () => {
  const engine = new PolicyEngine(new MemoryPolicyRepository(), Date.now, { rpId: 'localhost', rpName: 'Acceso Nostr', origins: [ORIGIN] });
  const policy = createPolicyApi(engine, { name: 'policy-console-test', adminPubkeys: [] });
  let url: string;
  beforeAll(async () => {
    url = await policy.listen();
  });
  afterAll(() => policy.close());
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('the person registers the passkey on their device, and each session asks the authenticator for an assertion', async () => {
    const sk = generateSecretKey();
    const pubkey = getPublicKey(sk);
    const api = new PolicyAdminApi(url, new LocalSigner(sk));
    const device = await engine.registerDevice('admin', pubkey);
    // Their own devices, signed with their own key, which is no admin's.
    expect((await api.listDevices(pubkey)).map((d) => [d.id, d.trust])).toEqual([[device.id, 'registered']]);
    await expect(api.listSubjects()).rejects.toEqual(new ApiError(403, 'admin only'));
    // Before a passkey, a session opens without an assertion.
    expect(await api.openSession(device.id)).toMatchObject({ deviceId: device.id, asserted: false });

    const auth = new TestAuthenticator();
    const asked = browserWith(auth);
    const attested = await registerPasskey(api, device.id);
    expect([attested.trust, attested.credentialId]).toEqual(['attested', auth.id]);
    expect(b64url(asked.create[0]!.user.id)).toBe(Buffer.from(pubkey, 'hex').toString('base64url'));

    // From now on a session needs the assertion, and each one asks the authenticator again, on a challenge of its own.
    await expect(api.openSession(device.id)).rejects.toMatchObject({ status: 403 });
    const sessions = [await openSessionWithPasskey(api, device.id), await openSessionWithPasskey(api, device.id)];
    expect(sessions.map((s) => [s.deviceId, s.asserted])).toEqual([
      [device.id, true],
      [device.id, true],
    ]);
    expect(asked.get).toHaveLength(2);
    expect(asked.get.map((o) => b64url(o.challenge))[0]).not.toBe(b64url(asked.get[1]!.challenge));
    for (const o of asked.get) {
      expect(o.rpId).toBe('localhost');
      expect(o.allowCredentials!.map((c) => b64url(c.id))).toEqual([auth.id]);
    }
    for (const s of sessions) expect(await engine.sessionValid(s.token)).toBe(true);

    // Revoking the device ends both sessions, and no other opens on it.
    await engine.revokeDevice('admin', device.id, 'perdido');
    for (const s of sessions) expect(await engine.sessionValid(s.token)).toBe(false);
    await expect(openSessionWithPasskey(api, device.id)).rejects.toMatchObject({ status: 409 });
  });

  it('another authenticator on the same key opens nothing, and a browser without WebAuthn is told so', async () => {
    const sk = generateSecretKey();
    const api = new PolicyAdminApi(url, new LocalSigner(sk));
    const device = await engine.registerDevice('admin', getPublicKey(sk));
    browserWith(new TestAuthenticator());
    await registerPasskey(api, device.id);
    // Whoever holds the Nostr key on another browser signs with an authenticator the policy-engine does not know.
    browserWith(new TestAuthenticator());
    await expect(openSessionWithPasskey(api, device.id)).rejects.toEqual(new ApiError(403, 'WebAuthn assertion rejected'));
    vi.unstubAllGlobals();
    vi.stubGlobal('window', {});
    await expect(openSessionWithPasskey(api, device.id)).rejects.toThrow('este navegador no admite passkeys (WebAuthn)');
  });
});
