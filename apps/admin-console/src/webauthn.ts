import type { CreationOptionsJSON, PolicyAdminApi, RegistrationCredentialJSON } from './api';

export function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToB64url(b: ArrayBuffer | Uint8Array): string {
  const bytes = b instanceof Uint8Array ? b : new Uint8Array(b);
  let bin = '';
  for (const x of bytes) bin += String.fromCharCode(x);
  const b64 = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_');
  let end = b64.length;
  while (end > 0 && b64[end - 1] === '=') end--; // no /=+$/: linear time
  return b64.slice(0, end);
}

/** JSON options from the server → the binary form navigator.credentials.create expects. */
export function creationOptionsFromJSON(o: CreationOptionsJSON): PublicKeyCredentialCreationOptions {
  const { excludeCredentials, ...rest } = o;
  return {
    ...rest,
    challenge: b64urlToBytes(o.challenge),
    user: { ...o.user, id: b64urlToBytes(o.user.id) },
    ...(excludeCredentials ? { excludeCredentials: excludeCredentials.map((c) => ({ type: c.type, id: b64urlToBytes(c.id), ...(c.transports ? { transports: c.transports as AuthenticatorTransport[] } : {}) })) } : {}),
  };
}

export function credentialToJSON(c: PublicKeyCredential): RegistrationCredentialJSON {
  const r = c.response as AuthenticatorAttestationResponse;
  return {
    id: c.id,
    rawId: bytesToB64url(c.rawId),
    type: 'public-key',
    authenticatorAttachment: c.authenticatorAttachment,
    response: { clientDataJSON: bytesToB64url(r.clientDataJSON), attestationObject: bytesToB64url(r.attestationObject), ...(r.getTransports ? { transports: r.getTransports() } : {}) },
    clientExtensionResults: c.getClientExtensionResults() as Record<string, unknown>,
  };
}

export const webauthnAvailable = () => typeof window !== 'undefined' && 'PublicKeyCredential' in window && !!navigator.credentials;

/** Options from the policy-engine → authenticator ceremony → attestation back to the policy-engine. */
export async function registerPasskey(api: PolicyAdminApi, deviceId: string) {
  if (!webauthnAvailable()) throw new Error('este navegador no admite passkeys (WebAuthn)');
  const options = creationOptionsFromJSON(await api.webauthnOptions(deviceId));
  const cred = (await navigator.credentials.create({ publicKey: options })) as PublicKeyCredential | null;
  if (!cred) throw new Error('el autenticador no devolvió ninguna credencial');
  return api.webauthnRegister(deviceId, credentialToJSON(cred));
}
