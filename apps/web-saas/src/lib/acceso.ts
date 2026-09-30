import { Amplify } from 'aws-amplify';
import { confirmSignIn, fetchAuthSession, getCurrentUser, signIn, signOut } from 'aws-amplify/auth';
import { cognitoUserPoolsTokenProvider } from 'aws-amplify/auth/cognito';
import { CookieStorage, defaultStorage, type KeyValueStorageInterface } from 'aws-amplify/utils';
import { announceSignOut } from './authChannel';
import type { CognitoSettings } from './config';

/**
 * Acceso login (AWS Cognito through Amplify), configured like acceso-frontend: same user pool, and the
 * session shared through cookies on the Acceso domain when cookieDomain is set. The Cognito session
 * only gates the SaaS; the Nostr key never leaves the browser vault.
 */
export interface AccesoUser {
  username: string;
}

export type SignInResult = { done: true; user: AccesoUser } | { done: false; step: 'NEW_PASSWORD_REQUIRED' };

let settings: CognitoSettings | undefined;
/** Where Amplify keeps this browser's Acceso tokens: its default storage, or the cookies shared with acceso-frontend. */
let tokenStorage: KeyValueStorageInterface = defaultStorage;
/** IR-2026-10-03: an isolated sign-in in progress (accesoReauthenticate); token reads wait for it. Never rejects. */
let reauthenticating: Promise<unknown> | undefined;

export function configureAcceso(c: CognitoSettings): void {
  settings = c;
  Amplify.configure({ Auth: { Cognito: { userPoolId: c.userPoolId, userPoolClientId: c.userPoolClientId } } });
  tokenStorage = c.cookieDomain ? new CookieStorage({ domain: c.cookieDomain, secure: true, sameSite: 'none' }) : defaultStorage;
  cognitoUserPoolsTokenProvider.setKeyValueStorage(tokenStorage);
}

/** The tokens of an isolated sign-in: what it wrote is the new session. */
class ScratchStorage implements KeyValueStorageInterface {
  readonly items = new Map<string, string>();
  async setItem(key: string, value: string) {
    this.items.set(key, value);
  }
  async getItem(key: string) {
    return this.items.get(key) ?? null;
  }
  async removeItem(key: string) {
    this.items.delete(key);
  }
  async clear() {
    this.items.clear();
  }
}

/**
 * IR-2026-10-03: signs in again with the password, for what the managed-signer only accepts from a recent sign-in
 * (exporting, migrating, deleting or cancelling the managed key; closing the other sessions). The new sign-in runs
 * apart from the current session, which stays as it was if the password is wrong or the sign-in asks for another step;
 * once it succeeds for the same user, its tokens become this browser's session. Whoever has this browser open but not
 * the password cannot do it.
 */
export async function accesoReauthenticate(password: string): Promise<void> {
  await reauthenticating;
  const run = (async () => {
    const before = await getCurrentUser();
    const scratch = new ScratchStorage();
    cognitoUserPoolsTokenProvider.setKeyValueStorage(scratch);
    let userId: string;
    try {
      const res = await signIn({ username: before.username, password, options: { authFlowType: settings?.authFlowType ?? 'USER_SRP_AUTH' } });
      if (res.nextStep.signInStep !== 'DONE') throw new Error(`paso de inicio de sesión no soportado al confirmar que eres tú: ${res.nextStep.signInStep}`);
      userId = (await getCurrentUser()).userId;
    } finally {
      cognitoUserPoolsTokenProvider.setKeyValueStorage(tokenStorage);
    }
    if (userId !== before.userId) throw new Error('esa contraseña es de otra cuenta de Acceso');
    for (const [key, value] of scratch.items) await tokenStorage.setItem(key, value);
  })();
  reauthenticating = run.catch(() => undefined);
  try {
    await run;
  } finally {
    reauthenticating = undefined;
  }
}

export async function currentAccesoUser(): Promise<AccesoUser | undefined> {
  await reauthenticating;
  try {
    const u = await getCurrentUser();
    return { username: u.username };
  } catch {
    return undefined;
  }
}

async function after(nextStep: string): Promise<SignInResult> {
  if (nextStep === 'DONE') return { done: true, user: (await currentAccesoUser())! };
  if (nextStep === 'CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED') return { done: false, step: 'NEW_PASSWORD_REQUIRED' };
  throw new Error(`paso de inicio de sesión no soportado: ${nextStep}`);
}

export async function accesoSignIn(username: string, password: string): Promise<SignInResult> {
  const res = await signIn({ username, password, options: { authFlowType: settings?.authFlowType ?? 'USER_SRP_AUTH' } });
  return after(res.nextStep.signInStep);
}

export async function accesoNewPassword(newPassword: string): Promise<SignInResult> {
  const res = await confirmSignIn({ challengeResponse: newPassword });
  return after(res.nextStep.signInStep);
}

/** ID token to attach the Acceso login to an identity-service account (sent only on explicit consent). */
export async function accesoIdToken(): Promise<string> {
  await reauthenticating;
  const t = (await fetchAuthSession()).tokens?.idToken?.toString();
  if (!t) throw new Error('sin sesión de Acceso');
  return t;
}

/** Access token that authorizes each managed signature (FR005-04). */
export async function accesoAccessToken(): Promise<string> {
  await reauthenticating;
  const t = (await fetchAuthSession()).tokens?.accessToken?.toString();
  if (!t) throw new Error('sin sesión de Acceso');
  return t;
}

export async function accesoSignOut(): Promise<void> {
  await signOut();
  announceSignOut();
}
