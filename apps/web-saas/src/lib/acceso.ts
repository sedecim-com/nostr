import { Amplify } from 'aws-amplify';
import { confirmSignIn, fetchAuthSession, getCurrentUser, signIn, signOut } from 'aws-amplify/auth';
import { cognitoUserPoolsTokenProvider } from 'aws-amplify/auth/cognito';
import { CookieStorage } from 'aws-amplify/utils';
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

export function configureAcceso(c: CognitoSettings): void {
  settings = c;
  Amplify.configure({ Auth: { Cognito: { userPoolId: c.userPoolId, userPoolClientId: c.userPoolClientId } } });
  if (c.cookieDomain) cognitoUserPoolsTokenProvider.setKeyValueStorage(new CookieStorage({ domain: c.cookieDomain, secure: true, sameSite: 'none' }));
}

export async function currentAccesoUser(): Promise<AccesoUser | undefined> {
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
  const t = (await fetchAuthSession()).tokens?.idToken?.toString();
  if (!t) throw new Error('sin sesión de Acceso');
  return t;
}

/** Access token that authorizes each managed signature (FR005-04). */
export async function accesoAccessToken(): Promise<string> {
  const t = (await fetchAuthSession()).tokens?.accessToken?.toString();
  if (!t) throw new Error('sin sesión de Acceso');
  return t;
}

export async function accesoSignOut(): Promise<void> {
  await signOut();
  announceSignOut();
}
