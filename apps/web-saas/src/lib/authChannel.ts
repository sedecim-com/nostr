// Cross-tab sign-out, as acceso-frontend does with BroadcastChannel('auth'). Kept apart from Amplify so
// self-hosted deployments never load the Cognito SDK.
const channel = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('auth') : undefined;

export function announceSignOut(): void {
  channel?.postMessage('signout');
}

export function onAccesoSignOut(cb: () => void): () => void {
  const h = (e: MessageEvent) => e.data === 'signout' && cb();
  channel?.addEventListener('message', h);
  return () => channel?.removeEventListener('message', h);
}
