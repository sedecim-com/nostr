// NIP-46 auth_url challenges (FR004-05) are raised deep inside signers; the workspace shows them.
let handler: ((url: string) => void) | undefined;

export function onSignerAuthUrl(fn: (url: string) => void): () => void {
  handler = fn;
  return () => {
    if (handler === fn) handler = undefined;
  };
}

export function raiseSignerAuthUrl(url: string): void {
  handler?.(url);
}
