/** Served next to the app as config.json (compose mounts infra/web/admin-config.json at /admin/config.json). */
export interface AdminConfig {
  policyEngineUrl: string;
  /** Unset: the identity lookup tab is hidden. */
  identityServiceUrl?: string;
  /** Development only: allow signing in by pasting an nsec. Never enable in production. */
  devLocalKey?: boolean;
}

export async function loadConfig(): Promise<AdminConfig> {
  const res = await fetch('./config.json', { cache: 'no-store' });
  if (!res.ok) throw new Error(`config.json: HTTP ${res.status}`);
  const cfg = (await res.json()) as Partial<AdminConfig>;
  if (!cfg.policyEngineUrl) throw new Error('config.json: falta policyEngineUrl');
  return { ...cfg, policyEngineUrl: cfg.policyEngineUrl };
}
