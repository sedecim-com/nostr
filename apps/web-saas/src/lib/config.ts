import type { DeploymentFlags } from '@sedecim/messaging';

export interface CognitoSettings {
  region: string;
  userPoolId: string;
  userPoolClientId: string;
  /** Same as Acceso: share the Amplify session through cookies on this domain (e.g. "dev.acce.so"). */
  cookieDomain?: string;
  authFlowType?: 'USER_SRP_AUTH' | 'USER_PASSWORD_AUTH';
}

/** Deployment settings served next to the app as config.json (compose mounts infra/web/config.json). */
export interface DeploymentConfig {
  /** 'saas': an Acceso (Cognito) login is required before any identity is opened (ADR 0008). */
  mode: 'self-hosted' | 'saas';
  relays: string[];
  /**
   * FR025-07 / ADR 0006: secondary secure relay(s) for Marmot/MLS groups (kinds 30443/444/445/10051), which
   * the pinned Buzz rejects. Unset: groups use the persona relays.
   */
  secureRelays?: string[];
  /**
   * FR010-03: extra relays where the recipients' DM relay lists (kinds 10050 and 10002) are looked up, besides the
   * persona's own relays, e.g. an indexer that collects relay lists. Unset: only the persona's relays. Each lookup
   * tells those relays which npub you are about to write to.
   */
  discoveryRelays?: string[];
  /** Blossom server of the Buzz relay: plain, sanitized channel images (FR018-04). */
  buzzMedia?: string;
  /** Client-encrypted blobs (DM attachments). */
  blobStore?: string;
  identityService?: string;
  /**
   * FR027-03: identity-service base URL of the encrypted backup vault (usually the same as
   * identityService). Unset: the cloud copy is not offered. Only ciphertext under the user's backup
   * password is uploaded.
   */
  backupVault?: string;
  /** SaaS only: custodial managed-signer (opt-in, ADR 0009). */
  managedSigner?: string;
  cognito?: CognitoSettings;
  /**
   * ADR 0010: services/notification-gateway base URL. Unset: the "Notificaciones" control is not shown.
   * Pushes are opaque (no content, sender or count); sovereign and Tor personas never register.
   */
  notificationGateway?: string;
}

export const DEFAULT_CONFIG: DeploymentConfig = { mode: 'self-hosted', relays: ['ws://localhost:3000'] };

export async function loadConfig(): Promise<DeploymentConfig> {
  let cfg: DeploymentConfig;
  try {
    const res = await fetch('./config.json', { cache: 'no-store' });
    cfg = res.ok ? { ...DEFAULT_CONFIG, ...((await res.json()) as Partial<DeploymentConfig>) } : DEFAULT_CONFIG;
  } catch {
    cfg = DEFAULT_CONFIG;
  }
  // Fail closed: a SaaS deployment without Cognito settings must not silently run without login.
  if (cfg.mode === 'saas' && !cfg.cognito) throw new Error('config.json: mode "saas" requiere la configuración de cognito');
  return cfg;
}

export async function loadFlags(): Promise<DeploymentFlags | undefined> {
  try {
    const res = await fetch('./flags.json', { cache: 'no-store' });
    return res.ok ? ((await res.json()) as DeploymentFlags) : undefined;
  } catch {
    return undefined;
  }
}
