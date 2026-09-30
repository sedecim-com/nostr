import type { DeploymentFlags } from '@sedecim/messaging';
import { normalizePubkey } from '@sedecim/nostr-core';

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
   * FR024-03: the organisation registers each browser as a device in its policy-engine. The managed persona then offers
   * to bind this browser's session to that device id, so that revoking the device turns this browser away.
   */
  organizationDevices?: boolean;
  /**
   * FR024-05: npub (or hex) of the organisation's rotation worker (services/rotation-worker). Set: every group created
   * here lists it as an admin and invites it, so that it can remove a member whose device the organisation revokes.
   * While in a group it can decrypt it; the group shows it as a member. Unset: groups get no such member.
   */
  rotationWorker?: string;
  /**
   * FR010-03: extra relays where the recipients' DM relay lists (kinds 10050 and 10002) are looked up, besides the
   * persona's own relays, e.g. an indexer that collects relay lists. Unset: only the persona's relays. Each lookup
   * tells those relays which npub you are about to write to.
   */
  discoveryRelays?: string[];
  /**
   * FR014-04: services/indexer base URL (its PUBLIC_BASE_URL, which NIP-98 signatures name). Unread counts and search
   * of channels for the personas whose profile allows it (mirrorPolicy); the read cursors stay in this browser. Unset:
   * the channels view shows neither.
   */
  mirror?: string;
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
  /**
   * VAULT-02 (ADR 0011): services/continuity-vault base URL. Unset: the Continuity Vault card is not shown. Only
   * envelopes sealed in the browser with the persona's archive key are uploaded; the operator sees the account,
   * how many archives, their size and when they change.
   */
  continuityVault?: string;
  /** SaaS only: custodial managed-signer (opt-in, ADR 0009). */
  managedSigner?: string;
  /**
   * FR005-08: the published terms of the managed custody (docs/legal/custodia-managed.md once legal approves it),
   * linked from the opt-in. Their version is recorded with the consent. Unset: the opt-in says they are not
   * published and records that.
   */
  managedTerms?: { url: string; version: string };
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
  // A worker the groups cannot add would leave them without rotation: a wrong key is a configuration error.
  if (cfg.rotationWorker) {
    try {
      cfg = { ...cfg, rotationWorker: normalizePubkey(cfg.rotationWorker) };
    } catch {
      throw new Error('config.json: rotationWorker debe ser una npub o 64 caracteres hex');
    }
  }
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
