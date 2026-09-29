import type { SovereigntyConfig } from './types';

/**
 * Reference configuration matrix (spec Appendix B). Crash reports are 'off' everywhere: they do not exist yet
 * (NFR007-03), and a preset must not promise them (PANEL-05). VAULT-04: private-resilient holds each send until
 * its copy is in the Continuity Vault; the sovereign profiles keep everything on the device.
 */
export const PRESETS = {
  convenience: {
    custody: 'local',
    network: 'direct',
    identity: 'linked',
    persistence: 'replicated',
    messaging: 'nip17',
    files: 'relay-plain',
    telemetry: 'minimal',
    notifications: 'push',
    cloudBackup: 'ciphertext-user-key',
    continuity: 'best-effort',
    crashReports: 'off',
    localProtection: 'passphrase',
    remotePreviews: true,
    deliveryReceipts: true,
    readReceipts: false,
    quorum: 1,
    stripFileMetadata: true,
  },
  'private-resilient': {
    custody: 'external',
    network: 'multi-relay',
    identity: 'pseudonymous',
    persistence: 'replicated',
    messaging: 'nip17',
    files: 'client-encrypted',
    telemetry: 'minimal',
    notifications: 'privacy-push',
    cloudBackup: 'ciphertext-user-key',
    continuity: 'required-for-resilient',
    crashReports: 'off',
    localProtection: 'passphrase',
    remotePreviews: false,
    deliveryReceipts: true,
    readReceipts: false,
    quorum: 2,
    stripFileMetadata: true,
  },
  institutional: {
    custody: 'managed',
    network: 'private-relay',
    identity: 'verified',
    persistence: 'replicated',
    messaging: 'marmot',
    files: 'client-encrypted',
    telemetry: 'standard',
    notifications: 'push',
    cloudBackup: 'operator-managed',
    continuity: 'best-effort',
    crashReports: 'off',
    localProtection: 'passphrase',
    remotePreviews: false,
    deliveryReceipts: true,
    readReceipts: false,
    quorum: 1,
    stripFileMetadata: true,
  },
  sovereign: {
    custody: 'offline',
    network: 'private-relay',
    identity: 'pseudonymous',
    persistence: 'device',
    messaging: 'nip17',
    files: 'client-encrypted',
    telemetry: 'none',
    notifications: 'none',
    cloudBackup: 'off',
    continuity: 'off',
    crashReports: 'off',
    localProtection: 'passphrase',
    remotePreviews: false,
    deliveryReceipts: false,
    readReceipts: false,
    quorum: 1,
    stripFileMetadata: true,
  },
  'sovereign-tor': {
    custody: 'offline',
    network: 'tor-only',
    identity: 'pseudonymous',
    persistence: 'device',
    messaging: 'marmot',
    files: 'client-encrypted',
    telemetry: 'none',
    notifications: 'none',
    cloudBackup: 'off',
    continuity: 'off',
    crashReports: 'off',
    localProtection: 'passphrase',
    remotePreviews: false,
    deliveryReceipts: false,
    readReceipts: false,
    quorum: 1,
    stripFileMetadata: true,
  },
} as const satisfies Record<string, SovereigntyConfig>;

export type PresetName = keyof typeof PRESETS;

export function preset(name: PresetName): SovereigntyConfig {
  return { ...PRESETS[name] };
}

/** VAULT-04: the Continuity Vault policy of a configuration; one stored before VAULT-04 has none, which is `off`. */
export function continuityPolicy(c: Partial<SovereigntyConfig>): SovereigntyConfig['continuity'] {
  return c.continuity ?? 'off';
}
