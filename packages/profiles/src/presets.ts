import type { SovereigntyConfig } from './types';

/**
 * Reference configuration matrix (spec Appendix B). Crash reports (NFR007-03, docs/crash-reports.md) never leave the
 * device by themselves: 'manual-export' (the last failure, not stored, saved in a file only by hand) where Appendix B
 * has 'manual-export' or 'opt-in', and 'off' in private-resilient and sovereign-tor. No preset picks 'opt-in', which
 * keeps reports in the device's store: only the person turns it on. VAULT-04: private-resilient holds each send until
 * its copy is in the Continuity Vault; the sovereign profiles keep everything on the device.
 *
 * Custody is the profile's reference, not a persona's: the sovereign profiles say 'offline' because spec §14 keeps
 * their key offline or in a signer. A client declares the custody of the persona's real key instead, never a promise
 * above it (PANEL-05, FR004-08): the sovereign CLI declares 'local' for a key sealed on the device (created there or
 * imported) and 'external' for a NIP-46 signer; validateConfig warns when a Tor-only key is on the device.
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
    crashReports: 'manual-export',
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
    crashReports: 'manual-export',
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
    crashReports: 'manual-export',
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
