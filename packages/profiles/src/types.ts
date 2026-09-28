export type CustodyOption = 'local' | 'offline' | 'external' | 'encrypted-backup' | 'managed' | 'managed-enclave';
export type NetworkOption = 'direct' | 'private-relay' | 'multi-relay' | 'tor-only';
export type IdentityOption = 'pseudonymous' | 'linked' | 'verified';
export type PersistenceOption = 'device' | 'relay' | 'replicated' | 'encrypted-cloud';
export type MessagingOption = 'nip17' | 'marmot';
export type FilesOption = 'relay-plain' | 'client-encrypted';
export type TelemetryOption = 'standard' | 'minimal' | 'none';
export type NotificationsOption = 'push' | 'privacy-push' | 'none';
export type CloudBackupOption = 'off' | 'ciphertext-user-key' | 'operator-managed';
export type CrashReportsOption = 'off' | 'manual-export' | 'opt-in';
/** How the local vault is unlocked (ADR 0007). */
export type LocalProtectionOption = 'passphrase' | 'device';
export type Platform = 'web' | 'desktop' | 'mobile' | 'cli';

/** The eight controls of the sovereignty/privacy panel (spec §9) plus Tor-mode specifics (§14). */
export interface SovereigntyConfig {
  custody: CustodyOption;
  network: NetworkOption;
  identity: IdentityOption;
  persistence: PersistenceOption;
  messaging: MessagingOption;
  files: FilesOption;
  telemetry: TelemetryOption;
  notifications: NotificationsOption;
  cloudBackup: CloudBackupOption;
  crashReports: CrashReportsOption;
  /** 'device': unlock without a passphrase in this browser/device; only for the convenience profile. */
  localProtection: LocalProtectionOption;
  remotePreviews: boolean;
  /** Gift-wrapped "delivered" receipts (ADR 0005). */
  deliveryReceipts: boolean;
  /** Gift-wrapped "read" receipts: always opt-in (ADR 0005). */
  readReceipts: boolean;
  /** relay acceptances required before a message counts as REPLICATED */
  quorum: number;
  stripFileMetadata: boolean;
}

/** The four independent dimensions the panel must keep separate (spec §9). */
export type Dimension = 'soberania' | 'privacidad-operador' | 'recuperabilidad' | 'control-institucional';

export interface Disclosure {
  control: keyof SovereigntyConfig;
  option: string;
  /** Verifiable statement shown to the user (never "100% anónimo"). */
  statement: string;
  /** What this choice improves and what it sacrifices. */
  improves: Dimension[];
  sacrifices: Dimension[];
  trustAssumptions: string[];
}

/** What validateConfig can check beyond the configuration itself. */
export interface ValidationContext {
  /** Relays of the persona the configuration applies to. */
  relays?: number;
}

export interface ValidationIssue {
  severity: 'error' | 'warning';
  code: string;
  message: string;
  controls: Array<keyof SovereigntyConfig>;
}
