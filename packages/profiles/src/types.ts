export type CustodyOption = 'local' | 'offline' | 'external' | 'encrypted-backup' | 'managed' | 'managed-enclave';
export type NetworkOption = 'direct' | 'private-relay' | 'multi-relay' | 'tor-only';
export type IdentityOption = 'pseudonymous' | 'linked' | 'verified';
export type PersistenceOption = 'device' | 'relay' | 'replicated' | 'encrypted-cloud';
export type MessagingOption = 'nip17' | 'marmot';
export type FilesOption = 'relay-plain' | 'client-encrypted';
export type TelemetryOption = 'standard' | 'minimal' | 'none';
export type NotificationsOption = 'push' | 'privacy-push' | 'none';
export type CloudBackupOption = 'off' | 'ciphertext-user-key' | 'operator-managed';
/**
 * VAULT-04 (ADR 0011): the copy of each sent event in the Continuity Vault. `best-effort` never delays a send;
 * `required-for-resilient` holds it until its copy is in the vault.
 */
export type ContinuityOption = 'off' | 'best-effort' | 'required-for-resilient';
export type CrashReportsOption = 'off' | 'manual-export' | 'opt-in';
/**
 * FR015-05: NIP-38 user status (kind 30315). `status`: the persona publishes the statuses its user writes and reads
 * those of the keys whose profiles it already looks up. Off in every preset; presencePolicy says which profiles allow it.
 */
export type PresenceOption = 'off' | 'status';
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
  /** VAULT-04: configurations stored before it have none, which means `off` (see `continuityPolicy`). */
  continuity: ContinuityOption;
  crashReports: CrashReportsOption;
  /** FR015-05: configurations stored before it have none, which means `off` (see `presenceOption`). */
  presence: PresenceOption;
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
  /** VAULT-04: whether a Continuity Vault is configured for the persona (unknown when undefined). */
  continuityVault?: boolean;
}

export interface ValidationIssue {
  severity: 'error' | 'warning';
  code: string;
  message: string;
  controls: Array<keyof SovereigntyConfig>;
}
