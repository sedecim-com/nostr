import { fileURLToPath } from 'node:url';
import { hexToBytes } from '@sedecim/nostr-core';
import { createPgPool, migrate } from '@sedecim/service-kit';
import { awsKms, awsSecretsManager, DEFAULT_AWS_REGION } from './aws';
import { MemoryDeviceStore, PgDeviceStore, type DeviceStore } from './devices';
import { MemoryKeyRegistry, PgKeyRegistry, type KeyRegistry } from './registry';
import { LocalEnvelopeVault, SecretsManagerVault, type Vault } from './vault';

export interface ManagedSignerStorage {
  vault: Vault;
  registry: KeyRegistry;
  devices: DeviceStore;
  /** Days the material is kept after a key is deleted (DEC-09: 30). */
  retentionDays: number;
  /** Months the usage log is kept (DEC-09: 12). */
  usageRetentionMonths: number;
  /** Whether the registry survives this process (Postgres) or not (memory). */
  persistent: boolean;
}

/**
 * The vault, key registry and device store the configuration names, shared by the service (main.ts) and the operator
 * commands (ops.ts) so both always act on the same storage.
 */
export async function openStorage(env: NodeJS.ProcessEnv): Promise<ManagedSignerStorage> {
  const retentionDays = Number(env.MANAGED_SIGNER_RETENTION_DAYS ?? 30);
  const usageRetentionMonths = Number(env.MANAGED_SIGNER_USAGE_RETENTION_MONTHS ?? 12);
  const region = env.AWS_REGION || DEFAULT_AWS_REGION;

  // Vault: local envelope files (self-hosted) or AWS Secrets Manager + KMS (SaaS, DEC-09).
  let vault: Vault;
  const vaultKind = env.MANAGED_SIGNER_VAULT || 'local';
  if (vaultKind === 'aws') {
    if (!env.MANAGED_SIGNER_KMS_KEY_ID) throw new Error('MANAGED_SIGNER_KMS_KEY_ID is required with MANAGED_SIGNER_VAULT=aws');
    const aws = { region, ...(env.MANAGED_SIGNER_AWS_ENDPOINT ? { endpoint: env.MANAGED_SIGNER_AWS_ENDPOINT } : {}) };
    vault = new SecretsManagerVault(awsSecretsManager(aws), awsKms(aws), {
      kmsKeyId: env.MANAGED_SIGNER_KMS_KEY_ID,
      retentionDays,
      ...(env.MANAGED_SIGNER_SECRET_PREFIX ? { prefix: env.MANAGED_SIGNER_SECRET_PREFIX } : {}),
    });
  } else if (vaultKind === 'local') {
    if (!env.MANAGED_SIGNER_KEK || !/^[0-9a-f]{64}$/.test(env.MANAGED_SIGNER_KEK)) throw new Error('MANAGED_SIGNER_KEK (64 hex chars) is required with MANAGED_SIGNER_VAULT=local');
    vault = new LocalEnvelopeVault(env.MANAGED_SIGNER_VAULT_DIR ?? '/data/vault', hexToBytes(env.MANAGED_SIGNER_KEK));
  } else throw new Error(`MANAGED_SIGNER_VAULT must be 'local' or 'aws', got '${vaultKind}'`);

  if (!env.DATABASE_URL) return { vault, registry: new MemoryKeyRegistry(), devices: new MemoryDeviceStore(), retentionDays, usageRetentionMonths, persistent: false };
  const pool = createPgPool(env.DATABASE_URL);
  await migrate(pool, fileURLToPath(new URL('../migrations', import.meta.url)), 'managed-signer');
  return { vault, registry: new PgKeyRegistry(pool), devices: new PgDeviceStore(pool), retentionDays, usageRetentionMonths, persistent: true };
}
