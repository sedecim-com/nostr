import { CreateSecretCommand, DeleteSecretCommand, GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { DecryptCommand, GenerateDataKeyCommand, KMSClient } from '@aws-sdk/client-kms';
import type { KmsLike, SecretsManagerLike } from './vault';

/** Region of Sedecim's Terraform and the Acceso Cognito pool (DEC-09). */
export const DEFAULT_AWS_REGION = 'us-east-1';

export interface AwsClientConfig {
  region?: string;
  /** Endpoint override (moto/LocalStack in tests). */
  endpoint?: string;
  /** Static credentials for tests; production uses the default provider chain (IAM role). */
  credentials?: { accessKeyId: string; secretAccessKey: string };
}

const clientConfig = (cfg: AwsClientConfig) => ({
  region: cfg.region || DEFAULT_AWS_REGION,
  ...(cfg.endpoint ? { endpoint: cfg.endpoint } : {}),
  ...(cfg.credentials ? { credentials: cfg.credentials } : {}),
});

const named = (err: unknown, name: string) => (err as { name?: string })?.name === name;

/** SDK v3 adapter for SecretsManagerVault. */
export function awsSecretsManager(cfg: AwsClientConfig = {}): SecretsManagerLike {
  const sm = new SecretsManagerClient(clientConfig(cfg));
  return {
    async createSecret(name, value) {
      await sm.send(new CreateSecretCommand({ Name: name, SecretString: value, Tags: [{ Key: 'app', Value: 'acceso-nostr' }] }));
    },
    async getSecretString(name) {
      try {
        return (await sm.send(new GetSecretValueCommand({ SecretId: name }))).SecretString;
      } catch (err) {
        if (named(err, 'ResourceNotFoundException')) return undefined;
        // A secret scheduled for deletion is unreadable until restored: treat it as gone.
        if (named(err, 'InvalidRequestException') && /marked (for )?delet/i.test((err as Error).message)) return undefined;
        throw err;
      }
    },
    async deleteSecret(name, recoveryWindowDays) {
      try {
        await sm.send(new DeleteSecretCommand({ SecretId: name, RecoveryWindowInDays: recoveryWindowDays }));
      } catch (err) {
        if (!named(err, 'ResourceNotFoundException')) throw err;
      }
    },
  };
}

/** SDK v3 adapter for the KMS envelope (GenerateDataKey / Decrypt pinned to the configured key). */
export function awsKms(cfg: AwsClientConfig = {}): KmsLike {
  const kms = new KMSClient(clientConfig(cfg));
  return {
    async generateDataKey(kmsKeyId, context) {
      const out = await kms.send(new GenerateDataKeyCommand({ KeyId: kmsKeyId, KeySpec: 'AES_256', EncryptionContext: context }));
      if (!out.Plaintext || !out.CiphertextBlob) throw new Error('KMS GenerateDataKey returned no key');
      return { plaintext: out.Plaintext, ciphertext: out.CiphertextBlob };
    },
    async decrypt(kmsKeyId, ciphertext, context) {
      const out = await kms.send(new DecryptCommand({ KeyId: kmsKeyId, CiphertextBlob: ciphertext, EncryptionContext: context }));
      if (!out.Plaintext) throw new Error('KMS Decrypt returned no plaintext');
      return out.Plaintext;
    },
  };
}
