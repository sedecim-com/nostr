import { DecryptCommand, GenerateDataKeyCommand, KMSClient } from '@aws-sdk/client-kms';
import type { AwsCredentials } from './protocol';

/**
 * KMS calls made from inside the enclave. Both pass the attestation document as Recipient, so KMS answers
 * with CiphertextForRecipient (CMS encrypted to the enclave's ephemeral RSA key) instead of plaintext, and
 * the key policy can require kms:RecipientAttestation:ImageSha384 / PCRn (deploy/terraform, enclave.tf).
 */
export interface EnclaveKms {
  generateDataKey(req: { keyId: string; context: Record<string, string>; attestationDocument: Uint8Array; credentials?: AwsCredentials }): Promise<{
    ciphertextBlob: Uint8Array;
    ciphertextForRecipient: Uint8Array;
  }>;
  decrypt(req: { keyId: string; ciphertextBlob: Uint8Array; context: Record<string, string>; attestationDocument: Uint8Array; credentials?: AwsCredentials }): Promise<{
    ciphertextForRecipient: Uint8Array;
  }>;
}

export interface EnclaveKmsConfig {
  region: string;
  /**
   * KMS endpoint reachable from the enclave. The enclave has no network: a socat bridge inside it forwards
   * to vsock-proxy on the parent (`vsock-proxy 8000 kms.<region>.amazonaws.com 443`). TLS terminates here.
   */
  endpoint?: string;
}

const RECIPIENT_ALG = 'RSAES_OAEP_SHA_256';

/** SDK v3 adapter. A client per call because credentials arrive with each request from the parent. */
export function awsEnclaveKms(cfg: EnclaveKmsConfig): EnclaveKms {
  const client = (credentials?: AwsCredentials) => new KMSClient({ region: cfg.region, ...(cfg.endpoint ? { endpoint: cfg.endpoint } : {}), ...(credentials ? { credentials } : {}) });
  return {
    async generateDataKey({ keyId, context, attestationDocument, credentials }) {
      const out = await client(credentials).send(
        new GenerateDataKeyCommand({ KeyId: keyId, KeySpec: 'AES_256', EncryptionContext: context, Recipient: { KeyEncryptionAlgorithm: RECIPIENT_ALG, AttestationDocument: attestationDocument } }),
      );
      if (out.Plaintext?.length) throw new Error('KMS returned a plaintext data key: Recipient was ignored');
      if (!out.CiphertextBlob || !out.CiphertextForRecipient) throw new Error('KMS GenerateDataKey returned no recipient ciphertext');
      return { ciphertextBlob: out.CiphertextBlob, ciphertextForRecipient: out.CiphertextForRecipient };
    },
    async decrypt({ keyId, ciphertextBlob, context, attestationDocument, credentials }) {
      const out = await client(credentials).send(
        new DecryptCommand({ KeyId: keyId, CiphertextBlob: ciphertextBlob, EncryptionContext: context, Recipient: { KeyEncryptionAlgorithm: RECIPIENT_ALG, AttestationDocument: attestationDocument } }),
      );
      if (out.Plaintext?.length) throw new Error('KMS returned plaintext: Recipient was ignored');
      if (!out.CiphertextForRecipient) throw new Error('KMS Decrypt returned no recipient ciphertext');
      return { ciphertextForRecipient: out.CiphertextForRecipient };
    },
  };
}
