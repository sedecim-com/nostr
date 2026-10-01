/**
 * Entry point of the enclave image (EIF). Inside the enclave the only I/O is vsock: socat maps
 * VSOCK-LISTEN:5005 to ENCLAVE_LISTEN and a local TCP port to vsock-proxy for KMS (docs/managed-enclave.md).
 *
 *   ENCLAVE_LISTEN        unix socket path or TCP port (default /run/enclave-signer.sock)
 *   ENCLAVE_KMS_KEY_ID    KMS key whose policy requires this image's PCRs
 *   ENCLAVE_KMS_REGION    default us-east-1 (ADR 0009)
 *   ENCLAVE_KMS_ENDPOINT  KMS endpoint through the vsock-proxy bridge
 *   ENCLAVE_NSM_HELPER    NSM attestation helper (see ExecNsm)
 *   ENCLAVE_ALLOW_EXPORT  1 enables FR-026 export (off by default: IR-2026-09-01); it then needs the four below
 *   ENCLAVE_PROOF_ISSUER     `iss` of the Acceso user pool whose tokens prove the owner (FR005-09)
 *   ENCLAVE_PROOF_CLIENT_ID  app client id of the Acceso web client (`aud` / `client_id`)
 *   ENCLAVE_PROOF_JWKS       path, inside the image, of the pool's jwks.json: the signing keys are pinned in the EIF
 *                            and so are part of its measurements (PCR0/PCR2); rotating them means a new image
 *   ENCLAVE_PROOF_MAX_AGE_S  how recent the password sign-in must be (default 300)
 *   ENCLAVE_REQUIRE_SEALED_SECRETS  1: import secrets and export passwords only sealed by the client to this enclave's
 *                            attested key (FR005-10); in clear, where the parent can read them, they are refused (403)
 */
import { EnclaveSigner, ExecNsm } from './enclave';
import { awsEnclaveKms } from './kms';
import { exportConfigFromEnv } from './proof';
import { serveEnclave } from './protocol';
import { flagFromEnv } from './sealed-secrets';

const env = process.env;
if (!env.ENCLAVE_KMS_KEY_ID) throw new Error('ENCLAVE_KMS_KEY_ID is required');
if (!env.ENCLAVE_NSM_HELPER) throw new Error('ENCLAVE_NSM_HELPER is required');
const { allowExport, proof } = exportConfigFromEnv(env);
const requireSealedSecrets = flagFromEnv(env, 'ENCLAVE_REQUIRE_SEALED_SECRETS');

const signer = new EnclaveSigner({
  nsm: new ExecNsm(env.ENCLAVE_NSM_HELPER),
  kms: awsEnclaveKms({ region: env.ENCLAVE_KMS_REGION || 'us-east-1', ...(env.ENCLAVE_KMS_ENDPOINT ? { endpoint: env.ENCLAVE_KMS_ENDPOINT } : {}) }),
  kmsKeyId: env.ENCLAVE_KMS_KEY_ID,
  allowExport,
  ...(proof ? { proof } : {}),
  requireSealedSecrets,
});
const listen = env.ENCLAVE_LISTEN || '/run/enclave-signer.sock';
await serveEnclave(signer, /^\d+$/.test(listen) ? { port: Number(listen), host: '127.0.0.1' } : { path: listen });
// No request content is ever logged (the console is visible to the parent in debug mode only).
console.log(`enclave signer listening on ${listen}`);
