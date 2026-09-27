/**
 * Entry point of the enclave image (EIF). Inside the enclave the only I/O is vsock: socat maps
 * VSOCK-LISTEN:5005 to ENCLAVE_LISTEN and a local TCP port to vsock-proxy for KMS (docs/managed-enclave.md).
 *
 *   ENCLAVE_LISTEN        unix socket path or TCP port (default /run/enclave-signer.sock)
 *   ENCLAVE_KMS_KEY_ID    KMS key whose policy requires this image's PCRs
 *   ENCLAVE_KMS_REGION    default us-east-1 (ADR 0009)
 *   ENCLAVE_KMS_ENDPOINT  KMS endpoint through the vsock-proxy bridge
 *   ENCLAVE_NSM_HELPER    NSM attestation helper (see ExecNsm)
 *   ENCLAVE_ALLOW_EXPORT  0 disables FR-026 export
 */
import { EnclaveSigner, ExecNsm } from './enclave';
import { awsEnclaveKms } from './kms';
import { serveEnclave } from './protocol';

const env = process.env;
if (!env.ENCLAVE_KMS_KEY_ID) throw new Error('ENCLAVE_KMS_KEY_ID is required');
if (!env.ENCLAVE_NSM_HELPER) throw new Error('ENCLAVE_NSM_HELPER is required');

const signer = new EnclaveSigner({
  nsm: new ExecNsm(env.ENCLAVE_NSM_HELPER),
  kms: awsEnclaveKms({ region: env.ENCLAVE_KMS_REGION || 'us-east-1', ...(env.ENCLAVE_KMS_ENDPOINT ? { endpoint: env.ENCLAVE_KMS_ENDPOINT } : {}) }),
  kmsKeyId: env.ENCLAVE_KMS_KEY_ID,
  allowExport: env.ENCLAVE_ALLOW_EXPORT !== '0',
});
const listen = env.ENCLAVE_LISTEN || '/run/enclave-signer.sock';
await serveEnclave(signer, /^\d+$/.test(listen) ? { port: Number(listen), host: '127.0.0.1' } : { path: listen });
// No request content is ever logged (the console is visible to the parent in debug mode only).
console.log(`enclave signer listening on ${listen}`);
