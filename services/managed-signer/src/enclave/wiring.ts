import { KMSClient } from '@aws-sdk/client-kms';
import { NITRO_ROOT_G1_SHA256 } from './attestation';
import { EnclaveClient } from './client';
import { proofVerifierFromEnv, type UserProofVerifier } from './proof';
import { inProcessTransport, socketTransport, type AwsCredentials } from './protocol';
import { createSimulatedEnclave, SIMULATION_WARNING } from './simulated';

export interface EnclaveBackend {
  client: EnclaveClient;
  /** True for the in-process simulation (NOT SECURE). */
  simulated: boolean;
}

const PCR = /^[0-9a-f]{96}$/i;

/**
 * MANAGED_SIGNER_BACKEND=enclave: signing is routed to the enclave client. Returns undefined for the default
 * in-process backend (`local`).
 *
 *   MANAGED_SIGNER_ENCLAVE_SOCKET      unix socket path or host:port of the socat bridge to vsock
 *   MANAGED_SIGNER_ENCLAVE_PCR0/1/2    expected measurements (hex, from `nitro-cli build-enclave`); PCR8 optional
 *   MANAGED_SIGNER_ENCLAVE_ROOT_SHA256 root pin override (default: AWS Nitro G1)
 *   MANAGED_SIGNER_ENCLAVE_SIMULATED=1 in-process simulated enclave, NOT SECURE, refused with NODE_ENV=production
 *   MANAGED_SIGNER_ENCLAVE_PROOF_ISSUER / _CLIENT_ID / _JWKS / _MAX_AGE_S  (simulated only) the user pool the simulated
 *       enclave checks export proofs against (FR005-09); `_JWKS` is the path of the pool's jwks.json. Without them the
 *       simulated enclave refuses every export, like the real one does without the keys pinned in its image.
 */
export function enclaveBackendFromEnv(env: NodeJS.ProcessEnv, warn: (msg: string) => void = console.warn, opts: { proof?: UserProofVerifier } = {}): EnclaveBackend | undefined {
  const kind = env.MANAGED_SIGNER_BACKEND || 'local';
  if (kind === 'local') return undefined;
  if (kind !== 'enclave') throw new Error(`MANAGED_SIGNER_BACKEND must be 'local' or 'enclave', got '${kind}'`);

  if (env.MANAGED_SIGNER_ENCLAVE_SIMULATED === '1') {
    if (env.NODE_ENV === 'production') throw new Error('MANAGED_SIGNER_ENCLAVE_SIMULATED=1 is refused with NODE_ENV=production');
    warn(SIMULATION_WARNING);
    const proof = opts.proof ?? proofVerifierFromEnv(env, 'MANAGED_SIGNER_ENCLAVE_PROOF');
    const sim = createSimulatedEnclave(proof ? { proof } : {});
    return { client: new EnclaveClient({ transport: inProcessTransport(sim.enclave), attestation: sim.policy, provider: 'simulated-enclave' }), simulated: true };
  }

  const socket = env.MANAGED_SIGNER_ENCLAVE_SOCKET;
  if (!socket) throw new Error('MANAGED_SIGNER_ENCLAVE_SOCKET is required with MANAGED_SIGNER_BACKEND=enclave');
  const expectedPcrs: Record<number, string> = {};
  for (const i of [0, 1, 2, 8]) {
    const v = env[`MANAGED_SIGNER_ENCLAVE_PCR${i}`];
    if (!v) {
      if (i !== 8) throw new Error(`MANAGED_SIGNER_ENCLAVE_PCR${i} is required with MANAGED_SIGNER_BACKEND=enclave`);
      continue;
    }
    if (!PCR.test(v)) throw new Error(`MANAGED_SIGNER_ENCLAVE_PCR${i} must be 96 hex chars`);
    expectedPcrs[i] = v.toLowerCase();
  }
  const hostPort = /^([^/:]+):(\d+)$/.exec(socket);
  const transport = socketTransport(hostPort ? { host: hostPort[1]!, port: Number(hostPort[2]) } : { path: socket });

  // The enclave calls KMS with the parent's principal (IAM user on kops, instance role on a Nitro host).
  const kms = new KMSClient({ region: env.AWS_REGION || 'us-east-1' });
  const credentials = async (): Promise<AwsCredentials> => {
    const c = await kms.config.credentials();
    return { accessKeyId: c.accessKeyId, secretAccessKey: c.secretAccessKey, ...(c.sessionToken ? { sessionToken: c.sessionToken } : {}) };
  };
  const client = new EnclaveClient({
    transport,
    credentials,
    attestation: { expectedPcrs, trustedRootFingerprints: [env.MANAGED_SIGNER_ENCLAVE_ROOT_SHA256 || NITRO_ROOT_G1_SHA256], requirePublicKey: true },
  });
  return { client, simulated: false };
}
