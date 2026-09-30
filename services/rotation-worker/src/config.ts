import { hexToBytes, nip19 } from '@sedecim/nostr-core';
import { normalizeRelayUrl } from '@sedecim/relay-pool';

/** A relay as clients name it (`public`: in the groups, key packages and NIP-42) and as the worker reaches it (`dial`). */
export interface RelayEntry {
  public: string;
  dial: string;
}

export interface RotationWorkerConfig {
  /** Worker identity: it must be an admin of every group it rotates (MIP-03). Not a policy-engine admin. */
  secretKey: Uint8Array;
  relays: RelayEntry[];
  policyUrl: string;
  /** Service bearer, one of the policy-engine POLICY_SERVICE_TOKENS: rotations and revocations are read with it. */
  policyToken: string;
  /** Where the MLS state is kept (a volume), encrypted with `stateKey`. */
  stateDir: string;
  stateKey: Uint8Array;
  intervalMs: number;
  /** FR024-03: managed-signer that receives the device revocations (one of MANAGED_SIGNER_REVOCATION_TOKENS). */
  managedSigner?: { baseUrl: string; token: string };
  port: number;
  host: string;
}

const HEX64 = /^[0-9a-f]{64}$/i;

/** `public=dial` or `url` entries, comma separated. */
export function parseRelays(value: string): RelayEntry[] {
  return value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((e) => {
      const [pub, dial] = e.split('=').map((s) => s.trim()) as [string, string | undefined];
      return { public: normalizeRelayUrl(pub), dial: normalizeRelayUrl(dial || pub) };
    });
}

function secretKey(raw: string): Uint8Array {
  if (raw.startsWith('nsec1')) {
    const d = nip19.decode(raw);
    if (d.type === 'nsec') return d.data;
  } else if (HEX64.test(raw)) return hexToBytes(raw.toLowerCase());
  throw new Error('ROTATION_WORKER_NSEC must be an nsec or 64 hex chars');
}

/** Reads the service configuration from the environment; throws naming every missing or invalid variable. */
export function parseConfig(env: Record<string, string | undefined>): RotationWorkerConfig {
  const errors: string[] = [];
  const required = (name: string) => {
    const v = env[name]?.trim();
    if (!v) errors.push(`${name} is required`);
    return v ?? '';
  };
  const nsec = required('ROTATION_WORKER_NSEC');
  const relaysRaw = required('ROTATION_WORKER_RELAYS');
  const policyToken = required('POLICY_ENGINE_TOKEN');
  const stateKeyRaw = required('ROTATION_STATE_KEY');

  let key: Uint8Array | undefined;
  if (nsec) {
    try {
      key = secretKey(nsec);
    } catch (e) {
      errors.push((e as Error).message);
    }
  }
  let relays: RelayEntry[] = [];
  if (relaysRaw) {
    try {
      relays = parseRelays(relaysRaw);
    } catch (e) {
      errors.push(`ROTATION_WORKER_RELAYS: ${(e as Error).message}`);
    }
  }
  if (stateKeyRaw && !HEX64.test(stateKeyRaw)) errors.push('ROTATION_STATE_KEY must be 64 hex chars (32 random bytes: openssl rand -hex 32)');
  const intervalMs = Number(env.ROTATION_INTERVAL_MS ?? 15_000);
  if (!Number.isInteger(intervalMs) || intervalMs < 1000) errors.push('ROTATION_INTERVAL_MS must be a whole number of milliseconds, at least 1000');
  const signerUrl = env.ROTATION_MANAGED_SIGNER_URL?.trim();
  const signerToken = env.ROTATION_MANAGED_SIGNER_TOKEN?.trim();
  if (!!signerUrl !== !!signerToken) errors.push('ROTATION_MANAGED_SIGNER_URL and ROTATION_MANAGED_SIGNER_TOKEN go together (device revocations to the managed-signer)');
  if (errors.length) throw new Error(`rotation worker configuration: ${errors.join('; ')}`);
  return {
    secretKey: key!,
    relays,
    policyUrl: env.POLICY_ENGINE_URL?.trim() || 'http://policy-engine:8083',
    policyToken,
    stateDir: env.ROTATION_STATE_DIR?.trim() || '/data',
    stateKey: hexToBytes(stateKeyRaw.toLowerCase()),
    intervalMs,
    ...(signerUrl && signerToken ? { managedSigner: { baseUrl: signerUrl, token: signerToken } } : {}),
    port: Number(env.PORT ?? 8089),
    host: env.HOST ?? '0.0.0.0',
  };
}
