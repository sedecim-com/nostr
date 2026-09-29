import WebSocket from 'ws';
import { EncryptedStore, FileBackend } from '@sedecim/encrypted-store';
import { EncryptedGroupStorage, MarmotTsProvider, PoolGroupNetwork, type GroupSession } from '@sedecim/marmot-adapter';
import { getPublicKey, npubEncode } from '@sedecim/nostr-core';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { HttpPolicySource, managedSignerSink, RevocationPropagator, RotationService, RotationWorker, type CursorStore } from '@sedecim/rotation-worker';
import { Service } from '@sedecim/service-kit';
import { LocalSigner } from '@sedecim/signer';
import { createLogger, type Logger } from '@sedecim/telemetry-policy';
import type { RotationWorkerConfig } from './config';
import { mappedNetwork, relayMapping } from './network';

export * from './config';
export * from './network';

/** The worker's device id: its key package slot and its leaf in every group. One worker per deployment. */
export const WORKER_DEVICE_ID = 'rotation-worker';
const STATE_CHECK = 'worker-state-check';

/** Opens the encrypted MLS state. A key that does not open what is stored fails here, before anything is touched. */
async function openState(dir: string, key: Uint8Array): Promise<EncryptedStore> {
  const backend = new FileBackend(dir);
  const store = EncryptedStore.withKey(backend, key);
  // Entry names derive from the key, so another key would just see an empty store: the check lives under a fixed name.
  const check = await backend.get(STATE_CHECK);
  if (!check) await backend.put(STATE_CHECK, store.seal(STATE_CHECK, 'check', { v: 1 }));
  else {
    try {
      store.open(STATE_CHECK, check);
    } catch {
      throw new Error('ROTATION_STATE_KEY does not open the state in ROTATION_STATE_DIR: it was encrypted with another key');
    }
  }
  return store;
}

/** The revocation cursor lives with the MLS state: a restart goes on from it. */
function cursorStore(store: EncryptedStore): CursorStore {
  const c = store.collection<number>('revocation-cursor');
  return { load: () => c.get('managed-signer'), save: (v) => c.put('managed-signer', v) };
}

export interface RunningRotationWorker {
  pubkey: string;
  service: RotationService;
  session: GroupSession;
  /** Base URL of the health endpoint (`GET /health`). */
  url: string;
  stop(): Promise<void>;
}

/**
 * FR024-05: starts the rotation worker service: the Marmot session of the worker identity (MLS state encrypted in
 * `stateDir`), the rotation and revocation loop, and `GET /health`. `loop: false` leaves the runs to the caller.
 */
export async function startRotationWorker(cfg: RotationWorkerConfig, deps: { logger?: Logger; loop?: boolean; fetch?: typeof fetch } = {}): Promise<RunningRotationWorker> {
  const logger = deps.logger ?? createLogger({ base: { service: 'rotation-worker' }, minimizeIp: true });
  const signer = new LocalSigner(cfg.secretKey);
  const pubkey = getPublicKey(cfg.secretKey);
  const store = await openState(cfg.stateDir, cfg.stateKey);
  const map = relayMapping(cfg.relays);
  // The worker dials the internal address and presents the public one (Host, and the NIP-42 relay tag).
  const webSocketFactory = (u: string) => {
    const pub = map.publicOf(u);
    const host = pub !== u ? new URL(pub.replace(/^ws/, 'http')).host : undefined;
    return new WebSocket(u, host && host !== new URL(u.replace(/^ws/, 'http')).host ? { headers: { host } } : {}) as unknown as WebSocketLike;
  };
  const pool = new RelayPool({ webSocketFactory, signer, authMode: 'auto', authRelayUrl: (u) => map.publicOf(u) });
  const network = mappedNetwork(new PoolGroupNetwork(pool, cfg.relays.map((r) => r.dial)), map.dialOf);
  const session = await new MarmotTsProvider().openSession({ signer, network, storage: new EncryptedGroupStorage(store), deviceId: WORKER_DEVICE_ID });
  const policy = new HttpPolicySource({ baseUrl: cfg.policyUrl, signer, bearer: cfg.policyToken, ...(deps.fetch ? { fetch: deps.fetch } : {}) });
  const worker = new RotationWorker({ source: policy, session, logger });
  const propagator = cfg.managedSigner
    ? new RevocationPropagator({ feed: policy, sinks: [managedSignerSink({ ...cfg.managedSigner, ...(deps.fetch ? { fetch: deps.fetch } : {}) })], cursor: cursorStore(store), logger })
    : undefined;
  if (!propagator) logger.warn('ROTATION_MANAGED_SIGNER_URL not set: device revocations are not propagated to the managed-signer');
  const service = new RotationService({ session, relays: cfg.relays.map((r) => r.public), worker, ...(propagator ? { propagator } : {}), logger });

  const health = new Service({ name: 'rotation-worker', logger });
  health.get('/health', () => ({ ...service.status, npub: npubEncode(pubkey) }));
  const url = await health.listen(cfg.port, cfg.host);

  const controller = new AbortController();
  const loop = deps.loop === false ? Promise.resolve() : service.run({ intervalMs: cfg.intervalMs, signal: controller.signal });
  return {
    pubkey,
    service,
    session,
    url,
    async stop() {
      controller.abort();
      await loop;
      await health.close();
      session.close();
      pool.close();
    },
  };
}
