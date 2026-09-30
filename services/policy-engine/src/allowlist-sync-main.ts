// FR023-04: relay allowlist sync job (compose service `relay-allowlist`, profile `institutional`).
import WebSocket from 'ws';
import { hexToBytes, nip19, normalizePubkey } from '@sedecim/nostr-core';
import { bearer, PolicyEngineClient } from '@sedecim/policy-client';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { createPgPool, Service } from '@sedecim/service-kit';
import { LocalSigner } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import { AdmissionServer, AllowlistSync, BuzzAllowlistSink, FileAllowlistSink, type AllowlistSink } from './allowlist-sync';
import { BuzzMembershipSync, nip11Self, parseRelayEntry } from './membership-sync';

const env = process.env;
const logger = createLogger({ base: { service: 'relay-allowlist' }, minimizeIp: true });
const list = (v?: string) => (v ?? '').split(',').map((s) => s.trim()).filter(Boolean);

if (!env.POLICY_ENGINE_TOKEN) throw new Error('POLICY_ENGINE_TOKEN is required (one of the policy-engine POLICY_SERVICE_TOKENS)');
const client = new PolicyEngineClient(env.POLICY_ENGINE_URL ?? 'http://policy-engine:8083', bearer(env.POLICY_ENGINE_TOKEN));

const sinks: AllowlistSink[] = [];
if (env.BUZZ_DATABASE_URL) sinks.push(new BuzzAllowlistSink(createPgPool(env.BUZZ_DATABASE_URL), list(env.BUZZ_ALLOWLIST_HOSTS)));
if (env.ALLOWLIST_FILE) sinks.push(new FileAllowlistSink(env.ALLOWLIST_FILE));

let admission: AdmissionServer | undefined;
if (env.ALLOWLIST_GRPC_PORT !== '') {
  admission = new AdmissionServer();
  const port = await admission.listen(Number(env.ALLOWLIST_GRPC_PORT ?? 50051), env.HOST ?? '0.0.0.0');
  logger.info('nauthz admission server listening', { port });
}
if (!sinks.length && !admission) logger.warn('no sink configured (BUZZ_DATABASE_URL, ALLOWLIST_FILE, ALLOWLIST_GRPC_PORT)');

const extraPubkeys = list(env.ALLOWLIST_EXTRA_PUBKEYS);

// FR023-10: NIP-29 membership of the channels registered in the policy-engine, on Buzz. BUZZ_MEMBERSHIP_NSEC is the
// identity that adds and removes members: an owner or admin of each registered channel. Empty: no membership sync.
let membership: BuzzMembershipSync | undefined;
const membershipKey = env.BUZZ_MEMBERSHIP_NSEC?.trim();
if (membershipKey) {
  const decoded = membershipKey.startsWith('nsec1') ? nip19.decode(membershipKey) : undefined;
  if (decoded && decoded.type !== 'nsec') throw new Error('BUZZ_MEMBERSHIP_NSEC must be an nsec or 64 hex chars');
  if (!decoded && !/^[0-9a-f]{64}$/i.test(membershipKey)) throw new Error('BUZZ_MEMBERSHIP_NSEC must be an nsec or 64 hex chars');
  const signer = new LocalSigner(decoded ? (decoded.data as Uint8Array) : hexToBytes(membershipKey.toLowerCase()));
  const self = await signer.getPublicKey();
  // Buzz is multi-tenant by Host: dial the internal address, present the public one (Host header and NIP-42 tag).
  const relay = parseRelayEntry(env.BUZZ_MEMBERSHIP_RELAY ?? 'ws://localhost:3000=ws://relay:3000');
  const host = new URL(relay.public.replace(/^ws/, 'http')).host;
  const pool = new RelayPool({ webSocketFactory: (u) => new WebSocket(u, { headers: { host } }) as unknown as WebSocketLike, signer, authMode: 'auto', authRelayUrl: () => relay.public });
  let relayKey = env.BUZZ_MEMBERSHIP_RELAY_KEY ? normalizePubkey(env.BUZZ_MEMBERSHIP_RELAY_KEY) : undefined;
  membership = new BuzzMembershipSync({
    relay: { query: (filters) => pool.query([relay.dial], filters, 8000), publish: async (t) => pool.publishTo(await signer.signEvent(t), relay.dial) },
    self,
    relayKey: async () => (relayKey ??= await nip11Self(relay)),
    log: (msg, fields) => logger.info(msg, fields),
  });
  // Buzz admits its NIP-42 AUTH only from the allowlist this job applies.
  if (!extraPubkeys.includes(self)) extraPubkeys.push(self);
  logger.info('NIP-29 membership sync enabled', { relay: relay.public, identity: self });
}

const sync = new AllowlistSync({
  fetch: () => client.relayAllowlist(),
  fetchGrants: () => client.relayGrants(),
  ...(membership
    ? {
        onGrants: async (grants) => {
          const r = await membership.apply(grants);
          if (r.errors.length) throw new Error(r.errors.join('; '));
        },
      }
    : {}),
  sinks,
  ...(admission ? { admission } : {}),
  extraPubkeys,
  intervalMs: Number(env.ALLOWLIST_SYNC_INTERVAL_MS ?? 30_000),
  log: (msg, fields) => logger.info(msg, fields),
});
sync.start();

const health = new Service({ name: 'relay-allowlist', logger });
health.get('/health', () => ({
  ok: sync.lastSyncAt !== undefined && !sync.lastError,
  pubkeys: sync.current.length,
  grants: sync.grants ?? null,
  lastSyncAt: sync.lastSyncAt ?? null,
  lastError: sync.lastError ?? null,
  // FR023-10: channels the membership sync cannot manage (withoutAuthority, unreachable) or that Buzz does not gate (notEnforced).
  membership: membership?.last ?? null,
}));
await health.listen(Number(env.PORT ?? 8087), env.HOST ?? '0.0.0.0');
