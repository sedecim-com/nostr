import WebSocket from 'ws';
import { generateSecretKey, getPublicKey, hexToBytes, nip19, npubEncode } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { normalizeRelayUrl, RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { createLogger } from '@sedecim/telemetry-policy';
import { rateLimitFromEnv, serveMetrics } from '@sedecim/service-kit';
import { b64u, createNotificationApi, createWebPushSender, DEFAULT_PUSH_HOSTS, generateVapidKeys, NotificationGateway, vapidKeysFromPrivate } from './index';

const env = process.env;
const logger = createLogger({ base: { service: 'notification-gateway' }, minimizeIp: true });
const list = (v: string | undefined) => (v ?? '').split(',').map((s) => s.trim()).filter(Boolean);

// NOTIFY_RELAYS: `public` or `public=dial` entries. Clients name relays by their public URL (the persona's
// DM relays); the gateway dials the internal address and presents the public one (Host + NIP-42 tag).
const relays = list(env.NOTIFY_RELAYS ?? 'ws://localhost:3000=ws://relay:3000').map((e) => {
  const [pub, dial] = e.split('=').map((s) => s.trim()) as [string, string | undefined];
  return { public: pub, dial: dial || pub };
});
const publicOf = new Map(relays.map((r) => [normalizeRelayUrl(r.dial), r.public]));

function vapid() {
  const raw = env.NOTIFY_VAPID_PRIVATE_KEY?.trim();
  if (raw) return vapidKeysFromPrivate(b64u.decode(raw));
  logger.warn('NOTIFY_VAPID_PRIVATE_KEY not set: ephemeral VAPID key, browsers must re-subscribe after each restart');
  return generateVapidKeys();
}

// NIP-42 identity of the watcher. Relays that only serve kind 1059 to its recipient (Buzz, the secure relay) show
// no gift wrap for anyone else to it, and granting it that would be read access to DMs: those relays are not
// watched (OPS-06, the canary below).
function serviceKey(): Uint8Array {
  const raw = env.NOTIFY_NSEC?.trim();
  if (!raw) {
    logger.warn('NOTIFY_NSEC not set: using an ephemeral service identity');
    return generateSecretKey();
  }
  if (raw.startsWith('nsec1')) {
    const d = nip19.decode(raw);
    if (d.type !== 'nsec') throw new Error('NOTIFY_NSEC must be an nsec or 64 hex chars');
    return d.data;
  }
  return hexToBytes(raw);
}

const keys = vapid();
const serviceSecret = serviceKey();
logger.info('watcher service identity', { npub: npubEncode(getPublicKey(serviceSecret)) });
const webSocketFactory = (u: string) => {
  const pub = publicOf.get(u);
  const host = pub ? new URL(pub.replace(/^ws/, 'http')).host : undefined;
  return new WebSocket(u, host && host !== new URL(u.replace(/^ws/, 'http')).host ? { headers: { host } } : {}) as unknown as WebSocketLike;
};
const pool = new RelayPool({ webSocketFactory, signer: new LocalSigner(serviceSecret), authMode: 'auto', authRelayUrl: (u) => publicOf.get(u) ?? u });

const gateway = new NotificationGateway({
  pool,
  sender: createWebPushSender({ vapid: keys, subject: env.NOTIFY_VAPID_SUBJECT ?? 'mailto:admin@localhost' }),
  relays,
  pushHosts: env.NOTIFY_PUSH_HOSTS === undefined ? DEFAULT_PUSH_HOSTS : list(env.NOTIFY_PUSH_HOSTS),
  maxSubscriptions: Number(env.NOTIFY_MAX_SUBSCRIPTIONS ?? 10_000),
  logger,
});

// OPS-06: which relays the gateway can watch without reading anyone's DMs, checked with a canary at start and every
// NOTIFY_PROBE_INTERVAL_MS (default 6 h). Until a relay passes, registrations for it are refused. Each check
// publishes a canary to every relay, so the interval has a floor of one minute.
const probeEvery = Number(env.NOTIFY_PROBE_INTERVAL_MS || 6 * 3600_000);
if (!(probeEvery >= 60_000)) throw new Error('NOTIFY_PROBE_INTERVAL_MS must be at least 60000 (ms)');
const probe = () =>
  void gateway
    .probeRelays()
    .then((found) => logger.info('relays checked', { observable: found.filter((o) => o.observable).length, relays: found.length }))
    .catch((err: Error) => logger.warn('relay check failed', { error: err.message }));
probe();
setInterval(probe, probeEvery).unref();

// No database: used NIP-98 ids are remembered per process (a capture can be replayed once per replica).
const api = createNotificationApi(gateway, { name: 'notification-gateway', publicBaseUrl: env.PUBLIC_BASE_URL, corsOrigins: list(env.CORS_ORIGINS), logger, vapid: keys, rateLimit: rateLimitFromEnv(env) });
if (env.METRICS_PORT && api.rateLimiter) await serveMetrics(() => api.rateLimiter!.render(), { port: Number(env.METRICS_PORT), host: env.METRICS_HOST ?? '0.0.0.0' });
await api.listen(Number(env.PORT ?? 8086), env.HOST ?? '0.0.0.0');
