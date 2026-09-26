import { HttpError, Service, type ServiceOptions } from '@sedecim/service-kit';
import type { NotificationGateway, RegisterInput } from './gateway';
import { b64u, type VapidKeys } from './webpush';

/**
 * HTTP API of the notification gateway. Registration is NIP-98: the watched pubkey is the one that signed
 * the request, so nobody can subscribe to another user's activity times.
 */
export function createNotificationApi(gateway: NotificationGateway, opts: ServiceOptions & { vapid: VapidKeys }) {
  const svc = new Service({ maxBodyBytes: 16_384, ...opts });
  svc.get('/health', () => ({ ok: true }));
  // Browsers need the VAPID public key as `applicationServerKey` to subscribe.
  svc.get('/v1/vapid', () => ({ publicKey: b64u.encode(opts.vapid.publicKey) }));
  svc.post(
    '/v1/subscriptions',
    (req) => {
      const reg = gateway.register(req.pubkey!, req.json<RegisterInput>());
      return { status: 201, body: { mode: reg.policy.mode, relays: reg.relays, minDelayMs: reg.policy.minDelayMs, maxDelayMs: reg.policy.maxDelayMs } };
    },
    'nip98',
  );
  svc.delete(
    '/v1/subscriptions',
    (req) => {
      const { endpoint } = req.json<{ endpoint?: string }>();
      if (endpoint !== undefined && typeof endpoint !== 'string') throw new HttpError(400, 'invalid endpoint');
      return { removed: gateway.unregister(req.pubkey!, endpoint) };
    },
    'nip98',
  );
  return svc;
}
