import { createECDH, createHmac, randomBytes } from 'node:crypto';
import type { Filter, NostrEvent } from '@sedecim/nostr-core';
import type { PoolSubscribeOptions, PoolSubscription } from '@sedecim/relay-pool';
import { normalizeRelayUrl } from '@sedecim/relay-pool';
import { NOTIFICATION_MODES, OPAQUE_PUSH_PAYLOAD, OPAQUE_PUSH_TOPIC, PRESETS, nextPushDelayMs, notificationPolicy, type NotificationPolicy, type PresetName } from '@sedecim/profiles';
import { HttpError } from '@sedecim/service-kit';
import { createLogger, type Logger } from '@sedecim/telemetry-policy';
import { b64u, type PushSubscriptionJSON, type WebPushSender } from './webpush';

/** Kind of NIP-59 gift wraps (NIP-17 DMs, receipts, Marmot welcomes). */
export const GIFT_WRAP_KIND = 1059;

/** What the gateway needs from @sedecim/relay-pool (RelayPool satisfies it). */
export interface WatchPool {
  subscribe(urls: string[], filters: Filter[], opts: PoolSubscribeOptions): PoolSubscription;
}

export interface RegisterInput {
  subscription: PushSubscriptionJSON;
  /** Reference profile of the persona, or 'custom' with an explicit mode. */
  profile: PresetName | 'custom';
  mode?: 'push' | 'privacy-push' | 'none';
  network?: string;
  /** Public relay URLs to watch (the persona's DM relays). Empty: every relay the gateway serves. */
  relays?: string[];
}

export interface Registration {
  id: string;
  pubkey: string;
  subscription: PushSubscriptionJSON;
  profile: PresetName | 'custom';
  policy: NotificationPolicy;
  relays: string[];
  createdAt: number;
  lastSentAt?: number;
  timer?: ReturnType<typeof setTimeout>;
}

export interface GatewayOptions {
  pool: WatchPool;
  sender: WebPushSender;
  /** Relays the gateway may watch, by public URL, and the URL it dials for each (e.g. ws://relay:3000). */
  relays: Array<{ public: string; dial?: string }>;
  /** Host suffixes of accepted push services (SSRF guard). Empty: any host. */
  pushHosts?: string[];
  /** Accept http:// endpoints (tests only). */
  allowInsecureEndpoints?: boolean;
  maxSubscriptions?: number;
  maxDevicesPerPubkey?: number;
  /** Registration attempts allowed per pubkey per minute. */
  registrationsPerMinute?: number;
  random?: () => number;
  /** Overrides the per-profile delay (tests only). */
  delayFor?: (policy: NotificationPolicy, now: number, lastSentAt: number | undefined) => number;
  logger?: Logger;
}

/** Push services of the major browsers (Chrome/Edge via FCM, Firefox autopush, Safari, legacy Edge/WNS). */
export const DEFAULT_PUSH_HOSTS = ['fcm.googleapis.com', 'android.googleapis.com', 'push.services.mozilla.com', 'push.apple.com', 'notify.windows.com'];

/** Push delays hide activity timing (ADR 0010): draw them from the CSPRNG, not Math.random. */
const cryptoRandom = () => randomBytes(4).readUInt32BE(0) / 2 ** 32;

const TOR_ONLY_PROFILES = new Set<string>(['sovereign', 'sovereign-tor']);

/**
 * Opaque push gateway (ADR 0010, OPS-06). Watches kind 1059 gift wraps addressed (`#p`) to registered
 * pubkeys and sends each device a push with no content, sender or count, batched and randomly delayed per
 * profile. State lives in memory only: clients re-register when the app opens.
 */
export class NotificationGateway {
  private readonly regs = new Map<string, Registration>();
  private readonly watchers = new Map<string, { sub: PoolSubscription; pubkeys: string }>();
  private readonly attempts = new Map<string, { windowStart: number; count: number }>();
  private readonly seen = new Set<string>();
  private readonly relayMap: Map<string, string>;
  private readonly logKey = randomBytes(32);
  private readonly logger: Logger;
  readonly stats = { sent: 0, failed: 0, dropped: 0, events: 0 };

  constructor(private readonly opts: GatewayOptions) {
    this.logger = opts.logger ?? createLogger({ base: { service: 'notification-gateway' } });
    this.relayMap = new Map(opts.relays.map((r) => [normalizeRelayUrl(r.public), r.dial ?? r.public]));
  }

  /** Keyed, truncated hash for logs: never a full pubkey or endpoint, and not linkable across restarts. */
  ref(value: string): string {
    return createHmac('sha256', this.logKey).update(value).digest('hex').slice(0, 12);
  }

  get size(): number {
    return this.regs.size;
  }

  registrations(): Registration[] {
    return [...this.regs.values()];
  }

  register(pubkey: string, input: RegisterInput): Registration {
    this.rateLimit(pubkey);
    const policy = this.resolvePolicy(input);
    const subscription = this.validateSubscription(input.subscription);
    const relays = this.resolveRelays(input.relays);

    const existing = [...this.regs.values()].find((r) => r.pubkey === pubkey && r.subscription.endpoint === subscription.endpoint);
    if (existing) this.remove(existing, 'replaced');
    else {
      if (this.regs.size >= (this.opts.maxSubscriptions ?? 10_000)) throw new HttpError(503, 'gateway at capacity');
      const devices = [...this.regs.values()].filter((r) => r.pubkey === pubkey).length;
      if (devices >= (this.opts.maxDevicesPerPubkey ?? 5)) throw new HttpError(429, 'too many devices for this pubkey');
    }
    const reg: Registration = { id: randomBytes(12).toString('hex'), pubkey, subscription, profile: input.profile, policy, relays, createdAt: Date.now() };
    this.regs.set(reg.id, reg);
    this.logger.info('subscription registered', { ref: this.ref(pubkey + subscription.endpoint), mode: policy.mode, relays: relays.length });
    for (const url of relays) this.rewatch(url);
    return reg;
  }

  /** Removes every registration of `pubkey` (optionally only the one for `endpoint`). */
  unregister(pubkey: string, endpoint?: string): number {
    let n = 0;
    for (const r of [...this.regs.values()]) {
      if (r.pubkey === pubkey && (endpoint === undefined || r.subscription.endpoint === endpoint)) {
        this.remove(r, 'unsubscribed');
        n++;
      }
    }
    return n;
  }

  /** A gift wrap for `pubkey` reached `relay`: schedule an opaque push for each of its devices. */
  onActivity(pubkey: string, relay?: string): void {
    for (const reg of this.regs.values()) {
      if (reg.pubkey !== pubkey || (relay && !reg.relays.includes(relay))) continue;
      if (reg.timer) continue; // already pending: this activity is batched into that push
      const delay = this.opts.delayFor ? this.opts.delayFor(reg.policy, Date.now(), reg.lastSentAt) : nextPushDelayMs(reg.policy, Date.now(), reg.lastSentAt, this.opts.random ?? cryptoRandom);
      reg.timer = setTimeout(() => void this.fire(reg), delay);
    }
  }

  stop(): void {
    for (const r of this.regs.values()) if (r.timer) clearTimeout(r.timer);
    for (const w of this.watchers.values()) w.sub.close();
    this.watchers.clear();
  }

  private async fire(reg: Registration): Promise<void> {
    reg.timer = undefined;
    if (this.regs.get(reg.id) !== reg) return;
    reg.lastSentAt = Date.now();
    const ref = this.ref(reg.pubkey + reg.subscription.endpoint);
    let status: number;
    try {
      status = await this.opts.sender.send(reg.subscription, {
        // Same bytes for every user and every event: no content, sender or count (ADR 0010).
        payload: reg.policy.payload === 'fixed-opaque' ? new TextEncoder().encode(OPAQUE_PUSH_PAYLOAD) : null,
        ttlSeconds: reg.policy.ttlSeconds,
        urgency: reg.policy.urgency,
        topic: OPAQUE_PUSH_TOPIC,
      });
    } catch (err) {
      this.stats.failed++;
      this.logger.warn('push failed', { ref, error: (err as Error).name });
      return;
    }
    if (status === 404 || status === 410) {
      this.stats.dropped++;
      this.remove(reg, 'expired at push service');
    } else if (status === 429) {
      this.stats.failed++;
      reg.lastSentAt = Date.now() + reg.policy.minIntervalMs; // back off one extra interval
      this.logger.warn('push rate limited', { ref });
    } else if (status >= 200 && status < 300) this.stats.sent++;
    else {
      this.stats.failed++;
      this.logger.warn('push rejected', { ref, status });
    }
  }

  private remove(reg: Registration, reason: string) {
    if (reg.timer) clearTimeout(reg.timer);
    this.regs.delete(reg.id);
    this.logger.info('subscription removed', { ref: this.ref(reg.pubkey + reg.subscription.endpoint), reason });
    for (const url of reg.relays) this.rewatch(url);
  }

  /** One REQ per relay with every watched pubkey: the relay sees the gateway, not which user is behind a push. */
  private rewatch(url: string) {
    const pubkeys = [...new Set([...this.regs.values()].filter((r) => r.relays.includes(url)).map((r) => r.pubkey))].sort();
    const key = pubkeys.join(',');
    const current = this.watchers.get(url);
    if (current?.pubkeys === key) return;
    let next: { sub: PoolSubscription; pubkeys: string } | undefined;
    if (pubkeys.length) {
      let eosed = false;
      const watched = new Set(pubkeys);
      // limit 0: live events only (NIP-59 backdates created_at, so `since` would miss them); anything a
      // relay replays before EOSE is ignored.
      const sub = this.opts.pool.subscribe([this.relayMap.get(url) ?? url], [{ kinds: [GIFT_WRAP_KIND], '#p': pubkeys, limit: 0 }], {
        onevent: (evt: NostrEvent) => {
          if (!eosed || evt.kind !== GIFT_WRAP_KIND || !this.firstSeen(evt.id)) return;
          this.stats.events++;
          for (const t of evt.tags) if (t[0] === 'p' && t[1] && watched.has(t[1])) this.onActivity(t[1], url);
        },
        oneose: () => (eosed = true),
      });
      next = { sub, pubkeys: key };
      this.watchers.set(url, next);
    } else this.watchers.delete(url);
    current?.sub.close(); // after opening the new REQ, so no live event falls in between
  }

  private firstSeen(id: string): boolean {
    if (this.seen.has(id)) return false;
    this.seen.add(id);
    if (this.seen.size > 10_000) this.seen.delete(this.seen.values().next().value!);
    return true;
  }

  private rateLimit(pubkey: string) {
    const now = Date.now();
    const a = this.attempts.get(pubkey);
    if (!a || now - a.windowStart >= 60_000) this.attempts.set(pubkey, { windowStart: now, count: 1 });
    else if (++a.count > (this.opts.registrationsPerMinute ?? 10)) throw new HttpError(429, 'too many registrations, retry later');
    if (this.attempts.size > 50_000) for (const [k, v] of this.attempts) if (now - v.windowStart >= 60_000) this.attempts.delete(k);
  }

  private resolvePolicy(input: RegisterInput): NotificationPolicy {
    if (input.network === 'tor-only' || TOR_ONLY_PROFILES.has(input.profile)) throw new HttpError(403, 'push is disabled for sovereign and Tor profiles (ADR 0010)');
    let policy: NotificationPolicy;
    if (input.profile === 'custom') {
      if (!input.mode || !(input.mode in NOTIFICATION_MODES)) throw new HttpError(400, 'custom profile requires mode push | privacy-push');
      policy = NOTIFICATION_MODES[input.mode];
    } else if (input.profile in PRESETS) {
      policy = notificationPolicy({ ...PRESETS[input.profile] });
      // A client may ask for the stricter mode of the two, never a laxer one than its profile.
      if (input.mode === 'privacy-push' || input.mode === 'none') policy = NOTIFICATION_MODES[input.mode];
    } else throw new HttpError(400, 'unknown profile');
    if (policy.mode === 'none') throw new HttpError(403, 'push is disabled for this profile (ADR 0010)');
    return policy;
  }

  private validateSubscription(s: PushSubscriptionJSON | undefined): PushSubscriptionJSON {
    if (!s || typeof s.endpoint !== 'string' || !s.keys || typeof s.keys.p256dh !== 'string' || typeof s.keys.auth !== 'string') throw new HttpError(400, 'invalid subscription');
    if (s.endpoint.length > 2048) throw new HttpError(400, 'endpoint too long');
    let url: URL;
    try {
      url = new URL(s.endpoint);
    } catch {
      throw new HttpError(400, 'invalid endpoint');
    }
    if (url.protocol !== 'https:' && !(this.opts.allowInsecureEndpoints && url.protocol === 'http:')) throw new HttpError(400, 'endpoint must be https');
    const hosts = this.opts.pushHosts ?? DEFAULT_PUSH_HOSTS;
    if (hosts.length && !hosts.some((h) => url.hostname === h || url.hostname.endsWith('.' + h))) throw new HttpError(400, 'endpoint is not a known push service');
    const p256dh = b64u.decode(s.keys.p256dh);
    const auth = b64u.decode(s.keys.auth);
    if (p256dh.length !== 65 || p256dh[0] !== 0x04 || auth.length !== 16) throw new HttpError(400, 'invalid subscription keys');
    try {
      const probe = createECDH('prime256v1');
      probe.generateKeys();
      probe.computeSecret(p256dh); // rejects points that are not on the curve
    } catch {
      throw new HttpError(400, 'invalid subscription keys');
    }
    return { endpoint: s.endpoint, keys: { p256dh: s.keys.p256dh, auth: s.keys.auth } };
  }

  private resolveRelays(requested: string[] | undefined): string[] {
    const allowed = [...this.relayMap.keys()];
    if (!requested || requested.length === 0) {
      if (!allowed.length) throw new HttpError(400, 'no relays configured');
      return allowed;
    }
    const out = new Set<string>();
    for (const r of requested.slice(0, 20)) {
      let url: string;
      try {
        url = normalizeRelayUrl(r);
      } catch {
        throw new HttpError(400, 'invalid relay url');
      }
      if (new URL(url).hostname.endsWith('.onion')) throw new HttpError(403, 'push is disabled for Tor relays (ADR 0010)');
      if (this.relayMap.has(url)) out.add(url);
    }
    if (!out.size) throw new HttpError(400, 'none of the relays is served by this gateway');
    return [...out];
  }
}
