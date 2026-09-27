import { TokenBucketLimiter } from '@sedecim/service-kit';

/** Token bucket: `burst` tokens at most, refilled at `perMinute` tokens per minute. */
export interface RateLimitRule {
  perMinute: number;
  /** Bucket size (default: perMinute). */
  burst?: number;
}

/**
 * FR005-06 limits for custodial operations. `perKey` caps everything a key does (sign + NIP-44);
 * `perKind` caps each event kind of a key (NIP-44 counts as its own pseudo-kind), with overrides in `kinds`.
 */
export interface RateLimitConfig {
  perKey: RateLimitRule;
  perKind: RateLimitRule;
  kinds?: Record<number, RateLimitRule>;
}

/** A person signs a few events per minute; auth kinds (NIP-42, NIP-98, Blossom) come in bursts. */
export const DEFAULT_RATE_LIMITS: RateLimitConfig = {
  perKey: { perMinute: 120, burst: 120 },
  perKind: { perMinute: 60, burst: 60 },
  kinds: { 22242: { perMinute: 120 }, 24242: { perMinute: 120 }, 27235: { perMinute: 120 } },
};

/** `perMinute[:burst]` per kind, comma separated: `22242:300,1:30` means kind 22242 → 300/min. */
export function parseKindLimits(v: string | undefined): Record<number, RateLimitRule> {
  const out: Record<number, RateLimitRule> = {};
  for (const part of (v ?? '').split(',').map((s) => s.trim()).filter(Boolean)) {
    const [kind, perMinute, burst] = part.split(':').map(Number);
    if (!Number.isInteger(kind) || !(perMinute! > 0) || (burst !== undefined && !(burst > 0))) throw new Error(`invalid kind rate limit: ${part}`);
    out[kind!] = { perMinute: perMinute!, ...(burst !== undefined ? { burst } : {}) };
  }
  return out;
}

interface Bucket {
  tokens: number;
  at: number;
}

export type RateDecision = { ok: true } | { ok: false; scope: 'key' | 'kind'; retryAfterMs: number };

const MAX_BUCKETS = 50_000;

/** In-process limiter (per replica: with N replicas the effective limit is up to N times higher). */
export class SigningRateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(private readonly config: RateLimitConfig = DEFAULT_RATE_LIMITS) {}

  private level(id: string, rule: RateLimitRule, now: number): Bucket {
    const cap = rule.burst ?? rule.perMinute;
    const b = this.buckets.get(id) ?? { tokens: cap, at: now };
    return { tokens: Math.min(cap, b.tokens + ((now - b.at) * rule.perMinute) / 60_000), at: now };
  }

  private wait(b: Bucket, rule: RateLimitRule) {
    return Math.ceil(((1 - b.tokens) * 60_000) / rule.perMinute);
  }

  /** Takes one token from the key bucket and from its kind bucket, or none if either is empty. */
  take(keyId: string, kind: number | 'nip44', now: number): RateDecision {
    const kindRule = (typeof kind === 'number' ? this.config.kinds?.[kind] : undefined) ?? this.config.perKind;
    const keyId_ = `k:${keyId}`;
    const kindId = `n:${keyId}:${kind}`;
    const key = this.level(keyId_, this.config.perKey, now);
    const kb = this.level(kindId, kindRule, now);
    if (key.tokens < 1) return { ok: false, scope: 'key', retryAfterMs: this.wait(key, this.config.perKey) };
    if (kb.tokens < 1) return { ok: false, scope: 'kind', retryAfterMs: this.wait(kb, kindRule) };
    if (this.buckets.size > MAX_BUCKETS) this.buckets.clear(); // bounded memory; a reset only forgives
    this.buckets.set(keyId_, { tokens: key.tokens - 1, at: now });
    this.buckets.set(kindId, { tokens: kb.tokens - 1, at: now });
    return { ok: true };
  }
}

/**
 * IR-2026-09-20: import and export run scrypt (up to 2^18, 256 MiB each). Per owner: a token bucket and one
 * operation at a time; per process: at most `maxConcurrent` running and `maxQueue` waiting.
 */
export interface ScryptLimitConfig {
  perOwner: RateLimitRule;
  maxConcurrent: number;
  maxQueue: number;
}

export const DEFAULT_SCRYPT_LIMITS: ScryptLimitConfig = { perOwner: { perMinute: 10, burst: 5 }, maxConcurrent: 2, maxQueue: 16 };

export type ScryptRejection = { ok: false; scope: 'owner' | 'busy'; retryAfterMs: number };

/** Admission for scrypt operations (per replica, like the signing buckets). */
export class ScryptGate {
  private readonly buckets: TokenBucketLimiter;
  private readonly inFlight = new Set<string>();
  private active = 0;
  private readonly waiting: Array<() => void> = [];

  constructor(private readonly config: ScryptLimitConfig = DEFAULT_SCRYPT_LIMITS, now?: () => number) {
    this.buckets = new TokenBucketLimiter({ maxKeys: MAX_BUCKETS, ...(now ? { now } : {}) });
  }

  /** Runs `fn` if admitted; otherwise returns the rejection without running it. */
  async run<T>(owner: string, fn: () => Promise<T>): Promise<{ ok: true; value: T } | ScryptRejection> {
    if (this.inFlight.has(owner)) return { ok: false, scope: 'owner', retryAfterMs: 1000 };
    if (this.active >= this.config.maxConcurrent && this.waiting.length >= this.config.maxQueue) return { ok: false, scope: 'busy', retryAfterMs: 1000 };
    const d = this.buckets.take(owner, this.config.perOwner);
    if (!d.ok) return { ok: false, scope: 'owner', retryAfterMs: d.retryAfterMs };
    this.inFlight.add(owner);
    try {
      // A finishing operation hands its slot straight to the next waiter.
      if (this.active >= this.config.maxConcurrent) await new Promise<void>((r) => this.waiting.push(r));
      else this.active++;
      try {
        return { ok: true, value: await fn() };
      } finally {
        const next = this.waiting.shift();
        if (next) next();
        else this.active--;
      }
    } finally {
      this.inFlight.delete(owner);
    }
  }
}
