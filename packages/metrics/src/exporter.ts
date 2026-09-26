import { FAILURE_CLASSES, classifyFailure, type AttemptEvent, type OutboxStats } from '@sedecim/delivery-engine';
import type { PublishResult } from '@sedecim/relay-pool';
import { TelemetryBlockedError, TelemetryPolicy, type TelemetryLevel } from '@sedecim/telemetry-policy';
import { relayLabel, regionFor, type RegionMap } from './labels';
import { Counter, Gauge, Histogram, Registry } from './registry';

/** Buckets (seconds) for publish→OK latency: fine below 1 s, coarse up to the 10 s publish timeout and beyond. */
export const ACK_LATENCY_BUCKETS = [0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1, 1.5, 2, 3, 5, 7.5, 10, 30];

export interface MetricsExporterOptions {
  /** Telemetry level of the profile (or its TelemetryPolicy). 'none' refuses to create an exporter. */
  telemetry: TelemetryLevel | TelemetryPolicy;
  /** relay → region (host or URL keys), e.g. from parseRegionMap(env.RELAY_REGIONS). */
  regions?: RegionMap;
  defaultRegion?: string;
  /** Salt for hashed relay labels (onion relays; every relay at level 'minimal'). */
  labelSalt?: string;
  buckets?: number[];
}

export interface PublishObservable {
  onPublishResult(fn: (r: PublishResult) => void): () => void;
}

export interface OutboxObservable {
  onAttempt(fn: (a: AttemptEvent) => void): () => void;
  stats(): Promise<OutboxStats>;
}

export function levelOf(t: TelemetryLevel | TelemetryPolicy): TelemetryLevel {
  return t instanceof TelemetryPolicy ? t.config.level : t;
}

/**
 * Prometheus exporter for relay ACK latency (NFR004-01) and outbox health (FR011-03) that respects the
 * profile's telemetry level (FR-022):
 *  - 'none' (Sovereign, Sovereign Tor): the exporter cannot be created (TelemetryBlockedError); nothing is
 *    recorded or served.
 *  - 'minimal': aggregated health only; relay hosts are replaced by stable hashes (which relays a person
 *    uses is a fingerprint).
 *  - 'standard': relay host labels.
 * Labels never contain pubkeys, event ids, operation ids, relay paths/queries or relay message text:
 * only relay host (or hash), region, and coarse result/reason classes.
 */
export class NostrMetricsExporter {
  readonly level: Exclude<TelemetryLevel, 'none'>;
  private readonly registry = new Registry();
  private readonly engines = new Set<OutboxObservable>();
  readonly ackLatency: Histogram;
  readonly publishes: Counter;
  readonly outboxFailures: Counter;
  private readonly outboxDepth: Gauge;
  private readonly outboxOldest: Gauge;
  private readonly outboxFailed: Gauge;
  private readonly info: Gauge;

  constructor(private readonly opts: MetricsExporterOptions) {
    const level = levelOf(opts.telemetry);
    if (level === 'none') throw new TelemetryBlockedError('metrics export is disabled at telemetry level "none" (profile forbids telemetry)');
    this.level = level;
    const r = this.registry;
    this.info = r.register(new Gauge('nostr_metrics_info', 'Exporter metadata: telemetry level of the profile in force.', ['telemetry_level']));
    this.info.set({ telemetry_level: level }, 1);
    this.ackLatency = r.register(new Histogram('nostr_relay_ack_latency_seconds', 'Publish to OK latency per relay (accepted or duplicate), NIP-01 OK=true only means accepted by that relay.', ['relay', 'region'], opts.buckets ?? ACK_LATENCY_BUCKETS));
    this.publishes = r.register(new Counter('nostr_relay_publish_total', 'Publish attempts per relay by result class (ok, duplicate, or failure class).', ['relay', 'region', 'result']));
    this.outboxFailures = r.register(new Counter('nostr_outbox_relay_failures_total', 'Failed outbox publish attempts per relay by reason class.', ['relay', 'region', 'reason']));
    this.outboxDepth = r.register(new Gauge('nostr_outbox_depth', 'Outbox operations not yet replicated (quorum not reached) and not failed.', []));
    this.outboxOldest = r.register(new Gauge('nostr_outbox_oldest_pending_age_seconds', 'Age of the oldest outbox operation not yet replicated (0 when empty).', []));
    this.outboxFailed = r.register(new Gauge('nostr_outbox_failed_operations', 'Outbox operations in FAILED (quorum unreachable).', []));
  }

  /** Exporter for a profile, or undefined when its telemetry level forbids it (never throws). */
  static forProfile(profile: { telemetry: TelemetryLevel }, opts: Omit<MetricsExporterOptions, 'telemetry'> = {}): NostrMetricsExporter | undefined {
    return profile.telemetry === 'none' ? undefined : new NostrMetricsExporter({ ...opts, telemetry: profile.telemetry });
  }

  private labels(url: string) {
    return { relay: relayLabel(url, { pseudonymize: this.level === 'minimal', salt: this.opts.labelSalt }), region: regionFor(url, this.opts.regions, this.opts.defaultRegion) };
  }

  observePublish(res: PublishResult): void {
    const l = this.labels(res.relay);
    if (res.ok) {
      this.ackLatency.observe(l, res.latencyMs / 1000);
      this.publishes.inc({ ...l, result: res.duplicate ? 'duplicate' : 'ok' });
    } else this.publishes.inc({ ...l, result: classifyFailure(res.message, res.blocked) });
  }

  observeAttempt(a: AttemptEvent): void {
    if (a.ok || !a.failure) return;
    this.outboxFailures.inc({ ...this.labels(a.relay), reason: FAILURE_CLASSES.includes(a.failure) ? a.failure : 'other' });
  }

  /** Records every publish of a RelayPool. Returns a detach function. */
  attachPool(pool: PublishObservable): () => void {
    return pool.onPublishResult((r) => this.observePublish(r));
  }

  /** Records failures of a DeliveryEngine and adds its outbox to the depth/age gauges (summed across engines). */
  attachEngine(engine: OutboxObservable): () => void {
    const off = engine.onAttempt((a) => this.observeAttempt(a));
    this.engines.add(engine);
    return () => {
      off();
      this.engines.delete(engine);
    };
  }

  /** Prometheus text exposition (text/plain; version=0.0.4). */
  async render(): Promise<string> {
    let depth = 0;
    let oldest = 0;
    let failed = 0;
    for (const e of this.engines) {
      const s = await e.stats();
      depth += s.depth;
      failed += s.failed;
      oldest = Math.max(oldest, s.oldestPendingAgeMs);
    }
    this.outboxDepth.set({}, depth);
    this.outboxOldest.set({}, oldest / 1000);
    this.outboxFailed.set({}, failed);
    return this.registry.render();
  }
}
