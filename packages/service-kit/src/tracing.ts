import { createTracer, logSpanExporter, OtlpHttpExporter, TelemetryPolicy, NOOP_TRACER, type Logger, type SpanExporter, type TelemetryLevel, type Tracer } from '@sedecim/telemetry-policy';

/** NFR007-02: traces of a service, as its deployment configures them (tracingFromEnv). */
export interface ServiceTracingOptions {
  /** Telemetry level of the deployment: traces only at 'standard'. 'none' (sovereign and Tor deployments) keeps them off. */
  telemetry: TelemetryLevel;
  /** Fraction of requests traced, decided once per trace at its root (0..1; 0 = off). */
  sampleRate: number;
  /** OTLP/HTTP JSON endpoint of the operator's collector. None by default: spans only go to the service's log. */
  exportUrl?: string;
}

const LEVELS: readonly TelemetryLevel[] = ['standard', 'minimal', 'none'];

/**
 * Env knobs shared by every service: TELEMETRY_LEVEL = standard (default) | minimal | none; TRACE_SAMPLE_RATE = 0..1
 * (default 0: no traces); TRACE_EXPORT_URL = the operator's OTLP/HTTP endpoint (optional). At TELEMETRY_LEVEL=none
 * the TRACE_* variables are not even read: nothing in the environment turns tracing on.
 */
export function tracingFromEnv(env: Record<string, string | undefined>): ServiceTracingOptions {
  const telemetry = (env.TELEMETRY_LEVEL?.trim() || 'standard') as TelemetryLevel;
  if (!LEVELS.includes(telemetry)) throw new Error('TELEMETRY_LEVEL must be standard, minimal or none');
  if (telemetry === 'none') return { telemetry, sampleRate: 0 };
  const raw = env.TRACE_SAMPLE_RATE?.trim();
  const sampleRate = raw ? Number(raw) : 0;
  if (!(sampleRate >= 0 && sampleRate <= 1)) throw new Error(`TRACE_SAMPLE_RATE must be a number between 0 and 1, got '${raw}'`);
  const exportUrl = env.TRACE_EXPORT_URL?.trim();
  if (exportUrl) {
    let u: URL;
    try {
      u = new URL(exportUrl);
    } catch {
      throw new Error('TRACE_EXPORT_URL must be an http(s) URL');
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('TRACE_EXPORT_URL must be an http(s) URL');
    if (u.username || u.password) throw new Error('TRACE_EXPORT_URL must not carry credentials');
  }
  return { telemetry, sampleRate, ...(exportUrl ? { exportUrl } : {}) };
}

/**
 * The tracer of a service: spans go to its logger, one line each, and to the operator's collector when an export URL
 * is set (the only endpoint the policy allows). NOOP_TRACER without options, at a level other than 'standard' or with
 * a sample rate of 0. A Tracer passes through (tests).
 */
export function createServiceTracer(name: string, opts: ServiceTracingOptions | Tracer | undefined, logger: Logger): Tracer {
  if (!opts) return NOOP_TRACER;
  if ('withSpan' in opts) return opts;
  const policy = new TelemetryPolicy({ level: opts.telemetry, traceSampleRate: opts.sampleRate, ...(opts.exportUrl ? { endpoints: [opts.exportUrl] } : {}) });
  if (!policy.tracingEnabled()) return NOOP_TRACER;
  const exporters: SpanExporter[] = [logSpanExporter(logger)];
  if (opts.exportUrl) {
    // Counts only: no URL, span or error text reaches the log.
    const onDrop = (reason: 'queue-full' | 'send-failed', spans: number) => logger.warn('trace export dropped spans', { reason, spans });
    exporters.push(new OtlpHttpExporter({ url: opts.exportUrl, policy, serviceName: name, onDrop }));
  }
  return createTracer({ policy, exporters });
}

/** A request addressed to an onion service (Host `….onion`): never traced, whatever the sampling (NFR007-02). */
export function isOnionHost(host: string | undefined): boolean {
  return /\.onion\.?(?::\d{1,5})?$/i.test(host ?? '');
}
