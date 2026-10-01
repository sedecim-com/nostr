import { redact, type RedactOptions } from './redact';

export type TelemetryLevel = 'standard' | 'minimal' | 'none';
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export interface TelemetryConfig {
  level: TelemetryLevel;
  /** Remote endpoints allowed to receive telemetry (none are allowed at level 'none'). */
  endpoints?: string[];
  minimizeIp?: boolean;
  /** Fraction of traces recorded at level 'standard' (0..1, default 0: off), decided at each root (NFR007-02). */
  traceSampleRate?: number;
}

export class TelemetryBlockedError extends Error {}

export interface TelemetryEvent {
  name: string;
  attributes?: Record<string, unknown>;
}

export type TelemetrySink = (endpoint: string, event: TelemetryEvent) => void | Promise<void>;

/**
 * Telemetry gate. At level 'none' (Sovereign/Tor) nothing is ever emitted and any attempt to reach a
 * telemetry endpoint throws (FR-022). Minimal keeps aggregated health only.
 */
export class TelemetryPolicy {
  readonly emitted: Array<{ endpoint: string; event: TelemetryEvent }> = [];
  constructor(readonly config: TelemetryConfig, private readonly sink?: TelemetrySink) {}

  allowedEndpoints(): string[] {
    return this.config.level === 'none' ? [] : (this.config.endpoints ?? []);
  }

  assertEndpointAllowed(url: string): void {
    const ok = this.allowedEndpoints().some((e) => url === e || url.startsWith(e.endsWith('/') ? e : e + '/'));
    if (!ok) throw new TelemetryBlockedError(`telemetry endpoint not allowed at level "${this.config.level}": ${url}`);
  }

  private allowedName(name: string): boolean {
    if (this.config.level === 'none') return false;
    if (this.config.level === 'minimal') return name.startsWith('health.') || name.startsWith('relay.health');
    return true;
  }

  async emit(event: TelemetryEvent): Promise<boolean> {
    if (!this.allowedName(event.name)) return false;
    const safe: TelemetryEvent = {
      name: event.name,
      ...(event.attributes ? { attributes: redact(this.config.level === 'minimal' ? {} : event.attributes, { minimizeIp: this.config.minimizeIp ?? true }) } : {}),
    };
    for (const endpoint of this.allowedEndpoints()) {
      this.emitted.push({ endpoint, event: safe });
      await this.sink?.(endpoint, safe);
    }
    return this.allowedEndpoints().length > 0;
  }

  /** Traces are only possible at level 'standard' with a sample rate above 0 (NFR007-02); 'minimal' and 'none' never trace. */
  tracingEnabled(): boolean {
    return this.config.level === 'standard' && (this.config.traceSampleRate ?? 0) > 0;
  }

  /** Sampling decision of one trace, taken once at its root (NFR007-02). */
  shouldTrace(random: () => number = Math.random): boolean {
    return this.tracingEnabled() && random() < (this.config.traceSampleRate ?? 0);
  }
}

export interface LogRecord {
  ts: string;
  level: LogLevel;
  msg: string;
  [k: string]: unknown;
}

export interface Logger {
  debug(msg: string, fields?: Record<string, unknown>): void;
  info(msg: string, fields?: Record<string, unknown>): void;
  warn(msg: string, fields?: Record<string, unknown>): void;
  error(msg: string, fields?: Record<string, unknown>): void;
  child(fields: Record<string, unknown>): Logger;
}

const ORDER: LogLevel[] = ['debug', 'info', 'warn', 'error'];

/** Structured logger that always redacts secrets and, when asked, IPs. */
export function createLogger(opts: { level?: LogLevel; write?: (r: LogRecord) => void; base?: Record<string, unknown> } & RedactOptions = {}): Logger {
  const min = ORDER.indexOf(opts.level ?? 'info');
  const write = opts.write ?? ((r) => process.stdout.write(JSON.stringify(r) + '\n'));
  const make = (base: Record<string, unknown>): Logger => {
    const log = (level: LogLevel, msg: string, fields: Record<string, unknown> = {}) => {
      if (ORDER.indexOf(level) < min) return;
      const rec = redact({ ...base, ...fields }, { minimizeIp: opts.minimizeIp });
      write({ ts: new Date().toISOString(), level, msg: redact(msg), ...rec });
    };
    return {
      debug: (m, f) => log('debug', m, f),
      info: (m, f) => log('info', m, f),
      warn: (m, f) => log('warn', m, f),
      error: (m, f) => log('error', m, f),
      child: (f) => make({ ...base, ...f }),
    };
  };
  return make(opts.base ?? {});
}
