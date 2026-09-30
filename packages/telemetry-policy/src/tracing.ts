import { AsyncLocalStorage } from 'node:async_hooks';
import { randomBytes } from 'node:crypto';
import type { Logger, TelemetryPolicy } from './policy';

/*
 * NFR007-02: traces of the services, small on purpose (no OpenTelemetry SDK, no dependency):
 *  - sampling is decided once per trace, at its root, from the policy (`traceSampleRate`, 0 by default): the spans
 *    of a trace are all recorded or none is;
 *  - redaction by construction: a span only carries the attributes of SPAN_ATTRIBUTE_KEYS, each with a bounded value
 *    (method, route template, status code, error class, database operation). Anything else is dropped, never cleaned:
 *    no URL, header, body, address, pubkey, token or error message can be recorded. Span names are a dotted
 *    identifier (`db.query`) or `METHOD /route/:template`;
 *  - off unless the policy is 'standard' with a sample rate above 0: at 'minimal' and 'none' (the sovereign and Tor
 *    profiles) the tracer is a no-op that creates no span, draws no id and exports nothing.
 * The context is local to the process (AsyncLocalStorage): nothing reads or sends `traceparent`.
 */

export type SpanKind = 'internal' | 'server' | 'client';
export type SpanStatus = 'unset' | 'ok' | 'error';

/** The only attributes a span can carry. Unknown keys, and values outside each rule, are dropped. */
export interface SpanAttributes {
  /** HTTP method; anything but the usual verbs is recorded as `_OTHER`. */
  'http.request.method'?: string;
  /** Route template as registered (`/v1/keys/:id`), never the path of a request: a segment that looks like a value drops it. */
  'http.route'?: string;
  /** HTTP status code (100-599). */
  'http.response.status_code'?: number;
  /** Error class (`TypeError`) or a status code (`503`), never a message; anything else is `_OTHER`. */
  'error.type'?: string;
  /** Database system: `postgresql`. */
  'db.system'?: string;
  /** First keyword of the statement (`SELECT`, `INSERT`…), never the statement or its values; anything else is `_OTHER`. */
  'db.operation.name'?: string;
}

/** The attribute allowlist (NFR007-02). */
export const SPAN_ATTRIBUTE_KEYS = ['http.request.method', 'http.route', 'http.response.status_code', 'error.type', 'db.system', 'db.operation.name'] as const satisfies ReadonlyArray<keyof SpanAttributes>;

export interface SpanOptions {
  kind?: SpanKind;
  attributes?: SpanAttributes;
  /** True: this span and everything under it is never recorded, whatever the sampling says (e.g. a request to a .onion host). */
  untraced?: boolean;
}

export interface Span {
  /** False for the shared no-op span (tracing off, trace not sampled or untraced): nothing is kept or exported. */
  readonly recording: boolean;
  /** 32 hex characters; undefined when not recording (no id is drawn for an unrecorded trace). */
  readonly traceId: string | undefined;
  /** 16 hex characters; undefined when not recording. */
  readonly spanId: string | undefined;
  setAttribute<K extends keyof SpanAttributes>(key: K, value: SpanAttributes[K]): this;
  setAttributes(attributes: SpanAttributes): this;
  /** Replaces the name (same rule as at creation: an unsafe name becomes `span`). */
  updateName(name: string): this;
  setStatus(status: 'ok' | 'error'): this;
  /** Marks the span failed and records the class of the error (`error.type`), never its message. */
  recordError(err: unknown): this;
  /** Ends the span and hands it to the exporters. Idempotent; later changes are ignored. */
  end(): void;
}

/** A span as the exporters receive it. */
export interface FinishedSpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  kind: SpanKind;
  /** Unix epoch, milliseconds (fractional). */
  startMs: number;
  endMs: number;
  status: SpanStatus;
  attributes: SpanAttributes;
}

/** Receives finished spans. `export` runs on the traced path: it must be synchronous and never wait on I/O. */
export interface SpanExporter {
  export(span: FinishedSpan): void;
  flush?(): Promise<void>;
  shutdown?(): Promise<void>;
}

export interface Tracer {
  /** False for the no-op tracer: telemetry level other than 'standard', or a sample rate of 0. */
  readonly enabled: boolean;
  /** A span, child of the active span of this tracer, or a root whose sampling is decided here. It is not made active. */
  startSpan(name: string, opts?: SpanOptions): Span;
  /** Runs `fn` with a new span as the active one and ends it when `fn` returns or its promise settles (errors mark it failed). */
  withSpan<T>(name: string, fn: (span: Span) => T, opts?: SpanOptions): T;
  /** Waits until the exporters have handed over what they hold (bounded by their timeouts). */
  flush(): Promise<void>;
  shutdown(): Promise<void>;
}

export interface TracerOptions {
  /** Level and `traceSampleRate` of the deployment: traces only at 'standard' with a rate above 0. */
  policy: TelemetryPolicy;
  exporters?: SpanExporter[];
  /** Sampling draws, one per trace root (default Math.random: the decision is not a secret). */
  random?: () => number;
  /** Random ids as hex, `bytes` long (default node:crypto randomBytes). */
  randomId?: (bytes: number) => string;
  /** Clock, Unix epoch in milliseconds. */
  now?: () => number;
}

const NOOP_SPAN: Span = Object.freeze({
  recording: false,
  traceId: undefined,
  spanId: undefined,
  setAttribute() {
    return NOOP_SPAN;
  },
  setAttributes() {
    return NOOP_SPAN;
  },
  updateName() {
    return NOOP_SPAN;
  },
  setStatus() {
    return NOOP_SPAN;
  },
  recordError() {
    return NOOP_SPAN;
  },
  end() {},
}) as Span;

/** The tracer of a service without tracing: no span, no id, no context, no export. */
export const NOOP_TRACER: Tracer = Object.freeze({
  enabled: false,
  startSpan: () => NOOP_SPAN,
  withSpan: <T>(_name: string, fn: (span: Span) => T) => fn(NOOP_SPAN),
  flush: async () => {},
  shutdown: async () => {},
});

interface Context {
  tracer: Tracer;
  span: Span;
}

const storage = new AsyncLocalStorage<Context>();

// ---- redaction by construction

const HTTP_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']);
const DB_OPERATIONS = new Set(['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'WITH', 'BEGIN', 'COMMIT', 'ROLLBACK', 'CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'LOCK']);

/** Shapes of values, not of words: 8+ hex characters in a row, 4+ digits in a row, or a NIP-19 entity. */
const VALUE_LIKE = /[0-9a-f]{8}|\d{4}|(?:npub|nsec|nprofile|nevent|naddr|note|nrelay|ncryptsec)1/i;
const STATIC_SEGMENT = /^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$/;
const PARAM_SEGMENT = /^:[A-Za-z_][A-Za-z0-9_]{0,31}$/;

/**
 * A route template (`/v1/keys/:id/export`): `:param` placeholders and lowercase words of at most 32 characters. A
 * segment shaped like a value (hex, digits, NIP-19, dots, `:` or `@` of an address, `?`, `=`, uppercase) makes it no
 * template.
 */
export function isRouteTemplate(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 160 || !value.startsWith('/')) return false;
  if (value === '/') return true;
  return value
    .slice(1)
    .replace(/\/$/, '')
    .split('/')
    .every((s) => PARAM_SEGMENT.test(s) || (s.length <= 32 && STATIC_SEGMENT.test(s) && !VALUE_LIKE.test(s)));
}

/** A status code, or a class name made of capitalised words without digits (`ReplayStoreFullError`). */
const isErrorType = (v: string) => /^[1-5]\d\d$/.test(v) || (v.length <= 64 && /^(?:[A-Z][a-z]{1,14})+$/.test(v) && !VALUE_LIKE.test(v));

const ATTRIBUTE_RULES: { [K in keyof Required<SpanAttributes>]: (v: unknown) => SpanAttributes[K] | undefined } = {
  'http.request.method': (v) => (typeof v === 'string' ? (HTTP_METHODS.has(v) ? v : '_OTHER') : undefined),
  'http.route': (v) => (isRouteTemplate(v) ? v : undefined),
  'http.response.status_code': (v) => (typeof v === 'number' && Number.isInteger(v) && v >= 100 && v <= 599 ? v : undefined),
  'error.type': (v) => (typeof v === 'string' ? (isErrorType(v) ? v : '_OTHER') : undefined),
  'db.system': (v) => (v === 'postgresql' ? v : undefined),
  'db.operation.name': (v) => (typeof v === 'string' ? (DB_OPERATIONS.has(v) ? v : '_OTHER') : undefined),
};

/** A span name: a dotted lowercase identifier (`db.query`) or `METHOD` followed by a route template; otherwise `span`. */
export function safeSpanName(name: unknown): string {
  if (typeof name !== 'string') return 'span';
  if (name.length <= 64 && /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){0,4}$/.test(name) && !VALUE_LIKE.test(name)) return name;
  const m = /^([A-Z]{3,7})(?: (\/\S*))?$/.exec(name);
  return m && HTTP_METHODS.has(m[1]!) && (m[2] === undefined || isRouteTemplate(m[2])) ? name : 'span';
}

function errorType(err: unknown): string {
  try {
    const name = err !== null && typeof err === 'object' ? (err as { constructor?: { name?: unknown } }).constructor?.name : undefined;
    return typeof name === 'string' ? name : '_OTHER';
  } catch {
    return '_OTHER';
  }
}

// ---- recording

class RecordingSpan implements Span {
  readonly recording = true;
  ended = false;
  private name: string;
  private status: SpanStatus = 'unset';
  private readonly attributes: SpanAttributes = {};
  private readonly startMs: number;

  constructor(
    private readonly tracer: RecordingTracer,
    readonly traceId: string,
    readonly spanId: string,
    private readonly parentSpanId: string | undefined,
    name: string,
    private readonly kind: SpanKind,
  ) {
    this.name = safeSpanName(name);
    this.startMs = tracer.now();
  }

  setAttribute<K extends keyof SpanAttributes>(key: K, value: SpanAttributes[K]): this {
    if (this.ended || typeof key !== 'string' || !Object.hasOwn(ATTRIBUTE_RULES, key)) return this;
    const clean = (ATTRIBUTE_RULES[key] as (v: unknown) => SpanAttributes[K] | undefined)(value);
    if (clean !== undefined) this.attributes[key] = clean;
    return this;
  }

  setAttributes(attributes: SpanAttributes): this {
    if (attributes !== null && typeof attributes === 'object') for (const [k, v] of Object.entries(attributes)) this.setAttribute(k as keyof SpanAttributes, v as never);
    return this;
  }

  updateName(name: string): this {
    if (!this.ended) this.name = safeSpanName(name);
    return this;
  }

  setStatus(status: 'ok' | 'error'): this {
    if (!this.ended && (status === 'ok' || status === 'error')) this.status = status;
    return this;
  }

  recordError(err: unknown): this {
    this.setAttribute('error.type', errorType(err));
    return this.setStatus('error');
  }

  end(): void {
    if (this.ended) return;
    this.ended = true;
    this.tracer.finish({
      traceId: this.traceId,
      spanId: this.spanId,
      ...(this.parentSpanId ? { parentSpanId: this.parentSpanId } : {}),
      name: this.name,
      kind: this.kind,
      startMs: this.startMs,
      endMs: Math.max(this.startMs, this.tracer.now()),
      status: this.status,
      attributes: { ...this.attributes },
    });
  }
}

const isLive = (span: Span | undefined): span is RecordingSpan => span instanceof RecordingSpan && !span.ended;
const isThenable = (v: unknown): v is PromiseLike<unknown> => v !== null && (typeof v === 'object' || typeof v === 'function') && typeof (v as { then?: unknown }).then === 'function';

/** Runs `fn` in `span` and ends it when `fn` returns, throws or its promise settles. */
function runIn<T>(span: Span, fn: (span: Span) => T): T {
  let out: T;
  try {
    out = fn(span);
  } catch (err) {
    span.recordError(err).end();
    throw err;
  }
  if (!isThenable(out)) {
    span.end();
    return out;
  }
  return Promise.resolve(out).then(
    (v) => (span.end(), v),
    (err: unknown) => {
      span.recordError(err).end();
      throw err;
    },
  ) as T;
}

class RecordingTracer implements Tracer {
  readonly enabled = true;
  readonly now: () => number;
  private readonly random: () => number;
  private readonly randomId: (bytes: number) => string;

  constructor(
    private readonly policy: TelemetryPolicy,
    private readonly exporters: SpanExporter[],
    opts: TracerOptions,
  ) {
    this.random = opts.random ?? Math.random;
    this.randomId = opts.randomId ?? ((n) => randomBytes(n).toString('hex'));
    this.now = opts.now ?? (() => performance.timeOrigin + performance.now());
  }

  /** A random id that is not all zeros (invalid for W3C trace context). */
  private id(bytes: number): string {
    for (;;) {
      const id = this.randomId(bytes);
      if (!/^0*$/.test(id)) return id;
    }
  }

  startSpan(name: string, opts: SpanOptions = {}): Span {
    if (opts.untraced) return NOOP_SPAN;
    const ctx = storage.getStore();
    // A parent of this tracer decides for its children: sampled or not, once per trace. One that already ended
    // (a timer started inside a request outlives it) adopts nothing: the work becomes a root of its own.
    const parent = ctx && ctx.tracer === this && (!ctx.span.recording || isLive(ctx.span)) ? ctx.span : undefined;
    let span: Span;
    if (parent) span = isLive(parent) ? new RecordingSpan(this, parent.traceId, this.id(8), parent.spanId, name, opts.kind ?? 'internal') : NOOP_SPAN;
    else span = this.policy.shouldTrace(this.random) ? new RecordingSpan(this, this.id(16), this.id(8), undefined, name, opts.kind ?? 'internal') : NOOP_SPAN;
    if (opts.attributes) span.setAttributes(opts.attributes);
    return span;
  }

  withSpan<T>(name: string, fn: (span: Span) => T, opts?: SpanOptions): T {
    const span = this.startSpan(name, opts);
    // An unrecorded root is still put in the context, so that its children inherit "not sampled".
    return storage.run({ tracer: this, span }, () => runIn(span, fn));
  }

  finish(span: FinishedSpan): void {
    for (const e of this.exporters) {
      try {
        e.export(span);
      } catch {
        // An exporter never breaks the traced work.
      }
    }
  }

  async flush(): Promise<void> {
    await Promise.all(this.exporters.map((e) => e.flush?.().catch(() => undefined)));
  }

  async shutdown(): Promise<void> {
    await Promise.all(this.exporters.map((e) => (e.shutdown ?? e.flush)?.call(e).catch(() => undefined)));
  }
}

/**
 * The tracer of a service (NFR007-02): NOOP_TRACER unless the policy allows tracing (level 'standard' and a
 * `traceSampleRate` above 0), so at 'none' no span, id or export can exist, whatever else is configured.
 */
export function createTracer(opts: TracerOptions): Tracer {
  const rate = opts.policy.config.traceSampleRate ?? 0;
  if (typeof rate !== 'number' || !(rate >= 0 && rate <= 1)) throw new RangeError(`traceSampleRate must be a number between 0 and 1, got ${String(rate)}`);
  if (!opts.policy.tracingEnabled()) return NOOP_TRACER;
  return new RecordingTracer(opts.policy, opts.exporters ?? [], opts);
}

/** The active span, if it is recording: code with no tracer at hand can tell whether a child would be kept. */
export function activeSpan(): Span | undefined {
  const span = storage.getStore()?.span;
  return isLive(span) ? span : undefined;
}

/**
 * Runs `fn` in a child of the active span when that span is recording (e.g. a database query inside a sampled
 * request), or just runs it otherwise: nothing starts a trace from here.
 */
export function inChildSpan<T>(name: string, fn: (span: Span) => T, opts?: Omit<SpanOptions, 'untraced'>): T {
  const ctx = storage.getStore();
  return ctx && isLive(ctx.span) ? ctx.tracer.withSpan(name, fn, opts) : fn(NOOP_SPAN);
}

// ---- exporters

/** One structured log line per finished span, through the service's logger (its level and redaction apply). */
export function logSpanExporter(logger: Logger): SpanExporter {
  return {
    export: (s) =>
      logger.info('span', {
        trace_id: s.traceId,
        span_id: s.spanId,
        ...(s.parentSpanId ? { parent_span_id: s.parentSpanId } : {}),
        span_name: s.name,
        span_kind: s.kind,
        span_status: s.status,
        duration_ms: Math.round((s.endMs - s.startMs) * 1000) / 1000,
        ...s.attributes,
      }),
  };
}

const OTLP_KIND: Record<SpanKind, number> = { internal: 1, server: 2, client: 3 };
const OTLP_STATUS: Record<SpanStatus, number> = { unset: 0, ok: 1, error: 2 };
const nanos = (ms: number) => (BigInt(Math.round(ms * 1000)) * 1000n).toString();

/** OTLP/HTTP JSON body (`ExportTraceServiceRequest`) for spans of one service. */
export function otlpTraceRequest(serviceName: string, spans: FinishedSpan[]): unknown {
  return {
    resourceSpans: [
      {
        resource: { attributes: [{ key: 'service.name', value: { stringValue: serviceName } }] },
        scopeSpans: [
          {
            scope: { name: '@sedecim/telemetry-policy' },
            spans: spans.map((s) => ({
              traceId: s.traceId,
              spanId: s.spanId,
              ...(s.parentSpanId ? { parentSpanId: s.parentSpanId } : {}),
              name: s.name,
              kind: OTLP_KIND[s.kind],
              startTimeUnixNano: nanos(s.startMs),
              endTimeUnixNano: nanos(s.endMs),
              attributes: Object.entries(s.attributes).map(([name, v]) => ({ key: name, value: typeof v === 'number' ? { intValue: String(v) } : { stringValue: String(v) } })),
              status: { code: OTLP_STATUS[s.status] },
            })),
          },
        ],
      },
    ],
  };
}

export interface OtlpHttpExporterOptions {
  /** Endpoint of the operator's collector, e.g. http://otel-collector:4318/v1/traces. */
  url: string;
  /** Must list `url` among its endpoints; at level 'none' the exporter cannot be built (TelemetryBlockedError). */
  policy: TelemetryPolicy;
  /** `service.name` of the resource: a lowercase slug (`identity-service`), `service` otherwise. */
  serviceName: string;
  /** Spans kept while waiting to be sent (default 2048); beyond it new spans are dropped and counted. */
  maxQueueSize?: number;
  /** Spans per request (default 512); a full batch is sent at once. */
  maxBatchSize?: number;
  /** A partial batch waits at most this long (default 5000 ms). */
  flushIntervalMs?: number;
  /** Per request (default 5000 ms). A batch that fails or times out is dropped: there are no retries. */
  timeoutMs?: number;
  fetch?: typeof fetch;
  /** Told how many spans were dropped: `queue-full` (reported once per send) or `send-failed` (one batch). */
  onDrop?: (reason: 'queue-full' | 'send-failed', spans: number) => void;
}

/**
 * OTLP/HTTP JSON exporter (NFR007-02), off unless the operator sets an endpoint. Never on the traced path: `export`
 * only queues (bounded), one request at a time leaves in the background, with a timeout, no redirects and no
 * retries; the policy must allow the endpoint before every request.
 */
export class OtlpHttpExporter implements SpanExporter {
  readonly stats = { exported: 0, dropped: 0, failed: 0 };
  private queue: FinishedSpan[] = [];
  private unreported = 0;
  private timer?: ReturnType<typeof setTimeout>;
  private draining?: Promise<void>;
  private closed = false;
  private readonly maxQueue: number;
  private readonly maxBatch: number;
  private readonly interval: number;
  private readonly timeout: number;
  private readonly fetchImpl: typeof fetch;
  private readonly serviceName: string;

  constructor(private readonly opts: OtlpHttpExporterOptions) {
    const u = new URL(opts.url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('the trace export URL must be http or https');
    if (u.username || u.password) throw new Error('the trace export URL must not carry credentials');
    opts.policy.assertEndpointAllowed(opts.url);
    const positive = (v: number | undefined, d: number) => (v !== undefined && Number.isFinite(v) && v > 0 ? Math.floor(v) : d);
    this.maxQueue = positive(opts.maxQueueSize, 2048);
    this.maxBatch = positive(opts.maxBatchSize, 512);
    this.interval = positive(opts.flushIntervalMs, 5000);
    this.timeout = positive(opts.timeoutMs, 5000);
    this.fetchImpl = opts.fetch ?? fetch;
    this.serviceName = /^[a-z][a-z0-9-]{0,63}$/.test(opts.serviceName) ? opts.serviceName : 'service';
  }

  export(span: FinishedSpan): void {
    if (this.closed) {
      this.stats.dropped++;
      return;
    }
    if (this.queue.length >= this.maxQueue) {
      this.stats.dropped++;
      this.unreported++;
      return;
    }
    this.queue.push(span);
    if (this.queue.length >= this.maxBatch) void this.flush();
    else this.timer ??= setTimeout(() => {
      this.timer = undefined;
      void this.flush();
    }, this.interval).unref();
  }

  /** Sends what is queued; callers during a send wait for that same drain. */
  flush(): Promise<void> {
    this.draining ??= this.drain().finally(() => (this.draining = undefined));
    return this.draining;
  }

  async shutdown(): Promise<void> {
    this.closed = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    await this.flush();
  }

  private async drain(): Promise<void> {
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    while (this.queue.length) {
      this.report();
      await this.send(this.queue.splice(0, this.maxBatch));
    }
    this.report();
  }

  private report(): void {
    if (!this.unreported) return;
    this.dropped('queue-full', this.unreported);
    this.unreported = 0;
  }

  /** A drain runs unawaited: a throwing `onDrop` must not turn into an unhandled rejection. */
  private dropped(reason: 'queue-full' | 'send-failed', spans: number): void {
    try {
      this.opts.onDrop?.(reason, spans);
    } catch {
      // Reporting never breaks exporting.
    }
  }

  private async send(batch: FinishedSpan[]): Promise<void> {
    try {
      this.opts.policy.assertEndpointAllowed(this.opts.url);
      const res = await this.fetchImpl(this.opts.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(otlpTraceRequest(this.serviceName, batch)),
        redirect: 'error',
        signal: AbortSignal.timeout(this.timeout),
      });
      await res.arrayBuffer().catch(() => undefined);
      if (!res.ok) throw new Error(`collector answered ${res.status}`);
      this.stats.exported += batch.length;
    } catch {
      this.stats.failed += batch.length;
      this.dropped('send-failed', batch.length);
    }
  }
}
