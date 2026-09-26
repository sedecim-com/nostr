/**
 * Minimal Prometheus text-format (0.0.4) registry: counters, gauges and histograms with fixed label
 * names. No dependency on prom-client, so the same code runs in services and in clients.
 */
export type Labels = Record<string, string>;

const escapeLabel = (v: string) => v.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
const fmt = (n: number) => (Number.isFinite(n) ? String(n) : n > 0 ? '+Inf' : n < 0 ? '-Inf' : 'NaN');

function labelString(names: readonly string[], values: Labels, extra?: [string, string]): string {
  const parts = names.map((n) => `${n}="${escapeLabel(values[n] ?? '')}"`);
  if (extra) parts.push(`${extra[0]}="${escapeLabel(extra[1])}"`);
  return parts.length ? `{${parts.join(',')}}` : '';
}

abstract class Metric {
  abstract readonly type: 'counter' | 'gauge' | 'histogram';
  constructor(
    readonly name: string,
    readonly help: string,
    readonly labelNames: readonly string[],
  ) {
    if (!/^[a-zA-Z_:][a-zA-Z0-9_:]*$/.test(name)) throw new Error(`invalid metric name ${name}`);
  }
  protected key(labels: Labels): string {
    for (const k of Object.keys(labels)) if (!this.labelNames.includes(k)) throw new Error(`${this.name}: unexpected label ${k}`);
    return JSON.stringify(this.labelNames.map((n) => labels[n] ?? ''));
  }
  protected parse(key: string): Labels {
    const vals = JSON.parse(key) as string[];
    return Object.fromEntries(this.labelNames.map((n, i) => [n, vals[i]!]));
  }
  abstract samples(): string[];
  abstract reset(): void;
  render(): string {
    return [`# HELP ${this.name} ${this.help.replace(/\n/g, ' ')}`, `# TYPE ${this.name} ${this.type}`, ...this.samples()].join('\n');
  }
}

export class Counter extends Metric {
  readonly type = 'counter';
  private readonly values = new Map<string, number>();
  inc(labels: Labels = {}, by = 1): void {
    if (by < 0) throw new Error('counters only go up');
    const k = this.key(labels);
    this.values.set(k, (this.values.get(k) ?? 0) + by);
  }
  get(labels: Labels = {}): number {
    return this.values.get(this.key(labels)) ?? 0;
  }
  samples(): string[] {
    return [...this.values].map(([k, v]) => `${this.name}${labelString(this.labelNames, this.parse(k))} ${fmt(v)}`);
  }
  reset(): void {
    this.values.clear();
  }
}

export class Gauge extends Metric {
  readonly type = 'gauge';
  private readonly values = new Map<string, number>();
  set(labels: Labels, value: number): void {
    this.values.set(this.key(labels), value);
  }
  get(labels: Labels = {}): number | undefined {
    return this.values.get(this.key(labels));
  }
  samples(): string[] {
    return [...this.values].map(([k, v]) => `${this.name}${labelString(this.labelNames, this.parse(k))} ${fmt(v)}`);
  }
  reset(): void {
    this.values.clear();
  }
}

interface HistogramState {
  counts: number[];
  sum: number;
  count: number;
}

/** Cumulative-bucket histogram, so `histogram_quantile(0.95, rate(<name>_bucket[5m]))` works. */
export class Histogram extends Metric {
  readonly type = 'histogram';
  private readonly states = new Map<string, HistogramState>();
  readonly buckets: readonly number[];
  constructor(name: string, help: string, labelNames: readonly string[], buckets: readonly number[]) {
    super(name, help, labelNames);
    if (labelNames.includes('le')) throw new Error('"le" is reserved');
    this.buckets = [...buckets].sort((a, b) => a - b);
  }
  observe(labels: Labels, value: number): void {
    const k = this.key(labels);
    let st = this.states.get(k);
    if (!st) this.states.set(k, (st = { counts: this.buckets.map(() => 0), sum: 0, count: 0 }));
    this.buckets.forEach((b, i) => {
      if (value <= b) st.counts[i]!++;
    });
    st.sum += value;
    st.count++;
  }
  count(labels: Labels = {}): number {
    return this.states.get(this.key(labels))?.count ?? 0;
  }
  samples(): string[] {
    const out: string[] = [];
    for (const [k, st] of this.states) {
      const labels = this.parse(k);
      this.buckets.forEach((b, i) => out.push(`${this.name}_bucket${labelString(this.labelNames, labels, ['le', fmt(b)])} ${st.counts[i]}`));
      out.push(`${this.name}_bucket${labelString(this.labelNames, labels, ['le', '+Inf'])} ${st.count}`);
      out.push(`${this.name}_sum${labelString(this.labelNames, labels)} ${fmt(st.sum)}`);
      out.push(`${this.name}_count${labelString(this.labelNames, labels)} ${st.count}`);
    }
    return out;
  }
  reset(): void {
    this.states.clear();
  }
}

export class Registry {
  private readonly metrics: Metric[] = [];
  register<M extends Metric>(m: M): M {
    if (this.metrics.some((x) => x.name === m.name)) throw new Error(`duplicate metric ${m.name}`);
    this.metrics.push(m);
    return m;
  }
  render(): string {
    return this.metrics.map((m) => m.render()).join('\n') + '\n';
  }
}

export const PROMETHEUS_CONTENT_TYPE = 'text/plain; version=0.0.4; charset=utf-8';
