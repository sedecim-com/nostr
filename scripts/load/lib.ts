// NFR005-02: load generator for the relay and the indexer (docs/load-testing.md).
// N NIP-42-authenticated clients publish (open loop, fixed rate) and subscribe at the same time; the run
// measures publish→OK latency, throughput, errors, subscription delivery latency and indexer lag (time
// until an acked event is returned by the mirror API).
import { monitorEventLoopDelay } from 'node:perf_hooks';
import WebSocket from 'ws';
import { bytesToHex, generateSecretKey, getPublicKey, hexToBytes, randomBytes, type NostrEvent } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { chatMessage, createDirectMessage, createGroup, joinRequest, parseGroupMetadata } from '@sedecim/messaging';
import { nip98Fetch } from '@sedecim/service-kit';

export interface LoadOptions {
  relay: string;
  /** Mirror API base URLs (several replicas: polled round robin). Empty: no indexer lag. */
  indexers: string[];
  clients: number;
  /** Events per second per publishing client. */
  rate: number;
  durationS: number;
  /** Content sizes in bytes, one picked at random per event. */
  sizes: number[];
  /** Kind weights: 9 (NIP-29 channel message), 1059 (NIP-17 gift wrap), 1 (note). */
  mix: Record<number, number>;
  channels: number;
  /** Fraction of acked mirrored events (kinds 9/1) whose indexer lag is measured. */
  lagSample: number;
  /** Seconds to wait after publishing for deliveries and the indexer. */
  drainS: number;
  maxInflight: number;
  /**
   * Relays without NIP-29 (the local test relay): hex secret that signs the channel state in place of the relay,
   * the metadata (39000) and a member list (39002) naming the load's admin. The local mirror trusts it as the
   * relay key (FR014-05). Default: the admin's own key.
   */
  groupKey?: string;
  label?: string;
  log?: (msg: string) => void;
}

export const DEFAULT_OPTIONS: Omit<LoadOptions, 'relay' | 'indexers'> = {
  clients: 10,
  rate: 2,
  durationS: 30,
  sizes: [256, 1024],
  mix: { 9: 80, 1059: 15, 1: 5 },
  channels: 4,
  lagSample: 0.2,
  drainS: 20,
  maxInflight: 200,
};

export const PROFILES: Record<string, Partial<LoadOptions>> = {
  smoke: { clients: 5, rate: 2, durationS: 10, drainS: 10 },
  baseline: { clients: 20, rate: 2, durationS: 60 },
  stress: { clients: 50, rate: 5, durationS: 60, sizes: [256, 1024, 4096] },
};

export interface Stats {
  count: number;
  mean: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
}

export function stats(samples: number[]): Stats {
  if (!samples.length) return { count: 0, mean: 0, p50: 0, p95: 0, p99: 0, max: 0 };
  const s = [...samples].sort((a, b) => a - b);
  const q = (p: number) => s[Math.min(s.length - 1, Math.ceil(p * s.length) - 1)]!;
  const r = (v: number) => Math.round(v * 10) / 10;
  return { count: s.length, mean: r(s.reduce((a, b) => a + b, 0) / s.length), p50: r(q(0.5)), p95: r(q(0.95)), p99: r(q(0.99)), max: r(s[s.length - 1]!) };
}

export interface LoadReport {
  label: string;
  relay: string;
  indexers: string[];
  startedAt: string;
  options: Omit<LoadOptions, 'log'>;
  setup: { connectedClients: number; channels: string[]; channelSetup: 'nip29' | 'metadata'; setupMs: number };
  publish: { attempted: number; ok: number; failed: number; skippedBackpressure: number; throughputOkPerS: number; offeredPerS: number; bytesOk: number; ackMs: Stats; errors: Record<string, number>; byKind: Record<string, { ok: number; failed: number; ackMs: Stats }> };
  delivery: { expected: number; delivered: number; ratio: number; latencyMs: Stats };
  indexer: { sampled: number; found: number; missing: number; lagMs: Stats; pollErrors: number };
  generator: { eventLoopP99Ms: number; eventLoopMaxMs: number };
}

const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function pickWeighted(mix: Record<number, number>): number {
  const entries = Object.entries(mix).filter(([, w]) => w > 0);
  const total = entries.reduce((n, [, w]) => n + w, 0);
  let x = Math.random() * total;
  for (const [k, w] of entries) if ((x -= w) < 0) return Number(k);
  return Number(entries[0]![0]);
}

function padding(size: number): string {
  return bytesToHex(randomBytes(Math.ceil(size / 2))).slice(0, size);
}

/** Error messages grouped by their machine-readable prefix (NIP-01 OK reasons). */
function errorKey(message: string): string {
  const m = message.trim();
  return (m.split(':')[0] || 'empty').slice(0, 60);
}

interface Client {
  sk: Uint8Array;
  pk: string;
  signer: LocalSigner;
  pool: RelayPool;
  inflight: number;
}

/**
 * Creates the channels: NIP-29 create-group (relays such as Buzz assign the id, publish kind 39000 and make the
 * creator owner); relays without NIP-29 (test relay) get the 39000 metadata and a 39002 member list naming the
 * admin published directly, signed with `groupKey`. Either way the admin is a member: it reads the mirror.
 */
async function setupChannels(opts: LoadOptions, admin: Client): Promise<{ ids: string[]; mode: 'nip29' | 'metadata' }> {
  const run = bytesToHex(randomBytes(4));
  const names = Array.from({ length: opts.channels }, (_, i) => `load-${run}-${i}`);
  for (const n of names) await admin.pool.publishTo(await admin.signer.signEvent(createGroup(n, 'open')), opts.relay);
  // A NIP-29 relay publishes the 39000 within a moment; no 39000 at all after ~3 s means no NIP-29 support.
  const started = Date.now();
  while (Date.now() - started < 15_000) {
    const metas = (await admin.pool.query([opts.relay], [{ kinds: [39000], limit: 1000 }], 5000)).map(parseGroupMetadata);
    const ids = names.map((n) => metas.find((m) => m?.name === n)?.id).filter((id): id is string => !!id);
    if (ids.length === names.length) return { ids, mode: 'nip29' };
    if (!ids.length && Date.now() - started > 3000) break;
    await sleep(500);
  }
  const ids = names.map((n) => n);
  const group = opts.groupKey ? new LocalSigner(hexToBytes(opts.groupKey)) : admin.signer;
  for (const id of ids) {
    await admin.pool.publishTo(await group.signEvent({ kind: 39000, content: '', tags: [['d', id], ['name', id]] }), opts.relay);
    await admin.pool.publishTo(await group.signEvent({ kind: 39002, content: '', tags: [['d', id], ['p', admin.pk, '', 'member']] }), opts.relay);
  }
  return { ids, mode: 'metadata' };
}

export async function runLoad(input: Partial<LoadOptions> & Pick<LoadOptions, 'relay'>): Promise<LoadReport> {
  const opts: LoadOptions = { ...DEFAULT_OPTIONS, indexers: [], ...input };
  const log = opts.log ?? (() => undefined);
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  const mk = (): Client => {
    const sk = generateSecretKey();
    const signer = new LocalSigner(sk);
    return { sk, pk: getPublicKey(sk), signer, pool: new RelayPool({ webSocketFactory: factory, signer, authMode: 'auto', autoReconnect: true, verifyEvents: false }), inflight: 0 };
  };
  const admin = mk();
  const clients = Array.from({ length: opts.clients }, mk);
  const loop = monitorEventLoopDelay({ resolution: 10 });

  try {
    const { ids: channels, mode } = await setupChannels(opts, admin);
    log(`channels ready (${mode}): ${channels.join(',')}`);

    // Delivery bookkeeping: publish start time per event id and who must receive it.
    const sentAt = new Map<string, number>();
    const delivered = new Set<string>();
    const deliveryMs: number[] = [];
    let expected = 0;
    const onDelivery = (subscriber: string, evt: NostrEvent) => {
      const t = sentAt.get(evt.id);
      if (t === undefined) return;
      const key = `${subscriber}|${evt.id}`;
      if (delivered.has(key)) return;
      delivered.add(key);
      deliveryMs.push(Date.now() - t);
    };

    await Promise.all(
      clients.map(async (c) => {
        for (const h of channels) await c.pool.publishTo(await c.signer.signEvent(joinRequest(h)), opts.relay).catch(() => undefined);
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, 10_000);
          c.pool.subscribe([opts.relay], [{ kinds: [9], '#h': channels, limit: 0 }, { kinds: [1059], '#p': [c.pk], limit: 0 }], {
            onevent: (evt) => onDelivery(c.pk, evt),
            oneose: () => {
              clearTimeout(timer);
              resolve();
            },
            onclosed: (_r, reason) => log(`subscription closed: ${reason}`),
          });
        });
      }),
    );
    const connectedClients = clients.filter((c) => c.pool.health().some((h) => h.status === 'connected')).length;
    const setupMs = Date.now() - t0;
    log(`${connectedClients}/${clients.length} clients connected and subscribed in ${setupMs} ms`);

    // Warm-up: one message per channel must reach the mirror before measuring (channel discovery is periodic).
    if (opts.indexers.length) {
      const probes = await Promise.all(channels.map(async (h) => {
        const evt = await admin.signer.signEvent(chatMessage(h, 'warm-up'));
        await admin.pool.publishTo(evt, opts.relay);
        return evt.id;
      }));
      // FR014-05: the mirror serves a channel only to its members; the admin created them.
      const reader = admin.sk;
      const end = Date.now() + 120_000;
      let seen = 0;
      while (Date.now() < end) {
        const res = await nip98Fetch(reader, `${opts.indexers[0]}/v1/events?kinds=9&ids=${probes.join(',')}&limit=100`).catch(() => undefined);
        seen = res?.status === 200 ? (res.json.events as NostrEvent[]).length : 0;
        if (seen === probes.length) break;
        await sleep(500);
      }
      log(`indexer warm-up: ${seen}/${probes.length} channels mirrored`);
    }

    // Indexer lag: acked events are polled by id until the mirror returns them.
    const lagPending = new Map<string, number>();
    const lagMs: number[] = [];
    let sampled = 0;
    let pollErrors = 0;
    let polling = opts.indexers.length > 0;
    const poller = (async () => {
      const reader = admin.sk;
      let rr = 0;
      while (polling || lagPending.size) {
        const ids = [...lagPending.keys()].slice(0, 50);
        if (ids.length) {
          const base = opts.indexers[rr++ % opts.indexers.length]!;
          try {
            const res = await nip98Fetch(reader, `${base}/v1/events?kinds=1,9&ids=${ids.join(',')}&limit=100`);
            if (res.status !== 200) pollErrors++;
            else for (const e of res.json.events as NostrEvent[]) {
              const at = lagPending.get(e.id);
              if (at === undefined) continue;
              lagMs.push(Date.now() - at);
              lagPending.delete(e.id);
            }
          } catch {
            pollErrors++;
          }
        }
        await sleep(ids.length ? 100 : 50);
      }
    })();

    const ack: Record<string, number[]> = {};
    const allAck: number[] = [];
    const errors: Record<string, number> = {};
    const byKind: Record<string, { ok: number; failed: number }> = {};
    let attempted = 0;
    let ok = 0;
    let failed = 0;
    let skipped = 0;
    let bytesOk = 0;

    const fire = async (c: Client) => {
      if (c.inflight >= opts.maxInflight) {
        skipped++;
        return;
      }
      c.inflight++;
      attempted++;
      const kind = pickWeighted(opts.mix);
      const size = opts.sizes[Math.floor(Math.random() * opts.sizes.length)]!;
      try {
        let evt: NostrEvent;
        let receivers = 0;
        if (kind === 9) {
          evt = await c.signer.signEvent(chatMessage(channels[Math.floor(Math.random() * channels.length)]!, padding(size)));
          receivers = clients.length;
        } else if (kind === 1059) {
          const to = clients[Math.floor(Math.random() * clients.length)]!;
          // Bounded timestamps: relays such as Buzz reject the 2-day NIP-59 jitter (docs/buzz-integration.md).
          const dm = await createDirectMessage(c.signer, { recipients: [to.pk], content: padding(size) }, { timestampJitterSeconds: 0 });
          evt = dm.wraps.find((w) => w.recipient === to.pk)!.event;
          receivers = 1;
        } else {
          evt = await c.signer.signEvent({ kind: 1, content: padding(size), tags: [] });
        }
        const started = Date.now();
        sentAt.set(evt.id, started);
        const res = await c.pool.publishTo(evt, opts.relay);
        const k = String(kind);
        byKind[k] ??= { ok: 0, failed: 0 };
        if (res.ok) {
          ok++;
          byKind[k].ok++;
          bytesOk += JSON.stringify(evt).length;
          (ack[k] ??= []).push(res.latencyMs);
          allAck.push(res.latencyMs);
          expected += receivers;
          if ((kind === 9 || kind === 1) && polling && Math.random() < opts.lagSample) {
            sampled++;
            lagPending.set(evt.id, started);
          }
        } else {
          failed++;
          byKind[k].failed++;
          sentAt.delete(evt.id);
          const key = errorKey(res.message);
          errors[key] = (errors[key] ?? 0) + 1;
        }
      } catch (err) {
        failed++;
        const key = errorKey(`client: ${(err as Error).message}`);
        errors[key] = (errors[key] ?? 0) + 1;
      } finally {
        c.inflight--;
      }
    };

    loop.enable();
    const pubStart = Date.now();
    const pending = new Set<Promise<void>>();
    const timers = clients.map((c, i) => {
      const every = 1000 / opts.rate;
      const start = setTimeout(() => {
        const tick = () => {
          const p = fire(c);
          pending.add(p);
          void p.finally(() => pending.delete(p));
        };
        tick();
        timers[i] = setInterval(tick, every);
      }, Math.random() * (1000 / opts.rate));
      return start as ReturnType<typeof setTimeout> | ReturnType<typeof setInterval>;
    });
    await sleep(opts.durationS * 1000);
    timers.forEach((t) => clearInterval(t as ReturnType<typeof setInterval>));
    const pubElapsed = (Date.now() - pubStart) / 1000;
    await Promise.all(pending);
    log(`published ${ok}/${attempted} in ${pubElapsed.toFixed(1)} s; draining`);

    const drainEnd = Date.now() + opts.drainS * 1000;
    while (Date.now() < drainEnd && (delivered.size < expected || lagPending.size)) await sleep(100);
    polling = false;
    const missing = lagPending.size;
    lagPending.clear();
    await poller;
    loop.disable();

    const byKindOut: LoadReport['publish']['byKind'] = {};
    for (const [k, v] of Object.entries(byKind)) byKindOut[k] = { ...v, ackMs: stats(ack[k] ?? []) };
    const { log: _log, ...optsOut } = opts;
    return {
      label: opts.label ?? 'custom',
      relay: opts.relay,
      indexers: opts.indexers,
      startedAt,
      options: optsOut,
      setup: { connectedClients, channels, channelSetup: mode, setupMs },
      publish: {
        attempted,
        ok,
        failed,
        skippedBackpressure: skipped,
        throughputOkPerS: Math.round((ok / pubElapsed) * 10) / 10,
        offeredPerS: Math.round(opts.clients * opts.rate * 10) / 10,
        bytesOk,
        ackMs: stats(allAck),
        errors,
        byKind: byKindOut,
      },
      delivery: { expected, delivered: delivered.size, ratio: expected ? Math.round((delivered.size / expected) * 10_000) / 10_000 : 1, latencyMs: stats(deliveryMs) },
      indexer: { sampled, found: lagMs.length, missing, lagMs: stats(lagMs), pollErrors },
      generator: { eventLoopP99Ms: Math.round(loop.percentile(99) / 1e5) / 10, eventLoopMaxMs: Math.round(loop.max / 1e5) / 10 },
    };
  } finally {
    admin.pool.close();
    clients.forEach((c) => c.pool.close());
  }
}

/** Limits used to call a step saturated (docs/slo.md: publish→OK P95 > 2 s pages a ticket). */
export const LIMITS = { ackP95Ms: 2000, errorRate: 0.01, deliveryRatio: 0.99, indexerLagP95Ms: 10_000 };

export function verdict(r: LoadReport): string[] {
  const out: string[] = [];
  if (r.publish.ackMs.p95 > LIMITS.ackP95Ms) out.push(`ACK p95 ${r.publish.ackMs.p95} ms > ${LIMITS.ackP95Ms}`);
  const errRate = r.publish.attempted ? (r.publish.failed + r.publish.skippedBackpressure) / r.publish.attempted : 0;
  if (errRate > LIMITS.errorRate) out.push(`errores ${(errRate * 100).toFixed(1)} %`);
  if (r.delivery.ratio < LIMITS.deliveryRatio) out.push(`entrega ${(r.delivery.ratio * 100).toFixed(1)} %`);
  if (r.indexer.sampled && (r.indexer.missing > 0 || r.indexer.lagMs.p95 > LIMITS.indexerLagP95Ms)) out.push(`indexer p95 ${r.indexer.lagMs.p95} ms, ${r.indexer.missing} sin indexar`);
  if (r.publish.throughputOkPerS < r.publish.offeredPerS * 0.9) out.push(`throughput ${r.publish.throughputOkPerS}/${r.publish.offeredPerS} ev/s`);
  return out;
}

const fmt = (s: Stats) => `${s.p50} / ${s.p95} / ${s.p99} (máx ${s.max})`;

/** Markdown summary (Spanish, like the docs): one row per step plus the details of each. */
export function toMarkdown(reports: LoadReport[], title = 'Informe de carga'): string {
  const lines = [`# ${title}`, '', `Relay: \`${reports[0]?.relay ?? '-'}\` · indexer: ${reports[0]?.indexers.map((u) => `\`${u}\``).join(', ') || '—'} · inicio ${reports[0]?.startedAt ?? '-'}`, ''];
  lines.push('| Paso | Clientes | Ofrecido ev/s | OK ev/s | Errores | ACK p50/p95/p99 ms | Entrega % | Entrega p50/p95/p99 ms | Lag indexer p50/p95/p99 ms | Bucle gen. p99 ms | Veredicto |');
  lines.push('|---|---|---|---|---|---|---|---|---|---|---|');
  for (const r of reports) {
    const v = verdict(r);
    const idx = r.indexer.sampled ? `${fmt(r.indexer.lagMs)}${r.indexer.missing ? `, ${r.indexer.missing} sin indexar` : ''}` : '—';
    lines.push(
      `| ${r.label} | ${r.options.clients} | ${r.publish.offeredPerS} | ${r.publish.throughputOkPerS} | ${r.publish.failed + r.publish.skippedBackpressure} | ${fmt(r.publish.ackMs)} | ${(r.delivery.ratio * 100).toFixed(2)} | ${fmt(r.delivery.latencyMs)} | ${idx} | ${r.generator.eventLoopP99Ms} | ${v.length ? v.join('; ') : 'OK'} |`,
    );
  }
  for (const r of reports) {
    const errs = Object.entries(r.publish.errors);
    lines.push('', `## ${r.label}`, '', `- Duración ${r.options.durationS} s, tasa ${r.options.rate} ev/s por cliente, tamaños ${r.options.sizes.join('/')} B, mezcla ${Object.entries(r.options.mix).map(([k, w]) => `${k}:${w}`).join(' ')}, canales ${r.setup.channels.length} (${r.setup.channelSetup}).`);
    lines.push(`- Publicados ${r.publish.ok}/${r.publish.attempted} (${(r.publish.bytesOk / 1024 / 1024).toFixed(2)} MiB), descartados por contrapresión ${r.publish.skippedBackpressure}.`);
    for (const [k, v] of Object.entries(r.publish.byKind)) lines.push(`- kind ${k}: ${v.ok} OK, ${v.failed} fallidos, ACK p50/p95/p99 ${fmt(v.ackMs)} ms.`);
    lines.push(`- Entregas ${r.delivery.delivered}/${r.delivery.expected}; indexer ${r.indexer.found}/${r.indexer.sampled} muestreados, ${r.indexer.pollErrors} errores de consulta.`);
    if (errs.length) lines.push(`- Errores: ${errs.map(([k, n]) => `\`${k}\` ×${n}`).join(', ')}.`);
  }
  return lines.join('\n') + '\n';
}
