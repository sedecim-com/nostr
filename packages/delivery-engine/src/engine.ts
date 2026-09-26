import { bytesToHex, randomBytes, type EventTemplate, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { normalizeRelayUrl } from '@sedecim/relay-pool';
import { classifyFailure, stateRank, type AttemptEvent, type DeliveryState, type OutboxStats, type EventLookup, type OutboxRecord, type Publisher, type RecordStore, type RelayAttempt, type RetryPolicy } from './types';

export interface DeliveryEngineOptions {
  store: RecordStore;
  publisher: Publisher;
  signer?: Signer;
  lookup?: EventLookup;
  retry?: Partial<RetryPolicy>;
  now?: () => number;
  random?: () => number;
  onChange?: (record: OutboxRecord) => void;
}

export interface SubmitOptions {
  relays: string[];
  /** Relay acceptances required to reach REPLICATED, e.g. 1 of N (normal) or 2 of N (resilient). */
  quorum?: number;
  opId?: string;
  groupId?: string;
  meta?: Record<string, string>;
  /** Wait for the first publish round to complete before resolving. */
  wait?: boolean;
}

const PERMANENT_PREFIXES = ['invalid:', 'blocked:', 'restricted:', 'pow:', 'unsupported:'];

export class DeliveryEngine {
  private readonly retry: RetryPolicy;
  private readonly timers = new Map<string, ReturnType<typeof setTimeout>>();
  private readonly running = new Map<string, Promise<OutboxRecord>>();
  private readonly rerun = new Set<string>();
  private readonly listeners = new Set<(r: OutboxRecord) => void>();
  private readonly attemptListeners = new Set<(a: AttemptEvent) => void>();
  private stopped = false;
  private resuming?: Promise<OutboxRecord[]>;
  private readonly now: () => number;
  private readonly random: () => number;

  constructor(private readonly opts: DeliveryEngineOptions) {
    this.retry = { baseMs: opts.retry?.baseMs ?? 1000, maxMs: opts.retry?.maxMs ?? 60_000, maxAttempts: opts.retry?.maxAttempts };
    this.now = opts.now ?? Date.now;
    this.random = opts.random ?? Math.random;
    if (opts.onChange) this.listeners.add(opts.onChange);
  }

  onChange(fn: (r: OutboxRecord) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  /** Observes every per-relay publish attempt (FR011-03 failure counters). Returns an unsubscribe function. */
  onAttempt(fn: (a: AttemptEvent) => void): () => void {
    this.attemptListeners.add(fn);
    return () => this.attemptListeners.delete(fn);
  }

  /** Outbox depth, oldest pending age and failures (FR011-03), computed from the persisted ledger. */
  async stats(): Promise<OutboxStats> {
    const now = this.now();
    const out: OutboxStats = { depth: 0, oldestPendingAgeMs: 0, failed: 0, byState: {} };
    for (const r of await this.list()) {
      out.byState[r.state] = (out.byState[r.state] ?? 0) + 1;
      if (r.state === 'FAILED') out.failed++;
      else if (stateRank(r.state) < stateRank('REPLICATED')) {
        out.depth++;
        out.oldestPendingAgeMs = Math.max(out.oldestPendingAgeMs, now - r.createdAt);
      }
    }
    return out;
  }

  private async save(rec: OutboxRecord): Promise<OutboxRecord> {
    rec.updatedAt = this.now();
    await this.opts.store.put(rec.opId, rec);
    const snapshot = structuredClone(rec);
    for (const l of this.listeners) l(snapshot);
    return rec;
  }

  private transition(rec: OutboxRecord, state: DeliveryState) {
    if (rec.state === state) return;
    rec.state = state;
    rec.history.push({ state, at: this.now() });
  }

  get(opId: string): Promise<OutboxRecord | undefined> {
    return this.opts.store.get(opId);
  }

  async list(): Promise<OutboxRecord[]> {
    return (await this.opts.store.all()).map((e) => e.value).sort((a, b) => a.createdAt - b.createdAt);
  }

  /**
   * Accepts a template (signed here) or an already-signed event (e.g. a NIP-59 gift wrap).
   * Persists locally BEFORE any transmission (FR-008). Idempotent on opId.
   */
  async submit(input: { template: EventTemplate } | { event: NostrEvent }, opts: SubmitOptions): Promise<OutboxRecord> {
    const opId = opts.opId ?? bytesToHex(randomBytes(16));
    const existing = await this.opts.store.get(opId);
    if (existing) {
      if (opts.wait) return this.process(opId);
      return existing;
    }
    const relays = [...new Set(opts.relays.map(normalizeRelayUrl))];
    if (relays.length === 0) throw new Error('at least one relay is required');
    const quorum = Math.max(1, Math.min(opts.quorum ?? 1, relays.length));
    const t = this.now();
    const rec: OutboxRecord = {
      opId,
      ...(opts.groupId ? { groupId: opts.groupId } : {}),
      state: 'DRAFT',
      relays,
      quorum,
      relayStatus: Object.fromEntries(relays.map((r) => [r, { relay: r, attemptCount: 0 } satisfies RelayAttempt])),
      createdAt: t,
      updatedAt: t,
      history: [{ state: 'DRAFT', at: t }],
      ...(opts.meta ? { meta: opts.meta } : {}),
    };
    if ('template' in input) rec.template = input.template;
    else rec.event = input.event;
    this.transition(rec, 'LOCAL_PERSISTED');
    await this.save(rec);
    await this.prepare(rec);
    const run = this.process(opId);
    if (opts.wait) return run;
    run.catch(() => undefined);
    return structuredClone(rec);
  }

  private async prepare(rec: OutboxRecord) {
    if (!rec.event) {
      if (!this.opts.signer) throw new Error('no signer configured for template submission');
      rec.event = await this.opts.signer.signEvent(rec.template!);
    }
    this.transition(rec, 'SIGNED');
    await this.save(rec);
    this.transition(rec, 'QUEUED');
    await this.save(rec);
  }

  private backoff(attempt: number): number {
    const exp = Math.min(this.retry.maxMs, this.retry.baseMs * 2 ** Math.max(0, attempt - 1));
    return Math.round(exp / 2 + this.random() * (exp / 2));
  }

  /** Runs one publish round for an operation. Concurrent calls for the same opId are coalesced. */
  process(opId: string): Promise<OutboxRecord> {
    const current = this.running.get(opId);
    if (current) {
      this.rerun.add(opId);
      return current;
    }
    const run = (async () => {
      let rec: OutboxRecord;
      do {
        this.rerun.delete(opId);
        rec = await this.round(opId);
      } while (this.rerun.has(opId));
      return rec;
    })().finally(() => this.running.delete(opId));
    this.running.set(opId, run);
    return run;
  }

  private accepted(rec: OutboxRecord): number {
    return Object.values(rec.relayStatus).filter((s) => s.acceptedAt).length;
  }

  private async round(opId: string): Promise<OutboxRecord> {
    const rec = await this.opts.store.get(opId);
    if (!rec) throw new Error(`unknown operation ${opId}`);
    if (rec.state === 'FAILED' || this.stopped) return rec;
    if (!rec.event) await this.prepare(rec);
    const pending = Object.values(rec.relayStatus).filter((s) => !s.acceptedAt && !s.permanent);
    if (pending.length === 0) return rec;
    if (stateRank(rec.state) < stateRank('PUBLISHING')) this.transition(rec, 'PUBLISHING');
    await this.save(rec);

    const results = await Promise.all(pending.map(async (s) => ({ s, res: await this.opts.publisher.publishTo(rec.event!, s.relay) })));
    let anyBlocked = false;
    for (const { s, res } of results) {
      s.attemptCount++;
      s.lastAttemptAt = this.now();
      s.latencyMs = res.latencyMs;
      s.blocked = !!res.blocked;
      if (res.ok) {
        s.acceptedAt = this.now();
        s.ackMessage = res.message;
        delete s.lastError;
      } else {
        s.lastError = res.message;
        if (res.blocked) anyBlocked = true;
        else if (PERMANENT_PREFIXES.some((p) => res.message.startsWith(p))) s.permanent = true;
        if (this.retry.maxAttempts !== undefined && s.attemptCount >= this.retry.maxAttempts) s.permanent = true;
      }
      const attempt: AttemptEvent = { relay: s.relay, ok: res.ok, latencyMs: res.latencyMs, permanent: !!s.permanent, ...(res.ok ? {} : { failure: classifyFailure(res.message, res.blocked) }) };
      for (const l of this.attemptListeners) {
        try {
          l(attempt);
        } catch {
          /* observers never break delivery */
        }
      }
    }
    rec.blockedReason = anyBlocked ? results.find((r) => r.res.blocked)!.res.message.replace(/^error: /, '') : undefined;
    if (!rec.blockedReason) delete rec.blockedReason;

    const accepted = this.accepted(rec);
    const stillPending = Object.values(rec.relayStatus).filter((s) => !s.acceptedAt && !s.permanent);
    if (accepted >= rec.quorum) {
      if (stateRank(rec.state) < stateRank('REPLICATED')) this.transition(rec, 'REPLICATED');
    } else if (accepted + stillPending.length < rec.quorum) {
      this.transition(rec, 'FAILED');
      rec.failureReason = `quorum ${rec.quorum} unreachable: ${Object.values(rec.relayStatus)
        .filter((s) => s.permanent)
        .map((s) => `${s.relay}: ${s.lastError}`)
        .join('; ')}`;
    } else {
      this.transition(rec, 'QUEUED');
    }

    if (stillPending.length > 0 && (rec.state as DeliveryState) !== 'FAILED') {
      const attempt = Math.max(...stillPending.map((s) => s.attemptCount));
      const delay = this.backoff(attempt);
      rec.nextAttemptAt = this.now() + delay;
      this.schedule(opId, delay);
    } else delete rec.nextAttemptAt;
    await this.save(rec);
    return rec;
  }

  private schedule(opId: string, delayMs: number) {
    if (this.stopped) return;
    const old = this.timers.get(opId);
    if (old) clearTimeout(old);
    const t = setTimeout(() => {
      this.timers.delete(opId);
      this.process(opId).catch(() => undefined);
    }, delayMs);
    (t as { unref?: () => void }).unref?.();
    this.timers.set(opId, t);
  }

  /**
   * Re-drive every unfinished operation (app start, reconnect, "network back" events) — FR-011.
   * Idempotent: calls made while a resume is in flight share it. Pending backoff timers are overtaken.
   * Wire it to connectivity with `pool.onReconnect(() => engine.resume())` and, in browsers, `window.online`.
   */
  resume(): Promise<OutboxRecord[]> {
    if (this.resuming) return this.resuming;
    this.stopped = false;
    this.resuming = (async () => {
      const recs = await this.list();
      const open = recs.filter((r) => r.state !== 'FAILED' && Object.values(r.relayStatus).some((s) => !s.acceptedAt && !s.permanent));
      return Promise.all(open.map((r) => this.process(r.opId)));
    })().finally(() => {
      this.resuming = undefined;
    });
    return this.resuming;
  }

  /**
   * Reconciliation: if an ack was lost but the relay actually stores the event, mark it accepted
   * without republishing.
   */
  async reconcile(): Promise<void> {
    const lookup = this.opts.lookup;
    if (!lookup) return;
    for (const rec of await this.list()) {
      if (!rec.event) continue;
      let changed = false;
      for (const s of Object.values(rec.relayStatus)) {
        if (s.acceptedAt) continue;
        try {
          if (await lookup.has(s.relay, rec.event.id)) {
            s.acceptedAt = this.now();
            s.ackMessage = 'reconciled: event present on relay';
            s.permanent = false;
            changed = true;
          }
        } catch {
          /* relay unreachable: keep state */
        }
      }
      if (changed) {
        if (this.accepted(rec) >= rec.quorum && stateRank(rec.state) < stateRank('REPLICATED')) {
          if (rec.state === 'FAILED') delete rec.failureReason;
          this.transition(rec, 'REPLICATED');
        }
        await this.save(rec);
      }
    }
  }

  private async advance(opId: string, state: 'RECIPIENT_ACKED' | 'READ') {
    const rec = await this.opts.store.get(opId);
    if (!rec) throw new Error(`unknown operation ${opId}`);
    if (stateRank(rec.state) >= stateRank(state)) return rec;
    if (stateRank(rec.state) < stateRank('REPLICATED')) {
      // A receipt proves delivery even if our own relay acks were lost; record it but keep the ledger honest.
      rec.meta = { ...rec.meta, receiptBeforeQuorum: 'true' };
    }
    this.transition(rec, state);
    return this.save(rec);
  }

  /** Application-level receipt from the recipient (optional feature). */
  markRecipientAcked(opId: string) {
    return this.advance(opId, 'RECIPIENT_ACKED');
  }

  /** Read receipt (opt-in, can be disabled by profile). */
  markRead(opId: string) {
    return this.advance(opId, 'READ');
  }

  /**
   * Applies an incoming application receipt (ADR 0005, `parseReceipt` in @sedecim/messaging) — FR-009.
   * It matches the wrap sent to `receipt.from` for that rumor (`groupId` = rumor id, `meta.recipient`),
   * so a receipt only counts when its authenticated sender (the seal signer) is that recipient.
   * States never move backwards. Returns undefined when no operation matches.
   */
  async applyReceipt(receipt: { rumorId: string; type: 'delivered' | 'read'; from: string }): Promise<OutboxRecord | undefined> {
    const rec = (await this.list()).find((r) => r.groupId === receipt.rumorId && r.meta?.recipient === receipt.from);
    if (!rec) return undefined;
    return this.advance(rec.opId, receipt.type === 'read' ? 'READ' : 'RECIPIENT_ACKED');
  }

  async findByEventId(eventId: string): Promise<OutboxRecord | undefined> {
    return (await this.list()).find((r) => r.event?.id === eventId);
  }

  stop(): void {
    this.stopped = true;
    for (const t of this.timers.values()) clearTimeout(t);
    this.timers.clear();
  }
}
