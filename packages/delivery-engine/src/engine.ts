import { bytesToHex, randomBytes, type EventTemplate, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { normalizeRelayUrl } from '@sedecim/relay-pool';
import { classifyFailure, stateRank, type AttemptEvent, type ContinuityPolicy, type ContinuitySink, type ContinuityStatus, type DeliveryState, type OutboxStats, type EventLookup, type OutboxRecord, type Publisher, type RecordStore, type RelayAttempt, type RetryPolicy } from './types';

/** Relays for a record that depend on when it is published (see DeliveryEngineOptions.router). */
export interface RouteUpdate {
  relays: string[];
  meta?: Record<string, string>;
}

export interface DeliveryEngineOptions {
  store: RecordStore;
  publisher: Publisher;
  signer?: Signer;
  lookup?: EventLookup;
  retry?: Partial<RetryPolicy>;
  now?: () => number;
  random?: () => number;
  onChange?: (record: OutboxRecord) => void;
  /**
   * FR010-03: relays that depend on when a record is published, e.g. a DM wrap whose recipient's DM relays could
   * not be found when it was written (messaging's dmRouter). Asked before every retry of a record that no relay has
   * accepted yet; a different answer replaces its relays and keeps the quorum asked for.
   */
  router?: (rec: OutboxRecord) => Promise<RouteUpdate | undefined>;
  /**
   * VAULT-04 (ADR 0011): the Continuity Vault track. `policy` is read when an operation is submitted (the record
   * keeps it) and again on each of its rounds while its copy is pending: relaxing it releases a held operation, and
   * `off` drops the copy still to make. Without a `sink` (no vault configured) nothing is copied and an operation
   * sent under `required-for-resilient` stays held.
   */
  continuity?: { policy: () => ContinuityPolicy; sink?: ContinuitySink };
}

/** VAULT-04: why a `required-for-resilient` operation has not gone to its relays yet (shown as its `blockedReason`). */
export const CONTINUITY_HELD = 'retenido hasta que su copia cifrada esté en el Continuity Vault (required-for-resilient)';
export const CONTINUITY_HELD_NO_VAULT = 'retenido: esta persona exige una copia en el Continuity Vault antes de enviar y no hay vault configurado';

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
    const out: OutboxStats = { depth: 0, oldestPendingAgeMs: 0, failed: 0, byState: {}, continuityPending: 0 };
    for (const r of await this.list()) {
      out.byState[r.state] = (out.byState[r.state] ?? 0) + 1;
      if (r.state === 'FAILED') out.failed++;
      else {
        if (stateRank(r.state) < stateRank('REPLICATED')) {
          out.depth++;
          out.oldestPendingAgeMs = Math.max(out.oldestPendingAgeMs, now - r.createdAt);
        }
        if (r.continuity?.state === 'PENDING') out.continuityPending++;
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
    // FR010-04: a quorum above the relays could never be met. It is capped, never in silence: the record keeps
    // what was asked for so the outbox and the UI can say so.
    const requested = Math.max(1, opts.quorum ?? 1);
    const quorum = Math.min(requested, relays.length);
    const t = this.now();
    const rec: OutboxRecord = {
      opId,
      ...(opts.groupId ? { groupId: opts.groupId } : {}),
      state: 'DRAFT',
      relays,
      quorum,
      ...(requested > quorum ? { requestedQuorum: requested } : {}),
      relayStatus: Object.fromEntries(relays.map((r) => [r, { relay: r, attemptCount: 0 } satisfies RelayAttempt])),
      createdAt: t,
      updatedAt: t,
      history: [{ state: 'DRAFT', at: t }],
      ...(opts.meta ? { meta: opts.meta } : {}),
    };
    if ('template' in input) rec.template = input.template;
    else rec.event = input.event;
    // VAULT-04: a best-effort copy needs a vault to go to; a required one is kept even without it (the send is held).
    const policy = this.opts.continuity?.policy() ?? 'off';
    if (policy === 'required-for-resilient' || (policy === 'best-effort' && this.opts.continuity?.sink)) rec.continuity = { policy, state: 'PENDING', attemptCount: 0 };
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

  /**
   * VAULT-04: applies the policy in force now to a copy still to make: `off` drops it, and a `required-for-resilient`
   * copy goes on as best-effort once the policy is relaxed to it. Returns whether the record changed.
   */
  private applyPolicy(rec: OutboxRecord): boolean {
    const c = rec.continuity;
    if (!c || c.state !== 'PENDING') return false;
    const now = this.opts.continuity?.policy() ?? 'off';
    if (now === 'off') {
      delete rec.continuity;
      if (rec.blockedReason === CONTINUITY_HELD || rec.blockedReason === CONTINUITY_HELD_NO_VAULT) delete rec.blockedReason;
      return true;
    }
    if (c.policy === 'required-for-resilient' && now === 'best-effort') {
      c.policy = 'best-effort';
      return true;
    }
    return false;
  }

  /** VAULT-04: one attempt to put the operation's signed event in the Continuity Vault. Never throws. */
  private async backup(rec: OutboxRecord, c: ContinuityStatus): Promise<void> {
    const sink = this.opts.continuity?.sink;
    if (!sink) return;
    c.attemptCount++;
    c.lastAttemptAt = this.now();
    try {
      await sink.backup(rec.event!);
      c.state = 'CONTINUITY_BACKED_UP';
      c.backedUpAt = this.now();
      delete c.lastError;
    } catch (e) {
      c.lastError = (e as Error).message;
      // A best-effort copy is given up like a relay; a required one holds the send, so it is tried until it lands.
      if (c.policy === 'best-effort' && this.retry.maxAttempts !== undefined && c.attemptCount >= this.retry.maxAttempts) c.state = 'FAILED';
    }
  }

  /** The next round of an operation: the sooner of its relay retry and its vault retry. */
  private scheduleNext(rec: OutboxRecord, stillPending: RelayAttempt[]) {
    const delays: number[] = [];
    if (rec.state !== 'FAILED') {
      if (stillPending.length > 0) delays.push(this.backoff(Math.max(...stillPending.map((s) => s.attemptCount))));
      if (rec.continuity?.state === 'PENDING' && this.opts.continuity?.sink) delays.push(this.backoff(rec.continuity.attemptCount));
    }
    if (delays.length === 0) {
      delete rec.nextAttemptAt;
      return;
    }
    const delay = Math.min(...delays);
    rec.nextAttemptAt = this.now() + delay;
    this.schedule(rec.opId, delay);
  }

  private async round(opId: string): Promise<OutboxRecord> {
    const rec = await this.opts.store.get(opId);
    if (!rec) throw new Error(`unknown operation ${opId}`);
    if (rec.state === 'FAILED' || this.stopped) return rec;
    if (!rec.event) await this.prepare(rec);
    const policyChanged = this.applyPolicy(rec);
    const copy = rec.continuity?.state === 'PENDING' ? rec.continuity : undefined;
    // VAULT-04: `required-for-resilient` publishes nothing until the copy is in the vault.
    if (copy?.policy === 'required-for-resilient') {
      await this.backup(rec, copy);
      if (copy.state !== 'CONTINUITY_BACKED_UP') {
        rec.blockedReason = this.opts.continuity?.sink ? CONTINUITY_HELD : CONTINUITY_HELD_NO_VAULT;
        this.scheduleNext(rec, []);
        await this.save(rec);
        return rec;
      }
      if (rec.blockedReason === CONTINUITY_HELD || rec.blockedReason === CONTINUITY_HELD_NO_VAULT) delete rec.blockedReason;
    }
    // FR010-03: a retry goes where the route points now. The first round keeps the route the record was written with.
    if (this.opts.router && this.accepted(rec) === 0 && Object.values(rec.relayStatus).some((s) => s.attemptCount > 0)) await this.reroute(rec);
    const pending = Object.values(rec.relayStatus).filter((s) => !s.acceptedAt && !s.permanent);
    // Best-effort: the copy goes beside the publishing, and neither waits for the other to succeed.
    const copying = copy?.state === 'PENDING' ? this.backup(rec, copy) : undefined;
    if (pending.length === 0) {
      if (copying || policyChanged || copy) {
        await copying;
        this.scheduleNext(rec, []);
        await this.save(rec);
      }
      return rec;
    }
    if (stateRank(rec.state) < stateRank('PUBLISHING')) this.transition(rec, 'PUBLISHING');
    await this.save(rec);

    const [results] = await Promise.all([Promise.all(pending.map(async (s) => ({ s, res: await this.opts.publisher.publishTo(rec.event!, s.relay) }))), copying]);
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

    this.scheduleNext(rec, stillPending);
    await this.save(rec);
    return rec;
  }

  private async reroute(rec: OutboxRecord) {
    let next: RouteUpdate | undefined;
    try {
      next = await this.opts.router!(structuredClone(rec));
    } catch {
      return; // no answer: keep the current relays
    }
    const relays = [...new Set((next?.relays ?? []).map(normalizeRelayUrl))];
    if (relays.length === 0) return;
    if (next!.meta) rec.meta = { ...rec.meta, ...next!.meta };
    if (relays.length === rec.relays.length && relays.every((r) => rec.relays.includes(r))) return;
    rec.relays = relays;
    rec.relayStatus = Object.fromEntries(relays.map((r) => [r, rec.relayStatus[r] ?? ({ relay: r, attemptCount: 0 } satisfies RelayAttempt)]));
    const requested = rec.requestedQuorum ?? rec.quorum;
    rec.quorum = Math.min(requested, relays.length);
    if (requested > rec.quorum) rec.requestedQuorum = requested;
    else delete rec.requestedQuorum;
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
      // VAULT-04: an operation whose copy is still pending is re-driven too (and a held one goes out if it can).
      const open = recs.filter((r) => r.state !== 'FAILED' && (Object.values(r.relayStatus).some((s) => !s.acceptedAt && !s.permanent) || r.continuity?.state === 'PENDING'));
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
