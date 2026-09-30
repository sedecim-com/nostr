import type { GroupSession } from '@sedecim/marmot-adapter';
import { createLogger, type Logger } from '@sedecim/telemetry-policy';
import type { RevocationPropagator } from './revocations';
import type { RotationWorker } from './worker';

export interface RotationServiceOptions {
  /** Marmot session of the worker identity: it joins the groups that invite it and commits the removals. */
  session: GroupSession;
  /** Relays (the URLs clients use) where the worker publishes its key package, so that groups can add it. */
  relays: string[];
  worker: RotationWorker;
  /** FR024-03/04: device revocations to the signers. Without it, only groups are rotated. */
  propagator?: RevocationPropagator;
  logger?: Logger;
  now?: () => number;
}

export type RotationServiceStep = 'keyPackage' | 'invites' | 'revocations' | 'rotations';

export interface RotationServiceStatus {
  /** True once a run finished without errors and none failed since. */
  ok: boolean;
  pubkey: string;
  startedAt?: number;
  lastRunAt?: number;
  lastOkAt?: number;
  /** Error of each step in its last run, if it failed. Ids and messages only, never content. */
  errors: Partial<Record<RotationServiceStep, string>>;
  groupsJoined: number;
  /** Joined groups where the worker is not an admin: it cannot rotate them (MIP-03). */
  groupsWithoutAdmin: number;
  rotations: { removed: number; alreadyRemoved: number; failed: number };
  revocationsPropagated: number;
}

/**
 * FR024-05: the rotation worker as a long-running service. Every run:
 * 1. joins the groups that invited the worker (they must list it as an admin to let it commit removals);
 * 2. propagates device revocations to the signers (FR024-03/04), when configured;
 * 3. removes revoked members from the groups the policy-engine flags (FR024-02).
 * A failing step does not stop the others; the next run retries it.
 */
export class RotationService {
  readonly status: RotationServiceStatus;
  private readonly log: Logger;
  private keyPackageDue = true;

  constructor(private readonly opts: RotationServiceOptions) {
    this.log = opts.logger ?? createLogger({ base: { component: 'rotation-service' } });
    this.status = { ok: false, pubkey: opts.session.pubkey, errors: {}, groupsJoined: 0, groupsWithoutAdmin: 0, rotations: { removed: 0, alreadyRemoved: 0, failed: 0 }, revocationsPropagated: 0 };
  }

  private now() {
    return (this.opts.now ?? Date.now)();
  }

  private async step(name: RotationServiceStep, fn: () => Promise<void>) {
    try {
      await fn();
      delete this.status.errors[name];
    } catch (err) {
      const error = (err as Error).message;
      this.status.errors[name] = error;
      this.log.warn(`rotation service: ${name} failed`, { error });
    }
  }

  /**
   * The key package lets groups add the worker. Each device keeps one under its own slot, so a new one replaces the
   * previous one on the relays. Published at start, since the stored state may be new; after an invite uses it, the
   * Marmot session publishes the next one itself.
   */
  private async publishKeyPackage() {
    await this.step('keyPackage', async () => {
      await this.opts.session.publishKeyPackage(this.opts.relays);
      this.keyPackageDue = false;
      this.log.info('key package published', { relays: this.opts.relays.length });
    });
  }

  /** One run of the three steps. */
  async runOnce(): Promise<void> {
    this.status.startedAt ??= this.now();
    const s = this.opts.session;
    if (this.keyPackageDue) await this.publishKeyPackage();
    await this.step('invites', async () => {
      const joined = await s.acceptInvites();
      if (!joined.length) return;
      const withoutAdmin = joined.filter((g) => !g.admins.includes(s.pubkey));
      this.status.groupsJoined += joined.length;
      this.status.groupsWithoutAdmin += withoutAdmin.length;
      this.log.info('groups joined', { groups: joined.map((g) => g.groupId.slice(0, 12)).join(',') });
      if (withoutAdmin.length) this.log.warn('joined groups that do not list the worker as admin: it cannot rotate them', { groups: withoutAdmin.map((g) => g.groupId.slice(0, 12)).join(',') });
    });
    const propagator = this.opts.propagator;
    if (propagator) {
      await this.step('revocations', async () => {
        this.status.revocationsPropagated += (await propagator.runOnce()).length;
        if (propagator.failing) throw new Error(`${propagator.failing} device revocation(s) not propagated yet: ${propagator.lastError ?? 'unknown error'}`);
      });
    }
    await this.step('rotations', async () => {
      const out = await this.opts.worker.runOnce();
      for (const o of out) {
        if (o.result === 'removed') this.status.rotations.removed++;
        else if (o.result === 'already-removed') this.status.rotations.alreadyRemoved++;
        else if (o.result === 'failed') this.status.rotations.failed++;
      }
      // A rotation waiting for its retry is still not done: the step stays in error until it is.
      const pending = out.filter((o) => o.result === 'failed' || o.result === 'deferred');
      const error = out.find((o) => o.error)?.error;
      if (pending.length) throw new Error(`${pending.length} rotation(s) not done yet${error ? `: ${error}` : ''}`);
    });
    const at = this.now();
    this.status.lastRunAt = at;
    this.status.ok = Object.keys(this.status.errors).length === 0;
    if (this.status.ok) this.status.lastOkAt = at;
  }

  /** Runs until `signal` aborts, one run every `intervalMs` (default 15 s). */
  async run(opts: { intervalMs?: number; signal?: AbortSignal } = {}): Promise<void> {
    const interval = opts.intervalMs ?? 15_000;
    while (!opts.signal?.aborted) {
      await this.runOnce();
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, interval);
        opts.signal?.addEventListener('abort', () => (clearTimeout(t), resolve()), { once: true });
      });
    }
  }
}
