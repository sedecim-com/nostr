import type { GroupSession } from '@sedecim/marmot-adapter';
import { createLogger, type Logger } from '@sedecim/telemetry-policy';
import type { Rotation, RotationSource } from './policy';

export interface RotationWorkerOptions {
  source: RotationSource;
  /**
   * Marmot session of a group ADMIN identity (MIP-03: only admins commit). Use a dedicated device (or a
   * dedicated admin persona) for the worker: it syncs the groups and discards the messages it decrypts.
   */
  session: GroupSession;
  /** Policy resource id -> Marmot group id. Default: the resource id is the MLS group id (hex). */
  groupIdOf?: (resourceId: string) => string | undefined;
  /** Retry backoff per rotation: base * 2^(failures-1), capped (defaults 5 s, 10 min). */
  backoff?: { baseMs?: number; maxMs?: number };
  logger?: Logger;
  now?: () => number;
}

export type RotationResult = 'removed' | 'already-removed' | 'failed' | 'deferred';

export interface RotationOutcome {
  id: string;
  result: RotationResult;
  /** Epoch after the Remove commit. */
  epoch?: number;
  error?: string;
  /** Next attempt (failed / deferred). */
  retryAt?: number;
}

const HEX = /^[0-9a-f]+$/;
const HEX64 = /^[0-9a-f]{64}$/;

/**
 * FR024-02: turns the rotations the policy-engine flags on revocation into MLS commits. For every pending
 * rotation it removes all leaves of the revoked pubkey from the group (one commit, new epoch) and marks
 * the rotation done only once the commit was accepted and the member is gone. Idempotent (a member already
 * gone is just marked done), retried with exponential backoff, never marked done on failure. Logs carry
 * ids and epochs only, never message content.
 */
export class RotationWorker {
  private readonly failures = new Map<string, { count: number; nextAt: number }>();
  private readonly log: Logger;

  constructor(private readonly opts: RotationWorkerOptions) {
    this.log = opts.logger ?? createLogger({ base: { component: 'rotation-worker' } });
  }

  private now() {
    return (this.opts.now ?? Date.now)();
  }

  private groupId(r: Rotation): string {
    const gid = this.opts.groupIdOf ? this.opts.groupIdOf(r.resourceId) : r.resourceId.toLowerCase();
    if (!gid || !HEX.test(gid)) throw new Error('resource is not a Marmot group id (hex)');
    return gid;
  }

  private async rotate(r: Rotation): Promise<Omit<RotationOutcome, 'id'>> {
    const s = this.opts.session;
    if (!HEX64.test(r.removedPubkey)) throw new Error('invalid removed pubkey');
    if (r.removedPubkey === s.pubkey) throw new Error('the worker identity cannot remove itself: use another admin');
    const gid = this.groupId(r);
    try {
      await s.group(gid);
    } catch {
      throw new Error('group not held by the worker identity (add it as admin of the group)');
    }
    // Catch up first: another admin may already have removed the member.
    await s.sync(gid);
    const before = await s.group(gid);
    if (!before.members.includes(r.removedPubkey)) return { result: 'already-removed', epoch: before.epoch };
    const after = await s.removeMember(gid, r.removedPubkey);
    if (after.members.includes(r.removedPubkey) || after.epoch <= before.epoch) throw new Error('remove commit not applied');
    return { result: 'removed', epoch: after.epoch };
  }

  /** Processes every pending rotation once. */
  async runOnce(): Promise<RotationOutcome[]> {
    const pending = await this.opts.source.pending();
    const out: RotationOutcome[] = [];
    for (const r of pending) {
      const f = this.failures.get(r.id);
      if (f && f.nextAt > this.now()) {
        out.push({ id: r.id, result: 'deferred', retryAt: f.nextAt });
        continue;
      }
      const group = r.resourceId.slice(0, 12);
      try {
        const res = await this.rotate(r);
        // Only now: the commit is on the relays and the member is out. If this call fails, the next run
        // finds the member gone and marks it done then.
        await this.opts.source.markDone(r.id);
        this.failures.delete(r.id);
        this.log.info('rotation done', { rotation_id: r.id, group, result: res.result, epoch: res.epoch });
        out.push({ id: r.id, ...res });
      } catch (err) {
        const count = (f?.count ?? 0) + 1;
        const base = this.opts.backoff?.baseMs ?? 5_000;
        const nextAt = this.now() + Math.min(this.opts.backoff?.maxMs ?? 600_000, base * 2 ** (count - 1));
        this.failures.set(r.id, { count, nextAt });
        const error = (err as Error).message;
        this.log.warn('rotation failed', { rotation_id: r.id, group, attempt: count, retry_at: new Date(nextAt).toISOString(), error });
        out.push({ id: r.id, result: 'failed', error, retryAt: nextAt });
      }
    }
    // Forget rotations that are no longer pending (done elsewhere).
    const ids = new Set(pending.map((r) => r.id));
    for (const id of this.failures.keys()) if (!ids.has(id)) this.failures.delete(id);
    return out;
  }

  /** Polls until `signal` aborts. A failing poll (policy-engine down) is logged and retried next tick. */
  async run(opts: { intervalMs?: number; signal?: AbortSignal } = {}): Promise<void> {
    const interval = opts.intervalMs ?? 15_000;
    while (!opts.signal?.aborted) {
      try {
        await this.runOnce();
      } catch (err) {
        this.log.error('rotation poll failed', { error: (err as Error).message });
      }
      await new Promise<void>((resolve) => {
        const t = setTimeout(resolve, interval);
        opts.signal?.addEventListener('abort', () => (clearTimeout(t), resolve()), { once: true });
      });
    }
  }
}
