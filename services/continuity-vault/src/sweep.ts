import type { Logger } from '@sedecim/telemetry-policy';
import type { ObjectStore } from './objects';
import type { ArchiveRepository } from './repository';

export interface SweepResult {
  /** Archives deleted because they were not written for longer than their account's retention. */
  expired: number;
  /** Objects no row points to, deleted after two sweeps in a row found them so. */
  orphans: number;
}

/**
 * VAULT-05 (ADR 0011): the vault's periodic sweep.
 * - Retention: deletes every archive not written for longer than its account keeps it (never more than the
 *   operator's `retentionDays`), row and object.
 * - Orphans: an upload writes its object before its row, and a crash in between (or a failed delete) leaves an
 *   object no row points to. One is deleted only when two sweeps in a row find it unreferenced, so an upload
 *   still in flight is never taken for an orphan.
 */
export class VaultSweeper {
  private suspects = new Set<string>();

  constructor(
    private readonly repo: ArchiveRepository,
    private readonly objects: ObjectStore,
    private readonly opts: { retentionDays?: number; now?: () => Date; logger?: Logger } = {},
  ) {}

  async sweep(): Promise<SweepResult> {
    const expiredKeys = await this.repo.expire((this.opts.now ?? (() => new Date()))(), this.opts.retentionDays);
    await this.discard(expiredKeys);
    const stored: string[] = [];
    for await (const k of this.objects.list()) stored.push(k);
    const referenced = await this.repo.objectKeys();
    const unreferenced = stored.filter((k) => !referenced.has(k));
    const orphans = unreferenced.filter((k) => this.suspects.has(k));
    await this.discard(orphans);
    this.suspects = new Set(unreferenced.filter((k) => !this.suspects.has(k)));
    const result = { expired: expiredKeys.length, orphans: orphans.length };
    if (result.expired || result.orphans) this.opts.logger?.info('vault sweep', result);
    return result;
  }

  private async discard(keys: string[]) {
    for (let i = 0; i < keys.length; i += 32) await Promise.all(keys.slice(i, i + 32).map((k) => this.objects.delete(k).catch(() => undefined)));
  }
}
