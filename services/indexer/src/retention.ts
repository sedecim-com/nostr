import type { RetentionPolicy } from '@sedecim/policy-client';
import type { EventRepository } from './repository';

export interface RetentionResult {
  resourceId: string;
  deleted: number;
}

/**
 * FR023-08: deletes mirrored events past their retention. A policy's resourceId is matched both as a
 * channel (`h` tag, NIP-29 group id) and as a workspace (COMMUNITY_ID of the mirror). Legal hold wins:
 * nothing of a held channel, nor of any channel in a held workspace, is deleted. A channel with its own
 * policy is governed by it, not by its workspace's. This only deletes the mirror copy: events replicated
 * on other relays or stored by clients are out of reach (see RETENTION_NOTICE in the policy-engine).
 */
export async function enforceRetention(repo: EventRepository, policies: RetentionPolicy[], nowMs = Date.now()): Promise<RetentionResult[]> {
  const held = policies.filter((p) => p.legalHold).map((p) => p.resourceId);
  const withPolicy = policies.map((p) => p.resourceId);
  const out: RetentionResult[] = [];
  for (const p of policies) {
    if (p.legalHold || p.days === null) continue;
    const before = Math.floor(nowMs / 1000) - p.days * 86_400;
    const deleted =
      (await repo.purge({ before, h: p.resourceId, exceptCommunities: held })) + (await repo.purge({ before, community: p.resourceId, exceptH: withPolicy }));
    out.push({ resourceId: p.resourceId, deleted });
  }
  return out;
}
