import { describe, expect, it } from 'vitest';
import type { GroupHandle, GroupSession } from '@sedecim/marmot-adapter';
import { createLogger } from '@sedecim/telemetry-policy';
import { RotationService, type RevocationPropagator, type RotationOutcome, type RotationWorker } from '../src/index';

const silent = createLogger({ write: () => {} });

/** Just what RotationService uses of each collaborator. */
function fakes() {
  const calls: string[] = [];
  const state = {
    keyPackageFails: 0,
    invites: [] as Array<Pick<GroupHandle, 'groupId' | 'admins'>>,
    invitesFail: false,
    outcomes: [] as RotationOutcome[],
    rotationsFail: false,
    propagated: [] as string[],
    failing: 0,
  };
  const session = {
    pubkey: 'ab'.repeat(32),
    publishKeyPackage: async () => {
      calls.push('keyPackage');
      if (state.keyPackageFails-- > 0) throw new Error('key package was not accepted by any relay');
      return {};
    },
    acceptInvites: async () => {
      calls.push('invites');
      if (state.invitesFail) throw new Error('relays down');
      return state.invites.splice(0);
    },
  } as unknown as GroupSession;
  const worker = {
    runOnce: async () => {
      calls.push('rotations');
      if (state.rotationsFail) throw new Error('policy-engine GET /v1/rotations?status=pending: 503');
      return state.outcomes;
    },
  } as unknown as RotationWorker;
  const propagator = {
    failing: 0,
    lastError: undefined as string | undefined,
    runOnce: async () => {
      calls.push('revocations');
      propagator.failing = state.failing;
      propagator.lastError = state.failing ? 'managed-signer revoke: 503' : undefined;
      return state.propagated.splice(0);
    },
  };
  return { calls, state, session, worker, propagator: propagator as unknown as RevocationPropagator };
}

describe('rotation service (FR024-05)', () => {
  it('publishes its key package, joins groups, propagates and rotates; each step in its order', async () => {
    const f = fakes();
    const service = new RotationService({ session: f.session, relays: ['wss://secure.example'], worker: f.worker, propagator: f.propagator, logger: silent, now: () => 1000 });
    f.state.invites.push({ groupId: 'aa'.repeat(32), admins: ['ab'.repeat(32)] }, { groupId: 'bb'.repeat(32), admins: ['cd'.repeat(32)] });
    f.state.propagated.push('dev-1');
    f.state.outcomes = [{ id: 'rot-1', result: 'removed', epoch: 3 }, { id: 'rot-2', result: 'already-removed', epoch: 3 }];
    await service.runOnce();
    expect(f.calls).toEqual(['keyPackage', 'invites', 'revocations', 'rotations']);
    expect(service.status).toMatchObject({ ok: true, errors: {}, groupsJoined: 2, groupsWithoutAdmin: 1, revocationsPropagated: 1, rotations: { removed: 1, alreadyRemoved: 1, failed: 0 }, lastRunAt: 1000, lastOkAt: 1000 });
    // The key package is published once; the Marmot session replaces it after an invite uses it.
    f.calls.length = 0;
    await service.runOnce();
    expect(f.calls).toEqual(['invites', 'revocations', 'rotations']);
  });

  it('a failing step does not stop the others, and the service stays in error until the work is done', async () => {
    const f = fakes();
    let now = 1000;
    const service = new RotationService({ session: f.session, relays: ['wss://secure.example'], worker: f.worker, propagator: f.propagator, logger: silent, now: () => now });
    f.state.keyPackageFails = 1;
    f.state.invitesFail = true;
    f.state.failing = 1;
    f.state.outcomes = [{ id: 'rot-1', result: 'failed', error: 'group not held by the worker identity (add it as admin of the group)', retryAt: 6000 }];
    await service.runOnce();
    expect(f.calls).toEqual(['keyPackage', 'invites', 'revocations', 'rotations']);
    expect(service.status.ok).toBe(false);
    expect(service.status.errors).toEqual({
      keyPackage: 'key package was not accepted by any relay',
      invites: 'relays down',
      revocations: '1 device revocation(s) not propagated yet: managed-signer revoke: 503',
      rotations: '1 rotation(s) not done yet: group not held by the worker identity (add it as admin of the group)',
    });
    expect(service.status.lastOkAt).toBeUndefined();

    // Next run: the key package is retried; a rotation waiting for its retry is still not done.
    f.calls.length = 0;
    now = 2000;
    f.state.invitesFail = false;
    f.state.failing = 0;
    f.state.outcomes = [{ id: 'rot-1', result: 'deferred', retryAt: 6000 }];
    await service.runOnce();
    expect(f.calls).toEqual(['keyPackage', 'invites', 'revocations', 'rotations']);
    expect(service.status.errors).toEqual({ rotations: '1 rotation(s) not done yet' });

    // Done: the service is healthy again.
    now = 7000;
    f.state.outcomes = [{ id: 'rot-1', result: 'removed', epoch: 4 }];
    await service.runOnce();
    expect(service.status).toMatchObject({ ok: true, errors: {}, lastOkAt: 7000, rotations: { removed: 1, failed: 1 } });

    // The policy-engine down: the rotations step fails, the others still run.
    f.calls.length = 0;
    f.state.rotationsFail = true;
    await service.runOnce();
    expect(f.calls).toEqual(['invites', 'revocations', 'rotations']);
    expect(service.status.errors).toEqual({ rotations: 'policy-engine GET /v1/rotations?status=pending: 503' });
  });

  it('runs until aborted', async () => {
    const f = fakes();
    const service = new RotationService({ session: f.session, relays: ['wss://secure.example'], worker: f.worker, logger: silent });
    const controller = new AbortController();
    const done = service.run({ intervalMs: 5, signal: controller.signal });
    await new Promise((r) => setTimeout(r, 40));
    controller.abort();
    await done;
    const runs = f.calls.filter((c) => c === 'rotations').length;
    expect(runs).toBeGreaterThan(1);
    // Without a propagator there is no revocations step.
    expect(f.calls).not.toContain('revocations');
    await new Promise((r) => setTimeout(r, 20));
    expect(f.calls.filter((c) => c === 'rotations').length).toBe(runs);
  });
});
