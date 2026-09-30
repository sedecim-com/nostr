import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
// @ts-expect-error plain ESM script without types
import { unblockOrder } from '../../scripts/backlog-order.mjs';

type T = { id: string; deps: string[]; status: string; priority: string; sp: number; type?: string; evidenceState?: string };
const t = (id: string, deps: string[] = [], over: Partial<T> = {}): T => ({ id, deps, status: 'Pendiente', priority: 'P1', sp: 1, ...over });
type Row = { task: T; wave: number; unlocks: number; waitsOn: string[]; blocker?: string; inPr: boolean; ready: boolean };
const order = (tasks: T[], blockers: Record<string, string> = {}) => unblockOrder(tasks, blockers) as Row[];
const wave = (rows: Row[], id: string) => rows.find((r) => r.task.id === id)!.wave;

describe('backlog unblock order (Orden de desbloqueo)', () => {
  it('puts each task one wave after the last open task it waits for', () => {
    const rows = order([t('A'), t('B', ['A']), t('C', ['A']), t('D', ['B', 'C']), t('E', ['D', 'A'])]);
    expect(rows.map((r) => [r.task.id, r.wave])).toEqual([['A', 0], ['B', 1], ['C', 1], ['D', 2], ['E', 3]]);
  });

  it('ignores dependencies that are done or discarded, and leaves them out of the order', () => {
    const rows = order([t('A', [], { status: 'Hecho' }), t('X', [], { status: 'Descartado' }), t('B', ['A', 'X']), t('C', ['B'])]);
    expect(rows.map((r) => r.task.id)).toEqual(['B', 'C']);
    expect(rows[0]).toMatchObject({ wave: 0, waitsOn: [] });
    expect(rows[1]).toMatchObject({ wave: 1, waitsOn: ['B'] });
  });

  it('counts what a task unlocks directly and through others, once each', () => {
    // A -> B -> D, A -> C -> D: D is reached through two paths and counts once.
    const rows = order([t('A'), t('B', ['A']), t('C', ['A']), t('D', ['B', 'C']), t('Z')]);
    const unlocks = Object.fromEntries(rows.map((r) => [r.task.id, r.unlocks]));
    expect(unlocks).toEqual({ A: 3, B: 1, C: 1, D: 0, Z: 0 });
  });

  it('inside a wave, puts first what unlocks the most, then the higher priority, then the id', () => {
    const rows = order([t('M', [], { priority: 'P0' }), t('B', [], { priority: 'P2' }), t('A', [], { priority: 'P2' }), t('K', [], { priority: 'P2' }), t('X', ['K'])]);
    expect(rows.filter((r) => r.wave === 0).map((r) => r.task.id)).toEqual(['K', 'M', 'A', 'B']);
  });

  it('marks a task ready only with no blocker, no open pull request and only code-merged dependencies', () => {
    const tasks = [
      t('PERSON', [], { status: 'Parcial' }), // the code is merged, a person has to act
      t('OPEN_CODE'), // nothing merged yet
      t('FREE'),
      t('IN_PR', [], { evidenceState: 'in-pr' }),
      t('AFTER_PERSON', ['PERSON']), // can be built on top of the merged code
      t('AFTER_CODE', ['OPEN_CODE']),
      t('BLOCKED_SELF'),
      t('AFTER_PENDING_BLOCKED', ['BLOCKED_SELF']), // the dependency has no code yet
    ];
    const rows = order(tasks, { PERSON: 'persona', BLOCKED_SELF: 'aws' });
    const ready = rows.filter((r) => r.ready).map((r) => r.task.id).sort();
    expect(ready).toEqual(['AFTER_PERSON', 'FREE', 'OPEN_CODE']);
    expect(rows.find((r) => r.task.id === 'IN_PR')).toMatchObject({ inPr: true, ready: false });
    expect(rows.find((r) => r.task.id === 'PERSON')).toMatchObject({ blocker: 'persona', ready: false });
  });

  it('does not build on a decision that is only proposed: its dependents wait for it to be taken', () => {
    const tasks = [
      t('ADR', [], { status: 'Parcial', type: 'Decisión' }), // drafted, pending approval
      t('AFTER_ADR', ['ADR']),
      t('DEV', [], { status: 'Parcial', type: 'Dev' }), // code merged, a person has to act
      t('AFTER_DEV', ['DEV']),
    ];
    const rows = order(tasks, { ADR: 'persona', DEV: 'persona' });
    expect(rows.filter((r) => r.ready).map((r) => r.task.id)).toEqual(['AFTER_DEV']);
  });

  it('does not loop on a dependency cycle (the validator rejects them before the order is drawn)', () => {
    const rows = order([t('A', ['B']), t('B', ['A'])]);
    expect(rows.map((r) => r.task.id).sort()).toEqual(['A', 'B']);
  });

  it('renders the real backlog: every open task once, acyclic waves, and only kinds declared in meta', () => {
    const { meta, tasks } = JSON.parse(readFileSync(new URL('../../docs/backlog/backlog.json', import.meta.url), 'utf8')) as { meta: { blockerKinds: Record<string, string>; externalBlockers: Record<string, string> }; tasks: T[] };
    const open = tasks.filter((x) => x.status !== 'Hecho' && x.status !== 'Descartado');
    const rows = order(tasks, meta.externalBlockers);
    expect(rows.map((r) => r.task.id).sort()).toEqual(open.map((x) => x.id).sort());
    for (const r of rows) for (const d of r.waitsOn) expect(wave(rows, d)).toBeLessThan(r.wave);
    for (const kind of Object.values(meta.externalBlockers)) expect(Object.keys(meta.blockerKinds)).toContain(kind);
    const readme = readFileSync(new URL('../../docs/backlog/README.md', import.meta.url), 'utf8');
    expect(readme).toContain('## Orden de desbloqueo');
    expect(readme).toContain(`**Listas para trabajar ahora (${rows.filter((r) => r.ready).length}):**`);
  });
});
