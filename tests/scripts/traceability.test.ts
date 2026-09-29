import { describe, expect, it } from 'vitest';
import {
  checkEvidence,
  evidenceCell,
  extractRefs,
  renderStatus,
  renderTraceability,
  repoIndex,
  requirementState,
  testCitations,
  // @ts-expect-error plain ESM script without types
} from '../../scripts/traceability.mjs';

// The fixtures use ids that are not in the backlog (TST…), and build the requirement ids, so that the traceability
// does not list this file as a test of real tasks or requirements.
const req = (kind: string, n: number) => `${kind}-${String(n).padStart(3, '0')}`;
const [FR1, FR2, NFR1] = [req('FR', 1), req('FR', 2), req('NFR', 1)];
type Task = { id: string; req: string; title: string; status: string; sprint: string; evidence: string; priority: string; sp: number; deps: string[]; issue?: number; evidenceState?: string };
const task = (t: Partial<Task> & { id: string }): Task => ({ req: FR1, title: t.id, status: 'Hecho', sprint: 'S9', evidence: '', priority: 'P1', sp: 2, deps: [], ...t });
const paths = (text: string) => extractRefs(text).paths.map((p: { path: string }) => p.path);

// OPS-18: the traceability and the status board come from the backlog and the tests; the evidence must exist.
describe('what an evidence text cites', () => {
  it('paths in backticks or in prose, and test file names; not hosts, MIME types, URLs, npm scopes nor build output', () => {
    expect(paths('`deploy/k8s` y tests/browser/web-saas.e2e.ts; `identity.test.ts`; lib/groups.ts.')).toEqual(['deploy/k8s', 'identity.test.ts', 'tests/browser/web-saas.e2e.ts', 'lib/groups.ts']);
    expect(paths('`ghcr.io/block/buzz@sha256:ac45…` `image/*` https://github.com/o/r `@sedecim/profiles` dist/keygen.html')).toEqual([]);
    expect(paths('`docs/slo.md#latencia` y (packages/a/src/x.ts:42)')).toEqual(['docs/slo.md', 'packages/a/src/x.ts']);
    // In prose, a path needs a file extension to be checked: "deploy/update/teardown" is words (see `checkable`).
    expect(extractRefs('scripts deploy/update/teardown').paths).toEqual([{ path: 'deploy/update/teardown', inCode: false }]);
  });

  it('commits standing alone in prose; not someone else’s (repo@sha), digests, ranges, hashes in backticks nor numbers', () => {
    const { shas } = extractRefs(
      'Commit 59a187c (PR #310) sobre main@75a18e5. Pin buzz@02c6309, digest sha256:8096413eb360, rango 781d395..b0d6fb8, `a6b968c`, informe docs/interop/buzz-02c6309-report.json, run 36219631189, obra acabada.',
    );
    expect(shas).toEqual(['59a187c', '75a18e5']);
  });

  it('ADRs, alone or in a list', () => {
    expect(extractRefs('ADR 0002/0003/0009, (ADR-0011) y ADRs 0004 y 0006').adrs).toEqual(['0002', '0003', '0009', '0011', '0004', '0006']);
  });
});

describe('evidence checked against the repository', () => {
  const index = repoIndex(['docs/adr/0003-politica.md', 'apps/web/src/lib/groups.ts', 'packages/a/test/a.test.ts', 'deploy/k8s/base/app.yaml', 'services/p/src/allowlist-sync.ts', 'services/p/src/allowlist-sync-main.ts']);
  const main = new Set(['59a187c']);
  const branch = new Set(['c0ffee1']);
  const repo = { index, commitExists: (s: string) => main.has(s) || branch.has(s), inHead: (s: string) => main.has(s) };

  it('accepts what exists: paths from the root, relative ones, globs, test names, commits of main and ADRs', () => {
    const t = task({ id: 'TSTA-01', evidence: 'Commit 59a187c: `deploy/k8s`, lib/groups.ts, services/p/src/allowlist-sync*.ts, a.test.ts (ADR 0003); scripts deploy/update/teardown' });
    expect(checkEvidence([t], repo)).toEqual([]);
  });

  it('reports each reference that does not exist', () => {
    const t = task({ id: 'TSTB-01', evidence: 'docs/missing.md, `deploy/nope`, ghost.test.ts, commit 1234abc, ADR 0009' });
    expect(checkEvidence([t], repo)).toEqual(['TSTB-01: no existe deploy/nope', 'TSTB-01: no existe docs/missing.md', 'TSTB-01: no existe ghost.test.ts', 'TSTB-01: no existe el commit 1234abc', 'TSTB-01: no existe el ADR 0009 en docs/adr']);
  });

  it('a task Hecho cites commits of main; a Parcial one may cite a branch; a Pendiente one is not checked', () => {
    const tasks = [task({ id: 'TSTC-01', evidence: 'c0ffee1' }), task({ id: 'TSTC-02', status: 'Parcial', evidence: 'c0ffee1' }), task({ id: 'TSTC-03', status: 'Pendiente', evidence: 'docs/missing.md 1234abc' })];
    expect(checkEvidence(tasks, repo)).toEqual(['TSTC-01: el commit c0ffee1 no está en la historia de main']);
    // Without the history (shallow clone) the commits are left out, never guessed.
    expect(checkEvidence(tasks, repo, { commits: false })).toEqual([]);
  });
});

describe('tests that cite tasks and requirements', () => {
  it('reads test files and check scripts, and only knows the backlog task ids', () => {
    const files = ['packages/a/test/a.test.ts', 'tests/browser/web.e2e.ts', 'scripts/tor-profile-check.sh', 'scripts/backup.sh', 'packages/a/src/a.ts', 'packages/a/test/vectors/v.json'];
    const text: Record<string, string> = {
      'packages/a/test/a.test.ts': `// TST01-01 and ${FR1}; not a task: ZZ99-99`,
      'tests/browser/web.e2e.ts': 'TST01-01 TST01-01',
      'scripts/tor-profile-check.sh': '# TSTOP-21',
      'scripts/backup.sh': '# TST01-01',
      'packages/a/src/a.ts': '// TST01-01',
      'packages/a/test/vectors/v.json': '"TST01-01"',
    };
    const { byTask, byReq } = testCitations(files, (f: string) => text[f], new Set(['TST01-01', 'TSTOP-21']));
    expect(Object.fromEntries(byTask)).toEqual({ 'TST01-01': ['packages/a/test/a.test.ts', 'tests/browser/web.e2e.ts'], 'TSTOP-21': ['scripts/tor-profile-check.sh'] });
    expect(Object.fromEntries(byReq)).toEqual({ [FR1]: ['packages/a/test/a.test.ts'] });
  });
});

describe('generated traceability and status board', () => {
  const meta = {
    github: 'o/r',
    requirements: { [FR1]: 'Crear identidad local', [FR2]: 'Importar identidad', [NFR1]: 'Disponibilidad SaaS' },
    sprints: [
      { id: 'S9', name: 'Código', phase: 'G0', start: '2026-09-28', end: '2026-10-09' },
      { id: 'Diferido', name: 'Después de v1.0', phase: '—', start: null, end: null },
    ],
  };
  const tasks = [
    task({ id: 'TST01-01', issue: 1, evidence: 'Commit 59a187c:\n\n- uno | dos;\n- tres', evidenceState: 'merged' }),
    task({ id: 'TST01-02', issue: 2, status: 'Pendiente', sprint: 'Diferido', priority: 'P0' }),
    task({ id: 'TST02-01', req: `${FR2}, ${FR1}`, issue: 3, status: 'Parcial', priority: 'P0', deps: ['TST01-01'] }),
    task({ id: 'NTST01-01', req: NFR1, issue: 4, status: 'Descartado', evidence: 'ADR 0003' }),
    task({ id: 'TSTOP-18', req: 'PRD GC-F03', issue: 5, status: 'Pendiente', priority: 'P0' }),
  ];
  const cites = { byTask: new Map([['TST01-01', ['packages/a/test/a.test.ts']]]), byReq: new Map([[FR1, ['tests/e2e/x.test.ts']]]) };

  it('a requirement is Hecho when all its tasks of the program are; deferred ones do not count, discarded ones neither', () => {
    const deferred = new Set(['Diferido']);
    expect(requirementState([tasks[0], tasks[1]], deferred)).toMatchObject({ state: 'Hecho', done: 1, active: 1 });
    expect(requirementState([tasks[0], tasks[2]], deferred)).toMatchObject({ state: 'Parcial', done: 1, active: 2 });
    expect(requirementState([task({ id: 'TSTX-01', status: 'Pendiente' })], deferred).state).toBe('Pendiente');
    expect(requirementState([tasks[1]], deferred).state).toBe('Diferido');
    expect(requirementState([tasks[3]], deferred).state).toBe('Descartado');
  });

  it('puts an evidence text on one line, lists joined and pipes escaped', () => {
    expect(evidenceCell('Commit 59a187c:\n\n- uno | dos;\n  - tres')).toBe('Commit 59a187c: uno \\| dos; · tres');
    expect(evidenceCell('')).toBe('—');
  });

  it('traceability: one row per requirement, one section per requirement with its tasks and tests, and the rest', () => {
    const md = renderTraceability({ meta, tasks }, cites);
    expect(md).toContain(`| ${FR1} | Crear identidad local | Parcial | 1 de 2 | TST01-02 (Diferido), TST02-01 (S9) |`);
    expect(md).toContain(`| ${NFR1} | Disponibilidad SaaS | Descartado | 0 de 0 | — |`);
    expect(md).toContain(`## ${FR1} · Crear identidad local\n\n**Parcial**: 1 de 2 tareas hechas. Tests que citan ${FR1}: [x.test.ts](../tests/e2e/x.test.ts).`);
    expect(md).toContain('| [TST01-01](https://github.com/o/r/issues/1) TST01-01 | Hecho · Merged | Commit 59a187c: uno \\| dos; · tres | [a.test.ts](../packages/a/test/a.test.ts) |');
    // A task of two requirements is under both; one of none is in the last section.
    expect(md.split('[TST02-01](https://github.com/o/r/issues/3)').length - 1).toBe(2);
    expect(md).toContain('| [TSTOP-18](https://github.com/o/r/issues/5) TSTOP-18 | PRD GC-F03 | Pendiente (S9) | — | — |');
  });

  it('status board: requirements and tasks by state, evidence levels, open sprints and open P0', () => {
    const md = renderStatus({ meta, tasks });
    expect(md).toContain(`| Parcial | 2 | ${FR1}, ${FR2} |`);
    expect(md).toContain(`| Descartado | 1 | ${NFR1} |`);
    expect(md).toContain('| Hecho | 1 | 2 |');
    expect(md).toContain('| Merged | 1 |');
    expect(md).toContain('| Sin label (anteriores a OPS-17) | 0 |');
    expect(md).toContain('| S9 | 2026-09-28 → 2026-10-09 | G0 | Código | 1 de 3 | 2 | 4 | 2 |');
    expect(md).toContain('| [TST02-01](https://github.com/o/r/issues/3) TST02-01 | S9 | Parcial | TST01-01 |');
    // Only open P0: a deferred P0 is still listed, the done or discarded ones are not.
    expect(md).toContain('| [TST01-02](https://github.com/o/r/issues/2) TST01-02 | Diferido | Pendiente | — |');
  });
});
