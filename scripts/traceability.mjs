#!/usr/bin/env node
// OPS-18 (PRD GC-F03): docs/requirements-traceability.md and docs/status.md are generated, never edited by hand.
// They come from the backlog (docs/backlog/backlog.json, itself generated from GitHub Issues) and from the code:
// the tests that cite each task or requirement. The evidence of every task that is not Pendiente is checked against
// the repository: the files and tests it names exist, its commits exist (for a task Hecho, in the history of HEAD)
// and so do its ADRs. How to cite so it is checked: docs/backlog/GITHUB.md.
//   node scripts/traceability.mjs          (write both files; a broken reference is a warning)
//   node scripts/traceability.mjs --check  (exit 1 on a broken reference or a stale file; CI job `traceability`,
//                                           which checks out the full history)
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EVIDENCE_STATES } from './backlog-github.mjs';

export const OUTPUTS = { traceability: 'docs/requirements-traceability.md', status: 'docs/status.md' };

const EXT = /\.(?:[cm]?[jt]sx?|md|json|ya?ml|sh|sql|toml|html|css|rs|txt|csv|conf|proto)$/;
const TEST_NAME = /\.(?:test|e2e|spec)\.[cm]?[jt]sx?$/;
const MIME = /^(?:image|video|audio|application|text|font|multipart)\//;
const TASK_ID = /\b[A-Z]{2,6}\d{0,3}-\d{2}\b/g;
const REQ_ID = /\b(?:FR|NFR)-\d{3}\b/g;
const escapeRe = (s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&');

/**
 * What an evidence text cites, before checking it against the repository:
 * - paths, in backticks or in prose; a bare test file name (`identity.test.ts`) too. `checkEvidence` decides which
 *   ones are checked (see `checkable`). URLs, hosts (ghcr.io/…), MIME types, npm scopes, elided text (…) and build
 *   output (dist/…) are not paths of the tree;
 * - commits: hex of 7 to 40 characters, with a digit and a letter, standing alone in prose. Someone else's commit is
 *   written repo@sha (buzz@02c6309), our main as main@sha; a digest (sha256:…), a range (a..b) or hex inside a path
 *   is not a commit, and a hash that is not a commit goes in backticks;
 * - ADRs: "ADR 0011", "ADR 0002/0003".
 */
export function extractRefs(text = '') {
  const paths = new Map();
  const shas = new Set();
  const adrs = new Set();
  const addPath = (word, inCode) => {
    let w = word.replace(/^[([{'"«]+/, '').replace(/[)\]}'"».,;:!?]+$/, '');
    if (!w || /:\/\/|@sha256|…/.test(w) || w.startsWith('@')) return;
    w = w.replace(/^(?:\.\.?\/)+/, '').replace(/[#?].*$/, '').replace(/:\d+(?::\d+)?$/, '').replace(/\/$/, '');
    if (!w || !/[a-z]/i.test(w)) return;
    if (!w.includes('/')) {
      if (TEST_NAME.test(w)) paths.set(w, paths.get(w) || inCode);
      return;
    }
    const first = w.split('/')[0];
    if (MIME.test(w) || !/^[\w.@*/-]+$/.test(w) || (first.includes('.') && !first.startsWith('.'))) return;
    if (w.split('/').some((s) => s === 'dist' || s === 'node_modules')) return; // build output, not in the tree
    paths.set(w, paths.get(w) || inCode);
  };
  const prose = text.replace(/`[^`\n]*`/g, (span) => {
    for (const w of span.slice(1, -1).split(/\s+/)) addPath(w, true);
    return ' ';
  });
  for (const w of prose.split(/[\s,;()[\]{}<>"'«»]+/)) addPath(w, false);
  for (const m of prose.matchAll(/[0-9a-f]{7,40}/g)) {
    const s = m[0];
    const before = prose.slice(0, m.index);
    const after = prose.slice(m.index + s.length);
    if (!/\d/.test(s) || !/[a-f]/.test(s)) continue;
    if (/[\w./:#@-]$/.test(before) && !/(?:^|\W)main@$/.test(before)) continue;
    if (/^(?:[\w/@-]|\.\.|\.\w)/.test(after)) continue;
    shas.add(s);
  }
  for (const m of text.matchAll(/\bADRs?[ -]?(\d{4}(?:\s*(?:\/|,|y|e)\s*\d{4})*)/g)) for (const n of m[1].match(/\d{4}/g)) adrs.add(n);
  return { paths: [...paths].map(([path, inCode]) => ({ path, inCode })), shas: [...shas], adrs: [...adrs] };
}

/** The tracked files of a repository, indexed to resolve the paths an evidence text cites. */
export function repoIndex(files) {
  const fileSet = new Set(files);
  const dirSet = new Set();
  const basenames = new Set();
  for (const f of files) {
    const parts = f.split('/');
    basenames.add(parts.at(-1));
    for (let i = 1; i < parts.length; i++) dirSet.add(parts.slice(0, i).join('/'));
  }
  return { files, fileSet, dirSet, basenames, top: new Set(files.map((f) => f.split('/')[0])) };
}

/**
 * Which cited paths must exist: a test file name; a path with a file extension; in backticks, a path from the root
 * of the repository (`deploy/k8s`). Prose such as "deploy/update/teardown" or "req/s" is not taken for a path.
 */
export function checkable({ path, inCode }, idx) {
  if (!path.includes('/')) return true;
  return EXT.test(path) || (inCode && idx.top.has(path.split('/')[0]));
}

/**
 * A path from the root must be there as written (a module may leave out its extension). One that does not start at
 * the root (`lib/groups.ts`, `marmot-adapter/test/x.test.ts`) must end some tracked path; a test name must be the name
 * of a tracked file. `*` matches within one directory.
 */
export function hasPath(idx, p) {
  const fromRoot = idx.top.has(p.split('/')[0]);
  if (p.includes('*')) {
    const re = new RegExp(`${fromRoot ? '^' : '(?:^|/)'}${p.split('*').map(escapeRe).join('[^/]*')}$`);
    return idx.files.some((f) => re.test(f));
  }
  if (idx.fileSet.has(p) || idx.dirSet.has(p)) return true;
  if (!p.includes('/')) return idx.basenames.has(p);
  if (['.ts', '.tsx', '.mjs', '.js'].some((e) => idx.fileSet.has(p + e))) return true;
  if (fromRoot) return false;
  const tail = `/${p}`;
  return idx.files.some((f) => f.endsWith(tail)) || [...idx.dirSet].some((d) => d.endsWith(tail));
}

/**
 * Broken references in the evidence of the tasks that are not Pendiente. `repo` answers `index`, and, unless
 * `commits` is false, `commitExists(sha)` and `inHead(sha)`: a task Hecho must cite commits of HEAD's history (main,
 * or main plus the PR under test), any other one commits that exist.
 */
export function checkEvidence(tasks, repo, { commits = true } = {}) {
  const problems = [];
  for (const t of tasks) {
    if (t.status === 'Pendiente' || !t.evidence) continue;
    const { paths, shas, adrs } = extractRefs(t.evidence);
    for (const p of paths) if (checkable(p, repo.index) && !hasPath(repo.index, p.path)) problems.push(`${t.id}: no existe ${p.path}`);
    if (commits)
      for (const s of shas) {
        if (!repo.commitExists(s)) problems.push(`${t.id}: no existe el commit ${s}`);
        else if (t.status === 'Hecho' && !repo.inHead(s)) problems.push(`${t.id}: el commit ${s} no está en la historia de main`);
      }
    for (const n of adrs) if (!repo.index.files.some((f) => f.startsWith(`docs/adr/${n}-`))) problems.push(`${t.id}: no existe el ADR ${n} en docs/adr`);
  }
  return problems;
}

const isTest = (f) => (/(^|\/)tests?\//.test(f) || TEST_NAME.test(f) || /^scripts\/[\w-]+-(?:test|check)\.sh$/.test(f)) && /\.(?:[cm]?[jt]sx?|sh)$/.test(f);

/** The tests (test files and check scripts) that cite each task id and each requirement id. */
export function testCitations(files, read, taskIds) {
  const byTask = new Map();
  const byReq = new Map();
  const add = (m, k, f) => m.set(k, [...(m.get(k) ?? []), f]);
  for (const f of files.filter(isTest).sort()) {
    const text = read(f);
    for (const id of new Set(text.match(TASK_ID) ?? [])) if (taskIds.has(id)) add(byTask, id, f);
    for (const id of new Set(text.match(REQ_ID) ?? [])) add(byReq, id, f);
  }
  return { byTask, byReq };
}

// ---- render
// A table cell: backslashes first, so that a "\|" in the text does not become an escaped backslash and a bare pipe.
const cell = (s) => String(s).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\s*\n\s*/g, ' ');
const LEVEL = new Map(EVIDENCE_STATES.map(([slug, label]) => [slug, label]));
const reqsOf = (t) => [...new Set(t.req.match(REQ_ID) ?? [])];

/**
 * A requirement is Hecho when all its tasks of the program are (neither Descartado nor deferred past v1.0: a sprint
 * that is not closed and has no dates), Parcial when one is Hecho or Parcial. `open` lists the deferred ones too.
 */
export function requirementState(ts, deferred = new Set()) {
  const live = ts.filter((t) => t.status !== 'Descartado');
  const active = live.filter((t) => !deferred.has(t.sprint));
  const done = active.filter((t) => t.status === 'Hecho').length;
  const state = !active.length ? (live.length ? 'Diferido' : 'Descartado') : done === active.length ? 'Hecho' : done || active.some((t) => t.status === 'Parcial') ? 'Parcial' : 'Pendiente';
  return { state, done, active: active.length, open: live.filter((t) => t.status !== 'Hecho') };
}
const deferredSprints = (meta) => new Set(meta.sprints.filter((s) => !s.closed && !s.start).map((s) => s.id));

/** The evidence of an issue on one line: list items and paragraphs joined with " · ". */
export function evidenceCell(text = '') {
  const items = text.split('\n').map((l) => l.trim().replace(/^[-*]\s+/, '')).filter(Boolean);
  if (!items.length) return '—';
  return cell(items.reduce((out, s) => (out ? `${out}${out.endsWith(':') ? ' ' : ' · '}${s}` : s), ''));
}

function renderers(backlog, cites) {
  const { meta } = backlog;
  const taskCell = (t) => `${meta.github && t.issue ? `[${t.id}](https://github.com/${meta.github}/issues/${t.issue})` : t.id} ${cell(t.title)}`;
  const stateCell = (t) => (t.status === 'Hecho' ? `Hecho${t.evidenceState ? ` · ${LEVEL.get(t.evidenceState) ?? t.evidenceState}` : ''}` : t.status === 'Descartado' ? 'Descartado' : `${t.status} (${t.sprint})`);
  const testsCell = (files = []) => (files.length ? files.map((f) => `[${f.split('/').at(-1)}](../${f})`).join(', ') : '—');
  return { taskCell, stateCell, testsCell, testsOf: (id) => testsCell(cites.byTask.get(id)) };
}

export function renderTraceability(backlog, cites) {
  const { meta, tasks } = backlog;
  const { taskCell, stateCell, testsCell, testsOf } = renderers(backlog, cites);
  const reqs = Object.entries(meta.requirements);
  const tasksOf = (r) => tasks.filter((t) => reqsOf(t).includes(r));
  const deferred = deferredSprints(meta);
  const source = meta.github ? `[GitHub Issues](https://github.com/${meta.github}/issues?q=label%3Abacklog)` : 'el backlog';
  const lines = [
    '# Trazabilidad de requisitos',
    '',
    `> Generado por \`node scripts/traceability.mjs\` (OPS-18) desde ${source}, vía \`docs/backlog/backlog.json\`, y desde los tests que citan cada tarea o requisito. No se edita a mano: se corrige el issue o el test y se regenera. El job \`traceability\` de CI falla si este archivo no está al día o si la evidencia de una tarea cita un archivo, una prueba, un commit o un ADR que no existe. Tablero: [status.md](status.md).`,
    '',
    'Un requisito está **Hecho** si lo están todas sus tareas del programa, sin contar las descartadas ni las diferidas a después de v1.0; **Parcial** si alguna está hecha o parcial, y **Pendiente** si ninguna. Las diferidas siguen en la lista de abiertas. El nivel de evidencia de una tarea hecha (Merged, CI Verified, Stage Verified, Externally Audited, Production Enabled) es su label `evidencia:*` (OPS-17).',
    '',
    '| Requisito | Nombre | Estado | Tareas hechas | Abiertas (sprint) |',
    '|---|---|---|---:|---|',
  ];
  for (const [id, name] of reqs) {
    const s = requirementState(tasksOf(id), deferred);
    lines.push(`| ${id} | ${cell(name)} | ${s.state} | ${s.done} de ${s.active} | ${s.open.map((t) => `${t.id} (${t.sprint})`).join(', ') || '—'} |`);
  }
  const head = ['| Tarea | Estado | Evidencia | Tests que la citan |', '|---|---|---|---|'];
  for (const [id, name] of reqs) {
    const ts = tasksOf(id);
    const s = requirementState(ts, deferred);
    const cited = cites.byReq.get(id);
    lines.push('', `## ${id} · ${name}`, '', `**${s.state}**: ${s.done} de ${s.active} tareas hechas.${cited ? ` Tests que citan ${id}: ${testsCell(cited)}.` : ''}`, '', ...head);
    for (const t of ts) lines.push(`| ${taskCell(t)} | ${stateCell(t)} | ${evidenceCell(t.evidence)} | ${testsOf(t.id)} |`);
  }
  const others = tasks.filter((t) => !reqsOf(t).some((r) => meta.requirements[r]));
  lines.push('', '## Tareas sin requisito FR o NFR', '', 'Decisiones, operación, seguridad, panel y gates, con la referencia que citan (PRD, especificación).', '');
  lines.push('| Tarea | Referencia | Estado | Evidencia | Tests que la citan |', '|---|---|---|---|---|');
  for (const t of others) lines.push(`| ${taskCell(t)} | ${cell(t.req) || '—'} | ${stateCell(t)} | ${evidenceCell(t.evidence)} | ${testsOf(t.id)} |`);
  return lines.join('\n') + '\n';
}

export function renderStatus(backlog) {
  const { meta, tasks } = backlog;
  const { taskCell } = renderers(backlog, { byTask: new Map(), byReq: new Map() });
  const sum = (ts) => ts.reduce((a, t) => a + t.sp, 0);
  const reqs = Object.keys(meta.requirements);
  const deferred = deferredSprints(meta);
  const byState = new Map(['Hecho', 'Parcial', 'Pendiente', 'Diferido', 'Descartado'].map((s) => [s, []]));
  for (const r of reqs) byState.get(requirementState(tasks.filter((t) => reqsOf(t).includes(r)), deferred).state).push(r);
  const lines = [
    '# Tablero de estado',
    '',
    '> Generado por `node scripts/traceability.mjs` (OPS-18) desde el backlog (GitHub Issues) y el código; no se edita a mano. Detalle por requisito: [requirements-traceability.md](requirements-traceability.md). Plan y criterio de hecho de cada tarea: [backlog/README.md](backlog/README.md).',
    '',
    '## Requisitos',
    '',
    '| Estado | Cuántos | Cuáles |',
    '|---|---:|---|',
    ...[...byState].filter(([, rs]) => rs.length).map(([s, rs]) => `| ${s} | ${rs.length} | ${rs.join(', ')} |`),
    '',
    '## Tareas',
    '',
    '| Estado | Tareas | Story points |',
    '|---|---:|---:|',
    ...['Hecho', 'Parcial', 'Pendiente', 'Descartado'].map((s) => {
      const ts = tasks.filter((t) => t.status === s);
      return `| ${s} | ${ts.length} | ${sum(ts)} |`;
    }),
    '',
    'Nivel de evidencia de las tareas hechas (label `evidencia:*`, OPS-17):',
    '',
    '| Nivel | Tareas |',
    '|---|---:|',
  ];
  const done = tasks.filter((t) => t.status === 'Hecho');
  for (const [slug, label] of [...EVIDENCE_STATES].reverse()) {
    if (slug === 'proposed' || slug === 'in-pr') continue;
    lines.push(`| ${label} | ${done.filter((t) => t.evidenceState === slug).length} |`);
  }
  lines.push(`| Sin label (anteriores a OPS-17) | ${done.filter((t) => !t.evidenceState).length} |`);
  lines.push('', '## Sprints abiertos', '', '| Sprint | Fechas | Fase | Objetivo | Hechas | Abiertas | SP abiertos | P0 abiertas |', '|---|---|---|---|---:|---:|---:|---:|');
  for (const s of meta.sprints.filter((x) => !x.closed)) {
    const ts = tasks.filter((t) => t.sprint === s.id && t.status !== 'Descartado');
    const open = ts.filter((t) => t.status !== 'Hecho');
    const dates = s.start ? `${s.start} → ${s.end}` : 'sin fecha';
    lines.push(`| ${s.id} | ${dates} | ${s.phase} | ${cell(s.name)} | ${ts.length - open.length} de ${ts.length} | ${open.length} | ${sum(open)} | ${open.filter((t) => t.priority === 'P0').length} |`);
  }
  const order = new Map(meta.sprints.map((s, i) => [s.id, i]));
  const p0 = tasks.filter((t) => t.priority === 'P0' && (t.status === 'Pendiente' || t.status === 'Parcial')).sort((a, b) => order.get(a.sprint) - order.get(b.sprint));
  lines.push('', '## P0 abiertas', '', '| Tarea | Sprint | Estado | Depende de |', '|---|---|---|---|');
  for (const t of p0) lines.push(`| ${taskCell(t)} | ${t.sprint} | ${t.status} | ${t.deps.join(', ') || '—'} |`);
  return lines.join('\n') + '\n';
}

/** The repository at `root`, through git: tracked files, their text and the commit history. */
export function gitRepo(root) {
  const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 << 20 });
  const ok = (...args) => {
    try {
      git(...args);
      return true;
    } catch {
      return false;
    }
  };
  const memo = new Map();
  const cached = (key, fn) => (memo.has(key) ? memo.get(key) : memo.set(key, fn()).get(key));
  const files = git('ls-files', '-z').split('\0').filter(Boolean);
  return {
    index: repoIndex(files),
    read: (f) => {
      try {
        return readFileSync(join(root, f), 'utf8');
      } catch {
        return '';
      }
    },
    shallow: git('rev-parse', '--is-shallow-repository').trim() === 'true',
    commitExists: (sha) => cached(`c${sha}`, () => ok('cat-file', '-e', `${sha}^{commit}`)),
    inHead: (sha) => cached(`h${sha}`, () => ok('merge-base', '--is-ancestor', sha, 'HEAD')),
  };
}

// ---- CLI
if (import.meta.url === `file://${process.argv[1]}`) {
  const root = fileURLToPath(new URL('..', import.meta.url));
  const check = process.argv.includes('--check');
  const backlog = JSON.parse(readFileSync(join(root, 'docs/backlog/backlog.json'), 'utf8'));
  const repo = gitRepo(root);
  const problems = [];
  if (repo.shallow) problems.push('el clon no tiene la historia completa (fetch-depth: 0): no se comprueban los commits de la evidencia');
  problems.push(...checkEvidence(backlog.tasks, repo, { commits: !repo.shallow }));
  const cites = testCitations(repo.index.files, repo.read, new Set(backlog.tasks.map((t) => t.id)));
  const out = [
    [OUTPUTS.traceability, renderTraceability(backlog, cites)],
    [OUTPUTS.status, renderStatus(backlog)],
  ];
  if (check) {
    for (const [f, c] of out) if (repo.read(f) !== c) problems.push(`${f} no está al día: node scripts/traceability.mjs`);
    if (problems.length) {
      console.error(problems.join('\n'));
      process.exit(1);
    }
  } else {
    for (const [f, c] of out) writeFileSync(join(root, f), c);
    for (const p of problems) console.log(`::warning::${p}`);
  }
  console.log(`traceability ok: ${Object.keys(backlog.meta.requirements).length} requisitos, ${backlog.tasks.length} tareas, ${cites.byTask.size} citadas por tests`);
}
