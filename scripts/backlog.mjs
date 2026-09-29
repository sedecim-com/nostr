#!/usr/bin/env node
// Validates docs/backlog/backlog.json and renders docs/backlog/README.md + backlog.csv.
// Once meta.github is set, backlog.json is itself generated from GitHub Issues (scripts/backlog-github.mjs,
// docs/backlog/GITHUB.md): edit the issues, not these files.
//   node scripts/backlog.mjs          (validate + render)
//   node scripts/backlog.mjs --check  (validate only; exits 1 on errors or stale outputs)
import { readFileSync, writeFileSync } from 'node:fs';

const dir = new URL('../docs/backlog/', import.meta.url);
const { meta, tasks } = JSON.parse(readFileSync(new URL('backlog.json', dir), 'utf8'));
const errors = [];
const byId = new Map();
const sprintOrder = new Map(meta.sprints.map((s, i) => [s.id, i]));
const closedSprints = new Set(meta.sprints.filter((s) => s.closed).map((s) => s.id));
const REQUIRED = [...Array.from({ length: 28 }, (_, i) => `FR-${String(i + 1).padStart(3, '0')}`), ...Array.from({ length: 10 }, (_, i) => `NFR-${String(i + 1).padStart(3, '0')}`)];

for (const t of tasks) {
  if (byId.has(t.id)) errors.push(`duplicate id ${t.id}`);
  byId.set(t.id, t);
  if (!meta.priorities[t.priority]) errors.push(`${t.id}: unknown priority ${t.priority}`);
  if (!sprintOrder.has(t.sprint)) errors.push(`${t.id}: unknown sprint ${t.sprint}`);
  if (!['Hecho', 'Parcial', 'Pendiente', 'Descartado'].includes(t.status)) errors.push(`${t.id}: unknown status ${t.status}`);
  if (t.sprint === 'v0.1' && t.status !== 'Hecho') errors.push(`${t.id}: only done tasks belong to v0.1`);
  if (closedSprints.has(t.sprint) && (t.status === 'Parcial' || t.status === 'Pendiente')) errors.push(`${t.id}: sprint ${t.sprint} is closed; move the open task to an open sprint`);
  if (t.status !== 'Pendiente' && !t.evidence) errors.push(`${t.id}: ${t.status} requires evidence`);
  if (![1, 2, 3, 5, 8].includes(t.sp)) errors.push(`${t.id}: story points must be 1,2,3,5,8`);
  if (t.issue !== undefined && !(Number.isInteger(t.issue) && t.issue > 0)) errors.push(`${t.id}: issue must be a GitHub issue number`);
}
if (meta.github !== undefined && !/^[\w.-]+\/[\w.-]+$/.test(meta.github)) errors.push(`meta.github must be "owner/repo"`);
// OPS-18: the names of the requirements the traceability (scripts/traceability.mjs) is generated for.
for (const r of REQUIRED) if (!meta.requirements?.[r]) errors.push(`meta.requirements has no name for ${r}`);
for (const r of Object.keys(meta.requirements ?? {})) if (!REQUIRED.includes(r)) errors.push(`meta.requirements: unknown requirement ${r}`);
for (const t of tasks) {
  for (const d of t.deps) {
    const dep = byId.get(d);
    if (!dep) {
      errors.push(`${t.id}: unknown dependency ${d}`);
      continue;
    }
    if (sprintOrder.get(dep.sprint) > sprintOrder.get(t.sprint)) errors.push(`${t.id} (${t.sprint}) depends on ${d} planned later (${dep.sprint})`);
    if (t.status === 'Hecho' && dep.status !== 'Hecho') errors.push(`${t.id} is done but depends on unfinished ${d}`);
    if (t.status !== 'Descartado' && dep.status === 'Descartado') errors.push(`${t.id} depends on discarded ${d}`);
  }
}
// cycle detection
const state = new Map();
const visit = (id, path) => {
  if (state.get(id) === 2) return;
  if (state.get(id) === 1) return errors.push(`dependency cycle: ${[...path, id].join(' -> ')}`);
  state.set(id, 1);
  for (const d of byId.get(id)?.deps ?? []) if (byId.has(d)) visit(d, [...path, id]);
  state.set(id, 2);
};
tasks.forEach((t) => visit(t.id, []));
const coverage = new Map(REQUIRED.map((r) => [r, tasks.filter((t) => t.req.split(/,\s*/).includes(r))]));
for (const [r, ts] of coverage) if (ts.length === 0) errors.push(`requirement ${r} has no task`);

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}

// ---- render
const esc = (s) => String(s).replace(/\|/g, '\\|');
const sum = (ts) => ts.reduce((a, t) => a + t.sp, 0);
const active = (ts) => ts.filter((t) => t.status !== 'Descartado');
const open = tasks.filter((t) => t.status !== 'Hecho' && t.status !== 'Descartado');
const dates = (s) => (s.start ? `${s.start} → ${s.end}` : s.end ? `hasta ${s.end}` : 'sin fecha');
const lines = [];
lines.push('# Backlog — Acceso Nostr', '');
lines.push(
  meta.github
    ? `> Fuente: [GitHub Issues](https://github.com/${meta.github}/issues?q=label%3Abacklog) (ver [GITHUB.md](GITHUB.md)). \`backlog.json\`, este archivo y \`backlog.csv\` se regeneran desde los issues; no editar a mano.`
    : `> Generado por \`node scripts/backlog.mjs\` desde \`backlog.json\`. Pendiente de sembrar en GitHub Issues (ver [GITHUB.md](GITHUB.md)); no editar a mano.`,
);
lines.push(`> Base: ${meta.source}. Estado del código: \`${meta.baseline}\` (${meta.version}).`, '');
lines.push('## Resumen', '');
lines.push(`- **${tasks.length} tareas** · ${tasks.filter((t) => t.status === 'Hecho').length} hechas · ${tasks.filter((t) => t.status === 'Parcial').length} parciales · ${tasks.filter((t) => t.status === 'Pendiente').length} pendientes · ${tasks.filter((t) => t.status === 'Descartado').length} descartadas`);
lines.push(`- **${sum(open)} story points** pendientes en ${meta.sprints.filter((s) => s.start).length} sprints de ${meta.sprintLengthDays} días (velocidad supuesta: ${meta.assumedVelocitySP} SP/sprint, equipo de ~4 personas; ajustar tras S1)`);
lines.push(`- Prioridades: ${Object.entries(meta.priorities).map(([k, v]) => `**${k}** ${v}`).join(' · ')}`);
lines.push('- Estados: **Hecho** (con evidencia en el repo) · **Parcial** (existe base, falta completar) · **Pendiente** · **Descartado** (fuera de alcance por una decisión; la evidencia cita el ADR)');
lines.push('- IDs: `FRnnn-xx` / `NFRnnn-xx` por requisito; `DEC`, `BUZZ`, `OPS`, `PANEL`, `SEC`, `REL` para decisiones, Buzz upstream, operación, panel y gates.', '');
lines.push('## Plan de sprints', '');
lines.push('| Sprint | Fechas | Fase | Objetivo | Tareas | SP | P0 |', '|---|---|---|---|---:|---:|---:|');
for (const s of meta.sprints) {
  const ts = tasks.filter((t) => t.sprint === s.id);
  lines.push(`| ${s.id}${s.closed ? ' (cerrado)' : ''} | ${dates(s)} | ${s.phase} | ${s.name} | ${active(ts).length} | ${sum(active(ts))} | ${active(ts).filter((t) => t.priority === 'P0').length} |`);
}
lines.push('', '## Cobertura de requisitos', '');
lines.push('| Requisito | Tareas | Hechas | Pendientes (sprint) |', '|---|---:|---:|---|');
for (const [r, ts] of coverage) {
  const pend = active(ts).filter((t) => t.status !== 'Hecho');
  lines.push(`| ${r} | ${ts.length} | ${ts.length - pend.length} | ${pend.map((t) => `${t.id} (${t.sprint})`).join(', ') || '—'} |`);
}
const idCell = (t) => (meta.github && t.issue ? `[${t.id}](https://github.com/${meta.github}/issues/${t.issue})` : t.id);
const row = (t) => `| ${idCell(t)} | ${t.priority} | ${esc(t.title)} | ${esc(t.req)} | ${t.type} | ${t.sp} | ${t.deps.join(', ') || '—'} | ${t.status} | ${esc(t.done)} |`;
const head = ['| ID | Prio | Tarea | Requisito | Tipo | SP | Depende de | Estado | Criterio de hecho |', '|---|---|---|---|---|---:|---|---|---|'];
for (const s of meta.sprints.filter((x) => x.id !== 'v0.1')) {
  const ts = tasks.filter((t) => t.sprint === s.id).sort((a, b) => a.priority.localeCompare(b.priority) || a.id.localeCompare(b.id));
  lines.push('', `## ${s.id} · ${s.name} (${s.phase}, ${dates(s)}) — ${sum(active(ts))} SP`, '', ...head, ...ts.map(row));
}
const done = tasks.filter((t) => t.sprint === 'v0.1');
lines.push('', `## Entregado en v0.1 — ${done.length} tareas`, '', '| ID | Tarea | Requisito | Evidencia |', '|---|---|---|---|');
for (const t of done) lines.push(`| ${idCell(t)} | ${esc(t.title)} | ${esc(t.req)} | \`${esc(t.evidence)}\` |`);
lines.push('');
const md = lines.join('\n');

const csvCell = (v) => `"${String(v).replace(/"/g, '""')}"`;
const csv = [['ID', 'Epic', 'Requisito', 'Tarea', 'Criterio de hecho', 'Tipo', 'Prioridad', 'Story points', 'Depende de', 'Sprint', 'Fecha fin sprint', 'Estado', 'Evidencia', 'Issue'].map(csvCell).join(',')]
  .concat(tasks.map((t) => [t.id, t.epic, t.req, t.title, t.done, t.type, t.priority, t.sp, t.deps.join(' '), t.sprint, meta.sprints.find((s) => s.id === t.sprint).end, t.status, t.evidence, t.issue && meta.github ? `https://github.com/${meta.github}/issues/${t.issue}` : ''].map(csvCell).join(',')))
  .join('\n') + '\n';

if (process.argv.includes('--check')) {
  const stale = [['README.md', md], ['backlog.csv', csv]].filter(([f, c]) => readFileSync(new URL(f, dir), 'utf8') !== c);
  if (stale.length) {
    console.error(`stale generated files: ${stale.map(([f]) => f).join(', ')} — run node scripts/backlog.mjs`);
    process.exit(1);
  }
} else {
  writeFileSync(new URL('README.md', dir), md);
  writeFileSync(new URL('backlog.csv', dir), csv);
}
console.log(`backlog ok: ${tasks.length} tasks, ${sum(open)} open SP, ${REQUIRED.length} requirements covered`);
