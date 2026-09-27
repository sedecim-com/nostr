#!/usr/bin/env node
// GitHub Issues are the source of truth of the backlog; docs/backlog/backlog.json is derived from them.
//   node scripts/backlog-github.mjs seed           create what is missing on GitHub from backlog.json; also keeps
//                                                  milestone titles in line with meta.sprints and "blocked by" links
//                                                  in line with each issue's "Depende de" (never edits an issue)
//   node scripts/backlog-github.mjs pull [--write] rebuild backlog.json tasks from the issues
// Env: GITHUB_TOKEN, GITHUB_REPOSITORY (owner/repo), GITHUB_API_URL (optional, tests).
//
// Mapping (docs/backlog/GITHUB.md): one issue per task titled "[ID] title" with label `backlog`; sprint =
// milestone "S3 · …"; priority = label P0–P3 (mirrored to the org field Priority); SP in the body (mirrored
// to Effort); epic = label "epic:…" and parent issue; state: open = Pendiente (label status:parcial =
// Parcial), closed completed = Hecho, closed not planned = Descartado; dependencies in the body and as
// native "blocked by" links.
import { readFileSync, writeFileSync } from 'node:fs';

export const TASK_LABEL = 'backlog';
export const EPIC_LABEL = 'epic';
export const PARTIAL_LABEL = 'status:parcial';
const PRIORITY_FIELD = { P0: 'Urgent', P1: 'High', P2: 'Medium', P3: 'Low' };
const effortOf = (sp) => (sp <= 2 ? 'Low' : sp === 3 ? 'Medium' : 'High');
const NONE = '_Sin información_';
const SECTIONS = ['Requisito', 'Tipo', 'Story points', 'Depende de', 'Criterio de hecho', 'Evidencia'];
const ID_RE = /\b[A-Z]{2,6}\d{0,3}-\d{2}\b/g;

export function createClient({ token, repo, baseUrl = 'https://api.github.com', writeDelayMs = 1000, log = console.log }) {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  async function request(method, path, body) {
    for (let attempt = 0; ; attempt++) {
      const res = await fetch(`${baseUrl}${path}`, {
        method,
        headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', ...(body ? { 'content-type': 'application/json' } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      // Secondary rate limits on content creation (~80/min, ~500/h): honour retry-after / the reset time and
      // wait. Seeding is resumable anyway: every step checks what already exists.
      const limited = (res.status === 403 || res.status === 429) && (res.headers.get('retry-after') || res.headers.get('x-ratelimit-remaining') === '0' || /rate limit/i.test(await res.clone().text()));
      if (limited && attempt < 30) {
        const reset = Number(res.headers.get('x-ratelimit-reset') ?? 0) * 1000 - Date.now();
        const wait = res.headers.get('retry-after') ? Number(res.headers.get('retry-after')) * 1000 : Math.max(60_000, reset);
        log(`rate limited, waiting ${Math.round(wait / 1000)}s`);
        await sleep(wait);
        continue;
      }
      const text = await res.text();
      const json = text ? JSON.parse(text) : undefined;
      if (!res.ok) throw Object.assign(new Error(`${method} ${path}: ${res.status} ${json?.message ?? text}${json?.errors ? ` ${JSON.stringify(json.errors)}` : ''}`), { status: res.status });
      if (method !== 'GET' && writeDelayMs) await sleep(writeDelayMs);
      return json;
    }
  }
  async function all(path) {
    const out = [];
    for (let page = 1; ; page++) {
      const items = await request('GET', `${path}${path.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
      out.push(...items);
      if (items.length < 100) return out;
    }
  }
  const [owner, name] = repo.split('/');
  return { request, all, owner, name, repo, log };
}

// ---- body format (same shape GitHub issue forms produce, so tasks can be created from the UI)
export function taskBody(t) {
  const v = { Requisito: t.req, Tipo: t.type, 'Story points': String(t.sp), 'Depende de': t.deps.join(', '), 'Criterio de hecho': t.done, Evidencia: t.evidence };
  return SECTIONS.map((s) => `### ${s}\n\n${v[s] || NONE}`).join('\n\n') + '\n';
}

export function parseBody(body = '') {
  const out = {};
  const parts = body.split(/^### /m).slice(1);
  for (const p of parts) {
    const nl = p.indexOf('\n');
    const key = p.slice(0, nl).trim();
    const val = p.slice(nl + 1).trim();
    out[key] = val === NONE || val === '_No response_' || val === '—' ? '' : val;
  }
  return out;
}

const taskTitle = (t) => `[${t.id}] ${t.title}`;
export function parseTitle(title) {
  const m = /^\[([A-Z0-9]+-[0-9A-Z]+)\]\s*(.+)$/.exec(title.trim());
  return m ? { id: m[1], title: m[2].trim() } : undefined;
}
// GitHub rejects commas in label names (422) and caps them at 50 chars; pull maps them back to the epic.
const epicLabel = (epic) => `epic:${epic.replace(/,/g, '')}`.slice(0, 50);
const milestoneTitle = (s) => `${s.id} · ${s.name}`;
const milestoneDescription = (s) => `Fase ${s.phase}${s.start ? ` · ${s.start} → ${s.end}` : s.end ? ` · hasta ${s.end}` : ''}`;
const sprintOfMilestone = (title) => title?.split(' · ')[0];

async function fieldIds(api) {
  // Org issue fields (Priority, Effort, Start/Target date) are optional: mirror them when available.
  try {
    const q = `query($o:String!,$n:String!){repository(owner:$o,name:$n){issueFields(first:100){nodes{__typename ... on IssueFieldSingleSelect{fullDatabaseId name options{name}} ... on IssueFieldDate{fullDatabaseId name}}}}}`;
    const r = await api.request('POST', '/graphql', { query: q, variables: { o: api.owner, n: api.name } });
    const nodes = r?.data?.repository?.issueFields?.nodes ?? [];
    return Object.fromEntries(nodes.filter((n) => n.name).map((n) => [n.name, Number(n.fullDatabaseId)]));
  } catch (e) {
    api.log(`issue fields unavailable (${e.message}): using labels only`);
    return {};
  }
}

function fieldValues(t, sprint, ids) {
  const v = [];
  if (ids.Priority) v.push({ field_id: ids.Priority, value: PRIORITY_FIELD[t.priority] });
  if (ids.Effort) v.push({ field_id: ids.Effort, value: effortOf(t.sp) });
  if (ids['Start date'] && sprint?.start) v.push({ field_id: ids['Start date'], value: sprint.start });
  if (ids['Target date'] && sprint?.end) v.push({ field_id: ids['Target date'], value: sprint.end });
  return v;
}

export async function seed(api, backlog) {
  const { meta, tasks } = backlog;
  const log = api.log;
  // labels
  const existingLabels = new Set((await api.all(`/repos/${api.repo}/labels`)).map((l) => l.name));
  const wanted = [
    [TASK_LABEL, '0e8a16', 'Tarea del backlog (fuente de docs/backlog)'],
    [EPIC_LABEL, '5319e7', 'Epic del backlog: agrupa tareas como sub-issues'],
    [PARTIAL_LABEL, 'fbca04', 'Existe base, falta completar'],
    ['P0', 'b60205', meta.priorities.P0],
    ['P1', 'd93f0b', meta.priorities.P1],
    ['P2', 'fbca04', meta.priorities.P2],
    ['P3', 'c5def5', meta.priorities.P3],
    ...[...new Set(tasks.map((t) => t.type))].map((ty) => [`tipo:${ty}`, 'bfdadc', `Tipo de tarea: ${ty}`]),
    ...[...new Set(tasks.map((t) => t.epic))].map((e) => [epicLabel(e), 'd4c5f9', e.slice(0, 100)]),
  ];
  for (const [name, color, description] of wanted) if (!existingLabels.has(name)) await api.request('POST', `/repos/${api.repo}/labels`, { name, color, description });
  // milestones = sprints. meta.sprints is not rebuilt from GitHub, so it owns the sprint names: a renamed sprint
  // renames its milestone. Due dates are only set on creation (GitHub normalises them).
  const milestones = new Map((await api.all(`/repos/${api.repo}/milestones?state=all`)).map((m) => [sprintOfMilestone(m.title), m]));
  let renamed = 0;
  for (const s of meta.sprints) {
    const want = { title: milestoneTitle(s), description: milestoneDescription(s) };
    const m = milestones.get(s.id);
    if (!m) {
      milestones.set(s.id, await api.request('POST', `/repos/${api.repo}/milestones`, { ...want, ...(s.end ? { due_on: `${s.end}T23:59:59Z` } : {}), ...(s.id === 'v0.1' ? { state: 'closed' } : {}) }));
    } else if (m.title !== want.title || (m.description ?? '') !== want.description) {
      log(`milestone "${m.title}" → "${want.title}"`);
      milestones.set(s.id, await api.request('PATCH', `/repos/${api.repo}/milestones/${m.number}`, want));
      renamed++;
    }
  }
  // issues
  const issues = await api.all(`/repos/${api.repo}/issues?state=all`);
  const byId = new Map();
  const epics = new Map();
  for (const i of issues) {
    if (i.pull_request) continue;
    const p = parseTitle(i.title);
    if (p && i.labels.some((l) => l.name === TASK_LABEL)) byId.set(p.id, i);
    if (i.labels.some((l) => l.name === EPIC_LABEL)) epics.set(i.title.replace(/^\[Epic\]\s*/, ''), i);
  }
  const ids = await fieldIds(api);
  for (const epic of new Set(tasks.map((t) => t.epic))) {
    if (epics.has(epic)) continue;
    log(`epic ${epic}`);
    epics.set(epic, await api.request('POST', `/repos/${api.repo}/issues`, { title: `[Epic] ${epic}`, labels: [EPIC_LABEL, epicLabel(epic)], body: `Epic del backlog. Sus tareas son los sub-issues de este issue.\n\nGenerado desde \`docs/backlog/backlog.json\`; a partir de ahora GitHub es la fuente (ver \`docs/backlog/GITHUB.md\`).\n` }));
  }
  const created = [];
  for (const t of tasks) {
    if (byId.has(t.id)) continue;
    const sprint = meta.sprints.find((s) => s.id === t.sprint);
    const labels = [TASK_LABEL, t.priority, `tipo:${t.type}`, epicLabel(t.epic), ...(t.status === 'Parcial' ? [PARTIAL_LABEL] : [])];
    const payload = { title: taskTitle(t), body: taskBody(t), labels, milestone: milestones.get(t.sprint).number };
    const fv = fieldValues(t, sprint, ids);
    let issue;
    try {
      issue = await api.request('POST', `/repos/${api.repo}/issues`, fv.length ? { ...payload, issue_field_values: fv } : payload);
    } catch (e) {
      if (!fv.length || e.status !== 422) throw e;
      log(`fields rejected for ${t.id} (${e.message}): creating without them`);
      issue = await api.request('POST', `/repos/${api.repo}/issues`, payload);
    }
    log(`#${issue.number} ${t.id}`);
    if (t.status === 'Hecho' || t.status === 'Descartado') issue = await api.request('PATCH', `/repos/${api.repo}/issues/${issue.number}`, { state: 'closed', state_reason: t.status === 'Hecho' ? 'completed' : 'not_planned' });
    byId.set(t.id, issue);
    created.push(t.id);
  }
  // relations: epic → sub-issues and native "blocked by" for dependencies. Existing links are read first,
  // so a run that was interrupted (rate limits, timeout) completes them on the next one.
  let linked = 0;
  for (const [epic, e] of epics) {
    const have = new Set((await api.all(`/repos/${api.repo}/issues/${e.number}/sub_issues`)).map((i) => i.id));
    for (const t of tasks.filter((x) => x.epic === epic)) {
      const issue = byId.get(t.id);
      if (!issue || have.has(issue.id)) continue;
      try {
        await api.request('POST', `/repos/${api.repo}/issues/${e.number}/sub_issues`, { sub_issue_id: issue.id });
        linked++;
      } catch (err) {
        log(`sub-issue ${t.id}: ${err.message}`);
      }
    }
  }
  // "blocked by" follows the "Depende de" section of each issue, which is what pull reads: missing links are
  // added and, on open issues, links to backlog tasks that the section no longer lists are removed. Links to
  // other issues, closed issues and bodies without the section are left alone.
  let unlinked = 0;
  const taskIssueIds = new Set([...byId.values()].map((i) => i.id));
  for (const [id, issue] of byId) {
    const sections = parseBody(issue.body ?? '');
    if (!('Depende de' in sections)) continue;
    const want = new Map([...new Set(sections['Depende de'].match(ID_RE) ?? [])].filter((d) => byId.has(d)).map((d) => [byId.get(d).id, d]));
    const open = issue.state === 'open';
    if (!want.size && !open) continue;
    let have;
    try {
      have = new Set((await api.all(`/repos/${api.repo}/issues/${issue.number}/dependencies/blocked_by`)).map((i) => i.id));
    } catch (err) {
      log(`dependencies unavailable (${err.message}): skipping "blocked by" links`);
      break;
    }
    for (const [depId, d] of want) {
      if (have.has(depId)) continue;
      try {
        await api.request('POST', `/repos/${api.repo}/issues/${issue.number}/dependencies/blocked_by`, { issue_id: depId });
        linked++;
      } catch (err) {
        log(`blocked_by ${id} ← ${d}: ${err.message}`);
      }
    }
    if (!open) continue;
    for (const h of have) {
      if (want.has(h) || !taskIssueIds.has(h)) continue;
      try {
        await api.request('DELETE', `/repos/${api.repo}/issues/${issue.number}/dependencies/blocked_by/${h}`);
        unlinked++;
      } catch (err) {
        log(`blocked_by ${id} ✕ ${h}: ${err.message}`);
      }
    }
  }
  return { created, linked, unlinked, renamed, labels: wanted.length, milestones: milestones.size, epics: epics.size };
}

export async function pull(api, backlog) {
  const issues = (await api.all(`/repos/${api.repo}/issues?state=all&labels=${TASK_LABEL}`)).filter((i) => !i.pull_request);
  const order = new Map(backlog.tasks.map((t, i) => [t.id, i]));
  const warnings = [];
  const tasks = [];
  for (const i of issues) {
    const p = parseTitle(i.title);
    if (!p) {
      warnings.push(`#${i.number} "${i.title}" no tiene un ID "[XXX-00]" en el título: se ignora`);
      continue;
    }
    const b = parseBody(i.body ?? '');
    const labels = i.labels.map((l) => l.name);
    const priority = ['P0', 'P1', 'P2', 'P3'].find((x) => labels.includes(x));
    // Labels are capped at 50 chars: map a truncated epic label back to the full epic name.
    const epicLbl = labels.find((l) => l.startsWith('epic:'));
    const epic = epicLbl && (backlog.tasks.find((t) => epicLabel(t.epic) === epicLbl)?.epic ?? epicLbl.slice(5));
    const sprint = sprintOfMilestone(i.milestone?.title);
    const status = i.state === 'closed' ? (i.state_reason === 'not_planned' ? 'Descartado' : 'Hecho') : labels.includes(PARTIAL_LABEL) ? 'Parcial' : 'Pendiente';
    const problems = [!priority && 'sin label de prioridad (P0–P3)', !epic && 'sin label epic:…', !sprint && 'sin milestone (sprint)'].filter(Boolean);
    if (problems.length) {
      warnings.push(`#${i.number} ${p.id}: ${problems.join(', ')}`);
      continue;
    }
    tasks.push({
      id: p.id,
      epic,
      req: b.Requisito ?? '',
      title: p.title,
      done: b['Criterio de hecho'] ?? '',
      type: b.Tipo ?? '',
      priority,
      sp: Number(b['Story points']),
      deps: [...new Set((b['Depende de'] ?? '').match(ID_RE) ?? [])],
      sprint,
      status,
      evidence: b.Evidencia ?? '',
      issue: i.number,
    });
  }
  tasks.sort((a, b) => (order.get(a.id) ?? 1e9) - (order.get(b.id) ?? 1e9) || a.id.localeCompare(b.id));
  return { backlog: { meta: { ...backlog.meta, github: api.repo }, tasks }, warnings };
}

// ---- CLI
const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const [cmd] = process.argv.slice(2);
  const path = new URL('../docs/backlog/backlog.json', import.meta.url);
  const backlog = JSON.parse(readFileSync(path, 'utf8'));
  const { GITHUB_TOKEN: token, GITHUB_REPOSITORY: repo, GITHUB_API_URL: baseUrl } = process.env;
  if (!token || !repo) {
    console.error('GITHUB_TOKEN and GITHUB_REPOSITORY are required');
    process.exit(2);
  }
  const api = createClient({ token, repo, ...(baseUrl ? { baseUrl } : {}) });
  if (cmd === 'seed') {
    const r = await seed(api, backlog);
    console.log(`seed: ${r.created.length} tareas creadas, ${r.linked} relaciones nuevas y ${r.unlinked} retiradas; ${r.epics} epics, ${r.milestones} milestones (${r.renamed} renombrados)`);
  } else if (cmd === 'pull') {
    const { backlog: next, warnings } = await pull(api, backlog);
    for (const w of warnings) console.log(`::warning::${w}`);
    if (next.tasks.length === 0) {
      console.error('no backlog issues found on GitHub: run seed first');
      process.exit(1);
    }
    if (process.argv.includes('--write')) writeFileSync(path, JSON.stringify(next, null, 1));
    console.log(`pull: ${next.tasks.length} tareas desde GitHub Issues${warnings.length ? ` (${warnings.length} avisos)` : ''}`);
  } else {
    console.error('usage: backlog-github.mjs seed | pull [--write]');
    process.exit(2);
  }
}
