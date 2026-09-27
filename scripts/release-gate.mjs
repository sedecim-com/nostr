#!/usr/bin/env node
/**
 * REL-01 / REL-02 — Definition of Done of a release (docs/release-checklist.md). Run by release.yml before
 * anything is published; each check fails with a message saying what is missing and how to fix it.
 *
 *   node scripts/release-gate.mjs all --tag vX.Y.Z --sha <commit> --sbom release/sbom.cdx.json [--actor login]…
 *   node scripts/release-gate.mjs ci|restore --sha <commit>        (GitHub API via `gh api`, needs actions: read)
 *   node scripts/release-gate.mjs sbom <file>
 *   node scripts/release-gate.mjs audits --tag vX.Y.Z [--actor login]…
 *   node scripts/release-gate.mjs notes --tag vX.Y.Z
 *
 * Env: GH_REPO / GITHUB_REPOSITORY (owner/repo), RESTORE_MAX_AGE_HOURS (default 72).
 * Plain Node, no dependencies: the release job runs it without `npm ci`.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

/** ci.yml jobs that must have succeeded on the tagged commit (job id = check name, no `name:` override). */
export const REQUIRED_CI_JOBS = [
  'test', // typecheck, unit + E2E in process, lint:claims, browser E2E (Playwright), keygen HTML, SBOM
  'secrets', // gitleaks over the history
  'compose', // compose config of every profile, Caddyfile
  'deploy-config', // k8s, Terraform, SLO rules, shellcheck
  'marmot-mdk', // marmot-ts <-> MDK interop
  'leak-tests', // network capture: Tor / direct profiles (FR020-03, FR022-02)
  'tor-profile', // compose tor profile end to end (FR021-02)
  'stack', // every image + interop gate against Buzz, secure relay, mirror, blob store; log scan
];

/** External security work that has to be done (or explicitly waived) for every release. */
export const REQUIRED_AUDITS = ['SEC-01', 'SEC-02'];

/** Mandatory subsections of "Cambios en el modelo de confianza" in docs/releases/<tag>.md. */
export const TRUST_SECTION = 'Cambios en el modelo de confianza';
export const TRUST_SUBSECTIONS = [
  'Custodia de llaves',
  'Qué puede ver y hacer el operador',
  'Dependencias criptográficas y su estabilidad',
  'Datos nuevos que se recopilan',
  'Valores por defecto que cambian',
];

const TAG_RE = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

/** `gh api <path>` parsed as JSON (the job's GITHUB_TOKEN via GH_TOKEN). */
export function ghApi(path) {
  return JSON.parse(execFileSync('gh', ['api', '-H', 'Accept: application/vnd.github+json', path], { encoding: 'utf8' }));
}

/**
 * CI (ci.yml) succeeded on this exact commit: at least one completed run with head_sha = sha whose
 * conclusion is success and whose latest attempt has every required job with conclusion success
 * (a skipped job does not count).
 */
export function checkCi({ repo, sha, api = ghApi }) {
  const runs = api(`repos/${repo}/actions/workflows/ci.yml/runs?head_sha=${sha}&status=completed&per_page=100`).workflow_runs ?? [];
  if (!runs.length)
    return [`CI: no hay ninguna ejecución terminada de ci.yml para ${sha}. Lánzala sobre el tag (gh workflow run ci.yml --ref <tag>) y repite el release cuando termine.`];
  const seen = [];
  for (const run of runs) {
    if (run.conclusion !== 'success') {
      seen.push(`${run.html_url ?? run.id}: ${run.conclusion}`);
      continue;
    }
    const jobs = api(`repos/${repo}/actions/runs/${run.id}/jobs?filter=latest&per_page=100`).jobs ?? [];
    const bad = REQUIRED_CI_JOBS.filter((name) => jobs.find((j) => j.name === name)?.conclusion !== 'success');
    if (!bad.length) return [];
    seen.push(`${run.html_url ?? run.id}: sin éxito en ${bad.join(', ')}`);
  }
  return [`CI: ninguna ejecución de ci.yml para ${sha} tiene en verde los jobs ${REQUIRED_CI_JOBS.join(', ')} (${seen.join('; ')}).`];
}

/** The restore drill (restore-drill.yml) succeeded on this exact commit within the last maxAgeHours. */
export function checkRestore({ repo, sha, api = ghApi, now = Date.now(), maxAgeHours = 72 }) {
  const runs = api(`repos/${repo}/actions/workflows/restore-drill.yml/runs?head_sha=${sha}&status=completed&per_page=100`).workflow_runs ?? [];
  const since = now - maxAgeHours * 3600_000;
  const ok = runs.filter((r) => r.conclusion === 'success' && Date.parse(r.updated_at ?? r.created_at) >= since);
  if (ok.length) return [];
  const hint = `Lánzalo sobre el tag (gh workflow run restore-drill.yml --ref <tag>) y repite el release cuando termine.`;
  if (!runs.some((r) => r.conclusion === 'success'))
    return [`Restore drill: ninguna ejecución con éxito de restore-drill.yml para ${sha}. ${hint}`];
  return [`Restore drill: el último éxito de restore-drill.yml para ${sha} tiene más de ${maxAgeHours} h. ${hint}`];
}

/** The SBOM produced by the build job is a CycloneDX document that lists components. */
export function checkSbom(text) {
  let bom;
  try {
    bom = JSON.parse(text);
  } catch {
    return ['SBOM: sbom.cdx.json no es JSON válido.'];
  }
  const out = [];
  if (bom.bomFormat !== 'CycloneDX') out.push('SBOM: bomFormat no es CycloneDX.');
  if (typeof bom.specVersion !== 'string') out.push('SBOM: falta specVersion.');
  if (!Array.isArray(bom.components) || bom.components.length === 0) out.push('SBOM: no lista ningún componente.');
  return out;
}

/** `- Campo: valor` lines of a Markdown record (bold field names allowed), keyed by lower-case field. */
export function parseFields(md) {
  const fields = {};
  for (const line of md.split('\n')) {
    const m = /^\s*[-*]\s+(?:\*\*)?([^:*]+?)(?:\*\*)?\s*:\s*(?:\*\*)?\s*(.*)$/.exec(line);
    if (m && !(m[1].toLowerCase() in fields)) fields[m[1].trim().toLowerCase()] = m[2].trim();
  }
  return fields;
}

const listAudits = (value = '') => value.split(/[,\s]+/).map((s) => s.trim().toUpperCase()).filter(Boolean);
const PLACEHOLDER = /^(|pendiente|todo|tbd|-|n\/a)$/i;

/**
 * Every REQUIRED_AUDITS item is covered for this tag by an audit record (docs/security/audits/<tag>.md:
 * Tag, Auditorías, Informe) or by a waiver (docs/security/audits/waivers/<tag>.md: Tag, Auditorías, Motivo,
 * Aprobado por, Fecha). The approver must be a GitHub @login different from whoever triggered the release.
 */
export function checkAudits({ tag, root = process.cwd(), actors = [] }) {
  const out = [];
  const covered = new Set();
  const record = join(root, 'docs/security/audits', `${tag}.md`);
  const waiver = join(root, 'docs/security/audits/waivers', `${tag}.md`);
  if (existsSync(record)) {
    const f = parseFields(readFileSync(record, 'utf8'));
    const where = `docs/security/audits/${tag}.md`;
    if (f.tag !== tag) out.push(`Auditorías: ${where} debe tener "- Tag: ${tag}".`);
    else if (PLACEHOLDER.test(f.informe ?? '')) out.push(`Auditorías: ${where} debe enlazar el informe ("- Informe: …").`);
    else listAudits(f['auditorías']).forEach((a) => covered.add(a));
  }
  if (existsSync(waiver)) {
    const f = parseFields(readFileSync(waiver, 'utf8'));
    const where = `docs/security/audits/waivers/${tag}.md`;
    const approver = f['aprobado por'] ?? '';
    const problems = [];
    if (f.tag !== tag) problems.push(`"- Tag: ${tag}"`);
    if ((f.motivo ?? '').length < 30 || PLACEHOLDER.test(f.motivo ?? '')) problems.push('un motivo concreto ("- Motivo: …", 30 caracteres o más)');
    if (!/^@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(approver)) problems.push('quién lo aprueba como @usuario de GitHub ("- Aprobado por: @usuario")');
    else if (actors.filter(Boolean).some((a) => a.toLowerCase() === approver.slice(1).toLowerCase()))
      problems.push(`un aprobador distinto de quien lanza el release (${approver})`);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(f.fecha ?? '')) problems.push('la fecha de aprobación ("- Fecha: AAAA-MM-DD")');
    if (problems.length) out.push(`Auditorías: el waiver ${where} no es válido: le falta ${problems.join(', ')}.`);
    else listAudits(f['auditorías']).forEach((a) => covered.add(a));
  }
  const missing = REQUIRED_AUDITS.filter((a) => !covered.has(a));
  if (missing.length && !out.length)
    out.push(
      `Auditorías: ${missing.join(', ')} sin informe ni waiver para ${tag}. Añade docs/security/audits/${tag}.md o un waiver revisado en docs/security/audits/waivers/${tag}.md (docs/security/audits/README.md).`,
    );
  else if (missing.length) out.push(`Auditorías: ${missing.join(', ')} quedan sin cubrir para ${tag}.`);
  return out;
}

/** Text of a Markdown section without HTML comments and blank lines. */
const content = (text) => text.replace(/<!--[\s\S]*?-->/g, '').split('\n').filter((l) => l.trim()).join('\n');

/**
 * docs/releases/<tag>.md is the GitHub Release body: title with the tag, the trust-model section with
 * every mandatory subsection filled (an explicit "Sin cambios." is fine) and no template placeholders.
 */
export function checkNotes(md, tag) {
  const where = `docs/releases/${tag}.md`;
  const out = [];
  const title = /^# (.+)$/m.exec(md)?.[1] ?? '';
  if (!title.includes(tag)) out.push(`Notas: el título (# …) de ${where} debe incluir ${tag}.`);
  if (/\{\{|\}\}|\bTODO\b/.test(content(md))) out.push(`Notas: ${where} conserva marcadores de la plantilla ({{…}} o TODO).`);
  const sections = md.split(/^## /m).slice(1);
  const trust = sections.find((s) => s.split('\n')[0].trim() === TRUST_SECTION);
  if (!trust) return [...out, `Notas: ${where} no tiene la sección obligatoria "## ${TRUST_SECTION}".`];
  const subs = new Map(trust.split(/^### /m).slice(1).map((s) => [s.split('\n')[0].trim(), content(s.split('\n').slice(1).join('\n'))]));
  for (const name of TRUST_SUBSECTIONS) {
    if (!subs.has(name)) out.push(`Notas: falta "### ${name}" en "${TRUST_SECTION}".`);
    else if (!subs.get(name)) out.push(`Notas: "### ${name}" está vacía (escribe "Sin cambios." si no hay cambios).`);
  }
  return out;
}

export function checkNotesFile({ tag, root = process.cwd() }) {
  const file = join(root, 'docs/releases', `${tag}.md`);
  if (!existsSync(file)) return [`Notas: falta docs/releases/${tag}.md (plantilla: docs/releases/TEMPLATE.md).`];
  return checkNotes(readFileSync(file, 'utf8'), tag);
}

function parseArgs(argv) {
  const opts = { actors: [], positional: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--tag') opts.tag = argv[++i];
    else if (a === '--sha') opts.sha = argv[++i];
    else if (a === '--sbom') opts.sbom = argv[++i];
    else if (a === '--actor') opts.actors.push(argv[++i]);
    else opts.positional.push(a);
  }
  return opts;
}

export function main(argv = process.argv.slice(2), env = process.env) {
  const [cmd, ...rest] = argv;
  const opts = parseArgs(rest);
  const repo = env.GH_REPO || env.GITHUB_REPOSITORY;
  const need = (name, value) => {
    if (!value) throw new Error(`falta ${name}`);
    return value;
  };
  if (opts.tag && !TAG_RE.test(opts.tag)) throw new Error(`tag inválido: ${opts.tag}`);
  const checks = {
    ci: () => checkCi({ repo: need('GH_REPO', repo), sha: need('--sha', opts.sha) }),
    restore: () => checkRestore({ repo: need('GH_REPO', repo), sha: need('--sha', opts.sha), maxAgeHours: Number(env.RESTORE_MAX_AGE_HOURS || 72) }),
    sbom: () => checkSbom(readFileSync(resolve(need('--sbom o <archivo>', opts.sbom ?? opts.positional[0])), 'utf8')),
    audits: () => checkAudits({ tag: need('--tag', opts.tag), actors: opts.actors }),
    notes: () => checkNotesFile({ tag: need('--tag', opts.tag) }),
  };
  const selected = cmd === 'all' ? Object.keys(checks) : cmd in checks ? [cmd] : null;
  if (!selected) throw new Error(`comando desconocido: ${cmd ?? ''} (all | ${Object.keys(checks).join(' | ')})`);
  const problems = [];
  for (const name of selected) {
    const found = checks[name]();
    console.log(`${found.length ? 'FALLO' : 'OK   '} ${name}`);
    problems.push(...found);
  }
  for (const p of problems) console.error(`  - ${p}`);
  return problems.length ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    process.exitCode = main();
  } catch (e) {
    console.error(`release-gate: ${e.message}`);
    process.exitCode = 2;
  }
}
