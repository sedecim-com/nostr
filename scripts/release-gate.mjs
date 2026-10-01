#!/usr/bin/env node
/**
 * REL-01 / REL-02 — Definition of Done of a release (docs/release-checklist.md). Run by release.yml before
 * anything is published; each check fails with a message saying what is missing and how to fix it.
 *
 *   node scripts/release-gate.mjs all --tag vX.Y.Z --sha <commit> --sbom release/sbom.cdx.json [--actor login]…
 *   node scripts/release-gate.mjs ci|restore --sha <commit>        (GitHub API via `gh api`, needs actions: read)
 *   node scripts/release-gate.mjs codeql --sha <commit>            (security-events: read)
 *   node scripts/release-gate.mjs dependabot                      (vulnerability-alerts: read)
 *   node scripts/release-gate.mjs environment                     (OPS-08, actions: read)
 *   node scripts/release-gate.mjs sbom <file>
 *   node scripts/release-gate.mjs audits|threat-models --tag vX.Y.Z [--actor login]…
 *   node scripts/release-gate.mjs notes --tag vX.Y.Z
 *   node scripts/release-gate.mjs config                          (OPS-20, deploy/production-gates.json)
 *
 * Env: GH_REPO / GITHUB_REPOSITORY (owner/repo), RESTORE_MAX_AGE_HOURS (default 72).
 * Plain Node, no dependencies: the release job runs it without `npm ci`.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { extname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

/** ci.yml jobs that must have succeeded on the tagged commit (job id = check name, no `name:` override). */
export const REQUIRED_CI_JOBS = [
  'test', // typecheck, unit + E2E in process, lint:claims, browser E2E (Playwright), keygen HTML, SBOM
  'secrets', // gitleaks over the history
  'traceability', // traceability and status board generated from the backlog, every cited reference exists (OPS-18)
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

/**
 * OPS-13: CodeQL gates the release. Its analysis (codeql.yml) succeeded on this exact commit, and the default
 * branch has no open code scanning alert of high or critical security severity (the job's token needs
 * `security-events: read`). A pull request already fails the CodeQL check when it adds one.
 */
export function checkCodeql({ repo, sha, api = ghApi }) {
  const out = [];
  const runs = api(`repos/${repo}/actions/workflows/codeql.yml/runs?head_sha=${sha}&status=completed&per_page=100`).workflow_runs ?? [];
  if (!runs.some((r) => r.conclusion === 'success'))
    out.push(`CodeQL: ninguna ejecución con éxito de codeql.yml para ${sha}. Lánzala sobre el tag (gh workflow run codeql.yml --ref <tag>) y repite el release cuando termine.`);
  const alerts = api(`repos/${repo}/code-scanning/alerts?state=open&tool_name=CodeQL&per_page=100`) ?? [];
  const serious = alerts.filter((a) => ['high', 'critical'].includes(a.rule?.security_severity_level));
  if (serious.length)
    out.push(`CodeQL: ${serious.length} alertas abiertas de severidad alta o crítica en la rama principal: ${serious.map((a) => `#${a.number} ${a.rule.id} (${a.most_recent_instance?.location?.path ?? '?'})`).join(', ')}. Corrígelas o descártalas con motivo antes del release.`);
  return out;
}

/** What `gh api` said about a failed call: the line with the HTTP status ("Not Found (HTTP 404)"), else the last one. */
function apiError(e) {
  const lines = `${e?.stderr ?? ''}\n${e?.message ?? e}`.split('\n').map((l) => l.trim()).filter(Boolean);
  return lines.find((l) => /HTTP \d{3}/.test(l)) ?? lines.at(-1) ?? 'error desconocido';
}

/**
 * REL-01: the default branch has no open Dependabot alert of high or critical severity (the job's token needs
 * `vulnerability-alerts: read`, and Dependabot alerts must be on in Settings → Advanced Security). A pull
 * request that adds a vulnerable dependency already fails dependency-review.
 */
export function checkDependabot({ repo, api = ghApi }) {
  let alerts;
  try {
    alerts = api(`repos/${repo}/dependabot/alerts?state=open&severity=high,critical&per_page=100`) ?? [];
  } catch (e) {
    return [`Dependabot: no se pudieron leer las alertas (${apiError(e)}). Actívalas en Settings → Advanced Security → Dependabot alerts; el job necesita vulnerability-alerts: read.`];
  }
  const severity = (a) => a.security_advisory?.severity ?? a.security_vulnerability?.severity;
  const serious = alerts.filter((a) => ['high', 'critical'].includes(severity(a)));
  if (!serious.length) return [];
  const list = serious.map((a) => `#${a.number} ${a.dependency?.package?.name ?? '?'} (${severity(a)})`).join(', ');
  return [`Dependabot: ${serious.length} alertas abiertas de severidad alta o crítica en la rama principal: ${list}. Actualiza la dependencia o descarta la alerta con motivo antes del release.`];
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
/** A GitHub @login, as approval records name their approver. */
const LOGIN_RE = /^@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
/** Whether the approver is one of whoever triggered the release (they may not approve their own release). */
const isActor = (approver, actors) => actors.filter(Boolean).some((a) => a.toLowerCase() === approver.slice(1).toLowerCase());

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
    if (!LOGIN_RE.test(approver)) problems.push('quién lo aprueba como @usuario de GitHub ("- Aprobado por: @usuario")');
    else if (isActor(approver, actors)) problems.push(`un aprobador distinto de quien lanza el release (${approver})`);
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

/** DEC-10: one document per profile, the general index and the vault's; approved per release (REL-01). */
export const THREAT_MODELS = 'docs/threat-models';

/** SHA-256 of each threat model (the .md files of docs/threat-models, approvals/ excluded), by file name. */
export function threatModelHashes(root = process.cwd()) {
  const dir = join(root, THREAT_MODELS);
  const files = readdirSync(dir, { withFileTypes: true }).filter((d) => d.isFile() && d.name.endsWith('.md')).map((d) => d.name).sort();
  return Object.fromEntries(files.map((f) => [f, createHash('sha256').update(readFileSync(join(dir, f))).digest('hex')]));
}

/**
 * DEC-10 / REL-01: the threat models are approved for this tag by someone other than whoever triggers the
 * release, in docs/threat-models/approvals/<tag>.md (Tag, Aprobado por, Fecha and one "- <documento>: <SHA-256>"
 * line per threat model). The SHA-256 is the one of the document as it is in this commit, so an edit after the
 * approval needs a new approval, and no document may still say it is «Propuesto».
 */
export function checkThreatModels({ tag, root = process.cwd(), actors = [] }) {
  const hashes = threatModelHashes(root);
  const files = Object.keys(hashes);
  const record = `${THREAT_MODELS}/approvals/${tag}.md`;
  // One "- <documento>: <SHA-256>" line per document, ready to paste into the record.
  const lines = (names) => names.map((f) => `\n- ${f}: ${hashes[f]}`).join('');
  const out = [];
  const md = readIfExists(join(root, record), 'utf8');
  const f = md === undefined ? undefined : parseFields(md);
  if (!f)
    out.push(`Threat models: falta la aprobación ${record} (DEC-10), con "- Tag: ${tag}", "- Aprobado por: @usuario", "- Fecha: AAAA-MM-DD" y la huella de cada documento:${lines(files)}`);
  else if (PLACEHOLDER.test(f['aprobado por'] ?? ''))
    out.push(`Threat models: la aprobación ${record} está pendiente: falta quién los aprueba, la fecha y la huella de cada documento tal como se aprueba (hoy):${lines(files)}`);
  else {
    const approver = f['aprobado por'];
    const problems = [];
    if (f.tag !== tag) problems.push(`"- Tag: ${tag}"`);
    if (!LOGIN_RE.test(approver)) problems.push('quién los aprueba como @usuario de GitHub ("- Aprobado por: @usuario")');
    else if (isActor(approver, actors)) problems.push(`un aprobador distinto de quien lanza el release (${approver})`);
    if (!DATE_RE.test(f.fecha ?? '')) problems.push('la fecha de aprobación ("- Fecha: AAAA-MM-DD")');
    const gone = Object.keys(f).filter((k) => k.endsWith('.md') && !files.some((file) => file.toLowerCase() === k));
    if (gone.length) problems.push(`quitar ${gone.join(', ')}, que ya no está en ${THREAT_MODELS}`);
    const changed = files.filter((file) => (f[file.toLowerCase()] ?? '').toLowerCase() !== hashes[file]);
    if (changed.length)
      problems.push(`una huella que coincida con ${changed.join(', ')}. Si ese es el texto aprobado, son estas; si cambió después, hace falta aprobarlo de nuevo:${lines(changed)}`);
    if (problems.length) out.push(`Threat models: la aprobación ${record} no es válida: le falta ${problems.join(', ')}`);
  }
  const proposed = files.filter((file) => /Estado:?\**:?\s*Propuesto/i.test(readFileSync(join(root, THREAT_MODELS, file), 'utf8').split('\n').slice(0, 12).join('\n')));
  if (proposed.length) out.push(`Threat models: ${proposed.join(', ')} siguen en «Propuesto»: al aprobarlos cambia su estado y su huella en ${record}.`);
  return out;
}

/** Text of a Markdown section without HTML comments and blank lines. */
const content = (text) => stripComments(text).split('\n').filter((l) => l.trim()).join('\n');

/** Removes every <!-- … --> (an unterminated one runs to the end), scanning once so nothing can reassemble. */
function stripComments(text) {
  let out = '';
  let i = 0;
  for (;;) {
    const start = text.indexOf('<!--', i);
    if (start < 0) return out + text.slice(i);
    out += text.slice(i, start);
    const end = text.indexOf('-->', start + 4);
    if (end < 0) return out;
    i = end + 3;
  }
}

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

/** PANEL-07: the maturity table that scripts/maturity.ts writes between these markers (undefined without it). */
export function maturityBlock(md) {
  const i = md.indexOf('<!-- maturity:start');
  const j = md.indexOf('<!-- maturity:end -->', i);
  return i < 0 || j < 0 ? undefined : md.slice(i, j + '<!-- maturity:end -->'.length);
}

export function checkNotesFile({ tag, root = process.cwd() }) {
  const file = join(root, 'docs/releases', `${tag}.md`);
  if (!existsSync(file)) return [`Notas: falta docs/releases/${tag}.md (plantilla: docs/releases/TEMPLATE.md).`];
  const md = readFileSync(file, 'utf8');
  const out = checkNotes(md, tag);
  // PANEL-07: the notes carry the maturity of each profile and function, the same table as the README (which CI
  // keeps equal to the catalog the web and the CLI show).
  const notes = maturityBlock(md);
  const readme = maturityBlock(readIfExists(join(root, 'README.md'), 'utf8') ?? '');
  const fix = `npx tsx scripts/maturity.ts docs/releases/${tag}.md`;
  if (!notes) out.push(`Notas: docs/releases/${tag}.md no tiene la tabla de madurez (PANEL-07): ${fix}.`);
  else if (notes !== readme) out.push(`Notas: la tabla de madurez de docs/releases/${tag}.md no es la del README: ${fix}.`);
  return out;
}

/** OPS-20: features the production configuration may only turn on with their evidence. */
export const PRODUCTION_GATES = 'deploy/production-gates.json';
export const MATURITY = ['GA', 'Beta', 'Preview', 'Experimental'];
const FEATURE_FIELDS = ['title', 'maturity', 'webKeys', 'termsKey', 'components', 'settings', 'terraform', 'legalApproval', 'auditReports', 'safeTrigger', 'evidence', 'testOnly'];
/** How a feature is found in the configuration; a feature without any would never be seen. */
const DETECTORS = ['webKeys', 'components', 'settings', 'terraform'];
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** A file's contents, or undefined when it does not exist (read once: no separate existence check). */
function readIfExists(path, encoding) {
  try {
    return readFileSync(path, encoding);
  } catch (e) {
    if (e.code === 'ENOENT') return undefined;
    throw e;
  }
}

/** Shape of deploy/production-gates.json. An unknown field is an error: a typo must not hide a feature. */
export function registryProblems(reg) {
  const out = [];
  const paths = (v) => Array.isArray(v) && v.every((s) => typeof s === 'string' && s.length > 0);
  for (const k of ['webConfigs', 'kubernetes', 'terraform', 'notProduction'])
    if (!paths(reg?.production?.[k])) out.push(`production.${k} debe ser una lista de rutas`);
  const features = reg?.features;
  if (!features || typeof features !== 'object' || !Object.keys(features).length) return [...out, 'features debe definir las funciones con gate'];
  for (const [name, f] of Object.entries(features)) {
    const at = `features.${name}`;
    if (!f || typeof f !== 'object') {
      out.push(`${at} debe ser un objeto`);
      continue;
    }
    for (const k of Object.keys(f)) if (!FEATURE_FIELDS.includes(k)) out.push(`${at}.${k} no es un campo conocido (${FEATURE_FIELDS.join(', ')})`);
    if (typeof f.title !== 'string' || !f.title) out.push(`${at}.title es obligatorio`);
    if (f.maturity !== undefined && !MATURITY.includes(f.maturity)) out.push(`${at}.maturity debe ser ${MATURITY.join(', ')}`);
    for (const k of ['webKeys', 'components', 'terraform', 'auditReports']) if (f[k] !== undefined && !paths(f[k])) out.push(`${at}.${k} debe ser una lista`);
    if (f.settings !== undefined && !(f.settings && typeof f.settings === 'object' && !Array.isArray(f.settings) && Object.values(f.settings).every((v) => typeof v === 'string' && v)))
      out.push(`${at}.settings debe ser un objeto { VARIABLE: "valor" }`);
    if (!DETECTORS.some((k) => f[k] && Object.keys(f[k]).length)) out.push(`${at} no dice cómo se detecta (${DETECTORS.join(', ')})`);
    if (f.legalApproval !== undefined && (typeof f.legalApproval !== 'string' || !f.legalApproval)) out.push(`${at}.legalApproval debe ser la ruta de la aprobación`);
    if (f.termsKey !== undefined && !(f.legalApproval && f.webKeys?.includes(f.termsKey))) out.push(`${at}.termsKey debe ser una de sus webKeys y necesita legalApproval`);
    if (f.safeTrigger !== undefined && typeof f.safeTrigger !== 'boolean') out.push(`${at}.safeTrigger debe ser true o false`);
    if (f.safeTrigger === true && !(typeof f.evidence === 'string' && f.evidence.length >= 30)) out.push(`${at}.safeTrigger = true necesita la evidencia ("evidence")`);
    if (f.testOnly !== undefined && !(typeof f.testOnly === 'string' && f.testOnly.length >= 30)) out.push(`${at}.testOnly debe decir por qué es solo para pruebas (30 caracteres o más)`);
  }
  return out;
}

/**
 * DEC-12: a legal approval record (Documento, Versión, SHA-256, Dictamen, Aprobado por, Fecha). The SHA-256
 * is the one of the document as it is in this commit, so an edit after the approval needs a new approval.
 */
export function checkLegalApproval({ root = process.cwd(), record }) {
  const md = readIfExists(join(root, record), 'utf8');
  if (md === undefined) return { problems: [`falta la aprobación legal (${record})`] };
  const f = parseFields(md);
  const version = f['versión'] ?? '';
  const pending = [version, f.dictamen, f['aprobado por']].every((v) => PLACEHOLDER.test(v ?? ''));
  const doc = f.documento ?? '';
  if (pending) return { problems: [`la aprobación legal de ${doc || 'su texto'} está pendiente (${record})`] };
  const missing = [];
  if (PLACEHOLDER.test(version)) missing.push('la versión aprobada ("- Versión: …")');
  if (PLACEHOLDER.test(f.dictamen ?? '')) missing.push('el dictamen ("- Dictamen: enlace o ruta")');
  if (PLACEHOLDER.test(f['aprobado por'] ?? '')) missing.push('quién lo aprueba ("- Aprobado por: …")');
  if (!DATE_RE.test(f.fecha ?? '')) missing.push('la fecha ("- Fecha: AAAA-MM-DD")');
  const text = doc ? readIfExists(join(root, doc)) : undefined;
  if (text === undefined) missing.push('el documento aprobado ("- Documento: <ruta en el repositorio>")');
  else {
    const sha = createHash('sha256').update(text).digest('hex');
    if ((f['sha-256'] ?? '').toLowerCase() !== sha)
      missing.push(`una huella que coincida con ${doc} ("- SHA-256: ${sha}" si ese es el texto aprobado; si cambió después, hace falta aprobarlo de nuevo)`);
    if (/borrador/i.test(text.toString('utf8').split('\n').slice(0, 5).join('\n'))) missing.push(`que ${doc} deje de marcarse como borrador`);
  }
  return { problems: missing.length ? [`la aprobación legal ${record} no es válida: le falta ${missing.join(', ')}`] : [], version };
}

/** Audits covered by the report of some release (docs/security/audits/<tag>.md with its report linked). */
export function auditReportsOnFile(root = process.cwd()) {
  const dir = join(root, 'docs/security/audits');
  const done = new Set();
  let names;
  try {
    names = readdirSync(dir);
  } catch (e) {
    if (e.code === 'ENOENT') return done;
    throw e;
  }
  for (const name of names) {
    const tag = name.replace(/\.md$/, '');
    if (tag === name || !TAG_RE.test(tag)) continue;
    const f = parseFields(readFileSync(join(dir, name), 'utf8'));
    if (f.tag === tag && !PLACEHOLDER.test(f.informe ?? '')) listAudits(f['auditorías']).forEach((a) => done.add(a));
  }
  return done;
}

/** Why a feature cannot be on in production yet (empty: it can). */
function blockers(f, root) {
  const out = [];
  if (f.maturity === 'Preview') out.push('es Preview, y lo Preview va apagado en producción');
  if (f.legalApproval) out.push(...checkLegalApproval({ root, record: f.legalApproval }).problems);
  if (f.auditReports) {
    const done = auditReportsOnFile(root);
    const missing = f.auditReports.filter((a) => !done.has(a));
    if (missing.length) out.push(`${missing.join(', ')} sin informe en docs/security/audits/<tag>.md (un waiver no basta)`);
  }
  if (f.safeTrigger === false) out.push(`no hay un disparador seguro${f.evidence ? ` (${f.evidence})` : ''}`);
  // OPS-16: a setting for tests and development never reaches production, whatever the evidence.
  if (f.testOnly) out.push(`es solo para pruebas y desarrollo: ${f.testOnly}`);
  return out;
}

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
/** Drops `#` comments (YAML, env, HCL); for HCL also `//` and block comments. */
const dropConfigComments = (text, hcl) => {
  const t = hcl ? text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1') : text;
  return t.replace(/(^|\s)#.*$/gm, '$1');
};
const isSet = (v) => v !== undefined && v !== null && v !== '';
/** `KEY=value`, `KEY: value`, `KEY = "value"` or `- name: KEY` + `value: value`, quoted or not. */
const setsValue = (text, key, value) => {
  const k = esc(key);
  const v = `["']?${esc(value)}["']?`;
  return new RegExp(`(^|[^\\w])${k}["']?\\s*[:=]\\s*${v}(?=[\\s,}]|$)`, 'm').test(text) || new RegExp(`name:\\s*["']?${k}["']?\\s*\\n\\s*value:\\s*${v}(?=\\s|$)`).test(text);
};
const usesComponent = (text, name) => new RegExp(`(^|[^\\w-])components/${esc(name)}(?![\\w-])`, 'm').test(text);
/** `name = true` (module argument, tfvars; Terraform also takes "true") or `variable "name" { … default = true … }`. */
const enablesVariable = (text, name) => {
  if (new RegExp(`(^|[^\\w.])${esc(name)}\\s*=\\s*"?true\\b`, 'm').test(text)) return true;
  const m = new RegExp(`variable\\s+"${esc(name)}"\\s*\\{`).exec(text);
  if (!m) return false;
  let i = m.index + m[0].length;
  for (let depth = 1; i < text.length && depth; i++) depth += text[i] === '{' ? 1 : text[i] === '}' ? -1 : 0;
  return /(^|\s)default\s*=\s*"?true\b/.test(text.slice(m.index, i));
};

/** Every file under a path of the repository, skipping hidden entries and the excluded paths. */
function filesUnder(root, rel, exclude) {
  if (exclude.some((x) => rel === x || rel.startsWith(`${x}/`))) return [];
  let names;
  try {
    names = readdirSync(join(root, rel));
  } catch (e) {
    if (e.code === 'ENOTDIR') return [rel];
    throw e;
  }
  return names
    .filter((name) => !name.startsWith('.'))
    .sort()
    .flatMap((name) => filesUnder(root, `${rel}/${name}`, exclude));
}

/**
 * Where the production configuration turns each feature on: the web configs, and every file of the
 * Kubernetes and Terraform paths except those listed in notProduction (a new overlay counts as production).
 */
export function productionSites({ root = process.cwd(), registry }) {
  const { production, features } = registry;
  const sites = Object.fromEntries(Object.keys(features).map((name) => [name, new Set()]));
  const webConfigs = [];
  const problems = [];
  const scanJson = (file, text) => {
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      problems.push(`${file} no es JSON válido`);
      return;
    }
    if (!json || typeof json !== 'object' || Array.isArray(json)) return;
    webConfigs.push({ file, json });
    for (const [name, f] of Object.entries(features)) for (const k of f.webKeys ?? []) if (isSet(json[k])) sites[name].add(`${file} ("${k}")`);
  };
  const scanText = (file, raw, hcl) => {
    const text = dropConfigComments(raw, hcl);
    for (const [name, f] of Object.entries(features)) {
      for (const k of f.webKeys ?? []) if (new RegExp(`"${esc(k)}"\\s*:\\s*(?!null\\b)`).test(text)) sites[name].add(`${file} ("${k}")`);
      for (const c of f.components ?? []) if (usesComponent(text, c)) sites[name].add(`${file} (components/${c})`);
      for (const [k, v] of Object.entries(f.settings ?? {})) if (setsValue(text, k, v)) sites[name].add(`${file} (${k}=${v})`);
      if (hcl) for (const v of f.terraform ?? []) if (enablesVariable(text, v)) sites[name].add(`${file} (${v} = true)`);
    }
  };
  for (const file of production.webConfigs) {
    const text = readIfExists(join(root, file), 'utf8');
    if (text === undefined) problems.push(`${file} no existe (production.webConfigs de ${PRODUCTION_GATES})`);
    else scanJson(file, text);
  }
  for (const dir of [...production.kubernetes, ...production.terraform]) {
    let files;
    try {
      files = filesUnder(root, dir, production.notProduction);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
      problems.push(`${dir} no existe (${PRODUCTION_GATES})`);
      continue;
    }
    for (const file of files) {
      const text = readFileSync(join(root, file), 'utf8');
      const ext = extname(file);
      if (ext === '.json') scanJson(file, text);
      else scanText(file, text, ext === '.tf' || ext === '.tfvars');
    }
  }
  return { sites: Object.fromEntries(Object.entries(sites).map(([name, s]) => [name, [...s]])), webConfigs, problems };
}

/**
 * OPS-20: with legal approval or audits pending the managed onboarding is not in the production configuration;
 * whatever is Preview (the enclave and its export) stays off; push stays off without a safe trigger. OPS-16: a setting
 * only for tests (webhooks to private destinations) never is.
 */
export function checkConfig({ root = process.cwd() } = {}) {
  const text = readIfExists(join(root, PRODUCTION_GATES), 'utf8');
  if (text === undefined) return [`Configuración: falta ${PRODUCTION_GATES}.`];
  let registry;
  try {
    registry = JSON.parse(text);
  } catch (e) {
    return [`Configuración: ${PRODUCTION_GATES} no es JSON válido (${e.message}).`];
  }
  const bad = registryProblems(registry);
  if (bad.length) return bad.map((p) => `Configuración: ${PRODUCTION_GATES}: ${p}.`);
  const { sites, webConfigs, problems } = productionSites({ root, registry });
  const out = problems.map((p) => `Configuración: ${p}.`);
  for (const [name, f] of Object.entries(registry.features)) {
    if (!sites[name].length) continue;
    const reasons = blockers(f, root);
    if (reasons.length) {
      out.push(
        `Configuración: ${name} (${f.title}) está en la configuración de producción (${sites[name].join(', ')}) y no puede estarlo: ${reasons.join('; ')}. Quita esa configuración o aporta lo que falta (${PRODUCTION_GATES}, docs/release-checklist.md).`,
      );
      continue;
    }
    // Consent records the terms version: it has to be the approved one wherever the feature is on.
    if (!f.termsKey) continue;
    const { version } = checkLegalApproval({ root, record: f.legalApproval });
    for (const c of webConfigs)
      if (f.webKeys.some((k) => isSet(c.json[k])) && c.json[f.termsKey]?.version !== version)
        out.push(`Configuración: ${c.file} activa ${name} sin "${f.termsKey}" con la versión aprobada (${version}, ${f.legalApproval}).`);
  }
  return out;
}

/** OPS-08: publish-images, publish and verify run in this protected environment. */
export const RELEASE_ENVIRONMENT = 'release';

/**
 * OPS-08: the environment the publishing jobs run in is configured as docs/building.md says: required reviewers
 * with «Prevent self-review», no administrator bypass and deployments only from v* tags. Checked before anything
 * is published: if the environment did not exist, the first publishing job would create it with no protection.
 * The job's token needs `actions: read`.
 */
export function checkEnvironment({ repo, api = ghApi }) {
  const fix = 'docs/building.md, «Configuración del repositorio»';
  const path = `repos/${repo}/environments/${RELEASE_ENVIRONMENT}`;
  let env;
  let policies = [];
  try {
    env = api(path);
    if (env.deployment_branch_policy?.custom_branch_policies) policies = api(`${path}/deployment-branch-policies?per_page=100`).branch_policies ?? [];
  } catch (e) {
    return [`Entorno release: no existe o no se puede leer (${apiError(e)}). Configúralo antes de publicar (${fix}): si no existe, el primer job que publica lo crearía sin protección.`];
  }
  const missing = [];
  const reviewers = (env.protection_rules ?? []).find((r) => r.type === 'required_reviewers');
  if (!reviewers?.reviewers?.length) missing.push('revisores obligatorios («Required reviewers»)');
  else if (reviewers.prevent_self_review !== true) missing.push('«Prevent self-review»');
  if (env.can_admins_bypass !== false) missing.push('desmarcar «Allow administrators to bypass configured protection rules»');
  if (!env.deployment_branch_policy?.custom_branch_policies || env.deployment_branch_policy.protected_branches)
    missing.push('«Selected branches and tags» con la regla de tag v* en «Deployment branches and tags»');
  else {
    if (!policies.some((p) => p.type === 'tag' && p.name === 'v*')) missing.push('la regla de tag v* en «Deployment branches and tags»');
    const branches = policies.filter((p) => p.type !== 'tag');
    if (branches.length) missing.push(`quitar las reglas de rama (${branches.map((p) => p.name).join(', ')}): solo se publica desde tags v*`);
  }
  return missing.length ? [`Entorno release: le falta ${missing.join(', ')} (${fix}).`] : [];
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
    codeql: () => checkCodeql({ repo: need('GH_REPO', repo), sha: need('--sha', opts.sha) }),
    dependabot: () => checkDependabot({ repo: need('GH_REPO', repo) }),
    restore: () => checkRestore({ repo: need('GH_REPO', repo), sha: need('--sha', opts.sha), maxAgeHours: Number(env.RESTORE_MAX_AGE_HOURS || 72) }),
    sbom: () => checkSbom(readFileSync(resolve(need('--sbom o <archivo>', opts.sbom ?? opts.positional[0])), 'utf8')),
    audits: () => checkAudits({ tag: need('--tag', opts.tag), actors: opts.actors }),
    'threat-models': () => checkThreatModels({ tag: need('--tag', opts.tag), actors: opts.actors }),
    notes: () => checkNotesFile({ tag: need('--tag', opts.tag) }),
    config: () => checkConfig(),
    environment: () => checkEnvironment({ repo: need('GH_REPO', repo) }),
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
