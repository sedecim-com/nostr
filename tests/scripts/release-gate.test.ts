import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  MATURITY,
  PRODUCTION_GATES,
  RELEASE_ENVIRONMENT,
  REQUIRED_AUDITS,
  REQUIRED_CI_JOBS,
  THREAT_MODELS,
  TRUST_SUBSECTIONS,
  checkAudits,
  checkCi,
  checkCodeql,
  checkConfig,
  checkDependabot,
  checkEnvironment,
  checkLegalApproval,
  checkNotes,
  checkNotesFile,
  checkRestore,
  checkSbom,
  checkThreatModels,
  parseFields,
  threatModelHashes,
  // @ts-expect-error plain ESM script without types
} from '../../scripts/release-gate.mjs';

const root = new URL('../..', import.meta.url).pathname;
const repo = 'o/r';
const sha = 'abc123';

type Run = { id: number; conclusion: string; created_at?: string; updated_at?: string };
/** Fake `gh api`: workflow runs per workflow file and jobs per run id. */
const fakeApi = (runs: Record<string, Run[]>, jobs: Record<number, Array<{ name: string; conclusion: string }>> = {}) => (path: string) => {
  const wf = /workflows\/([^/]+)\/runs\?head_sha=([^&]+)/.exec(path);
  if (wf) return { workflow_runs: wf[2] === sha ? (runs[wf[1] ?? ''] ?? []) : [] };
  const j = /runs\/(\d+)\/jobs/.exec(path);
  if (j) return { jobs: jobs[Number(j[1])] ?? [] };
  throw new Error(`unexpected ${path}`);
};
const allGreen = REQUIRED_CI_JOBS.map((name: string) => ({ name, conclusion: 'success' }));

const notes = (tag: string, trust: Record<string, string> = {}) =>
  [
    `# Acceso Nostr ${tag}`,
    '',
    '## Resumen',
    '',
    'Texto.',
    '',
    '## Cambios en el modelo de confianza',
    '',
    ...TRUST_SUBSECTIONS.flatMap((s: string) => (s in trust && trust[s] === undefined ? [] : [`### ${s}`, '', trust[s] ?? 'Sin cambios.', ''])),
    '## Limitaciones conocidas',
    '',
    '- Ninguna.',
  ].join('\n');

describe('scripts/release-gate.mjs (REL-01 / REL-02)', () => {
  it('every required CI job exists in ci.yml under that exact name', () => {
    const ci = readFileSync(join(root, '.github/workflows/ci.yml'), 'utf8');
    const jobsBlock = ci.slice(ci.indexOf('\njobs:\n'));
    for (const job of REQUIRED_CI_JOBS) {
      expect(jobsBlock, job).toMatch(new RegExp(`\\n  ${job}:\\n`));
      // A job-level `name:` would change the check name the gate looks for.
      const body = (jobsBlock.split(new RegExp(`\\n  ${job}:\\n`))[1] ?? '').split(/\n  [a-z-]+:\n/)[0];
      expect(body, job).not.toMatch(/^ {4}name:/m);
    }
    expect(REQUIRED_CI_JOBS).toEqual(expect.arrayContaining(['test', 'stack', 'leak-tests', 'tor-profile']));
  });

  it('CI: passes with a green run on the commit, fails when missing, failed or with a skipped job', () => {
    expect(checkCi({ repo, sha, api: fakeApi({ 'ci.yml': [{ id: 1, conclusion: 'success' }] }, { 1: allGreen }) })).toEqual([]);
    // An older green run counts even if a later one failed.
    expect(checkCi({ repo, sha, api: fakeApi({ 'ci.yml': [{ id: 2, conclusion: 'failure' }, { id: 1, conclusion: 'success' }] }, { 1: allGreen }) })).toEqual([]);
    expect(checkCi({ repo, sha, api: fakeApi({}) })[0]).toMatch(/no hay ninguna ejecución.*gh workflow run ci\.yml/);
    expect(checkCi({ repo, sha, api: fakeApi({ 'ci.yml': [{ id: 3, conclusion: 'failure' }] }) })[0]).toMatch(/failure/);
    const skipped = allGreen.map((j: { name: string }) => (j.name === 'tor-profile' ? { ...j, conclusion: 'skipped' } : j));
    expect(checkCi({ repo, sha, api: fakeApi({ 'ci.yml': [{ id: 4, conclusion: 'success' }] }, { 4: skipped }) })[0]).toMatch(/sin éxito en tor-profile/);
    const missing = allGreen.filter((j: { name: string }) => j.name !== 'leak-tests');
    expect(checkCi({ repo, sha, api: fakeApi({ 'ci.yml': [{ id: 5, conclusion: 'success' }] }, { 5: missing }) })[0]).toMatch(/leak-tests/);
  });

  it('CodeQL (OPS-13): a successful analysis of the commit and no open high or critical alert', () => {
    const alert = (number: number, level: string) => ({ number, rule: { id: `js/rule-${number}`, security_severity_level: level }, most_recent_instance: { location: { path: `src/f${number}.ts` } } });
    const api = (runs: Run[], alerts: unknown[]) => (path: string) => (path.includes('/code-scanning/alerts?') ? alerts : fakeApi({ 'codeql.yml': runs })(path));
    expect(checkCodeql({ repo, sha, api: api([{ id: 1, conclusion: 'success' }], [alert(3, 'medium'), alert(4, 'low')]) })).toEqual([]);
    expect(checkCodeql({ repo, sha, api: api([], []) })[0]).toMatch(/ninguna ejecución con éxito de codeql\.yml.*gh workflow run codeql\.yml/);
    expect(checkCodeql({ repo, sha, api: api([{ id: 2, conclusion: 'failure' }], []) })).toHaveLength(1);
    const found = checkCodeql({ repo, sha, api: api([{ id: 1, conclusion: 'success' }], [alert(18, 'high'), alert(19, 'critical'), alert(20, 'medium')]) });
    expect(found).toEqual([expect.stringMatching(/^CodeQL: 2 alertas abiertas de severidad alta o crítica.*#18 js\/rule-18 \(src\/f18\.ts\), #19 js\/rule-19/)]);
  });

  /** A failed `gh api` call as execFileSync throws it. */
  const ghFailure = (stderr: string) => () => {
    throw Object.assign(new Error('Command failed: gh api'), { stderr });
  };

  it('Dependabot (REL-01): no open high or critical alert on the default branch', () => {
    const api = (alerts: unknown[]) => (path: string) => {
      expect(path).toBe(`repos/${repo}/dependabot/alerts?state=open&severity=high,critical&per_page=100`);
      return alerts;
    };
    const alert = (number: number, severity: string, name = 'pkg') => ({ number, security_advisory: { severity }, dependency: { package: { name } } });
    expect(checkDependabot({ repo, api: api([]) })).toEqual([]);
    expect(checkDependabot({ repo, api: api([alert(1, 'medium'), alert(2, 'low')]) })).toEqual([]);
    const [p] = checkDependabot({ repo, api: api([alert(3, 'high', 'ws'), alert(4, 'critical', 'undici'), alert(5, 'low')]) });
    expect(p).toMatch(/^Dependabot: 2 alertas abiertas/);
    expect(p).toContain('#3 ws (high), #4 undici (critical)');
    // Alerts off (or no permission) block the release instead of passing unchecked.
    const [off] = checkDependabot({ repo, api: ghFailure('gh: Dependabot alerts are disabled for this repository. (HTTP 403)\n') });
    expect(off).toContain('no se pudieron leer las alertas (gh: Dependabot alerts are disabled for this repository. (HTTP 403))');
    expect(off).toContain('vulnerability-alerts: read');
  });

  describe('release environment (OPS-08)', () => {
    const configured = {
      name: 'release',
      can_admins_bypass: false,
      protection_rules: [
        { type: 'required_reviewers', prevent_self_review: true, reviewers: [{ type: 'User', reviewer: { login: 'ana' } }] },
        { type: 'branch_policy' },
      ],
      deployment_branch_policy: { protected_branches: false, custom_branch_policies: true },
    };
    const api = (env: unknown, policies: unknown[] = [{ name: 'v*', type: 'tag' }]) => (path: string) => {
      if (path === `repos/${repo}/environments/release`) return env;
      if (path === `repos/${repo}/environments/release/deployment-branch-policies?per_page=100`) return { total_count: policies.length, branch_policies: policies };
      throw new Error(`unexpected ${path}`);
    };
    const problems = (over: Record<string, unknown>, policies?: unknown[]) => checkEnvironment({ repo, api: api({ ...configured, ...over }, policies) }).join('\n');

    it('passes when it is configured as docs/building.md says', () => {
      expect(RELEASE_ENVIRONMENT).toBe('release');
      expect(checkEnvironment({ repo, api: api(configured) })).toEqual([]);
    });

    it('a missing environment blocks the release: the first publishing job would create it unprotected', () => {
      const [p] = checkEnvironment({ repo, api: ghFailure('gh: Not Found (HTTP 404)') });
      expect(p).toContain('no existe o no se puede leer (gh: Not Found (HTTP 404))');
      expect(p).toContain('sin protección');
    });

    it('names each missing protection', () => {
      expect(problems({ protection_rules: [{ type: 'branch_policy' }] })).toMatch(/revisores obligatorios/);
      expect(problems({ protection_rules: [{ type: 'required_reviewers', prevent_self_review: false, reviewers: [{}] }] })).toMatch(/«Prevent self-review»/);
      expect(problems({ can_admins_bypass: true })).toMatch(/Allow administrators to bypass/);
      expect(problems({ deployment_branch_policy: null })).toMatch(/«Selected branches and tags»/);
      expect(problems({ deployment_branch_policy: { protected_branches: true, custom_branch_policies: false } })).toMatch(/«Selected branches and tags»/);
      expect(problems({}, [])).toMatch(/la regla de tag v\*/);
      expect(problems({}, [{ name: 'v*', type: 'tag' }, { name: 'main', type: 'branch' }])).toMatch(/quitar las reglas de rama \(main\)/);
    });
  });

  it('restore drill: a success on the commit within the window', () => {
    const now = Date.parse('2026-10-01T12:00:00Z');
    const api = (updated_at: string, conclusion = 'success') => fakeApi({ 'restore-drill.yml': [{ id: 9, conclusion, updated_at }] });
    expect(checkRestore({ repo, sha, now, api: api('2026-09-30T04:30:00Z') })).toEqual([]);
    expect(checkRestore({ repo, sha, now, api: api('2026-09-20T04:30:00Z') })[0]).toMatch(/más de 72 h/);
    expect(checkRestore({ repo, sha, now, maxAgeHours: 24 * 14, api: api('2026-09-20T04:30:00Z') })).toEqual([]);
    expect(checkRestore({ repo, sha, now, api: api('2026-09-30T04:30:00Z', 'failure') })[0]).toMatch(/ninguna ejecución con éxito/);
    expect(checkRestore({ repo, sha, now, api: fakeApi({}) })[0]).toMatch(/gh workflow run restore-drill\.yml/);
  });

  it('SBOM: CycloneDX with components', () => {
    expect(checkSbom(JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [{ name: 'x' }] }))).toEqual([]);
    expect(checkSbom('{')).toEqual(['SBOM: sbom.cdx.json no es JSON válido.']);
    expect(checkSbom(JSON.stringify({ bomFormat: 'SPDX', components: [] }))).toHaveLength(3);
  });

  it('parses "- Campo: valor" records, bold names included', () => {
    expect(parseFields('# T\n\n- Tag: v1.0.0\n- **Aprobado por:** @ana\n* Motivo: a: b\n')).toEqual({ tag: 'v1.0.0', 'aprobado por': '@ana', motivo: 'a: b' });
  });

  describe('audits', () => {
    const tag = 'v1.2.0';
    const setup = (files: Record<string, string>) => {
      const dir = mkdtempSync(join(tmpdir(), 'release-gate-'));
      mkdirSync(join(dir, 'docs/security/audits/waivers'), { recursive: true });
      for (const [p, c] of Object.entries(files)) writeFileSync(join(dir, p), c);
      return dir;
    };
    const waiver = (over: Record<string, string> = {}) => {
      const f = { Tag: tag, 'Auditorías': 'SEC-01, SEC-02', Motivo: 'early release sin auditoría externa contratada todavía', 'Aprobado por': '@revisora', Fecha: '2026-10-01', ...over };
      return `# Waiver\n\n${Object.entries(f).map(([k, v]) => `- ${k}: ${v}`).join('\n')}\n`;
    };

    it('nothing on file blocks the release and says where to add it', () => {
      const [p] = checkAudits({ tag, root: setup({}) });
      expect(p).toMatch(/SEC-01, SEC-02 sin informe ni waiver/);
      expect(p).toContain(`docs/security/audits/waivers/${tag}.md`);
      expect(REQUIRED_AUDITS).toEqual(['SEC-01', 'SEC-02']);
    });

    it('a complete waiver approved by someone else passes', () => {
      expect(checkAudits({ tag, root: setup({ [`docs/security/audits/waivers/${tag}.md`]: waiver() }), actors: ['autor'] })).toEqual([]);
    });

    it('the waiver needs reason, @approver other than the releaser, date and the right tag', () => {
      const bad = (over: Record<string, string>, actors = ['autor']) => checkAudits({ tag, root: setup({ [`docs/security/audits/waivers/${tag}.md`]: waiver(over) }), actors }).join('\n');
      expect(bad({ 'Aprobado por': 'PENDIENTE' })).toMatch(/Aprobado por: @usuario/);
      expect(bad({}, ['Revisora'])).toMatch(/distinto de quien lanza el release/);
      expect(bad({ Motivo: 'porque sí' })).toMatch(/motivo concreto/);
      expect(bad({ Fecha: 'PENDIENTE' })).toMatch(/fecha de aprobación/);
      expect(bad({ Tag: 'v1.1.0' })).toMatch(/- Tag: v1\.2\.0/);
      expect(bad({ 'Auditorías': 'SEC-01' })).toMatch(/SEC-02 sin informe ni waiver/);
    });

    it('an audit report covers what it lists; a waiver can cover the rest', () => {
      const report = `# Auditorías\n\n- Tag: ${tag}\n- Auditorías: SEC-01\n- Informe: https://example.org/informe.pdf\n`;
      expect(checkAudits({ tag, root: setup({ [`docs/security/audits/${tag}.md`]: report }) })[0]).toMatch(/SEC-02 sin informe/);
      expect(checkAudits({ tag, root: setup({ [`docs/security/audits/${tag}.md`]: report, [`docs/security/audits/waivers/${tag}.md`]: waiver({ 'Auditorías': 'SEC-02' }) }), actors: ['autor'] })).toEqual([]);
      expect(checkAudits({ tag, root: setup({ [`docs/security/audits/${tag}.md`]: report.replace(/Informe: .*/, 'Informe: PENDIENTE') }) })[0]).toMatch(/enlazar el informe/);
    });

    it('the prepared v0.1.0 waiver covers SEC-01 and SEC-02 and is only missing the approval', () => {
      const f = parseFields(readFileSync(join(root, 'docs/security/audits/waivers/v0.1.0.md'), 'utf8'));
      expect(f.tag).toBe('v0.1.0');
      expect(f['auditorías']).toMatch(/SEC-01.*SEC-02/);
      expect(f.motivo.length).toBeGreaterThan(30);
    });
  });

  describe('threat models (DEC-10)', () => {
    const tag = 'v1.2.0';
    const docs = { 'README.md': '# Threat models\n\n- **Estado:** Aprobado (v1.2.0)\n', 'convenience.md': '# convenience\n\nActivos.\n' };
    const digest = (text: string) => createHash('sha256').update(text).digest('hex');
    const setup = (record: string | undefined, files: Record<string, string> = docs) => {
      const dir = mkdtempSync(join(tmpdir(), 'release-gate-tm-'));
      mkdirSync(join(dir, THREAT_MODELS, 'approvals'), { recursive: true });
      for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, THREAT_MODELS, name), text);
      if (record !== undefined) writeFileSync(join(dir, THREAT_MODELS, 'approvals', `${tag}.md`), record);
      return dir;
    };
    const record = (over: Record<string, string> = {}, files: Record<string, string> = docs) => {
      const hashes = Object.fromEntries(Object.entries(files).map(([name, text]) => [name, digest(text)]));
      const f = { Tag: tag, 'Aprobado por': '@revisora', Fecha: '2026-10-01', ...hashes, ...over };
      return `# Aprobación\n\n${Object.entries(f).map(([k, v]) => `- ${k}: ${v}`).join('\n')}\n`;
    };
    const check = (dir: string, actors = ['autor']) => checkThreatModels({ tag, root: dir, actors }).join('\n');

    it('an approval of the documents as they are, by someone other than the releaser, passes', () => {
      expect(checkThreatModels({ tag, root: setup(record()), actors: ['autor'] })).toEqual([]);
    });

    it('nothing on file blocks the release and prints the line of each document to approve', () => {
      const p = check(setup(undefined));
      expect(p).toContain(`falta la aprobación ${THREAT_MODELS}/approvals/${tag}.md`);
      expect(p).toContain(`\n- convenience.md: ${digest(docs['convenience.md'])}`);
      expect(check(setup(record({ 'Aprobado por': 'PENDIENTE' })))).toMatch(/está pendiente/);
    });

    it('an edit after the approval, a new document, the releaser as approver or a bad record invalidate it', () => {
      const edited = { ...docs, 'convenience.md': '# convenience\n\nOtro texto.\n' };
      expect(check(setup(record(), edited))).toContain(`una huella que coincida con convenience.md. Si ese es el texto aprobado, son estas; si cambió después, hace falta aprobarlo de nuevo:\n- convenience.md: ${digest(edited['convenience.md'])}`);
      expect(check(setup(record(), { ...docs, 'sovereign.md': '# sovereign\n' }))).toMatch(/una huella que coincida con sovereign\.md/);
      expect(check(setup(record()), ['Revisora'])).toMatch(/distinto de quien lanza el release \(@revisora\)/);
      expect(check(setup(record({ 'Aprobado por': 'revisora' })))).toMatch(/@usuario de GitHub/);
      expect(check(setup(record({ Fecha: 'mañana' })))).toMatch(/fecha de aprobación/);
      expect(check(setup(record({ Tag: 'v1.1.0' })))).toMatch(/"- Tag: v1\.2\.0"/);
      expect(check(setup(record({ 'old.md': 'abc' })))).toMatch(/quitar old\.md/);
    });

    it('a document that still says «Propuesto» blocks it, even with the approval on file', () => {
      const proposed = { ...docs, 'README.md': '# Threat models\n\n- **Versión:** v0.1 · **Estado:** Propuesto (pendiente de revisión)\n' };
      expect(check(setup(record({}, proposed), proposed))).toMatch(/README\.md siguen en «Propuesto»/);
    });

    it('the prepared v0.1.0 record lists every threat model and is only missing the approval', () => {
      const f = parseFields(readFileSync(join(root, THREAT_MODELS, 'approvals/v0.1.0.md'), 'utf8'));
      expect(f.tag).toBe('v0.1.0');
      expect(f['aprobado por']).toBe('PENDIENTE');
      for (const file of Object.keys(threatModelHashes(root))) expect(f).toHaveProperty(file.toLowerCase());
      const run = spawnSync(process.execPath, [join(root, 'scripts/release-gate.mjs'), 'threat-models', '--tag', 'v0.1.0'], { cwd: root, encoding: 'utf8' });
      expect(run.status).toBe(1);
      expect(run.stderr).toContain(`la aprobación ${THREAT_MODELS}/approvals/v0.1.0.md está pendiente`);
    });
  });

  it('release.yml gives dod what the gate reads and publishes -rc tags as pre-releases', () => {
    const wf = readFileSync(join(root, '.github/workflows/release.yml'), 'utf8');
    const dod = wf.slice(wf.indexOf('\n  dod:\n'), wf.indexOf('\n  publish-images:\n'));
    for (const permission of ['actions: read', 'security-events: read', 'vulnerability-alerts: read']) expect(dod).toContain(permission);
    expect(dod).toContain('node scripts/release-gate.mjs all --tag');
    expect(wf).toContain('case "$TAG" in *-*) prerelease=true ;; *) prerelease=false ;; esac');
    expect(wf).toContain('gh release create "$TAG" --draft --verify-tag --prerelease="$prerelease"');
    expect(wf).toContain('gh release edit "$TAG" --notes-file notes.md --prerelease="$prerelease"');
  });

  describe('production configuration (OPS-20)', () => {
    type Registry = { production: Record<string, string[]>; features: Record<string, Record<string, unknown>> };
    const registry: Registry = JSON.parse(readFileSync(join(root, PRODUCTION_GATES), 'utf8'));
    const withFeature = (name: string, over: Record<string, unknown>): Registry => ({ ...registry, features: { ...registry.features, [name]: { ...registry.features[name], ...over } } });
    const record = (f: Record<string, string>) => `# Registro\n\n${Object.entries(f).map(([k, v]) => `- ${k}: ${v}`).join('\n')}\n`;
    const terms = '# Términos de custodia managed · Acceso Nostr\n\n> Versión 1.0.0, aprobada.\n\nTexto.\n';
    const approval = (over: Record<string, string> = {}, text = terms) =>
      record({ Documento: 'docs/legal/custodia-managed.md', 'Versión': '1.0.0', 'SHA-256': createHash('sha256').update(text).digest('hex'), Dictamen: 'https://example.org/dictamen.pdf', 'Aprobado por': 'Despacho Ejemplo, S.C.', Fecha: '2026-11-02', ...over });
    const pending = approval({ 'Versión': 'PENDIENTE', 'SHA-256': 'PENDIENTE', Dictamen: 'PENDIENTE', 'Aprobado por': 'PENDIENTE', Fecha: 'PENDIENTE' });
    const reports = { 'docs/security/audits/v1.0.0.md': '# Auditorías\n\n- Tag: v1.0.0\n- Auditorías: SEC-01, SEC-02\n- Informe: https://example.org/informe.pdf\n' };
    const saas = (over: Record<string, unknown> = {}) => ({ 'infra/web/config.saas.example.json': { mode: 'saas', relays: ['wss://relay.example.org'], ...over } });
    const managedOn = { managedSigner: 'https://signer.example.org', managedTerms: { url: 'https://example.org/terminos', version: '1.0.0' } };
    /** A repository tree with the production paths of the committed registry; `files` adds, replaces or (undefined) drops files. */
    const tree = (files: Record<string, unknown> = {}, reg: Registry = registry) => {
      const dir = mkdtempSync(join(tmpdir(), 'production-gates-'));
      for (const p of [...registry.production.kubernetes!, ...registry.production.terraform!]) mkdirSync(join(dir, p), { recursive: true });
      const all: Record<string, unknown> = {
        [PRODUCTION_GATES]: reg,
        'infra/web/config.json': { mode: 'self-hosted', relays: ['ws://localhost:3000'] },
        ...saas(),
        'docs/legal/custodia-managed.md': terms,
        'docs/legal/approvals/custodia-managed.md': pending,
        ...files,
      };
      for (const [p, c] of Object.entries(all)) {
        if (c === undefined) continue;
        mkdirSync(dirname(join(dir, p)), { recursive: true });
        writeFileSync(join(dir, p), typeof c === 'string' ? c : JSON.stringify(c));
      }
      return dir;
    };
    const problems = (files: Record<string, unknown> = {}, reg?: Registry) => checkConfig({ root: tree(files, reg) }).join('\n');

    it('the repository passes: the enclave is Preview, push has no safe trigger and managed waits for DEC-12', () => {
      expect(checkConfig({ root })).toEqual([]);
      expect(Object.keys(registry.features)).toEqual(['managed', 'enclave', 'push', 'webhooks-private']);
      expect(registry.features.enclave).toMatchObject({ maturity: 'Preview', settings: { MANAGED_SIGNER_BACKEND: 'enclave', ENCLAVE_ALLOW_EXPORT: '1' } });
      expect(registry.features.push).toMatchObject({ safeTrigger: false, webKeys: ['notificationGateway'] });
      expect(registry.features.managed).toMatchObject({ webKeys: ['managedSigner', 'managedTerms'], auditReports: REQUIRED_AUDITS });
      expect(checkLegalApproval({ root, record: registry.features.managed!.legalApproval }).problems[0]).toMatch(/aprobación legal de docs\/legal\/custodia-managed\.md está pendiente/);
      expect(MATURITY).toEqual(['GA', 'Beta', 'Preview', 'Experimental']);
      expect(problems()).toBe('');
    });

    it('managed stays out of production while its legal approval or the audit reports are pending', () => {
      const p = problems(saas(managedOn));
      expect(p).toMatch(/managed \(custodia gestionada.*\) está en la configuración de producción \(infra\/web\/config\.saas\.example\.json \("managedSigner"\), infra\/web\/config\.saas\.example\.json \("managedTerms"\)\)/);
      expect(p).toMatch(/aprobación legal de docs\/legal\/custodia-managed\.md está pendiente/);
      expect(p).toMatch(/SEC-01, SEC-02 sin informe/);
      // Approved, but the audits were waived, not done.
      const waiver = { 'docs/security/audits/waivers/v1.0.0.md': record({ Tag: 'v1.0.0', 'Auditorías': 'SEC-01, SEC-02', Motivo: 'x'.repeat(40), 'Aprobado por': '@revisora', Fecha: '2026-11-02' }) };
      const waived = problems({ ...saas(managedOn), 'docs/legal/approvals/custodia-managed.md': approval(), ...waiver });
      expect(waived).toMatch(/SEC-01, SEC-02 sin informe.*un waiver no basta/);
      expect(waived).not.toMatch(/aprobación legal/);
      // Approved and audited: on, with the approved terms version.
      expect(problems({ ...saas(managedOn), 'docs/legal/approvals/custodia-managed.md': approval(), ...reports })).toBe('');
      expect(problems({ ...saas({ managedSigner: 'https://signer.example.org' }), 'docs/legal/approvals/custodia-managed.md': approval(), ...reports })).toMatch(
        /infra\/web\/config\.saas\.example\.json activa managed sin "managedTerms" con la versión aprobada \(1\.0\.0/,
      );
      expect(problems({ ...saas({ ...managedOn, managedTerms: { url: 'https://example.org/t', version: '0.9.0' } }), 'docs/legal/approvals/custodia-managed.md': approval(), ...reports })).toMatch(/versión aprobada/);
    });

    it('the approval is for the text as it is: an edit afterwards, a draft or a missing field invalidates it', () => {
      const withApproval = (a: string, text = terms) => problems({ ...saas(managedOn), 'docs/legal/custodia-managed.md': text, 'docs/legal/approvals/custodia-managed.md': a, ...reports });
      const edited = `${terms}Una cláusula nueva.\n`;
      expect(withApproval(approval(), edited)).toContain(`"- SHA-256: ${createHash('sha256').update(edited).digest('hex')}" si ese es el texto aprobado`);
      const draft = terms.replace('# Términos', '# (BORRADOR) Términos');
      expect(withApproval(approval({}, draft), draft)).toMatch(/deje de marcarse como borrador/);
      expect(withApproval(approval({ Fecha: 'mañana' }))).toMatch(/la fecha \("- Fecha: AAAA-MM-DD"\)/);
      expect(withApproval(approval({ Dictamen: 'PENDIENTE' }))).toMatch(/el dictamen/);
      expect(withApproval(approval({ Documento: 'docs/legal/otro.md' }))).toMatch(/el documento aprobado/);
      expect(problems({ ...saas(managedOn), ...reports, 'docs/legal/approvals/custodia-managed.md': undefined as unknown as string }).length).toBeGreaterThan(0);
    });

    it('a production overlay is anything but stage: including managed-signer there counts, in stage it does not', () => {
      const overlay = (name: string) => ({ [`deploy/k8s/overlays/${name}/kustomization.yaml`]: 'resources:\n  - ../../base\ncomponents:\n  - ../../components/managed-signer\n' });
      expect(problems(overlay('production'))).toMatch(/deploy\/k8s\/overlays\/production\/kustomization\.yaml \(components\/managed-signer\).*aprobación legal/);
      expect(problems(overlay('stage'))).toBe('');
      expect(problems({ 'deploy/k8s/overlays/stage/files/web-config.json': managedOn })).toBe('');
      expect(problems({ 'deploy/k8s/overlays/production/files/web-config.json': managedOn })).toMatch(/overlays\/production\/files\/web-config\.json \("managedSigner"\)/);
    });

    it('the enclave and its export stay off while they are Preview, however they are set', () => {
      const on = (files: Record<string, unknown>) => {
        const p = problems(files);
        expect(p).toMatch(/enclave \(custodia en Nitro Enclave y su exportación.*es Preview, y lo Preview va apagado en producción/);
        return p;
      };
      expect(on({ 'deploy/k8s/overlays/prod/kustomization.yaml': 'configMapGenerator:\n  - name: acceso-nostr-config\n    literals:\n      - MANAGED_SIGNER_BACKEND=enclave\n' })).toContain('(MANAGED_SIGNER_BACKEND=enclave)');
      expect(on({ 'deploy/k8s/components/managed-signer/managed-signer.yaml': 'env:\n  - name: ENCLAVE_ALLOW_EXPORT\n    value: "1"\n' })).toContain('(ENCLAVE_ALLOW_EXPORT=1)');
      expect(on({ 'deploy/k8s/base/config.yaml': 'data:\n  MANAGED_SIGNER_BACKEND: "enclave"\n' })).toContain('deploy/k8s/base/config.yaml');
      expect(on({ 'deploy/terraform/examples/production/main.tf': 'module "x" {\n  enable_enclave_signer = true\n}\n' })).toContain('(enable_enclave_signer = true)');
      expect(on({ 'deploy/terraform/modules/acceso-nostr/variables.tf': 'variable "enable_enclave_signer" {\n  type    = bool\n  default = true\n}\n' })).toContain('variables.tf');
      expect(on({ 'deploy/terraform/examples/production/terraform.tfvars': 'enable_enclave_signer = "true"\n' })).toContain('terraform.tfvars');
      // Commented out, off by default, another value, or stage: not on.
      expect(problems({ 'deploy/terraform/examples/production/main.tf': 'module "x" {\n  # enable_enclave_signer = true\n  // enable_enclave_signer = true\n}\n' })).toBe('');
      expect(problems({ 'deploy/terraform/modules/acceso-nostr/variables.tf': 'variable "enable_enclave_signer" {\n  default = false\n}\nvariable "other" {\n  default = true\n}\n' })).toBe('');
      expect(problems({ 'deploy/k8s/overlays/prod/kustomization.yaml': '- MANAGED_SIGNER_BACKEND=local\n- ENCLAVE_ALLOW_EXPORT=0\n# - MANAGED_SIGNER_BACKEND=enclave\n' })).toBe('');
      expect(problems({ 'deploy/k8s/overlays/stage/kustomization.yaml': '- MANAGED_SIGNER_BACKEND=enclave\n' })).toBe('');
      // Leaving Preview is a reviewed change of the registry.
      expect(problems({ 'deploy/k8s/overlays/prod/kustomization.yaml': '- MANAGED_SIGNER_BACKEND=enclave\n' }, withFeature('enclave', { maturity: 'Beta' }))).toBe('');
    });

    it('push stays off without a safe trigger on the production relays', () => {
      expect(problems(saas({ notificationGateway: 'https://push.example.org' }))).toMatch(/push \(notificaciones push.*\("notificationGateway"\)\) y no puede estarlo: no hay un disparador seguro \(ADR 0010/);
      expect(problems({ 'deploy/k8s/overlays/prod/kustomization.yaml': 'components:\n  - ../../components/notification-gateway\n' })).toMatch(/\(components\/notification-gateway\)/);
      // The component's own header mentions how to add it: a comment is not a use.
      expect(problems({ 'deploy/k8s/components/notification-gateway/kustomization.yaml': '# add `components: [../../components/notification-gateway]` to an overlay\nkind: Component\n' })).toBe('');
      const safe = withFeature('push', { safeTrigger: true, evidence: 'matriz de ADR 0010: el relay de producción entrega el canario al gateway' });
      expect(problems(saas({ notificationGateway: 'https://push.example.org' }), safe)).toBe('');
    });

    it('webhooks to private or local destinations are for tests only: never in a production manifest (OPS-16)', () => {
      expect(registry.features['webhooks-private']).toMatchObject({ settings: { POLICY_WEBHOOKS_ALLOW_PRIVATE: 'true' }, testOnly: expect.stringMatching(/SSRF/) });
      const on = (files: Record<string, unknown>) => {
        const p = problems(files);
        expect(p).toMatch(/webhooks-private \(webhooks del policy-engine hacia destinos privados o locales.*y no puede estarlo: es solo para pruebas y desarrollo: abre los webhooks a loopback/);
        return p;
      };
      expect(on({ 'deploy/k8s/overlays/prod/kustomization.yaml': 'configMapGenerator:\n  - name: acceso-nostr-config\n    literals:\n      - POLICY_WEBHOOKS_ALLOW_PRIVATE=true\n' })).toContain('(POLICY_WEBHOOKS_ALLOW_PRIVATE=true)');
      expect(on({ 'deploy/k8s/base/policy-engine.yaml': 'env:\n  - name: POLICY_WEBHOOKS_ALLOW_PRIVATE\n    value: "true"\n' })).toContain('deploy/k8s/base/policy-engine.yaml');
      expect(on({ 'deploy/k8s/components/institutional/config.yaml': 'data:\n  POLICY_WEBHOOKS_ALLOW_PRIVATE: "true"\n' })).toContain('components/institutional/config.yaml');
      // Off, commented out, or in stage (where tests may use it): not refused.
      expect(problems({ 'deploy/k8s/overlays/prod/kustomization.yaml': '- POLICY_WEBHOOKS_ALLOW_PRIVATE=false\n# - POLICY_WEBHOOKS_ALLOW_PRIVATE=true\n' })).toBe('');
      expect(problems({ 'deploy/k8s/overlays/stage/kustomization.yaml': '- POLICY_WEBHOOKS_ALLOW_PRIVATE=true\n' })).toBe('');
      // No evidence lifts it: only removing testOnly from the registry, a reviewed change.
      expect(problems({ 'deploy/k8s/overlays/prod/kustomization.yaml': '- POLICY_WEBHOOKS_ALLOW_PRIVATE=true\n' }, withFeature('webhooks-private', { evidence: 'x'.repeat(40) }))).toMatch(/solo para pruebas/);
      expect(problems({}, withFeature('webhooks-private', { testOnly: 'corto' }))).toMatch(/features\.webhooks-private\.testOnly debe decir por qué es solo para pruebas/);
    });

    it('the registry is validated, so a typo cannot hide a feature', () => {
      const reg = (over: Registry) => problems({}, over);
      const { webKeys, ...pushWithoutKeys } = registry.features.push!;
      expect(webKeys).toEqual(['notificationGateway']);
      expect(reg({ ...registry, features: { ...registry.features, push: { ...pushWithoutKeys, webkeys: webKeys } } })).toMatch(/features\.push\.webkeys no es un campo conocido/);
      expect(reg(withFeature('enclave', { maturity: 'Alpha' }))).toMatch(/features\.enclave\.maturity debe ser GA, Beta, Preview, Experimental/);
      expect(reg(withFeature('push', { safeTrigger: true, evidence: '' }))).toMatch(/safeTrigger = true necesita la evidencia/);
      expect(reg({ ...registry, features: { ...registry.features, nuevo: { title: 'algo' } } })).toMatch(/features\.nuevo no dice cómo se detecta/);
      expect(reg(withFeature('push', { termsKey: 'notificationGateway' }))).toMatch(/termsKey debe ser una de sus webKeys y necesita legalApproval/);
      expect(reg({ ...registry, production: { ...registry.production, kubernetes: ['deploy/k8s/nada'] } })).toMatch(/deploy\/k8s\/nada no existe/);
      expect(problems({ [PRODUCTION_GATES]: '{' })).toMatch(/no es JSON válido/);
      expect(problems({ 'deploy/k8s/base/files/web-config.json': '{ "mode": ' })).toMatch(/deploy\/k8s\/base\/files\/web-config\.json no es JSON válido/);
      expect(checkConfig({ root: mkdtempSync(join(tmpdir(), 'production-gates-')) })).toEqual([`Configuración: falta ${PRODUCTION_GATES}.`]);
    });
  });

  describe('release notes', () => {
    it('complete notes pass; an explicit "Sin cambios." is content', () => {
      expect(checkNotes(notes('v1.0.0'), 'v1.0.0')).toEqual([]);
    });

    it('fails without the trust-model section, a subsection, content, the tag, or with template markers', () => {
      expect(checkNotes('# Acceso Nostr v1.0.0\n\n## Resumen\n\nx\n', 'v1.0.0')[0]).toMatch(/sección obligatoria "## Cambios en el modelo de confianza"/);
      expect(checkNotes(notes('v1.0.0', { 'Custodia de llaves': undefined as unknown as string }), 'v1.0.0')).toEqual(['Notas: falta "### Custodia de llaves" en "Cambios en el modelo de confianza".']);
      expect(checkNotes(notes('v1.0.0', { 'Datos nuevos que se recopilan': '<!-- rellenar -->' }), 'v1.0.0')[0]).toMatch(/"### Datos nuevos que se recopilan" está vacía/);
      expect(checkNotes(notes('v1.0.0'), 'v2.0.0')[0]).toMatch(/debe incluir v2\.0\.0/);
      expect(checkNotes(notes('v1.0.0', { 'Custodia de llaves': '{{describir}}' }), 'v1.0.0')[0]).toMatch(/marcadores/);
    });

    it('the template is rejected as is, and the first release notes pass', () => {
      const template = readFileSync(join(root, 'docs/releases/TEMPLATE.md'), 'utf8');
      for (const s of TRUST_SUBSECTIONS) expect(template).toContain(`### ${s}`);
      expect(checkNotes(template, 'v0.0.0').length).toBeGreaterThan(0);
      expect(checkNotesFile({ tag: 'v0.1.0', root })).toEqual([]);
      expect(checkNotesFile({ tag: 'v9.9.9', root })[0]).toMatch(/falta docs\/releases\/v9\.9\.9\.md/);
    });

    it('the notes of a tag carry the maturity table of the README (PANEL-07)', () => {
      const dir = mkdtempSync(join(tmpdir(), 'notes-maturity-'));
      const table = '<!-- maturity:start (x) -->\n| Perfil | Hoy |\n|---|---|\n| sovereign-tor | Experimental |\n<!-- maturity:end -->';
      mkdirSync(join(dir, 'docs/releases'), { recursive: true });
      writeFileSync(join(dir, 'README.md'), `# x\n\n${table}\n`);
      const write = (body: string) => writeFileSync(join(dir, 'docs/releases/v1.0.0.md'), notes('v1.0.0') + body);
      write(`\n## Madurez por perfil y función\n\n${table}\n`);
      expect(checkNotesFile({ tag: 'v1.0.0', root: dir })).toEqual([]);
      write('');
      expect(checkNotesFile({ tag: 'v1.0.0', root: dir })).toEqual(['Notas: docs/releases/v1.0.0.md no tiene la tabla de madurez (PANEL-07): npx tsx scripts/maturity.ts docs/releases/v1.0.0.md.']);
      write(`\n${table.replace('Experimental', 'Beta')}\n`);
      expect(checkNotesFile({ tag: 'v1.0.0', root: dir })[0]).toMatch(/no es la del README/);
    });

    it('the CLI exits 0 / 1 and rejects malformed tags', () => {
      const run = (...args: string[]) => spawnSync(process.execPath, [join(root, 'scripts/release-gate.mjs'), ...args], { cwd: root, encoding: 'utf8' });
      expect(run('notes', '--tag', 'v0.1.0').status).toBe(0);
      const missing = run('notes', '--tag', 'v9.9.9');
      expect(missing.status).toBe(1);
      expect(missing.stderr).toContain('falta docs/releases/v9.9.9.md');
      expect(run('notes', '--tag', '../x').status).toBe(2);
      const config = run('config');
      expect(config.status).toBe(0);
      expect(config.stdout).toContain('OK    config');
    });
  });
});
