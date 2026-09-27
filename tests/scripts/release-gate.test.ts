import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  REQUIRED_AUDITS,
  REQUIRED_CI_JOBS,
  TRUST_SUBSECTIONS,
  checkAudits,
  checkCi,
  checkNotes,
  checkNotesFile,
  checkRestore,
  checkSbom,
  parseFields,
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

    it('the CLI exits 0 / 1 and rejects malformed tags', () => {
      const run = (...args: string[]) => spawnSync(process.execPath, [join(root, 'scripts/release-gate.mjs'), ...args], { cwd: root, encoding: 'utf8' });
      expect(run('notes', '--tag', 'v0.1.0').status).toBe(0);
      const missing = run('notes', '--tag', 'v9.9.9');
      expect(missing.status).toBe(1);
      expect(missing.stderr).toContain('falta docs/releases/v9.9.9.md');
      expect(run('notes', '--tag', '../x').status).toBe(2);
    });
  });
});
