import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { DEFAULT_ROOTS, lintClaims, scanSource } from '../../scripts/lint-claims';

const root = new URL('../..', import.meta.url).pathname;
const fixtures = 'tests/scripts/fixtures/lint-claims';
const tsx = join(root, 'node_modules/.bin/tsx');

describe('scripts/lint-claims.ts (FR028-03)', () => {
  it('reports absolute claims in string literals, templates, JSX text/attributes, HTML and Markdown with file:line', () => {
    const v = lintClaims([`${fixtures}/bad`], root);
    const where = v.map((x) => `${x.file.split('/').pop()}:${x.line}`).sort();
    expect(where).toEqual(['Landing.tsx:5', 'Landing.tsx:6', 'Landing.tsx:7', 'copy.ts:2', 'copy.ts:3', 'index.html:4', 'notes.md:3'].sort());
    expect(v.find((x) => x.file.endsWith('Landing.tsx') && x.line === 7)!.text).toBe('Tu actividad es 100% anónima con nosotros');
    expect(v.every((x) => x.file.startsWith(fixtures))).toBe(true);
  });

  it('accepts verifiable copy and ignores regexes and comments', () => {
    expect(lintClaims([`${fixtures}/ok`], root)).toEqual([]);
    expect(scanSource('x.ts', "const re = /untraceable/; // untraceable\nconst s = 'rastreable con esfuerzo';")).toEqual([]);
  });

  it('the CLI exits non-zero listing file:line, and the real UI copy passes', () => {
    const bad = spawnSync(tsx, [join(root, 'scripts/lint-claims.ts'), `${fixtures}/bad`], { cwd: root, encoding: 'utf8' });
    expect(bad.status).toBe(1);
    expect(bad.stderr).toMatch(new RegExp(`${fixtures}/bad/copy\\.ts:2:\\d+  afirmación absoluta de privacidad: "Private and untraceable messaging"`));
    expect(bad.stderr).toContain('7 afirmación(es)');
    expect(DEFAULT_ROOTS).toEqual(expect.arrayContaining(['apps/web-saas/src', 'docs/releases']));
    const ok = spawnSync(tsx, [join(root, 'scripts/lint-claims.ts')], { cwd: root, encoding: 'utf8' });
    expect(ok.status, ok.stderr).toBe(0);
  });
});
