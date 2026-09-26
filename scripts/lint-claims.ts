/**
 * FR028-03 — CI lint: no absolute privacy claims ("100% anónimo", "imposible de rastrear", …) in any
 * user-facing copy (spec §2.2). Scans string literals, template literal text and JSX text of the UI
 * sources with the same rules as assertNoAbsoluteClaims (packages/profiles), plus visible text of
 * HTML entry points. Read-only: it never modifies the scanned files.
 *
 *   npm run lint:claims                 (default roots)
 *   tsx scripts/lint-claims.ts DIR|FILE…
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import ts from 'typescript';
import { assertNoAbsoluteClaims } from '@sedecim/profiles';

export interface ClaimViolation {
  file: string;
  line: number;
  column: number;
  text: string;
}

export const DEFAULT_ROOTS = ['apps/web-saas/src', 'apps/web-saas/index.html', 'apps/sovereign-client/src', 'apps/key-generator/src', 'packages/profiles/src'];

const SOURCE_EXT = new Set(['.ts', '.tsx', '.mts', '.js', '.mjs', '.jsx']);
const SKIP_DIRS = new Set(['node_modules', 'dist', 'test', '__tests__']);

function isClaim(text: string): boolean {
  try {
    assertNoAbsoluteClaims(text);
    return false;
  } catch {
    return true;
  }
}

/** Finds absolute claims in the literals and JSX text of one TS/JS source. */
export function scanSource(file: string, source: string): ClaimViolation[] {
  const kind = file.endsWith('x') ? ts.ScriptKind.TSX : file.endsWith('.js') || file.endsWith('.mjs') ? ts.ScriptKind.JS : ts.ScriptKind.TS;
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, kind);
  const out: ClaimViolation[] = [];
  const report = (node: ts.Node, text: string) => {
    const normalized = text.replace(/\s+/g, ' ').trim();
    if (!normalized || !isClaim(normalized)) return;
    const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
    out.push({ file, line: line + 1, column: character + 1, text: normalized });
  };
  const visit = (node: ts.Node) => {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isJsxText(node)) report(node, node.text);
    else if (ts.isTemplateExpression(node)) {
      // Check each text span and the whole template with placeholders collapsed, so a claim split
      // around an interpolation is still caught.
      report(node, node.head.text + node.templateSpans.map((s) => ' ' + s.literal.text).join(''));
    } else if ((ts.isJsxElement(node) || ts.isJsxFragment(node)) && node.children.some((c) => ts.isJsxText(c) && c.text.trim())) {
      // JSX text split by inline elements (<p>100% <b>anónimo</b></p>) is checked as one sentence,
      // unless a single text node already carries the claim (reported on its own).
      const texts: string[] = [];
      // forEachChild stops at the first truthy return value, so collect must return undefined.
      const collect = (n: ts.Node): undefined => {
        if (ts.isJsxText(n)) texts.push(n.text);
        else if (ts.isJsxExpression(n)) texts.push(' ');
        else ts.forEachChild(n, collect);
        return undefined;
      };
      node.children.forEach(collect);
      if (!texts.some(isClaim)) report(node, texts.join(' '));
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}

/** Visible text of an HTML file (tags, scripts and styles removed), line by line. */
export function scanHtml(file: string, source: string): ClaimViolation[] {
  const blanked = source.replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, (m) => m.replace(/[^\n]/g, ' '));
  const out: ClaimViolation[] = [];
  blanked.split('\n').forEach((line, i) => {
    const text = line
      .replace(/<[^>]*?(?:title|alt|aria-label|content|placeholder)="([^"]*)"[^>]*>/gi, ' $1 ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    if (text && isClaim(text)) out.push({ file, line: i + 1, column: 1, text });
  });
  return out;
}

function* walk(path: string): Generator<string> {
  const st = statSync(path, { throwIfNoEntry: false });
  if (!st) return;
  if (st.isFile()) {
    yield path;
    return;
  }
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) yield* walk(join(path, entry.name));
    } else if (SOURCE_EXT.has(extname(entry.name)) || extname(entry.name) === '.html') yield join(path, entry.name);
  }
}

export function lintClaims(roots: string[] = DEFAULT_ROOTS, cwd = process.cwd()): ClaimViolation[] {
  const out: ClaimViolation[] = [];
  for (const root of roots)
    for (const abs of walk(resolve(cwd, root))) {
      const file = relative(cwd, abs) || abs;
      const source = readFileSync(abs, 'utf8');
      if (extname(abs) === '.html') out.push(...scanHtml(file, source));
      else if (SOURCE_EXT.has(extname(abs)) && !/\.d\.ts$/.test(abs)) out.push(...scanSource(file, source));
    }
  return out;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const roots = process.argv.slice(2);
  const violations = lintClaims(roots.length ? roots : DEFAULT_ROOTS);
  for (const v of violations) console.error(`${v.file}:${v.line}:${v.column}  afirmación absoluta de privacidad: "${v.text}"`);
  if (violations.length) {
    console.error(`\n${violations.length} afirmación(es) absoluta(s) encontradas. Usa lenguaje verificable (spec §2.2, FR-028).`);
    process.exit(1);
  }
  console.log(`lint:claims OK (${(roots.length ? roots : DEFAULT_ROOTS).join(', ')})`);
}
