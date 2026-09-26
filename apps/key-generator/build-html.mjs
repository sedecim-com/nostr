// Builds the air-gapped generator as ONE self-contained HTML file (FR003-05) plus its SHA-256 checksum:
// the browser bundle is inlined and pinned by hash in a CSP that forbids any network access.
//   node apps/key-generator/build-html.mjs [--outdir DIR]
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const here = new URL('.', import.meta.url).pathname;
const argOut = process.argv.indexOf('--outdir');
const outdir = argOut > 0 ? resolve(process.argv[argOut + 1]) : join(here, 'dist');
mkdirSync(outdir, { recursive: true });

const sha256Base64 = (text) => createHash('sha256').update(text, 'utf8').digest('base64');

// Browser bundle: no Node built-ins may leak in (platform=browser fails the build if they do).
const app = await build({
  entryPoints: [join(here, 'src/browser.ts')],
  bundle: true,
  platform: 'browser',
  format: 'iife',
  target: ['es2020'],
  minify: true,
  write: false,
  legalComments: 'eof',
});
// HTML shell (TypeScript), bundled in memory and loaded as a data: module.
const shell = await build({ entryPoints: [join(here, 'src/air-gapped-page.ts')], bundle: true, platform: 'neutral', format: 'esm', write: false });
const { airGappedPage } = await import(`data:text/javascript;base64,${Buffer.from(shell.outputFiles[0].text).toString('base64')}`);

const html = airGappedPage(app.outputFiles[0].text, sha256Base64);
const outfile = join(outdir, 'keygen.html');
writeFileSync(outfile, html);
const sum = createHash('sha256').update(html).digest('hex');
writeFileSync(`${outfile}.sha256`, `${sum}  keygen.html\n`);
console.log(`${outfile}\nsha256 ${sum}`);
