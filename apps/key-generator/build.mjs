// Builds a single-file, dependency-free offline bundle plus SHA-256 checksum (release artifact).
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';

mkdirSync(new URL('./dist', import.meta.url), { recursive: true });
const outfile = new URL('./dist/keygen.mjs', import.meta.url).pathname;
await build({
  entryPoints: [new URL('./src/cli.ts', import.meta.url).pathname],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  outfile,
  legalComments: 'inline',
  banner: { js: '#!/usr/bin/env node' },
});
const sum = createHash('sha256').update(readFileSync(outfile)).digest('hex');
writeFileSync(outfile + '.sha256', `${sum}  keygen.mjs\n`);
console.log(`${outfile}\nsha256 ${sum}`);
