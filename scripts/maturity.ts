// PANEL-07: the maturity table of README.md and of the release notes comes from packages/profiles/src/maturity.ts,
// the catalog the web and the CLI show. The release gate requires the notes of a tag to carry the README's table.
//   npx tsx scripts/maturity.ts                  (write README.md and docs/releases/TEMPLATE.md)
//   npx tsx scripts/maturity.ts --check          (exit 1 if either is stale; CI)
//   npx tsx scripts/maturity.ts docs/releases/vX.Y.Z.md   (the notes of a release that is not out yet)
import { readFileSync, writeFileSync } from 'node:fs';
import { maturityTable } from '@sedecim/profiles';

const START = '<!-- maturity:start (scripts/maturity.ts desde packages/profiles/src/maturity.ts; no editar a mano) -->';
const END = '<!-- maturity:end -->';

const args = process.argv.slice(2);
const check = args.includes('--check');
const files = args.filter((a) => a !== '--check');
const block = `${START}\n${maturityTable()}\n${END}`;

let failed = false;
for (const file of files.length ? files : ['README.md', 'docs/releases/TEMPLATE.md']) {
  const text = readFileSync(file, 'utf8');
  const i = text.indexOf('<!-- maturity:start');
  const j = text.indexOf(END, i);
  if (i < 0 || j < 0) {
    console.error(`${file}: add the lines "${START}" and "${END}" where the maturity table goes`);
    failed = true;
    continue;
  }
  const next = text.slice(0, i) + block + text.slice(j + END.length);
  if (next === text) continue;
  if (check) {
    console.error(`${file}: the maturity table is stale; run npx tsx scripts/maturity.ts${files.length ? ` ${file}` : ''}`);
    failed = true;
  } else {
    writeFileSync(file, next);
    console.log(`${file}: maturity table updated`);
  }
}
if (failed) process.exit(1);
if (check) console.log('maturity tables ok');
