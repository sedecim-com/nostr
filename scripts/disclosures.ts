// Generates docs/disclosures.md from the panel copy for legal/UX review (FR028-02).
//   npx tsx scripts/disclosures.ts          (write)
//   npx tsx scripts/disclosures.ts --check  (exit 1 if the committed document is stale)
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { DISCLOSURE_VERSION, disclosureCatalog } from '@sedecim/profiles';

const catalog = disclosureCatalog();
const digest = createHash('sha256').update(JSON.stringify(catalog)).digest('hex').slice(0, 16);
const esc = (s: string) => s.replace(/\|/g, '\\|');
const lines = [
  '# Textos de disclosure del panel de soberanía',
  '',
  '> Generado por `npx tsx scripts/disclosures.ts` desde `packages/profiles` (no editar a mano).',
  `> Versión **${DISCLOSURE_VERSION}** · huella \`${digest}\` · estado: **pendiente de aprobación legal y UX** (FR028-02).`,
  '',
  'Cambiar cualquier texto exige subir `DISCLOSURE_VERSION` y volver a pasar la revisión. Las afirmaciones absolutas',
  '("100 % anónimo", "imposible de rastrear") están prohibidas por `assertNoAbsoluteClaims`.',
  '',
  '| Control | Opción | Texto mostrado | Refuerza | Reduce | Confías en |',
  '|---|---|---|---|---|---|',
  ...catalog.map((d) => `| ${d.control} | ${d.option} | ${esc(d.statement)} | ${d.improves.join(', ') || '—'} | ${d.sacrifices.join(', ') || '—'} | ${esc(d.trustAssumptions.join(' ')) || '—'} |`),
  '',
  '## Aprobación',
  '',
  '| Rol | Nombre | Fecha | Versión aprobada |',
  '|---|---|---|---|',
  '| Legal | | | |',
  '| UX | | | |',
  '',
];
const out = lines.join('\n');
const path = new URL('../docs/disclosures.md', import.meta.url);
if (process.argv.includes('--check')) {
  let current = '';
  try {
    current = readFileSync(path, 'utf8');
  } catch {
    /* missing */
  }
  // The approval table is edited by hand: compare only the generated part.
  const generated = (s: string) => s.split('## Aprobación')[0];
  if (generated(current) !== generated(out)) {
    console.error('docs/disclosures.md is stale: run npx tsx scripts/disclosures.ts (and bump DISCLOSURE_VERSION if a text changed)');
    process.exit(1);
  }
  console.log(`disclosures ok: v${DISCLOSURE_VERSION} (${catalog.length} textos)`);
} else {
  let approval = '';
  try {
    approval = readFileSync(path, 'utf8').split('## Aprobación')[1] ?? '';
  } catch {
    /* first run */
  }
  writeFileSync(path, approval ? out.split('## Aprobación')[0] + '## Aprobación' + approval : out);
  console.log(`wrote docs/disclosures.md (v${DISCLOSURE_VERSION}, ${catalog.length} textos)`);
}
