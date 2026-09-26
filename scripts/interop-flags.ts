// Turns the interop gate report into the deployment flags served to clients (FR-017).
//   npx tsx scripts/interop-flags.ts [report] [--check]
// --check fails when the committed infra/web/flags.json disagrees with the gate result (drift).
import { readFileSync, writeFileSync } from 'node:fs';
import { flagsFromInteropReport } from '@sedecim/messaging';

const args = process.argv.slice(2);
const reportPath = args.find((a) => !a.startsWith('--')) ?? 'interop-report.json';
const out = new URL('../infra/web/flags.json', import.meta.url);
const pin = Object.fromEntries(
  readFileSync(new URL('../infra/buzz/PIN', import.meta.url), 'utf8')
    .split('\n')
    .filter((l) => /^[A-Z_]+=/.test(l))
    .map((l) => l.split('=') as [string, string]),
);
const flags = flagsFromInteropReport(JSON.parse(readFileSync(reportPath, 'utf8')), `buzz@${pin.BUZZ_COMMIT!.slice(0, 7)}`, 'tests/interop/buzz.interop.test.ts');
const comparable = (f: { nip17: unknown; relay: string }) => JSON.stringify({ nip17: f.nip17, relay: f.relay });

if (args.includes('--check')) {
  const committed = JSON.parse(readFileSync(out, 'utf8'));
  if (comparable(committed) !== comparable(flags)) {
    console.error(`flags drift: committed ${comparable(committed)} vs gate ${comparable(flags)}. Run npx tsx scripts/interop-flags.ts ${reportPath}`);
    process.exit(1);
  }
  console.log(`flags match gate: ${comparable(flags)}`);
} else {
  writeFileSync(out, JSON.stringify(flags, null, 2) + '\n');
  console.log(`wrote infra/web/flags.json: ${comparable(flags)}`);
}
