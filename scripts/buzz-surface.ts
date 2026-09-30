// SEC-12: what a client without credentials reaches on Buzz (docs/security/buzz-attack-surface.md).
//   npx tsx scripts/buzz-surface.ts --relay http://localhost:3000 [--out report.json]
//       the relay itself (CI job `stack`): no route that needs credentials may answer without them, and none may fail.
//   npx tsx scripts/buzz-surface.ts --edge https://<relay host> [--out report.json]
//       through the public edge (nginx or Caddy): only / and /media/* reach Buzz; every other route gets the edge's 404.
//   npx tsx scripts/buzz-surface.ts --table
//       prints the route table the inventory embeds.
// Exits 1 on any violation, 2 when the relay does not answer like Buzz (then the checks would pass for the wrong reason).
import { writeFileSync } from 'node:fs';
import { ROUTES, edgeViolations, probe, relayViolations, surfaceTable } from './buzz-surface-routes';

const args = process.argv.slice(2);
// Prints the route table of the inventory (docs/security/buzz-attack-surface.md, between its routes markers).
if (args.includes('--table')) {
  console.log(surfaceTable());
  process.exit(0);
}
const flag = (name: string) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
const edge = flag('--edge');
const relay = flag('--relay');
const out = flag('--out');
const base = edge ?? relay;
if (!base || (edge && relay)) {
  console.error('usage: buzz-surface.ts (--relay URL | --edge URL) [--out report.json]');
  process.exit(2);
}

// The NIP-11 document says it is Buzz and that the host is mapped to a community: an unmapped Host answers 404 everywhere.
let nip11Res: Response;
try {
  nip11Res = await fetch(base, { headers: { accept: 'application/nostr+json' }, signal: AbortSignal.timeout(10_000) });
} catch (e) {
  console.error(`${base} does not answer: ${(e as Error).message}`);
  process.exit(2);
}
const nip11 = (nip11Res.ok ? await nip11Res.json().catch(() => undefined) : undefined) as { software?: string; version?: string; supported_nips?: number[] } | undefined;
if (!nip11?.supported_nips?.includes(42) || !/buzz/i.test(nip11.software ?? '')) {
  console.error(`${base} does not answer with the NIP-11 document of Buzz (status ${nip11Res.status}): is the Host mapped to a community?`);
  process.exit(2);
}

const results = await probe(base);
const violations = edge ? edgeViolations(results) : relayViolations(results);
const pad = (s: string | number, n: number) => String(s).padEnd(n);
for (const p of results) console.log(`${pad(p.status, 4)} ${pad(p.route.method, 7)} ${pad(p.route.path, 52)} ${pad(p.route.exposure, 14)} edge:${p.route.edge}`);
if (out) {
  writeFileSync(
    out,
    JSON.stringify(
      {
        target: base,
        mode: edge ? 'edge' : 'relay',
        checkedAt: new Date().toISOString(),
        relay: { software: nip11.software, version: nip11.version, supportedNips: nip11.supported_nips },
        routes: results.map((p) => ({ method: p.route.method, path: p.route.path, exposure: p.route.exposure, edge: p.route.edge, status: p.status })),
        violations,
      },
      null,
      2,
    ) + '\n',
  );
}
if (violations.length) {
  console.error(`\nbuzz-surface: ${violations.length} violation(s)\n${violations.map((v) => `  - ${v}`).join('\n')}`);
  process.exit(1);
}
console.log(`\nbuzz-surface ok (${edge ? 'edge' : 'relay'}): ${results.length} routes probed on ${base}; ${ROUTES.filter((x) => x.edge === 'allow').length} of them are what the public edge forwards`);
