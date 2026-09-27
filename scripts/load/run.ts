// NFR005-02: load test of the relay and the indexer; writes <out>.json and <out>.md (docs/load-testing.md).
//   npx tsx scripts/load/run.ts --relay ws://localhost:3000 --indexer http://localhost:8081[,http://localhost:8091] \
//     [--profile smoke|baseline|stress] [--clients N] [--rate EV_PER_S_PER_CLIENT] [--duration S] [--sizes 256,1024]
//     [--mix 9=80,1059=15,1=5] [--channels N] [--lag-sample 0.2] [--drain S] [--steps 1,2,5] [--out load-report]
//   npx tsx scripts/load/run.ts --local [--local-indexers 2] [--database-url postgres://…] …   (test relay + in-process indexer)
// --steps runs one step per per-client rate (ramp) to find where the limits (lib.ts LIMITS) are crossed.
import { spawn, type ChildProcess } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { PROFILES, runLoad, toMarkdown, verdict, type LoadOptions, type LoadReport } from './lib';

const args = process.argv.slice(2);
const arg = (name: string) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
const num = (name: string) => (arg(name) !== undefined ? Number(arg(name)) : undefined);
const list = (name: string) => arg(name)?.split(',').map((s) => s.trim()).filter(Boolean);

const profileName = arg('--profile') ?? 'smoke';
const profile = PROFILES[profileName];
if (!profile) throw new Error(`unknown profile ${profileName} (${Object.keys(PROFILES).join(', ')})`);

/** Starts scripts/load/local-stack.ts in a child process so the target does not share the generator's CPU. */
async function localStack(indexers: number, databaseUrl?: string): Promise<{ relay: string; indexers: string[]; child: ChildProcess }> {
  const script = fileURLToPath(new URL('./local-stack.ts', import.meta.url));
  const child = spawn(process.execPath, ['--import', 'tsx', script, '--indexers', String(indexers), ...(databaseUrl ? ['--database-url', databaseUrl] : [])], { stdio: ['ignore', 'pipe', 'inherit'] });
  const lines = createInterface({ input: child.stdout! });
  for await (const line of lines) {
    if (line.startsWith('{"relay"')) return { ...(JSON.parse(line) as { relay: string; indexers: string[] }), child };
  }
  throw new Error('local stack exited before printing its URLs');
}

let child: ChildProcess | undefined;
let relay = arg('--relay');
let indexers = list('--indexer') ?? [];
if (args.includes('--local')) {
  const stack = await localStack(num('--local-indexers') ?? 1, arg('--database-url'));
  ({ relay, indexers, child } = stack);
}
if (!relay) throw new Error('--relay ws://… (or --local) is required');

const base: Partial<LoadOptions> & Pick<LoadOptions, 'relay'> = {
  ...profile,
  relay,
  indexers,
  ...(num('--clients') !== undefined ? { clients: num('--clients') } : {}),
  ...(num('--rate') !== undefined ? { rate: num('--rate') } : {}),
  ...(num('--duration') !== undefined ? { durationS: num('--duration') } : {}),
  ...(list('--sizes') ? { sizes: list('--sizes')!.map(Number) } : {}),
  ...(arg('--mix') ? { mix: Object.fromEntries(list('--mix')!.map((p) => p.split('=').map(Number) as [number, number])) } : {}),
  ...(num('--channels') !== undefined ? { channels: num('--channels') } : {}),
  ...(num('--lag-sample') !== undefined ? { lagSample: num('--lag-sample') } : {}),
  ...(num('--drain') !== undefined ? { drainS: num('--drain') } : {}),
  log: (m: string) => console.error(`[load] ${m}`),
};

const steps = list('--steps')?.map(Number) ?? [base.rate ?? 2];
const reports: LoadReport[] = [];
try {
  for (const rate of steps) {
    const label = `${arg('--label') ?? profileName} · ${base.clients ?? '?'}×${rate} ev/s`;
    console.error(`[load] step ${label}`);
    const r = await runLoad({ ...base, rate, label });
    reports.push(r);
    const v = verdict(r);
    console.error(`[load] ${label}: ${r.publish.throughputOkPerS} ev/s OK, ACK p95 ${r.publish.ackMs.p95} ms, entrega ${(r.delivery.ratio * 100).toFixed(1)} %, lag p95 ${r.indexer.lagMs.p95} ms → ${v.length ? v.join('; ') : 'OK'}`);
  }
} finally {
  child?.kill('SIGTERM');
}

const out = arg('--out') ?? 'load-report';
writeFileSync(`${out}.json`, JSON.stringify({ target: args.includes('--local') ? 'local test-relay + in-process indexer' : 'external', node: process.version, reports }, null, 2) + '\n');
writeFileSync(`${out}.md`, toMarkdown(reports, arg('--title') ?? 'Informe de carga'));
console.error(`[load] wrote ${out}.json and ${out}.md`);
