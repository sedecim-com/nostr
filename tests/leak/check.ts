/**
 * Leak / egress verdict for one capture (used by scripts/leak-test.sh).
 *
 *   tsx tests/leak/check.ts --pcap run.pcap --client 10.200.0.2 --allow tcp/10.200.0.1:9050
 *   tsx tests/leak/check.ts --pcap run.pcap --client 10.200.0.2 --socks 10.200.0.1:9050 \
 *        --personas personas.txt --persona ID [--socks-log socks.jsonl]      (allowlist from the CLI's config)
 *   tsx tests/leak/check.ts ... --expect dns [--expect direct]              (negative control: must be detected)
 *
 * Positive mode exits 0 only when there are no findings AND at least --min-outbound packets were seen
 * (so an empty capture cannot pass). Negative mode exits 0 only when every expected kind was found.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { analyzeCapture, checkSocksRequests, networkAllowlist, parseEndpoint, parsePersonaList, type Endpoint, type FindingKind, type SocksRequest } from './analyze';
import { parsePcap } from './pcap';

const argv = process.argv.slice(2);
const opt = (n: string) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : undefined);
const opts = (n: string) => argv.flatMap((a, i) => (a === n && argv[i + 1] ? [argv[i + 1]!] : []));
const label = opt('--label') ?? 'capture';

const pcapPath = opt('--pcap');
if (!pcapPath) throw new Error('--pcap FILE required');
const clientAddrs = (opt('--client') ?? '').split(',').filter(Boolean);
if (!clientAddrs.length) throw new Error('--client IP[,IP] required');

let allowed: Endpoint[] = opts('--allow').map(parseEndpoint);
let socksProblems: string[] = [];
const personasFile = opt('--personas');
if (personasFile) {
  const socks = opt('--socks');
  if (!socks) throw new Error('--socks ip:port required with --personas');
  const personas = parsePersonaList(readFileSync(personasFile, 'utf8'));
  const id = opt('--persona');
  const persona = id ? personas.find((p) => p.id === id) : personas[0];
  if (!persona) throw new Error(`persona ${id ?? '(first)'} not found in ${personasFile}`);
  allowed = [...allowed, ...networkAllowlist(persona, parseEndpoint(socks))];
  const socksLog = opt('--socks-log');
  if (socksLog) {
    const requests = readFileSync(socksLog, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l) as SocksRequest);
    // FR006-06: the stub logs the SOCKS username of each CONNECT, so every one must carry the persona id.
    socksProblems = checkSocksRequests(requests, persona, { requireIsolation: persona.network === 'tor-only' });
    if (persona.network === 'tor-only' && !requests.length) socksProblems.push('no SOCKS request was logged: the client did no work through the proxy');
    console.log(`[${label}] SOCKS requests: ${requests.map((r) => `${r.host}:${r.port}(${r.addressType}${r.username ? `, user ${r.username}` : ''})`).join(', ') || 'none'}`);
  }
  console.log(`[${label}] persona ${persona.id} network=${persona.network} relays=${persona.relays.map((u) => u.href).join(',')}`);
}

const { packets, linkType } = parsePcap(readFileSync(pcapPath));
const report = analyzeCapture(packets, { clientAddrs, allowed });
const reportPath = opt('--report');
if (reportPath) writeFileSync(reportPath, JSON.stringify({ label, linkType, allowed, socksProblems, ...report }, null, 2) + '\n');

console.log(`[${label}] ${report.packets} packets (link type ${linkType}), ${report.outbound} outbound; allowlist: ${allowed.map((e) => `${e.protocol ?? '*'}/${e.ip}:${e.port}`).join(', ') || 'empty'}`);
console.log(`[${label}] destinations: ${report.destinations.join(', ') || 'none'}`);
const grouped = new Map<string, number>();
for (const f of report.findings) grouped.set(`${f.kind.padEnd(6)} ${f.detail}`, (grouped.get(`${f.kind.padEnd(6)} ${f.detail}`) ?? 0) + 1);
for (const [line, n] of grouped) console.log(`[${label}]   ${line} (${n} packet${n === 1 ? '' : 's'})`);
for (const p of socksProblems) console.log(`[${label}]   socks  ${p}`);

const expected = opts('--expect') as FindingKind[];
if (expected.length) {
  const missing = expected.filter((k) => !report.counts[k]);
  if (missing.length) {
    console.error(`[${label}] FAIL negative control: the harness did not detect ${missing.join(', ')} (it would miss a real leak)`);
    process.exit(1);
  }
  console.log(`[${label}] ok - negative control detected: ${expected.map((k) => `${k}=${report.counts[k]}`).join(', ')}`);
} else {
  const minOutbound = Number(opt('--min-outbound') ?? 1);
  const failures = [...report.findings.map((f) => `${f.kind}: ${f.detail}`), ...socksProblems];
  if (report.outbound < minOutbound) failures.push(`only ${report.outbound} outbound packets captured (expected >= ${minOutbound}): the client did no network work or the capture is broken`);
  if (failures.length) {
    console.error(`[${label}] FAIL ${failures.length} problem(s): ${[...new Set(failures)].slice(0, 10).join(' | ')}`);
    process.exit(1);
  }
  console.log(`[${label}] ok - zero DNS, zero IPv6, every connection inside the allowlist`);
}
