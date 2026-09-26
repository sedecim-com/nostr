/**
 * sovereign — self-hosted Nostr client (Sovereign / Sovereign Tor modes).
 *
 *   sovereign persona create --label NAME --relay URL [--relay URL] [--tor] [--high-risk]
 *   sovereign persona list
 *   sovereign whoami --persona ID
 *   sovereign channel send --persona ID --group G "text"
 *   sovereign channel read --persona ID --group G
 *   sovereign dm send --persona ID --to NPUB "text"
 *   sovereign dm inbox --persona ID
 *   sovereign outbox --persona ID        (delivery states per relay)
 *   sovereign resume --persona ID        (retry pending messages)
 *   sovereign disclose --persona ID      (what each setting implies)
 *
 * Env: SOVEREIGN_DATA_DIR (default ./.data/sovereign), SOVEREIGN_PASSPHRASE, TOR_SOCKS (127.0.0.1:9050)
 */
import { SovereignClient } from './app';

const argv = process.argv.slice(2);
const opt = (n: string) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : undefined);
const opts = (n: string) => argv.flatMap((a, i) => (a === n && argv[i + 1] ? [argv[i + 1]!] : []));
const positional = () => argv.filter((a, i) => !a.startsWith('--') && !(argv[i - 1]?.startsWith('--') && !['--tor', '--high-risk'].includes(argv[i - 1]!))).slice(2);

async function main() {
  const passphrase = process.env.SOVEREIGN_PASSPHRASE;
  if (!passphrase) throw new Error('set SOVEREIGN_PASSPHRASE (protects the local encrypted stores)');
  const [socksHost, socksPort] = (process.env.TOR_SOCKS ?? '127.0.0.1:9050').split(':');
  const client = new SovereignClient({ dataDir: process.env.SOVEREIGN_DATA_DIR ?? './.data/sovereign', passphrase, socksHost, socksPort: Number(socksPort) });
  const persona = opt('--persona');
  const need = () => {
    if (!persona) throw new Error('--persona ID required');
    return persona;
  };
  try {
    const [a, b] = argv;
    if (a === 'persona' && b === 'create') {
      const p = await client.createPersona({ label: opt('--label') ?? 'persona', relays: opts('--relay'), tor: argv.includes('--tor'), highRisk: argv.includes('--high-risk') });
      console.log(JSON.stringify(p, null, 2));
    } else if (a === 'persona' && b === 'list') {
      for (const p of await (await client.identities()).list()) console.log(`${p.id}  ${p.label.padEnd(16)} ${p.network.padEnd(8)} ${p.compartment.padEnd(12)} ${p.relays.join(',')}`);
    } else if (a === 'whoami') {
      console.log(await (await client.identities()).sendingAs(need()));
    } else if (a === 'channel' && b === 'send') {
      const rec = await client.sendChannel(need(), opt('--group')!, positional().join(' '));
      console.log(`${rec.state}${rec.blockedReason ? ` — ${rec.blockedReason}` : ''} (op ${rec.opId})`);
    } else if (a === 'channel' && b === 'read') {
      for (const e of await client.readChannel(need(), opt('--group')!)) console.log(`[${new Date(e.created_at * 1000).toISOString()}] ${e.pubkey.slice(0, 8)}: ${e.content}`);
    } else if (a === 'dm' && b === 'send') {
      const recs = await client.sendDm(need(), opt('--to')!, positional().join(' '));
      for (const r of recs) console.log(`${r.meta?.recipient?.slice(0, 8)} ${r.state}${r.blockedReason ? ` — ${r.blockedReason}` : ''}`);
    } else if (a === 'dm' && b === 'inbox') {
      for (const m of await client.inbox(need())) console.log(`[${new Date(m.rumor.created_at * 1000).toISOString()}] ${m.sender.slice(0, 8)}: ${m.rumor.content}`);
    } else if (a === 'outbox') {
      for (const r of await client.outbox(need())) {
        console.log(`${r.opId.slice(0, 8)} ${r.state.padEnd(16)} ${r.blockedReason ?? ''}`);
        for (const s of Object.values(r.relayStatus)) console.log(`   ${s.relay} attempts=${s.attemptCount} ${s.acceptedAt ? 'ACK' : (s.lastError ?? 'pending')}`);
      }
    } else if (a === 'resume') {
      for (const r of await client.resume(need())) console.log(`${r.opId.slice(0, 8)} ${r.state}`);
    } else if (a === 'disclose') {
      for (const d of await client.disclosures(need())) console.log(`• [${d.control}=${d.option}] ${d.statement}`);
    } else {
      console.log('usage: see header of apps/sovereign-client/src/cli.ts');
      process.exitCode = 2;
    }
  } finally {
    client.close();
  }
}

main().catch((err: Error) => {
  console.error(`error: ${err.message}`);
  process.exit(1);
});
