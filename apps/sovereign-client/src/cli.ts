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
 *   sovereign group keypackage --persona ID            (publish MLS key package so others can add you)
 *   sovereign group create --persona ID --name NAME     (Marmot/MLS: forward secrecy + PCS)
 *   sovereign group invite --persona ID --group GID --to NPUB
 *   sovereign group accept --persona ID                 (join groups from pending Welcomes)
 *   sovereign group send --persona ID --group GID "text"
 *   sovereign group read --persona ID --group GID
 *   sovereign group remove --persona ID --group GID --member NPUB
 *   sovereign group rotate --persona ID --group GID     (self-update: post-compromise security)
 *   sovereign group list --persona ID
 *
 * Env: SOVEREIGN_DATA_DIR (default ./.data/sovereign), SOVEREIGN_PASSPHRASE, TOR_SOCKS (127.0.0.1:9050),
 *      SOVEREIGN_FLAGS (deployment flags from the interop gate, default infra/web/flags.json if present)
 */
import { existsSync, readFileSync } from 'node:fs';
import { BUZZ_PINNED_ADAPTER, wrapOptionsFromFlags, type DeploymentFlags } from '@sedecim/messaging';
import { SovereignClient } from './app';

function relayAdapter() {
  const path = process.env.SOVEREIGN_FLAGS ?? 'infra/web/flags.json';
  if (!existsSync(path)) return BUZZ_PINNED_ADAPTER;
  const flags = JSON.parse(readFileSync(path, 'utf8')) as DeploymentFlags;
  if (!flags.nip17.enabled) throw new Error(`NIP-17 deshabilitado por el gate de interoperabilidad (${flags.relay})`);
  return { ...BUZZ_PINNED_ADAPTER, wrap: wrapOptionsFromFlags(flags, BUZZ_PINNED_ADAPTER.wrap) };
}

const argv = process.argv.slice(2);
const opt = (n: string) => (argv.includes(n) ? argv[argv.indexOf(n) + 1] : undefined);
const opts = (n: string) => argv.flatMap((a, i) => (a === n && argv[i + 1] ? [argv[i + 1]!] : []));
const positional = () => argv.filter((a, i) => !a.startsWith('--') && !(argv[i - 1]?.startsWith('--') && !['--tor', '--high-risk'].includes(argv[i - 1]!))).slice(2);

async function main() {
  const passphrase = process.env.SOVEREIGN_PASSPHRASE;
  if (!passphrase) throw new Error('set SOVEREIGN_PASSPHRASE (protects the local encrypted stores)');
  const [socksHost, socksPort] = (process.env.TOR_SOCKS ?? '127.0.0.1:9050').split(':');
  const needsDm = argv[0] === 'dm' && argv[1] === 'send';
  const client = new SovereignClient({ dataDir: process.env.SOVEREIGN_DATA_DIR ?? './.data/sovereign', passphrase, socksHost, socksPort: Number(socksPort), ...(needsDm ? { relayAdapter: relayAdapter() } : {}) });
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
    } else if (a === 'group') {
      const id = need();
      const gid = opt('--group');
      const show = (g: { groupId: string; name: string; epoch: number; members: string[] }) => console.log(`${g.groupId}  ${g.name}  epoch=${g.epoch}  members=${g.members.length}`);
      if (b === 'keypackage') console.log(`key package publicado: ${(await client.groupPublishKeyPackage(id)).id}`);
      else if (b === 'create') show(await client.groupCreate(id, opt('--name') ?? 'grupo'));
      else if (b === 'invite') show(await client.groupInvite(id, gid!, opt('--to')!));
      else if (b === 'accept') (await client.groupAccept(id)).forEach(show);
      else if (b === 'send') await client.groupSend(id, gid!, positional().join(' '));
      else if (b === 'read') for (const m of await client.groupSync(id, gid!)) console.log(`[${new Date(m.createdAt * 1000).toISOString()}] ${m.sender.slice(0, 8)}: ${m.content}`);
      else if (b === 'remove') show(await client.groupRemove(id, gid!, opt('--member')!));
      else if (b === 'rotate') show(await client.groupRotate(id, gid!));
      else if (b === 'list') (await client.groupList(id)).forEach(show);
      else throw new Error(`unknown group command: ${b}`);
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
