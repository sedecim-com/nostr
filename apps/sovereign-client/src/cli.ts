/**
 * sovereign — self-hosted Nostr client (Sovereign / Sovereign Tor modes).
 *
 *   sovereign persona create --label NAME --relay URL [--relay URL] [--tor] [--high-risk]
 *   sovereign persona import --backup FILE --label NAME --relay URL [--tor] [--high-risk] [--password-file f]
 *                                        (key backup from keygen or the web; ncryptsec must match the npub)
 *   sovereign persona list
 *   sovereign backup export --persona ID --out FILE [--password-file f] [--no-mls]   (key, relays, panel, MLS state;
 *                                        --no-mls: to set up an additional device, then `group add-device`)
 *   sovereign backup restore FILE [--password-file f]
 *   sovereign whoami --persona ID
 *   sovereign channel join --persona ID --group G         (NIP-29 join request)
 *   sovereign channel send --persona ID --group G "text"
 *   sovereign channel read --persona ID --group G
 *   sovereign dm send --persona ID --to NPUB "text"
 *   sovereign dm inbox --persona ID
 *   sovereign outbox --persona ID        (delivery states per relay)
 *   sovereign resume --persona ID        (retry pending messages; any command that opens the persona does too)
 *   sovereign history sync --persona ID [--since UNIX] [--group G]   (rebuild channels/DMs; NIP-77 or REQ fallback)
 *   sovereign history export --persona ID --out FILE [--since UNIX]  (JSONL, one signed NIP-01 event per line)
 *   sovereign history import --persona ID FILE [--dry-run]           (verify signatures, republish valid events)
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
 *   sovereign group device --persona ID [--label NAME]           (this installation's MLS device id / label)
 *   sovereign group devices --persona ID --group GID             (leaves: one per device of each persona)
 *   sovereign group add-device --persona ID --group GID [--member NPUB]
 *                                        (admin: commit; member: propose; default member = this persona)
 *   sovereign group remove-device --persona ID --group GID --leaf N          (admin)
 *   sovereign group propose --persona ID --group GID (--add NPUB | --remove NPUB)   (any member)
 *   sovereign group proposals --persona ID --group GID
 *   sovereign group commit --persona ID --group GID [--ref REF ...]          (admin commits proposals)
 *   sovereign group rejoin --persona ID [--group GID]            (after backup restore: new leaf, old removed)
 *   sovereign group send-file --persona ID --group GID --file PATH [--mime TYPE] [--server URL] ["caption"]
 *   sovereign group fetch-file --persona ID --group GID --sha HEX --out FILE (MIP-04 download + decrypt)
 *   sovereign group rotation-worker --persona ID --policy URL [--managed-signer URL] [--interval S] [--once]
 *                                        (FR-024: MLS Remove for the rotations the policy-engine flags on
 *                                        revocation; with --managed-signer, propagates device revocations)
 *
 * Env: SOVEREIGN_DATA_DIR (default ./.data/sovereign), SOVEREIGN_PASSPHRASE, TOR_SOCKS (127.0.0.1:9050),
 *      SOVEREIGN_BACKUP_PASSWORD (backup files, when --password-file is not given),
 *      SOVEREIGN_BLOB_STORE (fallback Blossom/blob-store URL for encrypted group media),
 *      SOVEREIGN_FLAGS (deployment flags from the interop gate, default infra/web/flags.json if present),
 *      SOVEREIGN_POLICY_BEARER (optional service bearer for POST /v1/rotations/:id/done and GET /v1/revocations;
 *        NIP-98 otherwise),
 *      SOVEREIGN_REVOCATION_TOKEN (managed-signer revocation token, required with --managed-signer)
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, extname } from 'node:path';
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
const positional = () => argv.filter((a, i) => !a.startsWith('--') && !(argv[i - 1]?.startsWith('--') && !['--tor', '--high-risk', '--dry-run', '--no-mls', '--once'].includes(argv[i - 1]!))).slice(2);
const MIME: Record<string, string> = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.webp': 'image/webp', '.mp4': 'video/mp4', '.pdf': 'application/pdf', '.txt': 'text/plain' };
const since = () => (opt('--since') !== undefined ? Number(opt('--since')) : undefined);

/** Password of a backup file: --password-file (first line) or SOVEREIGN_BACKUP_PASSWORD. */
function backupPassword(): string {
  const file = opt('--password-file');
  const pw = file ? readFileSync(file, 'utf8').replace(/\r?\n$/, '') : process.env.SOVEREIGN_BACKUP_PASSWORD;
  if (!pw) throw new Error('backup password required: --password-file FILE or SOVEREIGN_BACKUP_PASSWORD');
  return pw;
}

async function main() {
  const passphrase = process.env.SOVEREIGN_PASSPHRASE;
  if (!passphrase) throw new Error('set SOVEREIGN_PASSPHRASE (protects the local encrypted stores)');
  const [socksHost, socksPort] = (process.env.TOR_SOCKS ?? '127.0.0.1:9050').split(':');
  const needsDm = argv[0] === 'dm' && argv[1] === 'send';
  const client = new SovereignClient({
    dataDir: process.env.SOVEREIGN_DATA_DIR ?? './.data/sovereign',
    passphrase,
    socksHost,
    socksPort: Number(socksPort),
    ...(needsDm ? { relayAdapter: relayAdapter() } : {}),
    ...(process.env.SOVEREIGN_BLOB_STORE ? { blobStore: process.env.SOVEREIGN_BLOB_STORE } : {}),
  });
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
    } else if (a === 'persona' && b === 'import') {
      const file = opt('--backup');
      if (!file) throw new Error('--backup FILE required (JSON from keygen or from the web)');
      const p = await client.importBackup(readFileSync(file, 'utf8'), backupPassword(), { label: opt('--label') ?? 'persona', relays: opts('--relay'), tor: argv.includes('--tor'), highRisk: argv.includes('--high-risk') });
      console.log(JSON.stringify(p, null, 2));
    } else if (a === 'backup' && b === 'export') {
      const out = opt('--out');
      if (!out) throw new Error('--out FILE required');
      const pkg = await client.exportBackup(need(), backupPassword(), argv.includes('--no-mls') ? { includeMls: false } : {});
      writeFileSync(out, JSON.stringify(pkg, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
      console.log(`backup cifrado (llave, relays, panel${argv.includes('--no-mls') ? '' : ', grupos MLS'}) escrito en ${out}`);
    } else if (a === 'backup' && b === 'restore') {
      const file = positional()[0];
      if (!file) throw new Error('usage: sovereign backup restore FILE');
      const p = await client.restoreBackup(JSON.parse(readFileSync(file, 'utf8')), backupPassword());
      console.log(JSON.stringify(p, null, 2));
    } else if (a === 'persona' && b === 'list') {
      for (const p of await (await client.identities()).list()) console.log(`${p.id}  ${p.label.padEnd(16)} ${p.network.padEnd(8)} ${p.compartment.padEnd(12)} ${p.relays.join(',')}`);
    } else if (a === 'whoami') {
      console.log(await (await client.identities()).sendingAs(need()));
    } else if (a === 'channel' && b === 'join') {
      const rec = await client.joinChannel(need(), opt('--group')!);
      console.log(`${rec.state}${rec.blockedReason ? ` — ${rec.blockedReason}` : ''} (op ${rec.opId})`);
    } else if (a === 'history' && b === 'sync') {
      const r = await client.syncHistory(need(), { since: since(), channels: opts('--group') });
      for (const [relay, strategy] of Object.entries(r.strategies)) console.log(`${relay}  ${strategy}`);
      for (const [g, events] of Object.entries(r.channels)) console.log(`canal ${g}: ${events.length} eventos`);
      console.log(`DMs: ${r.dms.length}; outbox: ${r.outbox.map((o) => o.state).join(', ') || 'vacío'}`);
    } else if (a === 'history' && b === 'export') {
      const out = opt('--out');
      if (!out) throw new Error('--out FILE required');
      const jsonl = await client.exportHistory(need(), { since: since() });
      writeFileSync(out, jsonl, { mode: 0o600, flag: 'wx' });
      console.log(`${jsonl ? jsonl.trimEnd().split('\n').length : 0} eventos firmados exportados a ${out} (JSONL)`);
    } else if (a === 'history' && b === 'import') {
      const file = positional()[0];
      if (!file) throw new Error('usage: sovereign history import --persona ID FILE [--dry-run]');
      const r = await client.importHistory(need(), readFileSync(file, 'utf8'), { dryRun: argv.includes('--dry-run') });
      for (const i of r.invalid) console.log(`línea ${i.line}: ${i.reason}`);
      console.log(`válidos=${r.valid} inválidos=${r.invalid.length} duplicados=${r.duplicates} publicados=${r.published} rechazados=${r.rejected}`);
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
      else if (b === 'read')
        for (const m of await client.groupSync(id, gid!)) {
          console.log(`[${new Date(m.createdAt * 1000).toISOString()}] ${m.sender.slice(0, 8)}: ${m.content}`);
          for (const f of m.media ?? []) console.log(`   [archivo ${f.filename} ${f.type} ${f.size ?? '?'} B] --sha ${f.sha256}`);
        }
      else if (b === 'remove') show(await client.groupRemove(id, gid!, opt('--member')!));
      else if (b === 'rotate') show(await client.groupRotate(id, gid!));
      else if (b === 'list') (await client.groupList(id)).forEach(show);
      else if (b === 'device') {
        const label = opt('--label');
        const d = label !== undefined ? await client.setDeviceLabel(id, label) : await client.device(id);
        console.log(`dispositivo ${d.id}${d.label ? ` (${d.label})` : ''}${d.cloned ? ' — restaurado de backup: ejecuta group rejoin' : ''}`);
      } else if (b === 'devices')
        for (const d of await client.groupDevices(id, gid!)) console.log(`hoja ${d.leafIndex}  ${d.pubkey.slice(0, 8)}  ${d.deviceId ?? '?'}${d.label ? ` (${d.label})` : ''}${d.self ? '  ← este dispositivo' : ''}`);
      else if (b === 'add-device') {
        const r = await client.groupAddDevice(id, gid!, opt('--member'));
        if (r.committed) show(r.group);
        else console.log(`propuesto (${r.proposals.length}); un admin debe ejecutar group commit`);
      } else if (b === 'remove-device') show(await client.groupRemoveDevice(id, gid!, Number(opt('--leaf'))));
      else if (b === 'propose') {
        const r = await client.groupPropose(id, gid!, { ...(opt('--add') ? { add: opt('--add')! } : {}), ...(opt('--remove') ? { remove: opt('--remove')! } : {}) });
        for (const p of r) console.log(`propuesta ${p.type} ${p.ref}`);
      } else if (b === 'proposals')
        for (const p of await client.groupProposals(id, gid!)) console.log(`${p.ref}  ${p.type.padEnd(7)} de ${p.proposer?.slice(0, 8) ?? '?'} → ${p.target?.slice(0, 8) ?? '-'}${p.admissible ? '' : '  (no admisible)'}`);
      else if (b === 'commit') show(await client.groupCommit(id, gid!, opts('--ref')));
      else if (b === 'rejoin') for (const r of await client.groupRejoin(id, gid)) console.log(`${r.groupId}  ${r.status === 'joined' ? 'nueva hoja propia' : 'pendiente del commit de un admin (repite group rejoin)'}`);
      else if (b === 'send-file') {
        const file = opt('--file');
        if (!file) throw new Error('--file PATH required');
        const mimeType = opt('--mime') ?? MIME[extname(file).toLowerCase()] ?? 'application/octet-stream';
        const servers = opts('--server');
        const ref = await client.groupSendFile(id, gid!, { data: new Uint8Array(readFileSync(file)), filename: basename(file), mimeType, caption: positional().join(' ') }, servers.length ? { servers } : {});
        console.log(`enviado ${ref.attachment.filename} (época ${ref.epoch}) → ${ref.attachment.url}`);
      } else if (b === 'fetch-file') {
        const out = opt('--out');
        if (!out) throw new Error('--out FILE required');
        const r = await client.groupFetchFile(id, gid!, opt('--sha')!);
        writeFileSync(out, r.data, { mode: 0o600, flag: 'wx' });
        console.log(`${r.attachment.filename} descifrado en ${out}`);
      }
      else if (b === 'rotation-worker') {
        const policyUrl = opt('--policy');
        if (!policyUrl) throw new Error('--policy URL required (policy-engine)');
        const signerUrl = opt('--managed-signer');
        const token = process.env.SOVEREIGN_REVOCATION_TOKEN;
        if (signerUrl && !token) throw new Error('SOVEREIGN_REVOCATION_TOKEN required with --managed-signer');
        const { worker, propagator } = await client.revocationWorker(id, {
          policyUrl,
          ...(process.env.SOVEREIGN_POLICY_BEARER ? { policyBearer: process.env.SOVEREIGN_POLICY_BEARER } : {}),
          ...(signerUrl && token ? { managedSigner: { url: signerUrl, token } } : {}),
        });
        const tick = async () => {
          for (const d of (await propagator?.runOnce()) ?? []) console.log(`dispositivo ${d}: revocación propagada al managed-signer`);
          for (const r of await worker.runOnce()) console.log(`${r.id}  ${r.result}${r.epoch !== undefined ? `  epoch=${r.epoch}` : ''}${r.error ? `  (${r.error})` : ''}`);
        };
        if (argv.includes('--once')) await tick();
        else {
          const stop = new AbortController();
          for (const sig of ['SIGINT', 'SIGTERM'] as const) process.once(sig, () => stop.abort());
          const interval = Number(opt('--interval') ?? 15) * 1000;
          while (!stop.signal.aborted) {
            await tick().catch((err: Error) => console.error(`error: ${err.message}`));
            await new Promise<void>((r) => {
              const t = setTimeout(r, interval);
              stop.signal.addEventListener('abort', () => (clearTimeout(t), r()), { once: true });
            });
          }
        }
      }
      else throw new Error(`unknown group command: ${b}`);
    } else if (a === 'disclose') {
      for (const d of await client.disclosures(need())) console.log(`• [${d.control}=${d.option}] ${d.statement}`);
    } else {
      console.log('usage: see header of apps/sovereign-client/src/cli.ts');
      process.exitCode = 2;
    }
  } finally {
    // FR011-04: let the retry of earlier pending messages (started when the persona opened) finish first.
    await client.settle().catch(() => undefined);
    client.close();
  }
}

main().catch((err: Error) => {
  console.error(`error: ${err.message}`);
  process.exit(1);
});
