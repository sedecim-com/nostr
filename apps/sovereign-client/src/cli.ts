/**
 * sovereign — self-hosted Nostr client (Sovereign / Sovereign Tor modes).
 *
 *   sovereign persona create --label NAME --relay URL [--relay URL] [--tor] [--high-risk] [--onion-only]
 *   sovereign persona import --backup FILE --label NAME --relay URL [--tor] [--high-risk] [--onion-only] [--password-file f]
 *     (--onion-only: Tor and nothing but .onion relays; with Tor, any SOCKS-level failure reads
 *      «No enviado: red de privacidad no disponible» and the message waits, FR021-03)
 *                                        (key backup from keygen or the web; ncryptsec must match the npub)
 *   sovereign persona import --key-file FILE --npub NPUB --label NAME --relay URL [--tor] [--high-risk] [--onion-only]
 *                            [--password-file f]
 *                                        (FR004-08: FILE holds an nsec or an ncryptsec (NIP-49, with its password); the key
 *                                         must be NPUB's. It is sealed here with the passphrase: custody local)
 *   sovereign persona connect (--bunker-file FILE | --nostrconnect [--signer-relay URL ...]) --label NAME --relay URL
 *                             [--tor] [--high-risk] [--onion-only] [--npub NPUB]
 *                                        (FR004-08: the key stays in a NIP-46 signer: custody external. It lists what the
 *                                         signer is asked for first; with Tor its traffic goes through Tor, fails closed)
 *   sovereign persona connect --persona ID (--bunker-file FILE | --nostrconnect [--signer-relay URL ...])
 *                                        (pairs this device again with the persona's signer, e.g. after backup restore;
 *                                         the signer must hold the persona's npub)
 *   sovereign persona list
 *   sovereign backup export --persona ID --out FILE [--password-file f] [--no-mls]   (key, relays, panel, MLS state;
 *                                        --no-mls: to set up an additional device, then `group add-device`;
 *                                        FR004-08: no key when it lives in a NIP-46 signer, and never the pairing)
 *   sovereign backup restore FILE [--password-file f]
 *   sovereign whoami --persona ID     (identity, custody, network and link level; also shown before every send;
 *                                        then the maturity of its configuration, PANEL-07)
 *   sovereign maturity                   (maturity of each profile and function today and at v1.0; no passphrase)
 *   sovereign channel join --persona ID --group G         (NIP-29 join request)
 *   sovereign channel send --persona ID --group G "text" [--op ID]
 *   sovereign channel read --persona ID --group G [--offline]
 *                                        (FR013-05: what it reads stays in the persona's encrypted event cache;
 *                                         --offline reads that cache instead: no connection, nothing retried)
 *   sovereign dm send --persona ID --to NPUB "text" [--op ID] [--confirm-reuse]   (to the recipient's DM relays,
 *                                        kind 10050, like the web)
 *     (FR011-05: each send is an operation, and its id is printed first; --op ID retries that send, even one cut
 *      off half way, without another event or rumor. Another text or recipient under the same id is refused)
 *     (FR006-07: a contact or a file another persona of this device already used is refused, with what it would
 *      cross, and nothing is sent; --confirm-reuse confirms it. Also for group invite, propose --add, add-device
 *      --member and send-file)
 *   sovereign dm inbox --persona ID [--offline]   (reads its DM relays; receipts for its DMs move them to
 *                                        RECIPIENT_ACKED/READ; --offline opens the gift wraps of the event cache
 *                                        with the key on this device: no connection, no receipts)
 *   sovereign dm watch --persona ID     (keeps reading them: DMs and receipts as they arrive; Ctrl-C to stop)
 *   sovereign dm relays --persona ID     (publish this persona's DM relay list, kind 10050; also on create/import)
 *   sovereign outbox --persona ID        (delivery states per relay)
 *   sovereign resume --persona ID        (retry pending messages; any command that opens the persona does too)
 *   sovereign history sync --persona ID [--since UNIX] [--group G] [--full]   (rebuild channels/DMs; NIP-77 or REQ
 *                                        fallback. FR013-05: each relay resumes from its cursor in the event cache and
 *                                        NIP-77 starts from what that relay already sent; --full asks for everything)
 *   sovereign cache status --persona ID  (FR013-05: events in the persona's encrypted cache and each relay's cursor)
 *   sovereign cache clear --persona ID   (deletes that cache: events, cursors; the rest of the persona stays)
 *   sovereign history export --persona ID --out FILE [--since UNIX]  (JSONL, one signed NIP-01 event per line)
 *   sovereign history import --persona ID FILE [--dry-run]           (verify signatures, republish valid events;
 *                                        FILE is a JSONL export or a `vault export` file)
 *   sovereign disclose --persona ID      (what each setting implies)
 *   sovereign vault push --persona ID [--vault URL]    (seal the history here and store it in the Continuity Vault:
 *                                        events, group messages, ledger, MLS state; the operator sees account, size
 *                                        and time, never content)
 *   sovereign vault restore --persona ID [--vault URL] [--no-republish]   (rebuild the history from the vault,
 *                                        even with empty relays; run on a device restored from the backup)
 *   sovereign persona continuity --persona ID off|best-effort|required-for-resilient [--vault URL]
 *                                        (VAULT-04: copy each sent event to the Continuity Vault; best-effort never
 *                                        delays a send, required-for-resilient holds it until the copy is there)
 *   sovereign vault list --persona ID [--vault URL]    (archives of this persona's vault account)
 *   sovereign vault verify --persona ID [--vault URL]  (download every archive and open it with this device's key)
 *   sovereign vault retention --persona ID [--vault URL] [--days N | --forever]
 *                                        (VAULT-05: how long the vault keeps each archive since its last write;
 *                                        --forever: until deleted, within the operator's maximum; no flag: show it)
 *   sovereign vault export --persona ID --out FILE [--vault URL]   (open JSON, decrypted here: signed events, group
 *                                        messages in clear, ledger; no MLS state. `history import` takes it back)
 *   sovereign vault delete --persona ID --yes [--vault URL]        (delete every archive and the vault account)
 *   sovereign group keypackage --persona ID            (publish MLS key package so others can add you)
 *   sovereign group create --persona ID --name NAME     (Marmot/MLS: forward secrecy + PCS)
 *   sovereign group invite --persona ID --group GID --to NPUB [--confirm-reuse]
 *   sovereign group accept --persona ID                 (join groups from pending Welcomes)
 *   sovereign group send --persona ID --group GID "text"   (without a relay it stays pending and goes out later, FR025-12)
 *   sovereign group read --persona ID --group GID
 *   sovereign group history --persona ID --group GID    (messages kept on this device, restored ones included)
 *   sovereign group remove --persona ID --group GID --member NPUB
 *   sovereign group rotate --persona ID --group GID     (self-update: post-compromise security)
 *   sovereign group list --persona ID                   (MLS id, name, epoch, members and h=nostr_group_id: the id
 *                                        relays see, which an organisation registers the group by, FR023-10)
 *   sovereign group device --persona ID [--label NAME]           (this installation's MLS device id / label)
 *   sovereign group devices --persona ID --group GID             (leaves: one per device of each persona)
 *   sovereign group add-device --persona ID --group GID [--member NPUB] [--confirm-reuse]
 *                                        (admin: commit; member: propose; default member = this persona)
 *   sovereign group remove-device --persona ID --group GID --leaf N          (admin)
 *   sovereign group propose --persona ID --group GID (--add NPUB | --remove NPUB) [--confirm-reuse]   (any member)
 *   sovereign group proposals --persona ID --group GID
 *   sovereign group commit --persona ID --group GID [--ref REF ...]          (admin commits proposals)
 *   sovereign group rejoin --persona ID [--group GID]            (after backup restore: new leaf, old removed)
 *   sovereign group pending --persona ID [--group GID]           (FR025-12: messages and commits waiting for a relay;
 *                                        they go out on the next sync and at the end of any command of the persona)
 *   sovereign group retry --persona ID [--group GID]             (sync and send them again now)
 *   sovereign group discard --persona ID --op ID                 (forget one, e.g. one every relay refused)
 *   sovereign group send-file --persona ID --group GID --file PATH [--mime TYPE] [--server URL] [--confirm-reuse] ["caption"]
 *   sovereign group fetch-file --persona ID --group GID --sha HEX --out FILE (MIP-04 download + decrypt)
 *   sovereign group rotation-worker --persona ID --policy URL [--managed-signer URL] [--interval S] [--once]
 *                                        (FR-024: MLS Remove for the rotations the policy-engine flags on
 *                                        revocation; with --managed-signer, propagates device revocations)
 *
 * Env: SOVEREIGN_DATA_DIR (default ./.data/sovereign), SOVEREIGN_PASSPHRASE, TOR_SOCKS (127.0.0.1:9050),
 *      SOVEREIGN_PASSPHRASE_FILE (a file with the passphrase, e.g. a compose secret; when set it is the only source),
 *      SOVEREIGN_BACKUP_PASSWORD (backup files, when --password-file is not given),
 *      SOVEREIGN_BLOB_STORE (fallback Blossom/blob-store URL for encrypted group media),
 *      SOVEREIGN_VAULT_URL (Continuity Vault URL, when --vault is not given),
 *      SOVEREIGN_DISCOVERY_RELAYS (comma-separated relays where recipients' DM relay lists are also looked up),
 *      SOVEREIGN_FLAGS (deployment flags from the interop gate, default infra/web/flags.json if present),
 *      SOVEREIGN_POLICY_BEARER (optional service bearer for GET /v1/rotations, POST /v1/rotations/:id/done and
 *        GET /v1/revocations; NIP-98 otherwise),
 *      SOVEREIGN_REVOCATION_TOKEN (managed-signer revocation token, required with --managed-signer),
 *      SOVEREIGN_CACHE (off: no event cache, FR013-05), SOVEREIGN_CACHE_MAX_EVENTS (default 5000),
 *      SOVEREIGN_CACHE_MAX_DAYS (events older than this are not kept; default: no age limit)
 */
import { createHash, randomBytes } from 'node:crypto';
import { closeSync, existsSync, fstatSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, extname } from 'node:path';
import type { OutboxRecord } from '@sedecim/delivery-engine';
import type { PendingGroupOperation } from '@sedecim/marmot-adapter';
import { ReuseNotConfirmedError } from '@sedecim/identity';
import { BUZZ_PINNED_ADAPTER, wrapOptionsFromFlags, type DeploymentFlags, type DirectMessage, type Receipt } from '@sedecim/messaging';
import { checkAttachmentSize } from '@sedecim/blossom-client';
import { CONTINUITY_VAULT_TEXTS, configMaturity, disclose, MATURITY, MATURITY_LABELS } from '@sedecim/profiles';
import { describePermissions, SOVEREIGN_NIP46_PERMISSIONS } from '@sedecim/signer';
import type { EventCacheOptions } from '@sedecim/sync';
import { SovereignClient, type PersonaInput, type SignerSource } from './app';

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
const positional = () => argv.filter((a, i) => !a.startsWith('--') && !(argv[i - 1]?.startsWith('--') && !['--tor', '--high-risk', '--onion-only', '--dry-run', '--no-mls', '--once', '--no-republish', '--confirm-reuse', '--offline', '--full'].includes(argv[i - 1]!))).slice(2);
/** FR006-07: the user confirms that this persona may use a contact or a file another of their personas already used. */
const confirmReuse = argv.includes('--confirm-reuse');
const MIME: Record<string, string> = { '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif', '.webp': 'image/webp', '.mp4': 'video/mp4', '.pdf': 'application/pdf', '.txt': 'text/plain' };
const since = () => (opt('--since') !== undefined ? Number(opt('--since')) : undefined);
/** FR013-05: `--offline` reads the persona's event cache and never opens a connection. */
const offline = argv.includes('--offline');
const iso = (seconds: number) => new Date(seconds * 1000).toISOString();

/** FR013-05: the persona event cache as the environment sets it (on by default, with the cache's own limits). */
function eventCacheOptions(): EventCacheOptions | false {
  if (/^(off|0|false|no)$/i.test(process.env.SOVEREIGN_CACHE ?? '')) return false;
  const whole = (name: string) => {
    const v = process.env[name];
    if (v === undefined || v === '') return undefined;
    if (!/^\d+$/.test(v)) throw new Error(`${name} must be a whole number`);
    return Number(v);
  };
  const maxEvents = whole('SOVEREIGN_CACHE_MAX_EVENTS');
  const days = whole('SOVEREIGN_CACHE_MAX_DAYS');
  return { ...(maxEvents !== undefined ? { maxEvents } : {}), ...(days !== undefined ? { maxAgeSeconds: days * 86_400 } : {}) };
}

/**
 * FR021-03 (spec §18.1): what the CLI logs about the network (errors, delivery states per relay, sync results)
 * carries no IP address. An IP literal becomes `ip-<8 hex>` (stable, so two relays can still be told apart);
 * host names and .onion addresses stay. Message contents and the persona's own configuration are not touched.
 */
const IPV4 = /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])/g;
const IPV6 = /\[[0-9a-f:.]*:[0-9a-f:.]*\]|(?<![\w:.])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:.])/gi;
const ipLabel = (ip: string) => `ip-${createHash('sha256').update(ip.replace(/^\[|\]$/g, '').toLowerCase()).digest('hex').slice(0, 8)}`;
export function maskIps(text: string): string {
  return text.replace(IPV6, (m) => (m.startsWith('[') || m.includes('::') || m.split(':').length === 8 ? ipLabel(m) : m)).replace(IPV4, ipLabel);
}
const dmLine = (m: DirectMessage) => `[${new Date(m.rumor.created_at * 1000).toISOString()}] ${m.sender.slice(0, 8)}: ${m.rumor.content}`;
/** FR009-03: a receipt for one of our DMs, and the state of that operation after it. */
const receiptLine = (r: Receipt, rec: OutboxRecord) => `acuse (${r.type === 'read' ? 'leído' : 'recibido'}) de ${r.from.slice(0, 8)}: ${rec.state}`;

/**
 * FR011-05: the operation of a send: --op repeats one (a retry), otherwise a new one. It is printed before anything
 * is sent, so a send that is cut off half way can still be retried without making it twice.
 */
function sendOperation(): string {
  const op = opt('--op') ?? randomBytes(16).toString('hex');
  console.error(`operación ${op} (para reintentar este envío sin duplicarlo: --op ${op})`);
  return op;
}

/** A new persona as the flags describe it (FR004-08: the same for a created, imported or connected one). */
const personaInput = (): PersonaInput => ({ label: opt('--label') ?? 'persona', relays: opts('--relay'), tor: argv.includes('--tor'), highRisk: argv.includes('--high-risk'), onionOnly: argv.includes('--onion-only') });

/**
 * FR018-06: the file of a group attachment, read only if it is within the limit. The size is measured on the open file
 * (not on its path), so it cannot change between the check and the read, and nothing is read into memory before it.
 */
function readGroupFile(path: string): Uint8Array {
  const fd = openSync(path, 'r');
  try {
    checkAttachmentSize('group', fstatSync(fd).size);
    return new Uint8Array(readFileSync(fd));
  } finally {
    closeSync(fd);
  }
}

/**
 * FR020-06: passphrase of the local stores. SOVEREIGN_PASSPHRASE_FILE, when set, is the only source (the compose
 * service reads a secret file and ignores any variable); otherwise SOVEREIGN_PASSPHRASE.
 */
function storePassphrase(): string {
  const file = process.env.SOVEREIGN_PASSPHRASE_FILE;
  if (!file) {
    const pass = process.env.SOVEREIGN_PASSPHRASE;
    if (!pass) throw new Error('set SOVEREIGN_PASSPHRASE or SOVEREIGN_PASSPHRASE_FILE (protects the local encrypted stores)');
    return pass;
  }
  const pass = readFileSync(file, 'utf8').replace(/\r?\n$/, '');
  if (!pass) throw new Error(`empty passphrase file: ${file} (SOVEREIGN_PASSPHRASE_FILE)`);
  return pass;
}

/** Password of a backup file: --password-file (first line) or SOVEREIGN_BACKUP_PASSWORD. */
function backupPassword(): string {
  const file = opt('--password-file');
  const pw = file ? readFileSync(file, 'utf8').replace(/\r?\n$/, '') : process.env.SOVEREIGN_BACKUP_PASSWORD;
  if (!pw) throw new Error('backup password required: --password-file FILE or SOVEREIGN_BACKUP_PASSWORD');
  return pw;
}

async function main() {
  // PANEL-07: the maturity catalog is public information: no store to open, no passphrase.
  if (argv[0] === 'maturity') {
    for (const m of MATURITY) console.log(`${MATURITY_LABELS[m.level].padEnd(14)} ${m.name}: ${m.why} En v1.0: ${m.atV1}`);
    return;
  }
  // FR013-05: --offline is never ignored. Any other command uses the network, so it stops before opening anything.
  if (offline && !((argv[0] === 'channel' && argv[1] === 'read') || (argv[0] === 'dm' && argv[1] === 'inbox'))) {
    throw new Error('--offline solo existe para channel read y dm inbox: esta orden usa la red, y no se ha hecho nada');
  }
  const passphrase = storePassphrase();
  const [socksHost, socksPort] = (process.env.TOR_SOCKS ?? '127.0.0.1:9050').split(':');
  const needsDm = argv[0] === 'dm' && argv[1] === 'send';
  const watching = argv[0] === 'dm' && argv[1] === 'watch';
  const client = new SovereignClient({
    dataDir: process.env.SOVEREIGN_DATA_DIR ?? './.data/sovereign',
    passphrase,
    socksHost,
    socksPort: Number(socksPort),
    ...(needsDm ? { relayAdapter: relayAdapter() } : {}),
    ...(process.env.SOVEREIGN_BLOB_STORE ? { blobStore: process.env.SOVEREIGN_BLOB_STORE } : {}),
    ...(process.env.SOVEREIGN_DISCOVERY_RELAYS ? { discoveryRelays: process.env.SOVEREIGN_DISCOVERY_RELAYS.split(',').map((r) => r.trim()).filter(Boolean) } : {}),
    ...(watching ? { autoReconnect: true } : {}),
    // VAULT-04: where each sent event is copied, when the persona's Continuity Vault policy asks for it.
    ...((opt('--vault') ?? process.env.SOVEREIGN_VAULT_URL) ? { vaultUrl: opt('--vault') ?? process.env.SOVEREIGN_VAULT_URL } : {}),
    // FR004-08: the signer asks for approval in a web page. Shown, never opened: outside Tor, that page sees the IP.
    onSignerAuthUrl: (url, p) => console.error(`el signer pide tu aprobación en ${url}${p.network === 'tor-only' ? ' (ábrela en Tor Browser: con otro navegador, quien sirve esa página ve tu dirección IP)' : ''}`),
    // FR006-07: what a confirmed reuse crosses stays on record next to what is sent.
    onConfirmedReuse: (warnings) => {
      for (const w of warnings) console.error(`aviso: compartimentación (confirmado con --confirm-reuse): ${w.message}`);
    },
    eventCache: eventCacheOptions(),
  });
  /**
   * FR017-06: contacts route their DMs to this list; offline it stays in the outbox and goes out later. FAILED
   * says what the relays answered, e.g. one that does not take kind 10050 (OPS-21).
   */
  const announceDmRelays = async (id: string) => {
    const rec = await client.publishDmRelays(id);
    const why = rec.blockedReason ?? rec.failureReason;
    console.error(`relays de DM (kind 10050): ${rec.state}${why ? ` — ${maskIps(why)}` : ''}`);
  };
  /** FR007-05: before every send, who is sending (identity, custody, network, link level), as the web's banner. */
  const banner = async (id: string) => console.error(await (await client.identities()).sendingAs(id));
  const persona = opt('--persona');
  const need = () => {
    if (!persona) throw new Error('--persona ID required');
    return persona;
  };
  try {
    const [a, b] = argv;
    if (a === 'persona' && b === 'create') {
      const p = await client.createPersona({ label: opt('--label') ?? 'persona', relays: opts('--relay'), tor: argv.includes('--tor'), highRisk: argv.includes('--high-risk'), onionOnly: argv.includes('--onion-only') });
      console.log(JSON.stringify(p, null, 2));
      for (const w of client.warningsFor(p)) console.error(`aviso: ${w}`);
      await announceDmRelays(p.id);
    } else if (a === 'persona' && b === 'import' && opt('--key-file')) {
      // FR004-08: the nsec or ncryptsec comes from a file, never from the command line (other users of the machine see it).
      const npub = opt('--npub');
      if (!npub) throw new Error('--npub NPUB required: the key must be that of the identity you expect');
      const secret = readFileSync(opt('--key-file')!, 'utf8').trim();
      const p = await client.importKey(secret, { ...personaInput(), npub, ...(secret.startsWith('ncryptsec1') ? { password: backupPassword() } : {}) });
      console.log(JSON.stringify(p, null, 2));
      for (const w of client.warningsFor(p)) console.error(`aviso: ${w}`);
      await announceDmRelays(p.id);
    } else if (a === 'persona' && b === 'connect') {
      // FR004-08: the key stays in a NIP-46 signer. A bunker URL may carry the signer's secret: from a file, too.
      const bunkerFile = opt('--bunker-file');
      if (!bunkerFile === !argv.includes('--nostrconnect')) throw new Error('--bunker-file FILE or --nostrconnect required (one of them)');
      // FR004-04, as the web does: what the signer is asked for, before any connection.
      for (const d of describePermissions(SOVEREIGN_NIP46_PERMISSIONS)) console.error(`permiso pedido al signer: ${d.label} (${d.permission})`);
      const source: SignerSource = bunkerFile
        ? { bunker: readFileSync(bunkerFile, 'utf8') }
        : { nostrconnect: { relays: opts('--signer-relay'), onOffer: (uri) => console.error(`abre esta URI en tu signer (o conviértela en un QR); se espera su respuesta hasta 5 minutos:\n${uri}`) } };
      if (persona) console.log(JSON.stringify(await client.reconnectSigner(persona, source), null, 2));
      else {
        const npub = opt('--npub');
        const p = await client.connectSigner({ ...personaInput(), ...source, ...(npub ? { npub } : {}) });
        console.log(JSON.stringify(p, null, 2));
        for (const w of client.warningsFor(p)) console.error(`aviso: ${w}`);
        await announceDmRelays(p.id);
      }
    } else if (a === 'persona' && b === 'import') {
      const file = opt('--backup');
      if (!file) throw new Error('--backup FILE (JSON from keygen or from the web) or --key-file FILE (nsec or ncryptsec) required');
      const p = await client.importBackup(readFileSync(file, 'utf8'), backupPassword(), { label: opt('--label') ?? 'persona', relays: opts('--relay'), tor: argv.includes('--tor'), highRisk: argv.includes('--high-risk'), onionOnly: argv.includes('--onion-only') });
      console.log(JSON.stringify(p, null, 2));
      for (const w of client.warningsFor(p)) console.error(`aviso: ${w}`);
      await announceDmRelays(p.id);
    } else if (a === 'backup' && b === 'export') {
      const out = opt('--out');
      if (!out) throw new Error('--out FILE required');
      const pkg = await client.exportBackup(need(), backupPassword(), argv.includes('--no-mls') ? { includeMls: false } : {});
      writeFileSync(out, JSON.stringify(pkg, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
      console.log(`backup cifrado (${pkg.ncryptsec ? 'llave, ' : ''}relays, panel${argv.includes('--no-mls') ? '' : ', grupos MLS'}) escrito en ${out}`);
      // FR004-08: a persona whose key lives in a NIP-46 signer backs up everything but that key and this device's pairing.
      if (!pkg.ncryptsec) console.error(`aviso: la llave de esta persona está en su signer NIP-46 y no va en el backup, ni el emparejamiento de este dispositivo: tras restaurarlo, sovereign persona connect --persona ${need()} --bunker-file FILE (o --nostrconnect)`);
    } else if (a === 'backup' && b === 'restore') {
      const file = positional()[0];
      if (!file) throw new Error('usage: sovereign backup restore FILE');
      const p = await client.restoreBackup(JSON.parse(readFileSync(file, 'utf8')), backupPassword());
      console.log(JSON.stringify(p, null, 2));
    } else if (a === 'persona' && b === 'continuity') {
      const policy = positional()[0];
      if (policy !== 'off' && policy !== 'best-effort' && policy !== 'required-for-resilient') throw new Error('usage: sovereign persona continuity --persona ID off|best-effort|required-for-resilient [--vault URL]');
      const config = await client.setContinuity(need(), policy);
      console.log(`continuidad: ${config.continuity} (backup en la nube: ${config.cloudBackup})`);
      for (const d of disclose(config).filter((x) => x.control === 'continuity' || x.control === 'cloudBackup')) console.error(`aviso: ${d.statement}`);
    } else if (a === 'persona' && b === 'list') {
      for (const p of await (await client.identities()).list()) console.log(`${p.id}  ${p.label.padEnd(16)} ${p.network.padEnd(8)} ${p.compartment.padEnd(12)} ${p.relays.join(',')}`);
    } else if (a === 'whoami') {
      console.log(await (await client.identities()).sendingAs(need()));
      const m = configMaturity(await client.profile(need()), { continuityVault: !!(opt('--vault') ?? process.env.SOVEREIGN_VAULT_URL) });
      console.log(`madurez: ${m.label} (${m.parts.filter((p) => p.level === m.level).map((p) => `${p.name}: ${p.why}`).join(' ')})`);
    } else if (a === 'channel' && b === 'join') {
      const rec = await client.joinChannel(need(), opt('--group')!);
      console.log(`${rec.state}${rec.blockedReason ? ` — ${rec.blockedReason}` : ''} (op ${rec.opId})`);
    } else if (a === 'history' && b === 'sync') {
      const r = await client.syncHistory(need(), { since: since(), channels: opts('--group'), full: argv.includes('--full') });
      for (const [relay, strategy] of Object.entries(r.strategies)) console.log(`${maskIps(relay)}  ${strategy}`);
      for (const [g, events] of Object.entries(r.channels)) console.log(`canal ${g}: ${events.length} eventos`);
      console.log(`DMs: ${r.dms.length}; outbox: ${r.outbox.map((o) => o.state).join(', ') || 'vacío'}`);
      if (r.cache) console.log(`caché local: ${r.cache.events} eventos (${Math.ceil(r.cache.bytes / 1024)} KB)`);
      if (r.cacheInUse) console.error(`aviso: otro proceso del CLI está escribiendo la caché de esta persona: esta sincronización no la ha usado ni actualizado (si no hay ningún otro proceso, borra ${client.cacheLockPath(need())})`);
    } else if (a === 'cache' && b === 'status') {
      const { stats, cursors } = await client.cacheStatus(need());
      console.log(`caché local: ${stats.events} eventos (${Math.ceil(stats.bytes / 1024)} KB)${stats.oldest !== undefined ? `, del ${iso(stats.oldest)} al ${iso(stats.newest!)}` : ''}`);
      if (stats.floor) console.log(`por sus límites, lo anterior al ${iso(stats.floor)} puede faltar`);
      const latest = new Map<string, number>();
      for (const c of cursors) latest.set(c.relay, Math.max(latest.get(c.relay) ?? 0, c.at));
      for (const [relay, at] of latest) console.log(`${maskIps(relay)}  última sincronización completa iniciada el ${iso(at)}`);
    } else if (a === 'cache' && b === 'clear') {
      await client.clearCache(need());
      console.log('caché local de eventos borrada: eventos y cursores (la persona sigue igual)');
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
      for (const i of r.invalid) console.log(i.line ? `línea ${i.line}: ${i.reason}` : i.reason);
      console.log(`válidos=${r.valid} inválidos=${r.invalid.length} duplicados=${r.duplicates} publicados=${r.published} rechazados=${r.rejected}${r.format === 'vault-export' ? ` (exportación del vault; ${r.othersWraps} cifrados para otras personas no se publican)` : ''}`);
    } else if (a === 'channel' && b === 'send') {
      await banner(need());
      const rec = await client.sendChannel(need(), opt('--group')!, positional().join(' '), { opId: sendOperation() });
      console.log(`${rec.state}${rec.blockedReason ? ` — ${maskIps(rec.blockedReason)}` : ''} (op ${rec.opId})`);
    } else if (a === 'channel' && b === 'read') {
      const events = await client.readChannel(need(), opt('--group')!, 50, { offline });
      for (const e of events) console.log(`[${new Date(e.created_at * 1000).toISOString()}] ${e.pubkey.slice(0, 8)}: ${e.content}`);
      if (offline) console.error(events.length ? 'sin conexión: leído de la caché local' : 'sin conexión: la caché local no tiene mensajes de este canal (se guardan al leerlo o con history sync)');
    } else if (a === 'dm' && b === 'send') {
      await banner(need());
      const recs = await client.sendDm(need(), opt('--to')!, positional().join(' '), { opId: sendOperation(), confirmReuse });
      for (const r of recs) console.log(`${r.meta?.recipient?.slice(0, 8)} ${r.state}${r.blockedReason ? ` — ${maskIps(r.blockedReason)}` : ''}`);
      // As in the web: a recipient without DM relays gets the wrap on a guess, and the user is told.
      for (const r of recs) if (r.meta?.dmRelaySource && r.meta.dmRelaySource !== 'self' && r.meta.dmRelaySource !== 'dm-relays') console.error(`aviso: ${r.meta.recipient?.slice(0, 8)} no publicó relays de DM (kind 10050): la entrega es incierta`);
    } else if (a === 'dm' && b === 'relays') {
      await announceDmRelays(need());
    } else if (a === 'dm' && b === 'inbox' && offline) {
      const dms = await client.inbox(need(), {}, { offline: true });
      for (const m of dms) console.log(dmLine(m));
      console.error(dms.length ? 'sin conexión: abiertos desde la caché local (sin acuses)' : 'sin conexión: la caché local no tiene DMs de esta persona (se guardan con dm inbox o history sync)');
    } else if (a === 'dm' && b === 'inbox') {
      const acks: string[] = [];
      for (const m of await client.inbox(need(), { onReceipt: (r, rec) => acks.push(receiptLine(r, rec)) })) console.log(dmLine(m));
      for (const line of acks) console.log(line);
    } else if (a === 'dm' && b === 'watch') {
      // FR009-03: DMs and receipts as they arrive on the persona's DM relays (kind 10050), until Ctrl-C.
      const stop = await client.watchDms(need(), { onMessage: (m) => console.log(dmLine(m)), onReceipt: (r, rec) => console.log(receiptLine(r, rec)) });
      console.error('escuchando tus relays de DM (kind 10050); Ctrl-C para salir');
      await new Promise<void>((resolve) => {
        process.once('SIGINT', resolve);
        process.once('SIGTERM', resolve);
      });
      stop();
    } else if (a === 'outbox') {
      for (const r of await client.outbox(need())) {
        console.log(`${r.opId.slice(0, 8)} ${r.state.padEnd(16)} ${maskIps(r.blockedReason ?? '')}`);
        for (const s of Object.values(r.relayStatus)) console.log(`   ${maskIps(s.relay)} attempts=${s.attemptCount} ${s.acceptedAt ? 'ACK' : maskIps(s.lastError ?? 'pending')}`);
        // VAULT-04: the Continuity Vault copy, a state of its own beside the relay ACKs.
        if (r.continuity) console.log(`   vault (${r.continuity.policy}) attempts=${r.continuity.attemptCount} ${r.continuity.state === 'PENDING' ? maskIps(r.continuity.lastError ?? 'pending') : r.continuity.state}`);
      }
    } else if (a === 'resume') {
      for (const r of await client.resume(need())) console.log(`${r.opId.slice(0, 8)} ${r.state}`);
    } else if (a === 'group') {
      const id = need();
      const gid = opt('--group');
      const pendingLine = (p: PendingGroupOperation) =>
        `${p.id}  ${p.type.padEnd(9)} ${new Date(p.createdAt).toISOString()}  intentos=${p.attempts}${p.target ? `  ${p.target.slice(0, 8)}` : ''}${p.failed ? `  RECHAZADA: ${p.failed}` : p.lastError ? `  (${p.lastError})` : ''}`;
      // FR023-10: `h=` is the id relays see (nostr_group_id): an organisation registers the group by it in its policy.
      const show = (g: { groupId: string; nostrGroupId?: string; name: string; epoch: number; members: string[]; pending?: PendingGroupOperation[] }) => {
        console.log(`${g.groupId}  ${g.name}  epoch=${g.epoch}  members=${g.members.length}${g.nostrGroupId ? `  h=${g.nostrGroupId}` : ''}`);
        // FR025-12: what no relay took yet is not lost: it goes out on the next sync (group pending / group retry).
        if (g.pending?.length) console.log(`pendiente sin relay (se reintenta solo; group pending para verlo):\n${g.pending.map((p) => `  ${pendingLine(p)}`).join('\n')}`);
      };
      if (b === 'keypackage') console.log(`key package publicado: ${(await client.groupPublishKeyPackage(id)).id}`);
      else if (b === 'create') show(await client.groupCreate(id, opt('--name') ?? 'grupo'));
      else if (b === 'invite') show(await client.groupInvite(id, gid!, opt('--to')!, { confirmReuse }));
      else if (b === 'accept') (await client.groupAccept(id)).forEach(show);
      else if (b === 'send') {
        await banner(id);
        const m = await client.groupSend(id, gid!, positional().join(' '));
        if (m.pending) console.log(`pendiente: ningún relay lo tomó; se reintenta en la próxima sincronización o comando (group pending --persona ${id})`);
      } else if (b === 'pending') for (const p of await client.groupPending(id, gid)) console.log(pendingLine(p));
      else if (b === 'retry') {
        const left = await client.groupRetry(id, gid);
        console.log(left.length ? `siguen pendientes ${left.length}:` : 'nada pendiente');
        for (const p of left) console.log(`  ${pendingLine(p)}`);
      } else if (b === 'discard') await client.groupDiscard(id, opt('--op')!);
      else if (b === 'read')
        for (const m of await client.groupSync(id, gid!)) {
          console.log(`[${new Date(m.createdAt * 1000).toISOString()}] ${m.sender.slice(0, 8)}: ${m.content}`);
          for (const f of m.media ?? []) console.log(`   [archivo ${f.filename} ${f.type} ${f.size ?? '?'} B] --sha ${f.sha256}`);
        }
      else if (b === 'history')
        for (const m of await client.groupHistory(id, gid!)) console.log(`[${new Date(m.createdAt * 1000).toISOString()}] ${m.sender.slice(0, 8)}: ${m.content}`);
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
        const r = await client.groupAddDevice(id, gid!, opt('--member'), { confirmReuse });
        if (r.committed) show(r.group);
        else console.log(`propuesto (${r.proposals.length}); un admin debe ejecutar group commit`);
      } else if (b === 'remove-device') show(await client.groupRemoveDevice(id, gid!, Number(opt('--leaf'))));
      else if (b === 'propose') {
        const r = await client.groupPropose(id, gid!, { ...(opt('--add') ? { add: opt('--add')! } : {}), ...(opt('--remove') ? { remove: opt('--remove')! } : {}) }, { confirmReuse });
        for (const p of r) console.log(`propuesta ${p.type} ${p.ref}`);
      } else if (b === 'proposals')
        for (const p of await client.groupProposals(id, gid!)) console.log(`${p.ref}  ${p.type.padEnd(7)} de ${p.proposer?.slice(0, 8) ?? '?'} → ${p.target?.slice(0, 8) ?? '-'}${p.admissible ? '' : '  (no admisible)'}`);
      else if (b === 'commit') show(await client.groupCommit(id, gid!, opts('--ref')));
      else if (b === 'rejoin') for (const r of await client.groupRejoin(id, gid)) console.log(`${r.groupId}  ${r.status === 'joined' ? 'nueva hoja propia' : 'pendiente del commit de un admin (repite group rejoin)'}`);
      else if (b === 'send-file') {
        const file = opt('--file');
        if (!file) throw new Error('--file PATH required');
        // FR018-06: the size is checked before the file is read into memory.
        const data = readGroupFile(file);
        const mimeType = opt('--mime') ?? MIME[extname(file).toLowerCase()] ?? 'application/octet-stream';
        const servers = opts('--server');
        const ref = await client.groupSendFile(id, gid!, { data, filename: basename(file), mimeType, caption: positional().join(' ') }, { ...(servers.length ? { servers } : {}), confirmReuse });
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
            await tick().catch((err: Error) => console.error(`error: ${maskIps(err.message)}`));
            await new Promise<void>((r) => {
              const t = setTimeout(r, interval);
              stop.signal.addEventListener('abort', () => (clearTimeout(t), r()), { once: true });
            });
          }
        }
      }
      else throw new Error(`unknown group command: ${b}`);
    } else if (a === 'vault') {
      const url = opt('--vault') ?? process.env.SOVEREIGN_VAULT_URL;
      if (!url) throw new Error('--vault URL or SOVEREIGN_VAULT_URL required');
      if (b === 'push') {
        // VAULT-07: what the operator can and cannot see, every time something is uploaded.
        for (const t of [CONTINUITY_VAULT_TEXTS.sealed, CONTINUITY_VAULT_TEXTS.metadata, CONTINUITY_VAULT_TEXTS.groups]) console.error(`aviso: ${t}`);
        const r = await client.vaultPush(need(), url);
        console.log(`historial sellado y guardado en el vault: ${r.events.uploaded} eventos nuevos (${r.events.kept} ya estaban), ${r.groupMessages.uploaded} mensajes de grupo nuevos, ledger de ${r.operations} operaciones${r.snapshots.includes('mls') ? ' y estado de los grupos' : ''}`);
        if (r.events.invalid) console.error(`aviso: ${r.events.invalid} eventos con firma inválida no se guardaron`);
      } else if (b === 'restore') {
        const r = await client.vaultRestore(need(), url, { republish: !argv.includes('--no-republish') });
        console.log(`vault: ${r.archives} archivos${r.skipped ? ` (${r.skipped} no se abren con esta llave o no son de esta persona)` : ''}`);
        console.log(`eventos: ${r.events} verificados; ${r.published} vuelven a los relays${r.rejected ? `, ${r.rejected} rechazados` : ''}${r.othersWraps ? `; ${r.othersWraps} cifrados para otras personas siguen en el vault` : ''}`);
        console.log(`mensajes de grupo: ${r.groupMessages} · ledger: ${r.ledger} operaciones añadidas`);
        if (r.mls === 'restored') console.log('grupos: restaurados; ejecuta group rejoin antes de enviar');
        else if (r.mls === 'kept') console.log('grupos: este dispositivo ya tenía grupos, se conservan');
        if (r.savedAt) console.log(`copia guardada el ${new Date(r.savedAt).toISOString()}`);
        if (r.missing) console.error(`aviso: faltan ${r.missing} archivos que el vault tenía en esa copia: caducaron por la retención, se borraron o se perdieron`);
      } else if (b === 'list') {
        const all = await client.vaultList(need(), url);
        for (const m of all) console.log(`${m.id.slice(0, 16)}…  ${String(m.size).padStart(8)} B  ${m.updated_at}`);
        console.log(`${all.length} archivos`);
      } else if (b === 'verify') {
        const r = await client.vaultVerify(need(), url);
        console.log(`${r.opened} de ${r.archives} archivos se abren con la llave de archivo de este dispositivo`);
        if (r.opened < r.archives) process.exitCode = 1;
      } else if (b === 'retention') {
        // VAULT-05: the account's retention (--days N or --forever), or what applies now.
        const days = opt('--days');
        if (days !== undefined && argv.includes('--forever')) throw new Error('--days N or --forever, not both');
        if (days !== undefined && !/^[1-9][0-9]*$/.test(days)) throw new Error('--days must be a positive integer');
        const r = days !== undefined || argv.includes('--forever') ? await client.vaultRetention(need(), url, days === undefined ? null : Number(days)) : (await client.vaultUsage(need(), url)).retention;
        if (!r) throw new Error('este vault no informa de su retención');
        console.log(`retención: ${r.effective_days ? `${r.effective_days} días desde la última vez que se guarda cada archivo` : 'hasta que lo borres'}${r.days ? ` (elegida: ${r.days} días)` : ''}${r.max_days ? `; máximo del operador: ${r.max_days} días` : ''}`);
      } else if (b === 'export') {
        const out = opt('--out');
        if (!out) throw new Error('--out FILE required');
        const { export: data, skipped } = await client.vaultExport(need(), url);
        writeFileSync(out, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
        console.log(`vault exportado a ${out} (${data.format} v${data.version}): ${data.events.length} eventos firmados, ${data.groupMessages.length} mensajes de grupo, ${data.ledger.length} operaciones del ledger`);
        if (skipped) console.error(`aviso: ${skipped} archivos no se abren con esta llave o no son de esta persona: no van en la exportación`);
        console.error(`aviso: ${CONTINUITY_VAULT_TEXTS.export}`);
      } else if (b === 'delete') {
        if (!argv.includes('--yes')) throw new Error(`borra todos los archivos de esta persona en el vault y su cuenta; repite con --yes. ${CONTINUITY_VAULT_TEXTS.deletion}`);
        const deleted = await client.vaultDelete(need(), url);
        console.log(`vault: ${deleted} archivos borrados y cuenta eliminada`);
        console.error(`aviso: ${CONTINUITY_VAULT_TEXTS.deletion}`);
        if ((await client.profile(need())).continuity !== 'off') console.error('aviso: la copia automática de cada envío sigue encendida: los próximos envíos vuelven a guardarse en el vault (persona continuity off para apagarla)');
      } else throw new Error('usage: sovereign vault push|restore|list|verify|retention|export|delete --persona ID [--vault URL]');
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
  console.error(`error: ${maskIps(err.message)}`);
  if (err instanceof ReuseNotConfirmedError) console.error('para usarlo también desde esta persona, repite el comando con --confirm-reuse');
  process.exit(1);
});
