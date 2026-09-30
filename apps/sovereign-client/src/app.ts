import { join } from 'node:path';
import WebSocket from 'ws';
import { bytesToHex, getTagValue, normalizePubkey, randomBytes, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { EncryptedStore, FileBackend } from '@sedecim/encrypted-store';
import { IdentityManager, type BackupPackage, type BackupPackageV2, type PersonaConfig } from '@sedecim/identity';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { NetworkGuard } from '@sedecim/tor-network';
import { DeliveryEngine, type OutboxRecord } from '@sedecim/delivery-engine';
import { BUZZ_PINNED_ADAPTER, chatMessage, channelFilter, DirectMessenger, DmInbox, dmRouter, joinRequest, OperationMismatchError, publishDmRelayList, type DirectMessage, type DmInboxOptions, type DmOperation, type InboxOutbox, type InboxPool, type OperationOutbox, type RelayAdapter } from '@sedecim/messaging';
import { FilterWindowSync, NegentropySync, exportEventsJsonl, importEventsJsonl, rebuildHistory, seenLookup, type JsonlImportIssue, type RebuiltHistory } from '@sedecim/sync';
import { continuityPolicy, disclose, preset, receiptPolicy, validateConfig, type ContinuityOption, type SovereigntyConfig } from '@sedecim/profiles';
import { TelemetryPolicy } from '@sedecim/telemetry-policy';
import {
  EncryptedGroupStorage,
  hasPendingGroupOperations,
  MarmotTsProvider,
  PoolGroupNetwork,
  assertHighSecurity,
  ciphertextHashFromUrl,
  isExtendedGroupSession,
  type ExtendedGroupSession,
  type GroupCryptoProvider,
  type GroupDevice,
  type GroupHandle,
  type GroupMediaAttachment,
  type GroupMediaReference,
  type GroupMessage,
  type GroupProposal,
  type GroupSession,
  type PendingGroupOperation,
} from '@sedecim/marmot-adapter';
import { HttpPolicySource, managedSignerSink, RevocationPropagator, RotationWorker } from '@sedecim/rotation-worker';
import { downloadFromServers, fetchServerList, refusesUnsanitized, sanitizeMetadata, selectUploadServers, UnsanitizableFileError, uploadToServers, type HttpClient, type PreparedBlob } from '@sedecim/blossom-client';
import { ArchiveVaultClient, archiveEvent, archiveHistory, belongsOnPersonaRelays, ledgerRecords, openArchive, parseVaultExport, restoreHistory, VAULT_EXPORT_FORMAT, vaultExport, type ArchiveMeta, type ArchiveRetention, type ArchiveUsage, type ArchivedGroupMessage, type HistoryArchiveResult, type MlsSnapshot, type RestoredHistory, type VaultExport } from '@sedecim/continuity';

/** VAULT-03: decrypted group messages this device read or sent, kept because MLS deletes the keys of past epochs. */
const GROUP_HISTORY = 'group-history';
/** NIP-29 group state (metadata, admins, members, roles), signed by the relay. */
const CHANNEL_STATE_KINDS = [39000, 39001, 39002, 39003];
/** The persona's own lists: profile, contacts, relays, DM relays (NIP-17) and Blossom servers. */
const OWN_LIST_KINDS = [0, 3, 10002, 10050, 10063];
/** Written as the owner of MLS state restored from the vault: no device has this id, so its groups need a rejoin. */
const RESTORED_MLS_OWNER = 'vault-restore';
/**
 * OPS-21: how long a read waits for its relays. Over Tor, reaching an onion service and answering NIP-42 can take
 * several seconds, so a read there gets the margin of a slow circuit instead of coming back empty.
 */
const readTimeoutMs = (persona: Pick<PersonaConfig, 'network'>) => (persona.network === 'tor-only' ? 30_000 : 10_000);

/** VAULT-05: a vault export is one JSON document of its own format; anything else is read as JSONL. */
function isVaultExport(text: string): boolean {
  try {
    const doc = JSON.parse(text) as { format?: unknown } | null;
    return !!doc && typeof doc === 'object' && doc.format === VAULT_EXPORT_FORMAT;
  } catch {
    return false;
  }
}

export interface SovereignOptions {
  dataDir: string;
  passphrase: string;
  socksHost?: string;
  socksPort?: number;
  scryptLogN?: number;
  retry?: { baseMs: number; maxMs: number };
  /** Relay compatibility adapter (explicit, never silent). Defaults to the pinned Buzz adapter. */
  relayAdapter?: RelayAdapter;
  /** High-security group provider (Marmot/MLS). Defaults to marmot-ts. */
  groupProvider?: GroupCryptoProvider;
  /**
   * Deployment default for encrypted blobs (the blob-store) when the persona has no usable kind 10063
   * Blossom server list (MIP-04 group media, FR018-05 routing).
   */
  blobStore?: string;
  /**
   * FR017-06: extra relays where recipients' DM relay lists (kinds 10050 and 10002) are looked up, besides the
   * persona's own relays, like the web's `discoveryRelays`. Each lookup tells them which npub you write to.
   */
  discoveryRelays?: string[];
  /**
   * Reconnect to relays that drop while a subscription is open (default false: a one-shot command ends instead).
   * `sovereign dm watch` turns it on (FR009-03).
   */
  autoReconnect?: boolean;
  /**
   * VAULT-04: the Continuity Vault each sent event is copied to, as the persona's policy says (`setContinuity`).
   * Without it nothing is copied, and a persona that requires the copy keeps its sends held.
   */
  vaultUrl?: string;
}

/** FR009-03: what `watchDms` reports. */
export type DmWatchHandlers = Pick<DmInboxOptions<OutboxRecord>, 'onMessage' | 'onReceipt'>;

/**
 * This installation's identity as an MLS device of a persona. Kept in the persona store *outside* the
 * `mls-*` collections, so it is never part of a backup: a restored backup gets a new device id.
 */
export interface DeviceRecord {
  /** Key package `d` slot of this installation. */
  id: string;
  label?: string;
  /** Written by `restoreBackup`: the MLS state here is a copy of another device's. */
  cloned?: boolean;
}

/** VAULT-03: what `vaultRestore` rebuilt on this device. */
export interface VaultRestoreResult {
  archives: number;
  /** Archives that do not open with this archive key, or do not hold a valid entry of this persona. */
  skipped: number;
  /** Verified events found in the vault, and how many of them a relay of the persona accepted again. */
  events: number;
  published: number;
  rejected: number;
  /** Gift wraps sent to other people (VAULT-04 copies each send): not republished, their place is those people's relays. */
  othersWraps: number;
  groupMessages: number;
  /** Ledger operations added to this device's outbox (those it already had are kept). */
  ledger: number;
  /** `restored`: the groups are back, marked restored until `group rejoin`; `kept`: this device already had groups. */
  mls: 'restored' | 'kept' | 'none';
  /** When the restored ledger was sealed (ms), and archives it counted that the vault no longer lists. */
  savedAt?: number;
  missing: number;
}

export interface HistorySyncResult {
  channels: Record<string, NostrEvent[]>;
  dms: DirectMessage[];
  /** outbox after reconciling the restored ledger with what the relays actually store */
  outbox: OutboxRecord[];
  /** strategy that completed per relay (e.g. nip77-negentropy or req-window) */
  strategies: Record<string, string>;
  history: RebuiltHistory;
}

interface Session {
  persona: PersonaConfig;
  signer: Signer;
  pool: RelayPool;
  engine: DeliveryEngine;
  guard: NetworkGuard;
  /** FR017-06: where recipients' DM relay lists are looked up (the persona's relays plus the configured ones). */
  dmDiscovery: string[];
  /** FR017-06: the outbox as DMs and receipts use it: queueing for someone's DM relays lets the guard reach them. */
  dmOutbox: InboxOutbox<OutboxRecord> & OperationOutbox<OutboxRecord>;
  store: EncryptedStore;
  groups?: Promise<GroupSession>;
  /** FR011-04: the retry of what earlier runs left pending, started when the persona was opened. */
  resumed: Promise<unknown>;
  /** VAULT-04: the persona's Continuity Vault policy, as its stored configuration says (the engine reads it here). */
  continuity: { policy: ContinuityOption };
}

/**
 * Self-hosted sovereign client. Every persona is a compartment: its own encrypted store directory,
 * relays, signer, outbox and (for Tor personas) an isolated Tor circuit. No telemetry is ever sent.
 */
export class SovereignClient {
  readonly telemetry = new TelemetryPolicy({ level: 'none' });
  private manager?: IdentityManager;
  private readonly sessions = new Map<string, Session>();

  constructor(private readonly opts: SovereignOptions) {}

  private async openStore(dir: string) {
    return EncryptedStore.open(new FileBackend(dir), this.opts.passphrase, { logN: this.opts.scryptLogN ?? 17 });
  }

  async identities(): Promise<IdentityManager> {
    if (!this.manager) {
      const account = await this.openStore(join(this.opts.dataDir, 'account'));
      this.manager = new IdentityManager(account, (id) => this.openStore(join(this.opts.dataDir, 'personas', id)));
    }
    return this.manager;
  }

  /**
   * The panel configuration of a CLI persona. PANEL-05: its key lives on this device, sealed with the passphrase,
   * so its custody is 'local' whatever the preset says ('offline' would describe an air-gapped key).
   */
  profileFor(p: PersonaConfig): SovereigntyConfig {
    const base: SovereigntyConfig = p.network === 'tor-only' ? preset('sovereign-tor') : { ...preset('sovereign'), network: p.relays.length > 1 ? 'multi-relay' : 'private-relay' };
    return { ...base, custody: 'local' };
  }

  /** PANEL-05: the warnings of a persona's profile (for Tor-only, its residual risks), shown when it is created. */
  warningsFor(p: PersonaConfig): string[] {
    return validateConfig(this.profileFor(p), 'cli')
      .filter((i) => i.severity === 'warning')
      .map((i) => i.message);
  }

  async createPersona(input: { label: string; relays: string[]; tor?: boolean; highRisk?: boolean; onionOnly?: boolean }): Promise<PersonaConfig> {
    const mgr = await this.identities();
    const persona = await mgr.createPersona({
      label: input.label,
      relays: input.relays,
      compartment: input.highRisk ? 'high-risk' : 'standard',
      network: input.tor || input.highRisk || input.onionOnly ? 'tor-only' : 'direct',
      onionOnly: input.onionOnly,
      keyPassphrase: this.opts.passphrase,
      scryptLogN: this.opts.scryptLogN,
    });
    const issues = validateConfig(this.profileFor(persona), 'cli').filter((i) => i.severity === 'error');
    if (issues.length) throw new Error(issues.map((i) => i.message).join('; '));
    await mgr.saveConfig(persona.id, this.profileFor(persona));
    return persona;
  }

  /**
   * FR002-03: create a persona from a key backup file (offline generator or web download). The
   * ncryptsec must decrypt to the declared npub; the key is re-sealed under the local passphrase.
   */
  async importBackup(json: unknown, backupPassword: string, input: { label: string; relays: string[]; tor?: boolean; highRisk?: boolean; onionOnly?: boolean }): Promise<PersonaConfig> {
    const mgr = await this.identities();
    const network = input.tor || input.highRisk || input.onionOnly ? 'tor-only' : 'direct';
    const issues = validateConfig(this.profileFor({ relays: input.relays, network } as PersonaConfig), 'cli').filter((i) => i.severity === 'error');
    if (issues.length) throw new Error(issues.map((i) => i.message).join('; '));
    const persona = await mgr.importKeyBackup(json, backupPassword, this.opts.passphrase, {
      label: input.label,
      relays: input.relays,
      compartment: input.highRisk ? 'high-risk' : 'standard',
      network,
      onionOnly: input.onionOnly,
      scryptLogN: this.opts.scryptLogN,
    });
    await mgr.saveConfig(persona.id, this.profileFor(persona));
    return persona;
  }

  /** FR-027: full encrypted backup (key, relays, panel configuration, MLS group state). */
  /**
   * `includeMls: false` exports only key, relays and panel: the way to set up an *additional* device of
   * the persona (then `group add-device`). A backup with MLS state restores this device's groups instead.
   */
  async exportBackup(personaId: string, backupPassword: string, opts: { scryptLogN?: number; includeMls?: boolean } = {}): Promise<BackupPackageV2> {
    return (await this.identities()).exportBackup(personaId, backupPassword, { keyPassphrase: this.opts.passphrase, scryptLogN: opts.scryptLogN, ...(opts.includeMls === false ? { includeMls: false } : {}) });
  }

  /**
   * Restores a backup. The MLS group state it carries belongs to the source device's leaves: this
   * installation gets a fresh device id and its groups are marked restored, so it cannot send with the
   * cloned leaf until `groupRejoin` makes it a new leaf and removes the old one (FR025-06).
   */
  async restoreBackup(pkg: BackupPackage, backupPassword: string): Promise<PersonaConfig> {
    const persona = await (await this.identities()).restoreBackup(pkg, backupPassword, this.opts.passphrase, { scryptLogN: this.opts.scryptLogN });
    const store = await this.openStore(join(this.opts.dataDir, 'personas', persona.id));
    const record: DeviceRecord = { id: bytesToHex(randomBytes(16)), cloned: true };
    await store.collection<DeviceRecord>('device').put('self', record);
    return persona;
  }

  /** This installation's device record for a persona (created on first use). */
  async device(personaId: string): Promise<DeviceRecord> {
    const s = await this.session(personaId);
    const col = s.store.collection<DeviceRecord>('device');
    let rec = await col.get('self');
    if (!rec) {
      // Original installation (and installs from before multi-device): the persona id was the `d` slot.
      rec = { id: s.persona.id };
      await col.put('self', rec);
    }
    return rec;
  }

  /** Local label of this device, announced only inside the groups (takes effect on the next session). */
  async setDeviceLabel(personaId: string, label: string): Promise<DeviceRecord> {
    const s = await this.session(personaId);
    const rec = { ...(await this.device(personaId)), label: label.slice(0, 64) };
    await s.store.collection<DeviceRecord>('device').put('self', rec);
    return rec;
  }

  async session(personaId: string): Promise<Session> {
    const cached = this.sessions.get(personaId);
    if (cached) return cached;
    const mgr = await this.identities();
    const persona = await mgr.get(personaId);
    const signer = await mgr.unlock(personaId, this.opts.passphrase);
    const dmDiscovery = [...new Set([...persona.relays, ...(this.opts.discoveryRelays ?? [])])];
    const guard = this.guardFor(persona, dmDiscovery);
    const pool = new RelayPool({
      webSocketFactory: persona.network === 'tor-only' ? guard.webSocketFactory() : async (u) => (await guard.assertRoute(u), new WebSocket(u) as unknown as WebSocketLike),
      signer,
      authMode: 'on-demand',
      autoReconnect: this.opts.autoReconnect ?? false,
      connectTimeoutMs: 15_000,
    });
    const store = await this.openStore(join(this.opts.dataDir, 'personas', personaId));
    // FR017-06: the same routing as the web. A DM wrap goes to the recipient's DM relays, looked up again on each
    // retry until one accepts it (FR010-03). Writing to someone lets the guard reach the relays they published.
    const allow = (urls: string[]) => guard.allowHosts(urls.map((u) => new URL(u).hostname));
    const route = dmRouter(pool, { discoveryRelays: dmDiscovery, fallback: persona.relays, timeoutMs: readTimeoutMs(persona) });
    const router = async (rec: { meta?: Record<string, string> }) => {
      const r = await route(rec);
      if (r) allow(r.relays);
      return r;
    };
    // VAULT-04: each sent event is copied to the Continuity Vault as the persona's policy says, through its guard.
    const continuity = { policy: continuityPolicy((await mgr.getConfig(personaId)) ?? {}) };
    const vaultUrl = this.opts.vaultUrl;
    const engine = new DeliveryEngine({
      store: store.collection<OutboxRecord>('outbox'),
      publisher: pool,
      signer,
      retry: this.opts.retry,
      router,
      continuity: { policy: () => continuity.policy, ...(vaultUrl ? { sink: { backup: (event: NostrEvent) => this.archiveSent(persona, vaultUrl, event) } } : {}) },
    });
    // FR-011: when a relay comes back (after a drop or a failed attempt) the whole outbox is re-driven.
    pool.onReconnect(() => void engine.resume().catch(() => undefined));
    // DM wraps an earlier run left pending may target the recipients' DM relays: the guard may reach them again.
    for (const r of await engine.list()) if (r.meta?.recipient) allow(Object.keys(r.relayStatus));
    const dmOutbox: Session['dmOutbox'] = {
      submit: (input, o) => (allow(o.relays), engine.submit(input, o)),
      applyReceipt: (r) => engine.applyReceipt(r),
      // FR011-05: a retried DM finds what it already queued (the guard already allows those relays, see above).
      get: (opId) => engine.get(opId),
      process: (opId) => engine.process(opId),
    };
    // FR011-04: what an earlier run left pending (sent without network, cut off) goes out as soon as the
    // persona is opened again, whatever the command. In the background: the command does not wait for it.
    const resumed = engine.resume().catch(() => undefined);
    const s: Session = { persona, signer, pool, engine, guard, dmDiscovery, dmOutbox, store, resumed, continuity };
    this.sessions.set(personaId, s);
    return s;
  }

  /**
   * FR011-05: `opId` is the operation of this send (the CLI's --op). Sent again with the same one, it retries that
   * message: no other event. Another text or channel under it is refused.
   */
  async sendChannel(personaId: string, groupId: string, text: string, opts: { opId?: string } = {}): Promise<OutboxRecord> {
    const s = await this.session(personaId);
    const opId = opts.opId ?? bytesToHex(randomBytes(16));
    const stored = (await s.engine.get(opId))?.template;
    if (stored && (stored.content !== text || getTagValue({ tags: stored.tags ?? [] }, 'h') !== groupId)) throw new OperationMismatchError(opId);
    return s.engine.submitOnce(opId, async () => ({ template: chatMessage(groupId, text) }), { relays: s.persona.relays, quorum: this.profileFor(s.persona).quorum, wait: true });
  }

  /** NIP-29 join request (kind 9021) for a channel. */
  async joinChannel(personaId: string, groupId: string): Promise<OutboxRecord> {
    const s = await this.session(personaId);
    return s.engine.submit({ template: joinRequest(groupId) }, { relays: s.persona.relays, quorum: this.profileFor(s.persona).quorum, wait: true });
  }

  /**
   * FR-013: rebuild channels and DMs from the persona's relays (NIP-77 where supported, REQ windows
   * otherwise) and reconcile the outbox restored from the backup against what the relays store.
   * `since` (seconds) limits the sync to what changed after the last sync; omit it for a full rebuild.
   */
  async syncHistory(personaId: string, opts: { since?: number; channels?: string[] } = {}): Promise<HistorySyncResult> {
    const s = await this.session(personaId);
    // FR011-04: reconcile after the retry of what was pending (started when the persona opened), not during it.
    await s.resumed;
    const now = Math.floor(Date.now() / 1000);
    const since = opts.since ?? 0;
    // Full rebuild: one paginated window; incremental: weekly windows back to `since`. The NIP-11
    // lookup of NIP-77 support goes through the guard (Tor/allowlist), never the global fetch.
    const window = new FilterWindowSync(s.pool, { since, windowSeconds: opts.since === undefined ? now + 1 : 7 * 24 * 3600, pageLimit: 500 });
    const history = await rebuildHistory({ relays: s.persona.relays, pubkey: s.persona.pubkey, since: opts.since, channels: opts.channels, strategies: [new NegentropySync(s.pool, { fetch: s.guard.fetchApi() }), window], signer: s.signer });
    const reconciler = new DeliveryEngine({ store: s.store.collection<OutboxRecord>('outbox'), publisher: s.pool, lookup: seenLookup(history.seenOn) });
    await reconciler.reconcile();
    const strategies = Object.fromEntries(Object.entries(history.reports.dms.perRelay).map(([relay, r]) => [relay, r.strategy]));
    return { channels: history.channels, dms: history.dms, outbox: await s.engine.list(), strategies, history };
  }

  /** NFR008-02: the persona's history (own activity, channels, gift wraps) as JSONL of signed events. */
  async exportHistory(personaId: string, opts: { since?: number } = {}): Promise<string> {
    const { history } = await this.syncHistory(personaId, opts);
    return exportEventsJsonl([...history.own, ...Object.values(history.channels).flat(), ...history.wraps]);
  }

  /**
   * Verifies an export and (unless dryRun) republishes the valid events to the persona's relays. It reads a JSONL of
   * signed events (NFR008-02) or a vault export (VAULT-05, `vault export`), whose gift wraps for other people stay
   * out: their place is those people's DM relays.
   */
  async importHistory(personaId: string, text: string, opts: { dryRun?: boolean } = {}): Promise<{ format: 'jsonl' | 'vault-export'; valid: number; invalid: JsonlImportIssue[]; duplicates: number; published: number; rejected: number; othersWraps: number }> {
    let events: NostrEvent[];
    let invalid: JsonlImportIssue[];
    let duplicates = 0;
    let othersWraps = 0;
    const format = isVaultExport(text) ? 'vault-export' : 'jsonl';
    if (format === 'vault-export') {
      const parsed = parseVaultExport(text);
      const { pubkey } = await (await this.identities()).get(personaId);
      if (parsed.export.pubkey !== pubkey) throw new Error('esta exportación del vault es de otra persona');
      events = parsed.export.events.filter((e) => belongsOnPersonaRelays(e, pubkey));
      othersWraps = parsed.export.events.length - events.length;
      invalid = parsed.invalid ? [{ line: 0, reason: `${parsed.invalid} eventos o mensajes de grupo inválidos en la exportación` }] : [];
    } else {
      const parsed = importEventsJsonl(text);
      ({ events, invalid, duplicates } = parsed);
    }
    let published = 0;
    let rejected = 0;
    if (!opts.dryRun) {
      const s = await this.session(personaId);
      for (const e of events) {
        const results = await s.pool.publish(e, s.persona.relays);
        if (results.some((r) => r.ok)) published++;
        else rejected++;
      }
    }
    return { format, valid: events.length, invalid, duplicates, published, rejected, othersWraps };
  }

  async readChannel(personaId: string, groupId: string, limit = 50): Promise<NostrEvent[]> {
    const s = await this.session(personaId);
    return s.pool.query(s.persona.relays, [{ ...channelFilter(groupId), limit }], readTimeoutMs(s.persona));
  }

  /**
   * FR017-06: a DM goes the way the web sends it. The recipient's wrap goes to the DM relays they published
   * (kind 10050, else their NIP-65 read relays, else this persona's relays as a disclosed fallback), and the
   * sender's copy to this persona's relays. Each record keeps `meta.recipient` and `meta.dmRelaySource`.
   * FR011-05: the DM is the operation `opId` (the CLI's --op), stored before its wraps are made. Sent again with the
   * same one, it retries that message: no other rumor, no other event. Another text or recipient under it is refused.
   */
  async sendDm(personaId: string, to: string, text: string, opts: { opId?: string } = {}): Promise<OutboxRecord[]> {
    const s = await this.session(personaId);
    const recipient = normalizePubkey(to);
    const warnings = await (await this.identities()).reuseWarnings(personaId, { contact: recipient });
    if (warnings.length) throw new Error(`compartimentación: ${warnings.join(' ')} (usa otra persona o confirma explícitamente)`);
    await (await this.identities()).recordUsage(personaId, { contact: recipient });
    // The NIP-17 gate is checked by the CLI before a DM is composed (flags.json of the interop gate).
    const messenger = new DirectMessenger(s.signer, { nip17: true, readReceipts: false }, (this.opts.relayAdapter ?? BUZZ_PINNED_ADAPTER).wrap);
    const operations = s.store.collection<DmOperation>('dm-ops');
    const { deliveries } = await messenger.sendDmOnce(opts.opId ?? bytesToHex(randomBytes(16)), { recipients: [recipient], content: text }, { pool: s.pool, outbox: s.dmOutbox, operations, ownRelays: s.persona.relays, discoveryRelays: s.dmDiscovery, timeoutMs: readTimeoutMs(s.persona), wait: true });
    return deliveries.map((d) => d.record);
  }

  /** FR017-06: publishes the persona's DM relay list (kind 10050), as the web does when a persona is created. */
  async publishDmRelays(personaId: string): Promise<OutboxRecord> {
    const s = await this.session(personaId);
    return s.engine.submit({ event: await publishDmRelayList(s.signer, s.persona.relays) }, { relays: s.persona.relays, quorum: 1, wait: true });
  }

  /**
   * FR009-03: the persona's DM inbox, on its own DM relays (its relays plus those of its kind 10050), as the web
   * reads it. Receipts for its DMs advance the outbox (RECIPIENT_ACKED, READ). Incoming DMs get the receipts the
   * profile allows (none with the sovereign presets), sent to the sender's DM relays. Reading its own list lets
   * the guard reach the relays it names; Tor-only still goes through Tor.
   */
  private dmInbox(s: Session, handlers: DmWatchHandlers = {}): DmInbox<OutboxRecord> {
    const allow = (urls: string[]) => s.guard.allowHosts(urls.map((u) => new URL(u).hostname));
    const pool: InboxPool = {
      query: (urls, filters, timeoutMs) => (allow(urls), s.pool.query(urls, filters, timeoutMs)),
      subscribe: (urls, filters, o) => (allow(urls), s.pool.subscribe(urls, filters, o)),
    };
    return new DmInbox(s.signer, {
      pool,
      outbox: s.dmOutbox,
      ownRelays: s.persona.relays,
      discoveryRelays: s.dmDiscovery,
      policy: () => receiptPolicy(this.profileFor(s.persona)),
      sent: s.store.collection<boolean>('receipts'),
      wrapOptions: (this.opts.relayAdapter ?? BUZZ_PINNED_ADAPTER).wrap,
      timeoutMs: readTimeoutMs(s.persona),
      ...handlers,
    });
  }

  /** Reads the persona's DM relays once; `onReceipt` reports the receipts that advanced its DMs. */
  async inbox(personaId: string, handlers: DmWatchHandlers = {}): Promise<DirectMessage[]> {
    const s = await this.session(personaId);
    return this.dmInbox(s, handlers).sync(readTimeoutMs(s.persona));
  }

  /** FR009-03: keeps reading the persona's DM relays as messages and receipts arrive. Returns the stop function. */
  async watchDms(personaId: string, handlers: DmWatchHandlers): Promise<() => void> {
    const s = await this.session(personaId);
    const inbox = this.dmInbox(s, handlers);
    await inbox.start();
    return () => inbox.close();
  }

  /**
   * FR011-04: waits, at most `timeoutMs`, for the retries started when the personas were opened, so that a
   * short-lived CLI command does not exit in the middle of delivering what an earlier run left pending.
   */
  async settle(timeoutMs = 20_000): Promise<void> {
    const pending = [...this.sessions.values()].map((s) => s.resumed.then(() => this.retryGroups(s)));
    if (pending.length === 0) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    await Promise.race([Promise.all(pending), new Promise<void>((r) => (timer = setTimeout(r, timeoutMs)))]);
    clearTimeout(timer);
  }

  /**
   * FR025-12: the group messages and commits that found no relay (in this run or an earlier one) go out at the end of
   * any command that opened the persona, as FR011-04 does for DMs. After the command, not during it: two operations on
   * the same MLS state must never interleave.
   */
  private async retryGroups(s: Session): Promise<void> {
    try {
      if (!(await hasPendingGroupOperations(new EncryptedGroupStorage(s.store)))) return;
      const gs = await this.groupSession(s.persona.id);
      if (isExtendedGroupSession(gs)) await gs.retryPending();
    } catch {
      /* they stay pending: the next command tries again */
    }
  }

  async outbox(personaId: string): Promise<OutboxRecord[]> {
    return (await this.session(personaId)).engine.list();
  }

  async resume(personaId: string): Promise<OutboxRecord[]> {
    const s = await this.session(personaId);
    s.guard.invalidateProbe();
    return s.engine.resume();
  }

  /**
   * High-security groups (Marmot/MLS): forward secrecy and post-compromise security. Traffic uses the
   * persona's pool (Tor-only / allowlist apply) and MLS state is sealed in the persona's encrypted store.
   */
  async groupSession(personaId: string): Promise<GroupSession> {
    const s = await this.session(personaId);
    s.groups ??= (async () => {
      const provider = this.opts.groupProvider ?? new MarmotTsProvider();
      assertHighSecurity(provider);
      const dev = await this.device(personaId);
      return provider.openSession({
        signer: s.signer,
        network: new PoolGroupNetwork(s.pool, s.persona.relays),
        storage: new EncryptedGroupStorage(s.store),
        deviceId: dev.id,
        ...(dev.label ? { deviceLabel: dev.label } : {}),
        ...(dev.cloned ? { clonedState: true } : {}),
        onMessage: (m) => this.keepGroupMessage(s, m),
      });
    })();
    s.groups.catch(() => (s.groups = undefined));
    return s.groups;
  }

  /** VAULT-03: keeps a group message this device decrypted or sent: MLS will not decrypt it again. */
  private async keepGroupMessage(s: Session, m: GroupMessage): Promise<void> {
    if (!m.rumorId) return;
    const entry: ArchivedGroupMessage = { groupId: m.groupId, rumorId: m.rumorId, sender: m.sender, kind: m.kind, content: m.content, createdAt: m.createdAt, ...(m.tags?.length ? { tags: m.tags } : {}), ...(m.epoch !== undefined ? { epoch: m.epoch } : {}) };
    await s.store.collection<ArchivedGroupMessage>(GROUP_HISTORY).put(`${m.groupId}:${m.rumorId}`, entry);
  }

  /** VAULT-03: the group messages this device read or sent, and those restored from the vault, oldest first. */
  async groupHistory(personaId: string, groupId?: string): Promise<ArchivedGroupMessage[]> {
    const s = await this.session(personaId);
    const all = (await s.store.collection<ArchivedGroupMessage>(GROUP_HISTORY).all()).map((e) => e.value);
    return all.filter((m) => !groupId || m.groupId === groupId).sort((a, b) => a.createdAt - b.createdAt || (a.rumorId < b.rumorId ? -1 : 1));
  }

  async groupPublishKeyPackage(personaId: string): Promise<NostrEvent> {
    const s = await this.session(personaId);
    return (await this.groupSession(personaId)).publishKeyPackage(s.persona.relays);
  }

  async groupCreate(personaId: string, name: string): Promise<GroupHandle> {
    const s = await this.session(personaId);
    return (await this.groupSession(personaId)).createGroup({ name, relays: s.persona.relays });
  }

  async groupInvite(personaId: string, groupId: string, member: string): Promise<GroupHandle> {
    const s = await this.session(personaId);
    const pubkey = normalizePubkey(member);
    const mgr = await this.identities();
    const warnings = await mgr.reuseWarnings(personaId, { contact: pubkey });
    if (warnings.length) throw new Error(`compartimentación: ${warnings.join(' ')}`);
    const gs = await this.groupSession(personaId);
    const kp = await gs.findKeyPackage(pubkey, s.persona.relays);
    if (!kp) throw new Error('el invitado no ha publicado un key package en los relays de esta persona');
    await mgr.recordUsage(personaId, { contact: pubkey });
    // Multi-device (FR025-06): add every current device of the persona in one commit.
    if (isExtendedGroupSession(gs)) return gs.invitePersona(groupId, pubkey, s.persona.relays);
    return gs.invite(groupId, kp);
  }

  private async extended(personaId: string): Promise<ExtendedGroupSession> {
    const gs = await this.groupSession(personaId);
    if (!isExtendedGroupSession(gs)) throw new Error('el proveedor de grupos no soporta multi-dispositivo/propuestas/MIP-04');
    return gs;
  }

  /**
   * Adds the devices of `member` (default: this persona) that are not in the group yet. Admins commit
   * directly; other members send Add proposals for an admin to commit (FR025-06/09).
   */
  async groupAddDevice(personaId: string, groupId: string, member?: string): Promise<{ committed: true; group: GroupHandle } | { committed: false; proposals: GroupProposal[] }> {
    const s = await this.session(personaId);
    const gs = await this.extended(personaId);
    const pubkey = member ? normalizePubkey(member) : s.persona.pubkey;
    await gs.sync(groupId);
    const g = await gs.group(groupId);
    if (g.admins.includes(s.persona.pubkey)) return { committed: true, group: await gs.invitePersona(groupId, pubkey, s.persona.relays) };
    const kps = await gs.missingDeviceKeyPackages(groupId, pubkey, s.persona.relays);
    if (!kps.length) throw new Error('no hay key packages de dispositivos que no estén ya en el grupo');
    return { committed: false, proposals: await gs.proposeAdd(groupId, kps) };
  }

  async groupDevices(personaId: string, groupId: string): Promise<GroupDevice[]> {
    const gs = await this.extended(personaId);
    await gs.sync(groupId);
    return gs.devices(groupId);
  }

  async groupRemoveDevice(personaId: string, groupId: string, leafIndex: number): Promise<GroupHandle> {
    return (await this.extended(personaId)).removeDevice(groupId, leafIndex);
  }

  /** Non-admin members propose; the proposal travels as a kind 445 group message (FR025-09). */
  async groupPropose(personaId: string, groupId: string, p: { add?: string; remove?: string }): Promise<GroupProposal[]> {
    const s = await this.session(personaId);
    const gs = await this.extended(personaId);
    if (p.add) {
      const pubkey = normalizePubkey(p.add);
      const mgr = await this.identities();
      const warnings = await mgr.reuseWarnings(personaId, { contact: pubkey });
      if (warnings.length) throw new Error(`compartimentación: ${warnings.join(' ')}`);
      await gs.sync(groupId);
      const kps = await gs.missingDeviceKeyPackages(groupId, pubkey, s.persona.relays);
      if (!kps.length) throw new Error('el invitado no tiene key packages de dispositivos fuera del grupo');
      await mgr.recordUsage(personaId, { contact: pubkey });
      return gs.proposeAdd(groupId, kps);
    }
    if (p.remove) return gs.proposeRemove(groupId, { pubkey: normalizePubkey(p.remove) });
    throw new Error('indica --add NPUB o --remove NPUB');
  }

  async groupProposals(personaId: string, groupId: string): Promise<GroupProposal[]> {
    const gs = await this.extended(personaId);
    await gs.sync(groupId);
    return gs.pendingProposals(groupId);
  }

  /** Admin: commit pending proposals (all admissible ones, or the given refs). */
  async groupCommit(personaId: string, groupId: string, refs?: string[]): Promise<GroupHandle> {
    return (await this.extended(personaId)).commitProposals(groupId, refs?.length ? { refs } : {});
  }

  /**
   * After a backup restore: re-enter the restored groups as a new leaf of this device (the cloned leaf
   * is removed). Admins finish at once; members wait for an admin commit and run it again.
   */
  async groupRejoin(personaId: string, groupId?: string): Promise<Array<{ groupId: string; status: 'joined' | 'pending' }>> {
    const s = await this.session(personaId);
    const gs = await this.extended(personaId);
    const ids = groupId ? [groupId] : await gs.restoredGroups();
    const out: Array<{ groupId: string; status: 'joined' | 'pending' }> = [];
    for (const id of ids) out.push({ groupId: id, status: (await gs.rejoin(id, s.persona.relays)).status });
    return out;
  }

  /**
   * VAULT-02: the persona's Continuity Vault (ADR 0011). Requests are signed (NIP-98) with the key derived
   * from its archive key, never with the persona key, and go through its network guard (Tor for Tor-only).
   */
  /** The persona's vault client, through a guard of its own: Tor-only stays Tor-only, onion-only reaches only a .onion vault. */
  private async vaultClient(persona: PersonaConfig, url: string): Promise<{ client: ArchiveVaultClient; key: Uint8Array }> {
    const guard = this.guardFor(persona, [...persona.relays, url]);
    const key = await (await this.identities()).archiveKey(persona.id);
    return { client: new ArchiveVaultClient({ baseUrl: url, auth: { archiveKey: key }, fetch: guard.fetchApi() }), key };
  }

  private async vault(personaId: string, url: string): Promise<{ client: ArchiveVaultClient; key: Uint8Array; session: Session }> {
    const s = await this.session(personaId);
    return { ...(await this.vaultClient(s.persona, url)), session: s };
  }

  /** VAULT-04: the Continuity Vault copy of one sent event, sealed on this device with the persona's archive key. */
  private async archiveSent(persona: PersonaConfig, url: string, event: NostrEvent): Promise<void> {
    const { client, key } = await this.vaultClient(persona, url);
    try {
      await archiveEvent(client, key, event);
    } finally {
      key.fill(0);
    }
  }

  /**
   * VAULT-04: the persona's Continuity Vault policy. Anything but `off` is a cloud copy, so the stored profile says
   * so too; `required-for-resilient` needs a vault (this client's `vaultUrl`) or every send would be held. A held
   * send goes out as soon as the policy is relaxed.
   */
  async setContinuity(personaId: string, policy: ContinuityOption): Promise<SovereigntyConfig> {
    const mgr = await this.identities();
    const p = await mgr.get(personaId);
    const stored = (await mgr.getConfig(personaId)) ?? this.profileFor(p);
    const next: SovereigntyConfig = { ...stored, continuity: policy, ...(policy !== 'off' && stored.cloudBackup === 'off' ? { cloudBackup: 'ciphertext-user-key' as const } : {}) };
    const refused = validateConfig(next, 'cli', { relays: p.relays.length, continuityVault: !!this.opts.vaultUrl }).filter((i) => i.severity === 'error' && i.controls.includes('continuity'));
    if (refused.length) throw new Error(refused.map((i) => i.message).join(' '));
    await mgr.saveConfig(personaId, next);
    const s = this.sessions.get(personaId);
    if (s) {
      s.continuity.policy = policy;
      void s.engine.resume().catch(() => undefined);
    }
    return next;
  }

  /** The profile of a persona with what `setContinuity` stored over the derived one (cloud copy and its policy). */
  async profile(personaId: string): Promise<SovereigntyConfig> {
    const mgr = await this.identities();
    const base = this.profileFor(await mgr.get(personaId));
    const stored = await mgr.getConfig(personaId);
    return { ...base, ...(stored ? { cloudBackup: stored.cloudBackup } : {}), continuity: continuityPolicy(stored ?? {}) };
  }

  /**
   * VAULT-03: seals on this device, and stores in the vault, what a clean device needs to rebuild the persona's
   * history with empty relays (ADR 0011): every canonical event its relays hold for it (its own activity, its
   * channels with their state, the gift wraps addressed to it), the group messages it read or sent, the delivery
   * ledger and the MLS group state. Events and messages are written once; the ledger and the MLS state replace
   * their previous copy. The vault only receives sealed envelopes.
   */
  async vaultPush(personaId: string, url: string): Promise<HistoryArchiveResult & { operations: number }> {
    const { client, key, session: s } = await this.vault(personaId, url);
    try {
      const ledger = await s.engine.list();
      const mls = await this.mlsSnapshot(s);
      const result = await archiveHistory(client, key, {
        pubkey: s.persona.pubkey,
        events: await this.canonicalHistory(s),
        groupMessages: (await s.store.collection<ArchivedGroupMessage>(GROUP_HISTORY).all()).map((e) => e.value),
        ledger,
        ...(Object.keys(mls).length ? { mls } : {}),
      });
      return { ...result, operations: ledger.length };
    } finally {
      key.fill(0);
    }
  }

  /** VAULT-03: every event the persona's relays hold for it: own activity and lists, its channels and their state, its gift wraps. */
  private async canonicalHistory(s: Session): Promise<NostrEvent[]> {
    await s.resumed;
    const now = Math.floor(Date.now() / 1000);
    const strategies = [new NegentropySync(s.pool, { fetch: s.guard.fetchApi() }), new FilterWindowSync(s.pool, { since: 0, windowSeconds: now + 1, pageLimit: 500 })];
    const history = await rebuildHistory({ relays: s.persona.relays, pubkey: s.persona.pubkey, strategies });
    const channels = Object.keys(history.channels);
    const filters = [{ authors: [s.persona.pubkey], kinds: OWN_LIST_KINDS }, ...(channels.length ? [{ kinds: CHANNEL_STATE_KINDS, '#d': channels }] : [])];
    const lists = await s.pool.query(s.persona.relays, filters, readTimeoutMs(s.persona));
    return [...history.own, ...lists, ...Object.values(history.channels).flat(), ...history.wraps];
  }

  /** VAULT-03: the persona's MLS state by namespace, without private key packages (a copy never joins with them). */
  private async mlsSnapshot(s: Session): Promise<MlsSnapshot> {
    const out: MlsSnapshot = {};
    for (const name of await s.store.collectionNames('mls-')) {
      const ns = name.slice('mls-'.length);
      if (ns !== 'keypackages') out[ns] = await s.store.collection<unknown>(name).all();
    }
    return out;
  }

  /**
   * VAULT-03: rebuilds the persona's history on this device from the vault, with nothing but its archive key (from
   * the persona's backup), even if every relay lost its events:
   * - the verified events go back to the persona's relays (unless `republish` is false), so it reads as before;
   * - the ledger operations this device lacks join its outbox;
   * - the group messages join this device's group history;
   * - the MLS state is written only if this device has no groups, owned by no device: its groups count as
   *   restored, and `group rejoin` makes this device a new leaf before it sends (FR025-06).
   */
  async vaultRestore(personaId: string, url: string, opts: { republish?: boolean } = {}): Promise<VaultRestoreResult> {
    const { client, key, session: s } = await this.vault(personaId, url);
    let restored: RestoredHistory;
    try {
      restored = await restoreHistory(client, key, { pubkey: s.persona.pubkey });
    } finally {
      key.fill(0);
    }
    let published = 0;
    let rejected = 0;
    // VAULT-04 copies each send, gift wraps for other people included: their place is those people's relays.
    const own = restored.events.filter((e) => belongsOnPersonaRelays(e, s.persona.pubkey));
    if (opts.republish ?? true) {
      for (const e of own) {
        if ((await s.pool.publish(e, s.persona.relays)).some((r) => r.ok)) published++;
        else rejected++;
      }
    }
    const outbox = s.store.collection<OutboxRecord>('outbox');
    let ledger = 0;
    for (const rec of ledgerRecords<OutboxRecord>(restored.ledger?.outbox ?? [])) {
      if (await outbox.get(rec.opId)) continue; // never overwrite newer local state
      await outbox.put(rec.opId, rec);
      ledger++;
    }
    const history = s.store.collection<ArchivedGroupMessage>(GROUP_HISTORY);
    for (const m of restored.groupMessages) await history.put(`${m.groupId}:${m.rumorId}`, m);
    const mls = await this.restoreMls(s, restored.mls?.namespaces);
    return { archives: restored.archives, skipped: restored.skipped, events: restored.events.length, published, rejected, othersWraps: restored.events.length - own.length, groupMessages: restored.groupMessages.length, ledger, mls, ...(restored.ledger ? { savedAt: restored.ledger.at } : {}), missing: restored.missing };
  }

  private async restoreMls(s: Session, namespaces: MlsSnapshot | undefined): Promise<VaultRestoreResult['mls']> {
    if (!namespaces?.groups?.length) return 'none';
    if ((await s.store.collection<unknown>('mls-groups').all()).length) return 'kept';
    // An open session would keep the old state in memory: the next one reads what is written here.
    const open = s.groups;
    s.groups = undefined;
    await open?.then((g) => g.close(), () => undefined);
    for (const [ns, entries] of Object.entries(namespaces)) {
      if (ns === 'keypackages' || !/^[a-z0-9-]+$/.test(ns)) continue;
      const col = s.store.collection<unknown>(`mls-${ns}`);
      for (const e of entries) await col.put(e.id, e.value);
    }
    // Owned by no device: the next session marks every group restored (a cloned leaf) until `group rejoin`.
    await new EncryptedGroupStorage(s.store).put('device', 'owner', RESTORED_MLS_OWNER);
    return 'restored';
  }

  async vaultList(personaId: string, url: string): Promise<ArchiveMeta[]> {
    const { client, key } = await this.vault(personaId, url);
    try {
      return await client.listAll();
    } finally {
      key.fill(0);
    }
  }

  /** Downloads every archive and opens it here: shows that this device's archive key opens what the vault keeps. */
  async vaultVerify(personaId: string, url: string): Promise<{ archives: number; opened: number }> {
    const { client, key } = await this.vault(personaId, url);
    try {
      const all = await client.listAll();
      let opened = 0;
      for (const meta of all) {
        try {
          openArchive(key, meta.id, (await client.get(meta.id)).envelope).fill(0);
          opened++;
        } catch {
          // Counted as not opened: another archive key (e.g. before a restore) or a damaged envelope.
        }
      }
      return { archives: all.length, opened };
    } finally {
      key.fill(0);
    }
  }

  /** VAULT-05: what the persona's vault account uses, its limits and its retention. */
  async vaultUsage(personaId: string, url: string): Promise<ArchiveUsage> {
    const { client, key } = await this.vault(personaId, url);
    try {
      return await client.usage();
    } finally {
      key.fill(0);
    }
  }

  /** VAULT-05: keeps the persona's archives `days` since their last write (null: until deleted, within the operator's maximum). */
  async vaultRetention(personaId: string, url: string, days: number | null): Promise<ArchiveRetention> {
    const { client, key } = await this.vault(personaId, url);
    try {
      return await client.setRetention(days);
    } finally {
      key.fill(0);
    }
  }

  /**
   * VAULT-05: the persona's vault in an open, portable format, decrypted on this device: signed NIP-01 events any
   * Nostr client can verify and publish (and `history import` takes back), the group messages and the ledger. The
   * MLS state stays out.
   */
  async vaultExport(personaId: string, url: string): Promise<{ export: VaultExport; skipped: number }> {
    const { client, key, session: s } = await this.vault(personaId, url);
    try {
      const restored = await restoreHistory(client, key, { pubkey: s.persona.pubkey });
      return { export: vaultExport(restored, s.persona.pubkey), skipped: restored.skipped };
    } finally {
      key.fill(0);
    }
  }

  /** VAULT-05: deletes every archive of the persona and its vault account (its retention choice included). */
  async vaultDelete(personaId: string, url: string): Promise<number> {
    const { client, key } = await this.vault(personaId, url);
    try {
      return await client.remove();
    } finally {
      key.fill(0);
    }
  }

  /**
   * The persona's network policy for these destinations: Tor-only goes through SOCKS on circuits of its own
   * (FR006-06) and onion-only reaches .onion hosts only (FR021-03). Every guard of a persona comes from here, so none
   * forgets part of the policy (IR-2026-10-02: group media and the rotation worker did not carry onion-only).
   */
  private guardFor(persona: PersonaConfig, urls: string[]): NetworkGuard {
    return new NetworkGuard({
      mode: persona.network,
      ...(persona.onionOnly ? { onionOnly: true } : {}),
      socksHost: this.opts.socksHost,
      socksPort: this.opts.socksPort,
      isolationKey: persona.id,
      allowedHosts: [...new Set(urls.map((u) => new URL(u).hostname))],
    });
  }

  /** HTTP through a guard with the persona's network policy, allowing only these extra hosts. */
  private async blobHttp(personaId: string, urls: string[]): Promise<HttpClient> {
    const s = await this.session(personaId);
    const guard = this.guardFor(s.persona, [...s.persona.relays, ...urls]);
    return (url, init) => guard.fetch(url, init);
  }

  /**
   * MIP-04: sanitize → encrypt with a key derived from the MLS exporter of the current epoch → upload the
   * ciphertext to the persona's Blossom servers (kind 10063; blob-store fallback) → kind 9 with `imeta`.
   * FR019-03: every sovereign profile has stripFileMetadata, so an image whose metadata cannot be removed
   * (HEIC, TIFF/RAW, an image format the sanitizer does not know) is refused before anything is uploaded.
   */
  async groupSendFile(
    personaId: string,
    groupId: string,
    file: { data: Uint8Array; filename: string; mimeType: string; caption?: string },
    opts: { servers?: string[]; sanitize?: boolean } = {},
  ): Promise<GroupMediaReference> {
    const s = await this.session(personaId);
    let data = file.data;
    if (opts.sanitize ?? true) {
      const clean = sanitizeMetadata(file.data);
      if (refusesUnsanitized(clean, this.profileFor(s.persona).stripFileMetadata && 'images', file.mimeType)) throw new UnsanitizableFileError(clean.format, clean.reason);
      data = clean.data;
    }
    const gs = await this.extended(personaId);
    const userServers = opts.servers ?? (await fetchServerList(s.pool, s.persona.relays, s.persona.pubkey).catch(() => []));
    const servers = selectUploadServers({ userServers, encrypted: true, ...(this.opts.blobStore ? { fallback: this.opts.blobStore } : {}) });
    if (!servers.length) throw new Error('sin servidor Blossom: publica tu lista (kind 10063) o configura el blob-store');
    const http = await this.blobHttp(personaId, servers);
    return gs.sendMedia(
      groupId,
      { data, filename: file.filename, type: file.mimeType },
      async (ciphertext, sha256) => {
        const blob: PreparedBlob = { data: ciphertext, sha256, originalSha256: sha256, mimeType: 'application/octet-stream', removedMetadata: [] };
        const up = await uploadToServers(blob, servers, s.signer, { http, mirror: true });
        return { url: up.descriptor.url || `${up.server}/${sha256}` };
      },
      file.caption ?? '',
    );
  }

  /** Downloads (hash-verified) and decrypts a MIP-04 attachment received in the group. */
  async groupFetchFile(personaId: string, groupId: string, sha256: string): Promise<{ data: Uint8Array; attachment: GroupMediaAttachment }> {
    const s = await this.session(personaId);
    const gs = await this.extended(personaId);
    await gs.sync(groupId);
    const ref = await gs.mediaReference(groupId, sha256);
    if (!ref) throw new Error('adjunto desconocido en este grupo (ejecuta group read primero)');
    const url = ref.attachment.url;
    const hash = url ? ciphertextHashFromUrl(url) : undefined;
    if (!url || !hash) throw new Error('el adjunto no tiene una URL Blossom válida');
    const servers = await fetchServerList(s.pool, s.persona.relays, ref.sender).catch(() => []);
    const http = await this.blobHttp(personaId, [url, ...servers]);
    const { data } = await downloadFromServers(hash, { url, servers }, s.signer, { http });
    return { data: await gs.decryptMedia(groupId, data, ref.attachment, ref.epoch), attachment: ref.attachment };
  }

  /**
   * FR024-02/03 revocation worker run by this persona, which must be an admin of the groups (MIP-03) and a
   * policy-engine admin (NIP-98). Use a dedicated device/persona: it syncs the groups and discards what it
   * decrypts. HTTP goes through the persona's network policy (Tor-only / allowlist + these hosts). The
   * revocation cursor (FR024-04) is kept per policy-engine in the persona's encrypted store.
   */
  async revocationWorker(
    personaId: string,
    opts: { policyUrl: string; policyBearer?: string; managedSigner?: { url: string; token: string }; backoff?: { baseMs?: number; maxMs?: number } },
  ): Promise<{ worker: RotationWorker; propagator?: RevocationPropagator }> {
    const s = await this.session(personaId);
    const urls = [opts.policyUrl, ...(opts.managedSigner ? [opts.managedSigner.url] : [])];
    const guard = this.guardFor(s.persona, [...s.persona.relays, ...urls]);
    const f = guard.fetchApi();
    const source = new HttpPolicySource({ baseUrl: opts.policyUrl, signer: s.signer, fetch: f, ...(opts.policyBearer ? { bearer: opts.policyBearer } : {}) });
    const worker = new RotationWorker({ source, session: await this.groupSession(personaId), ...(opts.backoff ? { backoff: opts.backoff } : {}) });
    const cursors = s.store.collection<{ cursor: number }>('revocation-cursors');
    const propagator = opts.managedSigner
      ? new RevocationPropagator({
          feed: source,
          sinks: [managedSignerSink({ baseUrl: opts.managedSigner.url, token: opts.managedSigner.token, fetch: f })],
          cursor: { load: async () => (await cursors.get(opts.policyUrl))?.cursor, save: (cursor) => cursors.put(opts.policyUrl, { cursor }) },
        })
      : undefined;
    return { worker, ...(propagator ? { propagator } : {}) };
  }

  async groupAccept(personaId: string): Promise<GroupHandle[]> {
    return (await this.groupSession(personaId)).acceptInvites();
  }

  /** FR025-12: without a relay, the message comes back `pending` and goes out later (sync, `groupRetry`, next command). */
  async groupSend(personaId: string, groupId: string, text: string): Promise<GroupMessage> {
    const gs = await this.groupSession(personaId);
    await gs.sync(groupId);
    return gs.send(groupId, text);
  }

  /** FR025-12: group messages and commits of this persona still waiting for a relay (one group, or all). */
  async groupPending(personaId: string, groupId?: string): Promise<PendingGroupOperation[]> {
    return (await this.extended(personaId)).pendingOperations(groupId);
  }

  /** FR025-12: syncs the groups with pending operations and sends them again; returns what is still pending. */
  async groupRetry(personaId: string, groupId?: string): Promise<PendingGroupOperation[]> {
    return (await this.extended(personaId)).retryPending(groupId);
  }

  /** FR025-12: forgets a pending operation (e.g. one every relay refused). */
  async groupDiscard(personaId: string, id: string): Promise<void> {
    await (await this.extended(personaId)).discardPending(id);
  }

  /** New messages of the group (each is also kept in this device's group history, VAULT-03). */
  async groupSync(personaId: string, groupId: string): Promise<GroupMessage[]> {
    return (await this.groupSession(personaId)).sync(groupId);
  }

  async groupRemove(personaId: string, groupId: string, member: string): Promise<GroupHandle> {
    return (await this.groupSession(personaId)).removeMember(groupId, normalizePubkey(member));
  }

  async groupRotate(personaId: string, groupId: string): Promise<GroupHandle> {
    return (await this.groupSession(personaId)).rotate(groupId);
  }

  async groupList(personaId: string): Promise<GroupHandle[]> {
    return (await this.groupSession(personaId)).groups();
  }

  async disclosures(personaId: string) {
    return disclose(await this.profile(personaId));
  }

  close() {
    for (const s of this.sessions.values()) {
      void s.groups?.then((g) => g.close(), () => undefined);
      s.engine.stop();
      s.pool.close();
    }
    this.sessions.clear();
  }
}
