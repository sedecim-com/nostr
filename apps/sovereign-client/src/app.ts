import { join } from 'node:path';
import WebSocket from 'ws';
import { bytesToHex, normalizePubkey, randomBytes, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { EncryptedStore, FileBackend } from '@sedecim/encrypted-store';
import { IdentityManager, type BackupPackage, type BackupPackageV2, type PersonaConfig } from '@sedecim/identity';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { NetworkGuard } from '@sedecim/tor-network';
import { DeliveryEngine, type OutboxRecord } from '@sedecim/delivery-engine';
import { BUZZ_PINNED_ADAPTER, chatMessage, channelFilter, createDirectMessage, dmInboxFilter, joinRequest, openDirectMessage, type DirectMessage, type RelayAdapter } from '@sedecim/messaging';
import { FilterWindowSync, NegentropySync, exportEventsJsonl, importEventsJsonl, rebuildHistory, seenLookup, type JsonlImportIssue, type RebuiltHistory } from '@sedecim/sync';
import { disclose, preset, validateConfig, type SovereigntyConfig } from '@sedecim/profiles';
import { TelemetryPolicy } from '@sedecim/telemetry-policy';
import {
  EncryptedGroupStorage,
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
} from '@sedecim/marmot-adapter';
import { HttpPolicySource, managedSignerSink, RevocationPropagator, RotationWorker } from '@sedecim/rotation-worker';
import { downloadFromServers, fetchServerList, sanitizeMetadata, selectUploadServers, uploadToServers, type HttpClient, type PreparedBlob } from '@sedecim/blossom-client';

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
}

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
  store: EncryptedStore;
  groups?: Promise<GroupSession>;
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

  profileFor(p: PersonaConfig): SovereigntyConfig {
    return p.network === 'tor-only' ? preset('sovereign-tor') : { ...preset('sovereign'), network: p.relays.length > 1 ? 'multi-relay' : 'private-relay' };
  }

  async createPersona(input: { label: string; relays: string[]; tor?: boolean; highRisk?: boolean }): Promise<PersonaConfig> {
    const mgr = await this.identities();
    const persona = await mgr.createPersona({
      label: input.label,
      relays: input.relays,
      compartment: input.highRisk ? 'high-risk' : 'standard',
      network: input.tor || input.highRisk ? 'tor-only' : 'direct',
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
  async importBackup(json: unknown, backupPassword: string, input: { label: string; relays: string[]; tor?: boolean; highRisk?: boolean }): Promise<PersonaConfig> {
    const mgr = await this.identities();
    const network = input.tor || input.highRisk ? 'tor-only' : 'direct';
    const issues = validateConfig(this.profileFor({ relays: input.relays, network } as PersonaConfig), 'cli').filter((i) => i.severity === 'error');
    if (issues.length) throw new Error(issues.map((i) => i.message).join('; '));
    const persona = await mgr.importKeyBackup(json, backupPassword, this.opts.passphrase, {
      label: input.label,
      relays: input.relays,
      compartment: input.highRisk ? 'high-risk' : 'standard',
      network,
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
    const guard = new NetworkGuard({
      mode: persona.network,
      socksHost: this.opts.socksHost,
      socksPort: this.opts.socksPort,
      isolationKey: persona.id,
      allowedHosts: persona.relays.map((r) => new URL(r).hostname),
    });
    const pool = new RelayPool({
      webSocketFactory: persona.network === 'tor-only' ? guard.webSocketFactory() : async (u) => (await guard.assertRoute(u), new WebSocket(u) as unknown as WebSocketLike),
      signer,
      authMode: 'on-demand',
      autoReconnect: false,
      connectTimeoutMs: 15_000,
    });
    const store = await this.openStore(join(this.opts.dataDir, 'personas', personaId));
    const engine = new DeliveryEngine({ store: store.collection<OutboxRecord>('outbox'), publisher: pool, signer, retry: this.opts.retry });
    // FR-011: when a relay comes back (after a drop or a failed attempt) the whole outbox is re-driven.
    pool.onReconnect(() => void engine.resume().catch(() => undefined));
    const s: Session = { persona, signer, pool, engine, guard, store };
    this.sessions.set(personaId, s);
    return s;
  }

  async sendChannel(personaId: string, groupId: string, text: string): Promise<OutboxRecord> {
    const s = await this.session(personaId);
    return s.engine.submit({ template: chatMessage(groupId, text) }, { relays: s.persona.relays, quorum: this.profileFor(s.persona).quorum, wait: true });
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

  /** Verifies a JSONL export and (unless dryRun) republishes the valid events to the persona's relays. */
  async importHistory(personaId: string, jsonl: string, opts: { dryRun?: boolean } = {}): Promise<{ valid: number; invalid: JsonlImportIssue[]; duplicates: number; published: number; rejected: number }> {
    const parsed = importEventsJsonl(jsonl);
    let published = 0;
    let rejected = 0;
    if (!opts.dryRun) {
      const s = await this.session(personaId);
      for (const e of parsed.events) {
        const results = await s.pool.publish(e, s.persona.relays);
        if (results.some((r) => r.ok)) published++;
        else rejected++;
      }
    }
    return { valid: parsed.events.length, invalid: parsed.invalid, duplicates: parsed.duplicates, published, rejected };
  }

  async readChannel(personaId: string, groupId: string, limit = 50): Promise<NostrEvent[]> {
    const s = await this.session(personaId);
    return s.pool.query(s.persona.relays, [{ ...channelFilter(groupId), limit }], 10_000);
  }

  async sendDm(personaId: string, to: string, text: string): Promise<OutboxRecord[]> {
    const s = await this.session(personaId);
    const recipient = normalizePubkey(to);
    const warnings = await (await this.identities()).reuseWarnings(personaId, { contact: recipient });
    if (warnings.length) throw new Error(`compartimentación: ${warnings.join(' ')} (usa otra persona o confirma explícitamente)`);
    await (await this.identities()).recordUsage(personaId, { contact: recipient });
    const msg = await createDirectMessage(s.signer, { recipients: [recipient], content: text }, (this.opts.relayAdapter ?? BUZZ_PINNED_ADAPTER).wrap);
    const groupId = msg.rumor.id;
    return Promise.all(msg.wraps.map((w) => s.engine.submit({ event: w.event }, { relays: s.persona.relays, groupId, meta: { recipient: w.recipient }, wait: true })));
  }

  async inbox(personaId: string): Promise<DirectMessage[]> {
    const s = await this.session(personaId);
    const wraps = await s.pool.query(s.persona.relays, [dmInboxFilter(s.persona.pubkey)], 10_000);
    const out: DirectMessage[] = [];
    for (const w of wraps) {
      try {
        out.push(await openDirectMessage(s.signer, w));
      } catch {
        /* not for us / malformed */
      }
    }
    return out.sort((a, b) => a.rumor.created_at - b.rumor.created_at);
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
      });
    })();
    s.groups.catch(() => (s.groups = undefined));
    return s.groups;
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

  /** HTTP through a guard with the persona's network policy, allowing only these extra hosts. */
  private async blobHttp(personaId: string, urls: string[]): Promise<HttpClient> {
    const s = await this.session(personaId);
    const guard = new NetworkGuard({
      mode: s.persona.network,
      socksHost: this.opts.socksHost,
      socksPort: this.opts.socksPort,
      isolationKey: s.persona.id,
      allowedHosts: [...new Set([...s.persona.relays, ...urls].map((u) => new URL(u).hostname))],
    });
    return (url, init) => guard.fetch(url, init);
  }

  /**
   * MIP-04: sanitize → encrypt with a key derived from the MLS exporter of the current epoch → upload the
   * ciphertext to the persona's Blossom servers (kind 10063; blob-store fallback) → kind 9 with `imeta`.
   */
  async groupSendFile(
    personaId: string,
    groupId: string,
    file: { data: Uint8Array; filename: string; mimeType: string; caption?: string },
    opts: { servers?: string[]; sanitize?: boolean } = {},
  ): Promise<GroupMediaReference> {
    const s = await this.session(personaId);
    const gs = await this.extended(personaId);
    const userServers = opts.servers ?? (await fetchServerList(s.pool, s.persona.relays, s.persona.pubkey).catch(() => []));
    const servers = selectUploadServers({ userServers, encrypted: true, ...(this.opts.blobStore ? { fallback: this.opts.blobStore } : {}) });
    if (!servers.length) throw new Error('sin servidor Blossom: publica tu lista (kind 10063) o configura el blob-store');
    const http = await this.blobHttp(personaId, servers);
    const data = (opts.sanitize ?? true) ? sanitizeMetadata(file.data).data : file.data;
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
    const guard = new NetworkGuard({
      mode: s.persona.network,
      socksHost: this.opts.socksHost,
      socksPort: this.opts.socksPort,
      isolationKey: s.persona.id,
      allowedHosts: [...new Set([...s.persona.relays, ...urls].map((u) => new URL(u).hostname))],
    });
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

  async groupSend(personaId: string, groupId: string, text: string): Promise<void> {
    const gs = await this.groupSession(personaId);
    await gs.sync(groupId);
    await gs.send(groupId, text);
  }

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
    const p = await (await this.identities()).get(personaId);
    return disclose(this.profileFor(p));
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
