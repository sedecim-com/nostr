import { join } from 'node:path';
import WebSocket from 'ws';
import { normalizePubkey, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { EncryptedStore, FileBackend } from '@sedecim/encrypted-store';
import { IdentityManager, type BackupPackage, type BackupPackageV2, type PersonaConfig } from '@sedecim/identity';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { NetworkGuard } from '@sedecim/tor-network';
import { DeliveryEngine, type OutboxRecord } from '@sedecim/delivery-engine';
import { BUZZ_PINNED_ADAPTER, chatMessage, channelFilter, createDirectMessage, dmInboxFilter, openDirectMessage, type DirectMessage, type RelayAdapter } from '@sedecim/messaging';
import { disclose, preset, validateConfig, type SovereigntyConfig } from '@sedecim/profiles';
import { TelemetryPolicy } from '@sedecim/telemetry-policy';
import { EncryptedGroupStorage, MarmotTsProvider, PoolGroupNetwork, assertHighSecurity, type GroupCryptoProvider, type GroupHandle, type GroupMessage, type GroupSession } from '@sedecim/marmot-adapter';

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
  async exportBackup(personaId: string, backupPassword: string, opts: { scryptLogN?: number } = {}): Promise<BackupPackageV2> {
    return (await this.identities()).exportBackup(personaId, backupPassword, { keyPassphrase: this.opts.passphrase, scryptLogN: opts.scryptLogN });
  }

  async restoreBackup(pkg: BackupPackage, backupPassword: string): Promise<PersonaConfig> {
    return (await this.identities()).restoreBackup(pkg, backupPassword, this.opts.passphrase, { scryptLogN: this.opts.scryptLogN });
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
      return provider.openSession({ signer: s.signer, network: new PoolGroupNetwork(s.pool, s.persona.relays), storage: new EncryptedGroupStorage(s.store), deviceId: s.persona.id });
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
    return gs.invite(groupId, kp);
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
