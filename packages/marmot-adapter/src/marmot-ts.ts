/**
 * Marmot provider backed by marmot-ts (MIT, Marmot protocol org) on ts-mls (RFC 9420).
 * Pinned: @internet-privacy/marmot-ts 0.5.1 / ts-mls 2.0.0-rc.16 (override). Upstream marks it ALPHA: this provider
 * stays behind the high-security feature flag until an independent review (spec §20.3).
 */
import {
  MarmotClient,
  defaultMarmotClientConfig,
  deserializeApplicationData,
  getCredentialPubkey,
  getEpoch,
  getGroupIdHex,
  getGroupMembers,
  getKeyPackage,
  getKeyPackageIdentifier,
  getNostrGroupIdHex,
  getPubkeyLeafNodeIndexes,
  getWelcomeKeyPackageRefs,
  type MarmotGroup,
} from '@internet-privacy/marmot-ts';
import type { EventSigner } from 'applesauce-core';
import { contentTypes, defaultKeyPackageEqualityConfig, defaultProposalTypes, getOwnLeafNode, mlsExporter, nodeTypes, type ClientState, type Proposal } from 'ts-mls';
import { bytesToHex, randomBytes, generateSecretKey, finalizeEvent, getEventHash, getPublicKey, nip44, toUnsigned, type EventTemplate, type Filter, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { MemoryGroupNetwork, VolatileGroupStorage } from './memory-network';
import { MEDIA_SECRET_RETENTION_EPOCHS, MIP04_EXPORTER_CONTEXT, MIP04_EXPORTER_LABEL, buildMediaImetaTag, decryptGroupMedia, encryptGroupMedia, parseMediaAttachments } from './media';
import {
  MARMOT_KINDS,
  MediaKeyUnavailableError,
  NotGroupAdminError,
  PendingProposalsError,
  RestoredGroupStateError,
  type ExtendedGroupSession,
  type GroupCryptoProperties,
  type GroupCryptoProvider,
  type GroupDevice,
  type GroupHandle,
  type GroupMediaAttachment,
  type GroupMediaInput,
  type GroupMediaReference,
  type GroupMessage,
  type GroupNetwork,
  type GroupProposal,
  type GroupProposalType,
  type GroupStorage,
  type GroupSyncReport,
  type MediaUploader,
  type SessionOptions,
} from './types';

export const MARMOT_TS_VERSION = '0.5.1';
export const TS_MLS_VERSION = '2.0.0-rc.16';
export const DEFAULT_CIPHERSUITE = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519';

/** GenericKeyValueStore<T> expected by marmot-ts, over our encrypted GroupStorage. */
function kv<T>(storage: GroupStorage, ns: string) {
  return {
    async getItem(key: string): Promise<T | null> {
      return ((await storage.get(ns, key)) as T | undefined) ?? null;
    },
    async setItem(key: string, value: T): Promise<T> {
      await storage.put(ns, key, value);
      return value;
    },
    async removeItem(key: string) {
      await storage.delete(ns, key);
    },
    async clear() {
      for (const k of await storage.keys(ns)) await storage.delete(ns, k);
    },
    async keys() {
      return storage.keys(ns);
    },
  };
}

function eventSigner(signer: Signer): EventSigner {
  return {
    getPublicKey: () => signer.getPublicKey(),
    signEvent: (draft) => signer.signEvent({ kind: draft.kind, content: draft.content, tags: draft.tags, created_at: draft.created_at }) as never,
    nip44: {
      encrypt: (pk: string, pt: string) => signer.nip44Encrypt(pk, pt),
      decrypt: (pk: string, ct: string) => signer.nip44Decrypt(pk, ct),
    },
  };
}

function networkInterface(net: GroupNetwork) {
  const arr = (f: Filter | Filter[]) => (Array.isArray(f) ? f : [f]) as Filter[];
  return {
    async publish(relays: string[], event: NostrEvent) {
      const res = await net.publish(relays, event);
      return Object.fromEntries(res.map((r) => [r.relay, { from: r.relay, ok: r.ok, message: r.message }]));
    },
    request: (relays: string[], filters: Filter | Filter[]) => net.query(relays, arr(filters)),
    subscription(relays: string[], filters: Filter | Filter[]) {
      return {
        subscribe(observer: { next?: (e: NostrEvent) => void }) {
          const sub = net.subscribe(relays, arr(filters), (e) => observer.next?.(e));
          return { unsubscribe: () => sub.close() };
        },
      };
    },
    getUserInboxRelays: (pubkey: string) => net.inboxRelays(pubkey),
  };
}

const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Marmot credentials are the Nostr pubkey and MIP-00 lets a persona join with one leaf per device, but
 * ts-mls 2.0.0-rc.16's default equality policy treats an Add whose *credential* already has a leaf as
 * "someone already in the group" (marmot-ts 0.5.1 passes no ClientConfig, so the default applies both
 * when committing and when validating received commits/proposals). Relax it to what RFC 9420 §7.3 / §12.1.1
 * actually requires, unique signature (and HPKE) keys, which ts-mls keeps checking separately. Applied to
 * both ts-mls copies (marmot-ts' and ours). Idempotent; every member must apply it to accept multi-device
 * commits (unpatched peers reject them: documented interop limit).
 */
export function allowMultiDeviceCredentials(): void {
  for (const cfg of [defaultMarmotClientConfig.keyPackageEqualityConfig, defaultKeyPackageEqualityConfig] as unknown as Array<{ compareKeyPackageToLeafNode: (kp: { leafNode: { signaturePublicKey: Uint8Array } }, leaf: { signaturePublicKey: Uint8Array }) => boolean }>) {
    cfg.compareKeyPackageToLeafNode = (kp, leaf) => sameBytes(kp.leafNode.signaturePublicKey, leaf.signaturePublicKey);
  }
}
allowMultiDeviceCredentials();

export class MarmotTsProvider implements GroupCryptoProvider {
  readonly properties: GroupCryptoProperties = {
    forwardSecrecy: true,
    postCompromiseSecurity: true,
    multiDevice: true,
    implementation: 'marmot-ts',
    version: `${MARMOT_TS_VERSION} (ts-mls ${TS_MLS_VERSION})`,
    ciphersuite: DEFAULT_CIPHERSUITE,
  };

  async openSession(opts: SessionOptions): Promise<ExtendedGroupSession> {
    await assertRemovalSecrecy();
    const session = new MarmotTsSession(opts);
    await session.init();
    return session;
  }
}

export class UnsafeMlsImplementationError extends Error {
  constructor(detail: string) {
    super(`MLS self-test failed, refusing to open high-security groups (fail closed): ${detail}`);
  }
}

/** Minimal in-memory signer for the self-test (throwaway keys, never persisted). */
function ephemeralSigner(): Signer {
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);
  return {
    custody: 'local',
    getPublicKey: async () => pk,
    signEvent: async (t: EventTemplate) => finalizeEvent(toUnsigned(t, pk), sk),
    nip44Encrypt: async (peer, pt) => nip44.encrypt(pt, nip44.getConversationKey(sk, peer)),
    nip44Decrypt: async (peer, ct) => nip44.decrypt(ct, nip44.getConversationKey(sk, peer)),
  };
}

/**
 * marmot-ts 0.5.1 stamps key packages (including the creator's own leaf) with not_before = the current
 * second and no clock-skew margin. OpenMLS, used by MDK, accepts a lifetime only while
 * not_before < now (strict), so a key package or Welcome processed by MDK within the same second is
 * rejected ("Lifetime is not acceptable"). Before handing out either, let the clock move past that
 * second. See docs/marmot.md (interoperabilidad con MDK).
 */
async function settleLifetime(): Promise<void> {
  const second = Math.floor(Date.now() / 1000);
  const wait = (second + 1) * 1000 - Date.now() + 50;
  if (wait > 0) await new Promise((r) => setTimeout(r, wait));
}

const META_NS = 'meta';
const SLOT_KEY = 'keypackage-slot';

let selfTest: Promise<void> | undefined;

/**
 * Behavioural guard run once per process: a member removed by a single-Remove commit must not be able
 * to read the next epoch. ts-mls <= 2.0.0-rc.10 omitted the UpdatePath for a single Remove (RFC 9420
 * §12.4 violation), leaving commit_secret = 0 so the removed member could derive the new epoch.
 */
export function assertRemovalSecrecy(): Promise<void> {
  selfTest ??= (async () => {
    const network = new MemoryGroupNetwork();
    const open = (name: string) => new MarmotTsSession({ signer: ephemeralSigner(), network, storage: new VolatileGroupStorage(), deviceId: `selftest-${name}` });
    const [a, b] = [open('a'), open('b')];
    await Promise.all([a.init(), b.init()]);
    const g = await a.createGroup({ name: 'selftest', relays: ['wss://selftest.invalid'] });
    await a.invite(g.groupId, await b.publishKeyPackage(['wss://selftest.invalid']));
    await b.acceptInvites();
    await a.send(g.groupId, 'before');
    if (!(await b.sync(g.groupId)).some((m) => m.content === 'before')) throw new UnsafeMlsImplementationError('member cannot read group messages');
    await a.removeMember(g.groupId, b.pubkey);
    await a.send(g.groupId, 'after-removal');
    const leaked = await b.sync(g.groupId).catch(() => []);
    a.close();
    b.close();
    if (leaked.some((m) => m.content === 'after-removal')) throw new UnsafeMlsImplementationError('removed member can decrypt the next epoch (missing UpdatePath on Remove)');
  })();
  selfTest.catch(() => {
    selfTest = undefined;
  });
  return selfTest;
}


/**
 * Inner rumor kind (inside MLS application messages only, never published in clear) with which each
 * device announces its key package `d` slot and optional label, keyed by its leaf signature key. Admins
 * re-broadcast the roster after adding members so newcomers learn the existing devices. Other Marmot
 * clients ignore the unknown kind.
 */
export const DEVICE_ROSTER_KIND = 9443;

/** Storage namespaces added on top of marmot-ts' own (`groups`, `keypackages`, `invites`). */
const NS = { device: 'device', roster: 'roster', restored: 'restored', mediaKeys: 'mediakeys', mediaRefs: 'mediarefs' } as const;

interface RosterEntry {
  deviceId: string;
  /** Random `d` slot of the device's kind 30443 key package (distinct from the device id since FR025-04). */
  slot?: string;
  label?: string;
  /** `self`: announced by the leaf itself; `admin`: re-broadcast by an admin. */
  src: 'self' | 'admin';
}
type Roster = Record<string, RosterEntry>;

interface RestoredRecord {
  /** Leaf index and signature key of the cloned leaf (the source device's). */
  oldLeaf: number;
  oldSig: string;
  fromDevice: string;
  proposedAtEpoch?: number;
}

interface WelcomeRecipient {
  pubkey: string;
  keyPackageEventId?: string;
  keyPackageEvent?: NostrEvent;
}

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const ok = (res: Record<string, { ok: boolean }>) => Object.values(res).some((r) => r.ok);
const utf8 = new TextEncoder();

function exportMedia(state: ClientState, ciphersuite: unknown, exporter = state.keySchedule.exporterSecret) {
  return mlsExporter(exporter, MIP04_EXPORTER_LABEL, utf8.encode(MIP04_EXPORTER_CONTEXT), 32, ciphersuite as never);
}

function leafAt(state: ClientState, leafIndex: number) {
  const node = state.ratchetTree[leafIndex * 2];
  return node && node.nodeType === nodeTypes.leaf ? node.leaf : undefined;
}

function pubkeyAt(state: ClientState, leafIndex: number | undefined): string | undefined {
  if (leafIndex === undefined) return undefined;
  const leaf = leafAt(state, leafIndex);
  try {
    return leaf ? getCredentialPubkey(leaf.credential) : undefined;
  } catch {
    return undefined;
  }
}

function proposalType(p: Proposal): GroupProposalType {
  switch (p.proposalType) {
    case defaultProposalTypes.add:
      return 'add';
    case defaultProposalTypes.remove:
      return 'remove';
    case defaultProposalTypes.update:
      return 'update';
    case defaultProposalTypes.group_context_extensions:
      return 'group-context-extensions';
    default:
      return 'other';
  }
}

const removeProposal = (removed: number) => ({ proposalType: defaultProposalTypes.remove, remove: { removed } }) as Proposal;

export class MarmotTsSession implements ExtendedGroupSession {
  pubkey = '';
  /** Addressable `d` slot of this device's kind 30443 key package: random 32-byte hex (MIP-00). */
  private slot = '';
  private readonly client: MarmotClient;
  private readonly seen = new Map<string, Set<string>>();
  private readonly restoredIds = new Set<string>();
  private readonly needsAnnounce = new Set<string>();
  private mediaChain: Promise<void> = Promise.resolve();
  private readonly label?: string;

  constructor(private readonly opts: SessionOptions) {
    this.label = opts.deviceLabel;
    this.client = new MarmotClient({
      signer: eventSigner(opts.signer),
      network: networkInterface(opts.network) as never,
      groupStateStore: kv(opts.storage, 'groups'),
      keyPackageStore: kv(opts.storage, 'keypackages'),
      inviteStore: kv(opts.storage, 'invites'),
      clientId: opts.deviceId,
    });
  }

  get deviceId(): string {
    return this.opts.deviceId;
  }

  async init() {
    this.pubkey = await this.opts.signer.getPublicKey();
    const st = this.opts.storage;
    const owner = (await st.get(NS.device, 'owner')) as string | undefined;
    const cloned = owner !== undefined ? owner !== this.opts.deviceId : !!this.opts.clonedState;
    if (cloned) {
      // Private key packages of the source device belong to its `d` slot: never join with them here.
      for (const k of await st.keys('keypackages')) await st.delete('keypackages', k);
    }
    await st.put(NS.device, 'owner', this.opts.deviceId);
    // MDK rejects key packages whose `d` is not 64 hex chars, and the device id must not leak on relays:
    // one random slot per device, persisted with the MLS state. A restored copy gets a slot of its own so it
    // never overwrites the source device's key package.
    const stored = await st.get(META_NS, SLOT_KEY);
    if (!cloned && typeof stored === 'string' && /^[0-9a-f]{64}$/.test(stored)) this.slot = stored;
    else {
      this.slot = bytesToHex(randomBytes(32));
      await st.put(META_NS, SLOT_KEY, this.slot);
    }
    await this.client.groups.loadAll();
    for (const g of this.client.groups.loaded) {
      if (cloned && !(await st.get(NS.restored, g.idStr))) {
        const rec: RestoredRecord = { oldLeaf: g.state.privatePath.leafIndex, oldSig: hex(getOwnLeafNode(g.state).signaturePublicKey), fromDevice: owner ?? 'unknown' };
        await st.put(NS.restored, g.idStr, rec);
      }
      this.attach(g);
    }
    for (const id of await st.keys(NS.restored)) this.restoredIds.add(id);
  }

  private attach(g: MarmotGroup<any, any>) {
    const marked = g as unknown as { __sedecim?: boolean };
    if (marked.__sedecim) return;
    marked.__sedecim = true;
    this.recordMediaSecret(g.idStr, g.state, g.ciphersuite);
    g.on('stateChanged', (state: ClientState) => this.recordMediaSecret(g.idStr, state, g.ciphersuite));
  }

  /** MIP-04: keep each epoch's media secret so media is decrypted with the epoch it was sent in. */
  private recordMediaSecret(groupId: string, state: ClientState, ciphersuite: unknown) {
    const epoch = getEpoch(state);
    const exporter = state.keySchedule.exporterSecret.slice();
    this.mediaChain = this.mediaChain
      .then(async () => {
        const key = `${groupId}:${epoch}`;
        if (await this.opts.storage.get(NS.mediaKeys, key)) return;
        await this.opts.storage.put(NS.mediaKeys, key, await exportMedia(state, ciphersuite, exporter));
        if (epoch % 16 === 0) {
          for (const k of await this.opts.storage.keys(NS.mediaKeys)) {
            const [gid, e] = k.split(':');
            if (gid === groupId && Number(e) < epoch - MEDIA_SECRET_RETENTION_EPOCHS) await this.opts.storage.delete(NS.mediaKeys, k);
          }
        }
      })
      .catch(() => undefined);
  }

  private async roster(groupId: string): Promise<Roster> {
    return ((await this.opts.storage.get(NS.roster, groupId)) as Roster | undefined) ?? {};
  }

  private deviceList(g: MarmotGroup<any, any>, roster: Roster): GroupDevice[] {
    const own = g.state.privatePath.leafIndex;
    const out: GroupDevice[] = [];
    g.state.ratchetTree.forEach((node, i) => {
      if (i % 2 !== 0 || !node || node.nodeType !== nodeTypes.leaf) return;
      const leafIndex = i / 2;
      let pubkey: string;
      try {
        pubkey = getCredentialPubkey(node.leaf.credential);
      } catch {
        return;
      }
      const self = leafIndex === own;
      const r = roster[hex(node.leaf.signaturePublicKey)];
      const d: GroupDevice = { pubkey, leafIndex, self };
      const deviceId = self ? this.opts.deviceId : r?.deviceId;
      const label = self ? this.label : r?.label;
      if (deviceId) d.deviceId = deviceId;
      if (label) d.label = label;
      out.push(d);
    });
    return out;
  }

  private async handle(g: MarmotGroup<any, any>): Promise<GroupHandle> {
    const data = g.groupData;
    const h: GroupHandle = {
      groupId: getGroupIdHex(g.state),
      nostrGroupId: getNostrGroupIdHex(g.state),
      name: data?.name ?? '',
      epoch: getEpoch(g.state),
      members: getGroupMembers(g.state),
      admins: data?.adminPubkeys ?? [],
      relays: data?.relays ?? [],
      devices: this.deviceList(g, await this.roster(g.idStr)),
      pendingProposals: Object.keys(g.state.unappliedProposals).length,
    };
    if (this.restoredIds.has(g.idStr)) h.restored = true;
    return h;
  }

  private async load(groupId: string) {
    const g = await this.client.groups.get(groupId);
    this.attach(g);
    return g;
  }

  private assertNotRestored(g: MarmotGroup<any, any>) {
    if (this.restoredIds.has(g.idStr)) throw new RestoredGroupStateError(g.idStr);
  }

  private isAdmin(g: MarmotGroup<any, any>) {
    return (g.groupData?.adminPubkeys ?? []).includes(this.pubkey);
  }

  async publishKeyPackage(relays: string[]): Promise<NostrEvent> {
    const kp = await this.client.keyPackages.create({ relays, client: 'sedecim-nostr', identifier: this.slot });
    const evt = (await this.client.keyPackages.get(kp.keyPackageRef))?.published?.at(-1) as NostrEvent | undefined;
    if (!evt) throw new Error('key package event was not recorded');
    // marmot-ts ignores relay OK responses when publishing key packages: verify it is actually retrievable.
    // Relays such as nostr-rs-relay acknowledge before their batched write lands: retry briefly.
    for (let attempt = 0; ; attempt++) {
      const found = await this.opts.network.query(relays, [{ ids: [evt.id], kinds: [evt.kind] }]);
      if (found.length > 0) break;
      if (attempt >= 8) throw new Error('key package was not accepted by any relay');
      await new Promise((r) => setTimeout(r, 250 * (attempt + 1)));
    }
    await settleLifetime();
    return evt;
  }

  async findKeyPackage(pubkey: string, relays: string[]): Promise<NostrEvent | undefined> {
    const events = await this.opts.network.query(relays, [{ kinds: [MARMOT_KINDS.KeyPackage, MARMOT_KINDS.LegacyKeyPackage], authors: [pubkey], limit: 10 }]);
    return events.sort((a, b) => b.created_at - a.created_at)[0];
  }

  async findKeyPackages(pubkey: string, relays: string[]): Promise<NostrEvent[]> {
    const events = await this.opts.network.query(relays, [{ kinds: [MARMOT_KINDS.KeyPackage, MARMOT_KINDS.LegacyKeyPackage], authors: [pubkey] }]);
    const valid = events
      .filter((e) => {
        if (e.pubkey !== pubkey) return false;
        try {
          return getCredentialPubkey(getKeyPackage(e as never).leafNode.credential) === pubkey;
        } catch {
          return false;
        }
      })
      .sort((a, b) => b.created_at - a.created_at || (a.id < b.id ? -1 : 1));
    // One per device: kind 30443 is addressable per `d` slot (MIP-00); legacy 443 only without any 30443.
    const perSlot = new Map<string, NostrEvent>();
    for (const e of valid.filter((x) => x.kind === MARMOT_KINDS.KeyPackage)) {
      const d = getKeyPackageIdentifier(e as never) ?? '';
      if (!perSlot.has(d)) perSlot.set(d, e);
    }
    if (perSlot.size) return [...perSlot.values()];
    const legacy = valid.find((x) => x.kind === MARMOT_KINDS.LegacyKeyPackage);
    return legacy ? [legacy] : [];
  }

  async missingDeviceKeyPackages(groupId: string, pubkey: string, relays: string[]): Promise<NostrEvent[]> {
    const g = await this.load(groupId);
    const devices = this.deviceList(g, await this.roster(g.idStr)).filter((d) => d.pubkey === pubkey);
    const roster = await this.roster(g.idStr);
    const knownDevices = new Set(
      devices.flatMap((d) => {
        const slot = roster[hex(leafAt(g.state, d.leafIndex)!.signaturePublicKey)]?.slot;
        return [...(d.deviceId ? [d.deviceId] : []), ...(slot ? [slot] : [])];
      }),
    );
    if (pubkey === this.pubkey) knownDevices.add(this.opts.deviceId).add(this.slot);
    const leafSigs = new Set(devices.map((d) => hex(leafAt(g.state, d.leafIndex)!.signaturePublicKey)));
    return (await this.findKeyPackages(pubkey, relays)).filter((e) => {
      const d = getKeyPackageIdentifier(e as never);
      if (d !== undefined && knownDevices.has(d)) return false;
      return !leafSigs.has(hex(getKeyPackage(e as never).leafNode.signaturePublicKey));
    });
  }

  async createGroup(o: { name: string; description?: string; relays: string[]; admins?: string[] }): Promise<GroupHandle> {
    const g = await this.client.groups.create(o.name, { description: o.description ?? '', relays: o.relays, adminPubkeys: o.admins ?? [this.pubkey] });
    this.attach(g);
    await settleLifetime();
    return this.handle(g);
  }

  private describe(g: MarmotGroup<any, any>): GroupProposal[] {
    const admins = g.groupData?.adminPubkeys ?? [];
    return Object.entries(g.state.unappliedProposals).map(([ref, pws]) => {
      const type = proposalType(pws.proposal);
      const proposer = pubkeyAt(g.state, pws.senderLeafIndex);
      const out: GroupProposal = { ref, type, admissible: false };
      if (proposer) out.proposer = proposer;
      if (pws.senderLeafIndex !== undefined) out.proposerLeaf = pws.senderLeafIndex;
      const p = pws.proposal as { add?: { keyPackage: { leafNode: { credential: never } } }; remove?: { removed: number } };
      if (type === 'add' && p.add) {
        try {
          out.target = getCredentialPubkey(p.add.keyPackage.leafNode.credential);
        } catch {
          /* not a Marmot credential: stays inadmissible below */
        }
      }
      if (type === 'remove' && p.remove) {
        out.targetLeaf = p.remove.removed;
        const t = pubkeyAt(g.state, p.remove.removed);
        if (t) out.target = t;
      }
      const byAdmin = !!proposer && admins.includes(proposer);
      out.admissible =
        byAdmin ||
        (type === 'add' && !!out.target) ||
        type === 'update' ||
        (type === 'remove' && !!out.target && (out.target === proposer || !admins.includes(out.target)));
      return out;
    });
  }

  /**
   * Proposals an admin commits implicitly with any other commit (ts-mls always bundles every pending
   * proposal): adds, updates, removals of the proposer's own leaves, anything proposed by an admin.
   * Removing someone else needs an explicit `commitProposals`.
   */
  private incidental(p: GroupProposal, admins: string[]) {
    if (!p.admissible) return false;
    if (p.proposer && admins.includes(p.proposer)) return true;
    return p.type === 'add' || p.type === 'update' || (p.type === 'remove' && p.target === p.proposer);
  }

  /** Every admin commit goes through here: proposal policy + one Welcome per new persona. */
  private async adminCommit(g: MarmotGroup<any, any>, extra: Proposal[], recipients: WelcomeRecipient[], opts: { approve?: string[]; allowRestored?: boolean } = {}) {
    if (!opts.allowRestored) this.assertNotRestored(g);
    if (!g.groupData) throw new Error('group has no Marmot metadata');
    if (!this.isAdmin(g)) throw new NotGroupAdminError('commit');
    const admins = g.groupData.adminPubkeys;
    const pending = this.describe(g);
    const keep = pending.filter((p) => (opts.approve ? opts.approve.includes(p.ref) && p.admissible : this.incidental(p, admins)));
    if (keep.length !== pending.length) {
      g.state = { ...g.state, unappliedProposals: Object.fromEntries(keep.map((p) => [p.ref, g.state.unappliedProposals[p.ref]!])) };
    }
    const byPubkey = new Map<string, WelcomeRecipient>();
    for (const r of recipients) if (!byPubkey.has(r.pubkey)) byPubkey.set(r.pubkey, r);
    for (const p of keep) if (p.type === 'add' && p.target && !byPubkey.has(p.target)) byPubkey.set(p.target, { pubkey: p.target });
    const res = await g.commit({ extraProposals: extra, ...(byPubkey.size ? { welcomeRecipients: [...byPubkey.values()] as never } : {}) });
    if (!ok(res)) throw new Error('commit not accepted by any relay');
    if (byPubkey.size) await this.announce(g, true);
    return keep;
  }

  private addProposal(kp: NostrEvent): Proposal {
    if (kp.kind !== MARMOT_KINDS.KeyPackage && kp.kind !== MARMOT_KINDS.LegacyKeyPackage) throw new Error(`not a key package event (kind ${kp.kind})`);
    const keyPackage = getKeyPackage(kp as never);
    if (getCredentialPubkey(keyPackage.leafNode.credential) !== kp.pubkey) throw new Error('key package credential does not match the event pubkey');
    return { proposalType: defaultProposalTypes.add, add: { keyPackage } } as Proposal;
  }

  async invite(groupId: string, keyPackage: NostrEvent): Promise<GroupHandle> {
    return this.inviteMany(groupId, [keyPackage]);
  }

  async inviteMany(groupId: string, keyPackages: NostrEvent[]): Promise<GroupHandle> {
    if (keyPackages.length === 0) throw new Error('no key packages to add');
    const g = await this.load(groupId);
    this.assertNotRestored(g);
    await this.sync(groupId);
    const proposals = keyPackages.map((kp) => this.addProposal(kp));
    await this.adminCommit(
      g,
      proposals,
      keyPackages.map((kp) => ({ pubkey: kp.pubkey, keyPackageEventId: kp.id, keyPackageEvent: kp })),
    );
    return this.handle(g);
  }

  async invitePersona(groupId: string, pubkey: string, relays: string[]): Promise<GroupHandle> {
    await this.sync(groupId);
    const kps = await this.missingDeviceKeyPackages(groupId, pubkey, relays);
    if (kps.length === 0) throw new Error('no key package of a device that is not already in the group');
    return this.inviteMany(groupId, kps);
  }

  async removeMember(groupId: string, pubkey: string): Promise<GroupHandle> {
    const g = await this.load(groupId);
    this.assertNotRestored(g);
    await this.sync(groupId);
    // One Remove per leaf: a persona with several devices loses all of them. (marmot-ts 0.5.1 commit()
    // does not flatten multi-proposal actions, so the concrete proposals are built here.)
    const leaves = getPubkeyLeafNodeIndexes(g.state, pubkey);
    if (leaves.length === 0) throw new Error('pubkey is not a member of this group');
    await this.adminCommit(g, leaves.map(removeProposal), []);
    return this.handle(g);
  }

  async removeDevice(groupId: string, leafIndex: number): Promise<GroupHandle> {
    const g = await this.load(groupId);
    this.assertNotRestored(g);
    await this.sync(groupId);
    if (!pubkeyAt(g.state, leafIndex)) throw new Error(`no member leaf at index ${leafIndex}`);
    if (leafIndex === g.state.privatePath.leafIndex) throw new Error('a committer cannot remove its own leaf (RFC 9420): use leave or ask another admin');
    await this.adminCommit(g, [removeProposal(leafIndex)], []);
    return this.handle(g);
  }

  async devices(groupId: string): Promise<GroupDevice[]> {
    const g = await this.load(groupId);
    return this.deviceList(g, await this.roster(g.idStr));
  }

  async rotate(groupId: string): Promise<GroupHandle> {
    const g = await this.load(groupId);
    this.assertNotRestored(g);
    await this.sync(groupId);
    // A self-update must carry no foreign proposals: other members reject a non-admin commit that does
    // (MIP-03), and ts-mls bundles every pending proposal. Pending proposals become stale (re-propose).
    if (Object.keys(g.state.unappliedProposals).length) g.state = { ...g.state, unappliedProposals: {} };
    const res = await g.selfUpdate();
    if (!ok(res)) throw new Error('self-update commit not accepted by any relay');
    return this.handle(g);
  }

  private async sendProposals(g: MarmotGroup<any, any>, proposals: Proposal[]): Promise<GroupProposal[]> {
    const before = new Set(Object.keys(g.state.unappliedProposals));
    for (const p of proposals) await g.sendProposal(p);
    return this.describe(g).filter((p) => !before.has(p.ref));
  }

  async proposeAdd(groupId: string, keyPackages: NostrEvent[]): Promise<GroupProposal[]> {
    if (keyPackages.length === 0) throw new Error('no key packages to propose');
    const g = await this.load(groupId);
    this.assertNotRestored(g);
    await this.sync(groupId);
    return this.sendProposals(g, keyPackages.map((kp) => this.addProposal(kp)));
  }

  async proposeRemove(groupId: string, target: { pubkey: string } | { leafIndex: number }): Promise<GroupProposal[]> {
    const g = await this.load(groupId);
    this.assertNotRestored(g);
    await this.sync(groupId);
    const leaves = 'pubkey' in target ? getPubkeyLeafNodeIndexes(g.state, target.pubkey) : pubkeyAt(g.state, target.leafIndex) ? [target.leafIndex] : [];
    if (leaves.length === 0) throw new Error('no such member leaf');
    return this.sendProposals(g, leaves.map(removeProposal));
  }

  async pendingProposals(groupId: string): Promise<GroupProposal[]> {
    return this.describe(await this.load(groupId));
  }

  async commitProposals(groupId: string, opts: { refs?: string[] } = {}): Promise<GroupHandle> {
    const g = await this.load(groupId);
    this.assertNotRestored(g);
    await this.sync(groupId);
    if (!this.isAdmin(g)) throw new NotGroupAdminError('commit proposals');
    const pending = this.describe(g);
    const approve = (opts.refs ?? pending.map((p) => p.ref)).filter((r) => pending.some((p) => p.ref === r && p.admissible));
    if (approve.length === 0) throw new Error(pending.length ? 'no admissible pending proposal to commit' : 'no pending proposals in this epoch (stale proposals must be sent again)');
    await this.adminCommit(g, [], [], { approve });
    return this.handle(g);
  }

  private rumor(kind: number, content: string, tags: string[][] = []) {
    const r = { id: '', kind, pubkey: this.pubkey, created_at: Math.floor(Date.now() / 1000), content, tags };
    r.id = getEventHash(r);
    return r;
  }

  /** Device roster announcement (best effort: pending proposals block application messages). */
  private async announce(g: MarmotGroup<any, any>, asAdmin = false): Promise<void> {
    try {
      const own = getOwnLeafNode(g.state);
      const devices: Array<{ sig: string; device: string; slot?: string; label?: string }> = [
        { sig: hex(own.signaturePublicKey), device: this.opts.deviceId, slot: this.slot, ...(this.label ? { label: this.label } : {}) },
      ];
      if (asAdmin) {
        const roster = await this.roster(g.idStr);
        for (const d of this.deviceList(g, roster)) {
          if (d.self || !d.deviceId) continue;
          const sig = hex(leafAt(g.state, d.leafIndex)!.signaturePublicKey);
          const slot = roster[sig]?.slot;
          devices.push({ sig, device: d.deviceId, ...(slot ? { slot } : {}), ...(d.label ? { label: d.label } : {}) });
        }
      }
      const pending = Object.keys(g.state.unappliedProposals).length;
      if (pending) throw new PendingProposalsError(pending);
      const res = await g.sendApplicationRumor(this.rumor(DEVICE_ROSTER_KIND, JSON.stringify({ v: 1, devices })) as never);
      if (!ok(res)) throw new Error('not accepted');
      this.needsAnnounce.delete(g.idStr);
    } catch {
      this.needsAnnounce.add(g.idStr);
    }
  }

  private async onRoster(g: MarmotGroup<any, any>, senderLeaf: number, sender: string, content: string) {
    if (pubkeyAt(g.state, senderLeaf) !== sender) return;
    let body: { v?: number; devices?: Array<{ sig?: unknown; device?: unknown; slot?: unknown; label?: unknown }> };
    try {
      body = JSON.parse(content);
    } catch {
      return;
    }
    if (body?.v !== 1 || !Array.isArray(body.devices)) return;
    const senderSig = hex(leafAt(g.state, senderLeaf)!.signaturePublicKey);
    const senderIsAdmin = (g.groupData?.adminPubkeys ?? []).includes(sender);
    const liveSigs = new Set(g.state.ratchetTree.flatMap((n, i) => (i % 2 === 0 && n && n.nodeType === nodeTypes.leaf ? [hex(n.leaf.signaturePublicKey)] : [])));
    const roster = await this.roster(g.idStr);
    for (const d of body.devices.slice(0, 256)) {
      if (typeof d.sig !== 'string' || typeof d.device !== 'string' || d.device.length > 128 || !liveSigs.has(d.sig)) continue;
      const label = typeof d.label === 'string' ? d.label.slice(0, 64) : undefined;
      const slot = typeof d.slot === 'string' && /^[0-9a-f]{64}$/.test(d.slot) ? d.slot : undefined;
      const entry: RosterEntry = { deviceId: d.device, src: d.sig === senderSig ? 'self' : 'admin', ...(slot ? { slot } : {}), ...(label ? { label } : {}) };
      if (entry.src === 'self' || (senderIsAdmin && roster[d.sig]?.src !== 'self')) roster[d.sig] = entry;
    }
    for (const sig of Object.keys(roster)) if (!liveSigs.has(sig)) delete roster[sig];
    await this.opts.storage.put(NS.roster, g.idStr, roster);
  }

  async send(groupId: string, content: string, tags: string[][] = []): Promise<GroupMessage> {
    const g = await this.load(groupId);
    this.assertNotRestored(g);
    const pending = Object.keys(g.state.unappliedProposals).length;
    if (pending) throw new PendingProposalsError(pending);
    if (this.needsAnnounce.has(g.idStr)) await this.announce(g, this.isAdmin(g));
    // The rumor is built here (as sendChatMessage would) so the sender keeps its own message: an MLS sender
    // cannot decrypt its own ciphertext later (VAULT-03 archives what the persona read and sent).
    const rumor = this.rumor(9, content, tags);
    const epoch = Number(getEpoch(g.state));
    const res = await g.sendApplicationRumor(rumor);
    if (!ok(res)) throw new Error('group message not accepted by any relay');
    const sent: GroupMessage = { groupId: g.idStr, sender: this.pubkey, content, kind: rumor.kind, createdAt: rumor.created_at, rumorId: rumor.id, epoch, senderLeaf: g.state.privatePath.leafIndex, tags };
    await this.opts.onMessage?.(sent);
    return sent;
  }

  async sync(groupId: string): Promise<GroupMessage[]> {
    return (await this.syncWithReport(groupId)).messages;
  }

  async syncWithReport(groupId: string): Promise<GroupSyncReport> {
    const g = await this.load(groupId);
    const relays = g.relays ?? [];
    const events = await this.opts.network.query(relays, [{ kinds: [MARMOT_KINDS.GroupMessage], '#h': [getNostrGroupIdHex(g.state)] }]);
    const seen = this.seen.get(groupId) ?? new Set<string>();
    this.seen.set(groupId, seen);
    const fresh = events.filter((e) => !seen.has(e.id)).sort((a, b) => a.created_at - b.created_at);
    const report: GroupSyncReport = { messages: [], proposals: 0, commits: 0, rejectedCommits: 0, unreadable: 0 };
    for await (const r of g.ingest(fresh as never)) {
      if (r.kind === 'unreadable') {
        report.unreadable++;
        continue;
      }
      seen.add(r.event.id);
      if (r.kind === 'rejected') report.rejectedCommits++;
      if (r.kind !== 'processed') continue;
      const wire = r.message as { privateMessage?: { epoch: bigint; contentType: number } };
      if (r.result.kind === 'applicationMessage') {
        const epoch = Number(wire.privateMessage?.epoch ?? getEpoch(g.state));
        let rumor: ReturnType<typeof deserializeApplicationData>;
        try {
          rumor = deserializeApplicationData(r.result.message);
        } catch {
          continue;
        }
        const leafOwner = pubkeyAt(g.state, r.result.senderLeafIndex);
        if (leafOwner && leafOwner !== rumor.pubkey) continue; // a member cannot speak as another pubkey
        if (rumor.kind === DEVICE_ROSTER_KIND) {
          await this.onRoster(g, r.result.senderLeafIndex, rumor.pubkey, rumor.content);
          continue;
        }
        const m: GroupMessage = { groupId: g.idStr, sender: rumor.pubkey, content: rumor.content, kind: rumor.kind, createdAt: rumor.created_at, rumorId: rumor.id, epoch, senderLeaf: r.result.senderLeafIndex, tags: rumor.tags };
        const media = parseMediaAttachments(rumor.tags);
        if (media.length) {
          m.media = media;
          for (const attachment of media) await this.storeMediaRef({ groupId: g.idStr, epoch, attachment, sender: rumor.pubkey, rumorId: rumor.id });
        }
        report.messages.push(m);
        await this.opts.onMessage?.(m);
      } else if (wire.privateMessage?.contentType === contentTypes.commit) report.commits++;
      else report.proposals++;
    }
    return report;
  }

  async acceptInvites(): Promise<GroupHandle[]> {
    const relays = await this.opts.network.inboxRelays(this.pubkey);
    const wraps = await this.opts.network.query(relays, [{ kinds: [1059], '#p': [this.pubkey] }]);
    await this.client.invites.ingestEvents(wraps as never);
    await this.client.invites.decryptGiftWraps();
    const ownRefs = new Set<string>();
    for (const kp of await this.client.keyPackages.list()) if (await this.client.keyPackages.getPrivateKey(kp.keyPackageRef)) ownRefs.add(hex(kp.keyPackageRef));
    const joined: GroupHandle[] = [];
    for (const welcome of await this.client.invites.getUnread()) {
      try {
        // Welcomes are gift-wrapped per persona, so every device of the invitee sees each one. Only the
        // device holding one of the Welcome's key packages can (and may) join; the others skip it.
        let refs: string[] = [];
        try {
          refs = getWelcomeKeyPackageRefs(welcome as never).map(hex);
        } catch {
          continue;
        }
        if (!refs.some((r) => ownRefs.has(r))) continue;
        const group = await this.joinWelcome(welcome);
        if (!group) continue;
        this.attach(group);
        await this.announce(group);
        joined.push(await this.handle(group));
      } finally {
        await this.client.invites.markAsRead(welcome.id);
      }
    }
    // Consumed key packages must not be reused: rotate them (MIP-00).
    for (const kp of await this.client.keyPackages.list()) {
      if (kp.used) await this.client.keyPackages.rotate(kp.keyPackageRef).catch(() => undefined);
    }
    return joined;
  }

  /** Joins from a Welcome; a restored (cloned) local copy of the same group is replaced by the new leaf. */
  private async joinWelcome(welcome: unknown): Promise<MarmotGroup<any, any> | undefined> {
    try {
      return (await this.client.joinGroupFromWelcome({ welcomeRumor: welcome as never })).group;
    } catch (err) {
      const m = /Group ([0-9a-f]+) already exists/.exec((err as Error).message);
      if (!m || !this.restoredIds.has(m[1]!)) return undefined;
      const id = m[1]!;
      const saved = await this.opts.storage.get('groups', id);
      await this.client.groups.destroy(id);
      try {
        const { group } = await this.client.joinGroupFromWelcome({ welcomeRumor: welcome as never });
        await this.opts.storage.delete(NS.restored, id);
        this.restoredIds.delete(id);
        this.seen.delete(id);
        return group;
      } catch (e) {
        if (saved !== undefined) await this.opts.storage.put('groups', id, saved);
        throw e;
      }
    }
  }

  async restoredGroups(): Promise<string[]> {
    return [...this.restoredIds];
  }

  async rejoin(groupId: string, relays: string[]): Promise<{ status: 'joined' | 'pending'; group: GroupHandle }> {
    let g = await this.load(groupId);
    const rec = (await this.opts.storage.get(NS.restored, g.idStr)) as RestoredRecord | undefined;
    if (!rec || !this.restoredIds.has(g.idStr)) return { status: 'joined', group: await this.handle(g) };
    // An admin may already have committed an earlier request: the Welcome for the new leaf is waiting.
    await this.acceptInvites();
    if (!this.restoredIds.has(g.idStr)) return { status: 'joined', group: await this.handle(await this.load(groupId)) };
    if (rec.proposedAtEpoch !== undefined) {
      await this.sync(groupId);
      g = await this.load(groupId);
      if (getEpoch(g.state) === rec.proposedAtEpoch && Object.keys(g.state.unappliedProposals).length) return { status: 'pending', group: await this.handle(g) };
    }
    await this.sync(groupId);
    g = await this.load(groupId);
    const kp = await this.publishKeyPackage(relays);
    if (this.isAdmin(g)) {
      // 1. The cloned leaf adds this device's new leaf (Welcome to our own pubkey).
      await this.adminCommit(g, [this.addProposal(kp)], [{ pubkey: this.pubkey, keyPackageEventId: kp.id, keyPackageEvent: kp }], { allowRestored: true });
      // 2. Join as the new leaf, replacing the clone.
      await this.acceptInvites();
      if (this.restoredIds.has(g.idStr)) throw new Error('could not join the group as a new leaf');
      // 3. The new leaf removes the cloned one (a committer cannot remove itself, hence two commits).
      const fresh = await this.load(groupId);
      const old = getPubkeyLeafNodeIndexes(fresh.state, this.pubkey).find((i) => hex(leafAt(fresh.state, i)!.signaturePublicKey) === rec.oldSig);
      if (old !== undefined) await this.adminCommit(fresh, [removeProposal(old)], []);
      return { status: 'joined', group: await this.handle(fresh) };
    }
    // Non-admin: the cloned leaf proposes Add(new leaf) + Remove(itself); an admin commits both and
    // sends the Welcome; `acceptInvites` (or `rejoin` again) then replaces the clone.
    if (hex(getOwnLeafNode(g.state).signaturePublicKey) !== rec.oldSig) throw new Error('restored leaf changed unexpectedly');
    await this.sendProposals(g, [this.addProposal(kp), removeProposal(g.state.privatePath.leafIndex)]);
    await this.opts.storage.put(NS.restored, g.idStr, { ...rec, proposedAtEpoch: getEpoch(g.state) });
    return { status: 'pending', group: await this.handle(g) };
  }

  private async storeMediaRef(ref: GroupMediaReference) {
    await this.opts.storage.put(NS.mediaRefs, `${ref.groupId}:${ref.attachment.sha256}`, ref);
  }

  async sendMedia(groupId: string, file: GroupMediaInput, upload: MediaUploader, caption = ''): Promise<GroupMediaReference> {
    const g = await this.load(groupId);
    this.assertNotRestored(g);
    await this.sync(groupId);
    const pending = Object.keys(g.state.unappliedProposals).length;
    if (pending) throw new PendingProposalsError(pending);
    const epoch = getEpoch(g.state);
    const { ciphertext, ciphertextSha256, attachment } = encryptGroupMedia(await exportMedia(g.state, g.ciphersuite), file.data, file);
    const { url } = await upload(ciphertext, ciphertextSha256);
    if (getEpoch(g.state) !== epoch) throw new Error('the group epoch changed during the upload: send the file again');
    const full: GroupMediaAttachment = { ...attachment, url };
    const sent = await this.send(groupId, caption, [buildMediaImetaTag({ ...full, url })]);
    const ref: GroupMediaReference = { groupId: g.idStr, epoch, attachment: full, sender: this.pubkey, rumorId: sent.rumorId };
    await this.storeMediaRef(ref);
    return ref;
  }

  async decryptMedia(groupId: string, ciphertext: Uint8Array, attachment: GroupMediaAttachment, epoch: number): Promise<Uint8Array> {
    const g = await this.load(groupId);
    await this.mediaChain;
    let secret = (await this.opts.storage.get(NS.mediaKeys, `${g.idStr}:${epoch}`)) as Uint8Array | undefined;
    if (!secret && getEpoch(g.state) === epoch) secret = await exportMedia(g.state, g.ciphersuite);
    if (!secret) throw new MediaKeyUnavailableError(epoch);
    return decryptGroupMedia(secret, ciphertext, attachment);
  }

  async mediaReference(groupId: string, sha256: string): Promise<GroupMediaReference | undefined> {
    return (await this.opts.storage.get(NS.mediaRefs, `${groupId}:${sha256.toLowerCase()}`)) as GroupMediaReference | undefined;
  }

  async leave(groupId: string): Promise<void> {
    await this.client.groups.leave(groupId);
  }

  async groups(): Promise<GroupHandle[]> {
    const all = await this.client.groups.loadAll();
    all.forEach((g) => this.attach(g));
    return Promise.all(all.map((g) => this.handle(g)));
  }

  async group(groupId: string): Promise<GroupHandle> {
    return this.handle(await this.load(groupId));
  }

  close(): void {
    for (const g of this.client.groups.loaded) g.removeAllListeners();
  }
}
