/**
 * Marmot provider backed by marmot-ts (MIT, Marmot protocol org) on ts-mls (RFC 9420).
 * Pinned: @internet-privacy/marmot-ts 0.5.1 / ts-mls 2.0.0-rc.10. Upstream marks it ALPHA: this provider
 * stays behind the high-security feature flag until an independent review (spec §20.3).
 */
import { MarmotClient, Proposals, deserializeApplicationData, getGroupMembers, getEpoch, getGroupIdHex, getNostrGroupIdHex, type MarmotGroup } from '@internet-privacy/marmot-ts';
import type { EventSigner } from 'applesauce-core';
import { generateSecretKey, finalizeEvent, getPublicKey, nip44, toUnsigned, type EventTemplate, type Filter, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { MemoryGroupNetwork, VolatileGroupStorage } from './memory-network';
import { MARMOT_KINDS, type GroupCryptoProperties, type GroupCryptoProvider, type GroupHandle, type GroupMessage, type GroupNetwork, type GroupSession, type GroupStorage, type SessionOptions } from './types';

export const MARMOT_TS_VERSION = '0.5.1';
export const TS_MLS_VERSION = '2.0.0-rc.11';
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

export class MarmotTsProvider implements GroupCryptoProvider {
  readonly properties: GroupCryptoProperties = {
    forwardSecrecy: true,
    postCompromiseSecurity: true,
    multiDevice: true,
    implementation: 'marmot-ts',
    version: `${MARMOT_TS_VERSION} (ts-mls ${TS_MLS_VERSION})`,
    ciphersuite: DEFAULT_CIPHERSUITE,
  };

  async openSession(opts: SessionOptions): Promise<GroupSession> {
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

class MarmotTsSession implements GroupSession {
  pubkey = '';
  private readonly client: MarmotClient;
  private readonly seen = new Map<string, Set<string>>();
  private readonly inbox: GroupMessage[] = [];

  constructor(private readonly opts: SessionOptions) {
    this.client = new MarmotClient({
      signer: eventSigner(opts.signer),
      network: networkInterface(opts.network) as never,
      groupStateStore: kv(opts.storage, 'groups'),
      keyPackageStore: kv(opts.storage, 'keypackages'),
      inviteStore: kv(opts.storage, 'invites'),
      clientId: opts.deviceId,
    });
  }

  async init() {
    this.pubkey = await this.opts.signer.getPublicKey();
    await this.client.groups.loadAll();
    for (const g of this.client.groups.loaded) this.attach(g);
  }

  private attach(g: MarmotGroup<any, any>) {
    if ((g as unknown as { __sedecim?: boolean }).__sedecim) return;
    (g as unknown as { __sedecim?: boolean }).__sedecim = true;
    g.on('applicationMessage', (data: Uint8Array) => {
      try {
        const rumor = deserializeApplicationData(data);
        this.inbox.push({ groupId: g.idStr, sender: rumor.pubkey, content: rumor.content, kind: rumor.kind, createdAt: rumor.created_at, rumorId: rumor.id });
      } catch {
        /* malformed application payload */
      }
    });
  }

  private handle(g: MarmotGroup<any, any>): GroupHandle {
    const data = g.groupData;
    return {
      groupId: getGroupIdHex(g.state),
      nostrGroupId: getNostrGroupIdHex(g.state),
      name: data?.name ?? '',
      epoch: getEpoch(g.state),
      members: getGroupMembers(g.state),
      admins: data?.adminPubkeys ?? [],
      relays: data?.relays ?? [],
    };
  }

  private async load(groupId: string) {
    const g = await this.client.groups.get(groupId);
    this.attach(g);
    return g;
  }

  async publishKeyPackage(relays: string[]): Promise<NostrEvent> {
    const kp = await this.client.keyPackages.create({ relays, client: 'sedecim-nostr' });
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
    return evt;
  }

  async findKeyPackage(pubkey: string, relays: string[]): Promise<NostrEvent | undefined> {
    const events = await this.opts.network.query(relays, [{ kinds: [MARMOT_KINDS.KeyPackage, MARMOT_KINDS.LegacyKeyPackage], authors: [pubkey], limit: 10 }]);
    return events.sort((a, b) => b.created_at - a.created_at)[0];
  }

  async createGroup(o: { name: string; description?: string; relays: string[]; admins?: string[] }): Promise<GroupHandle> {
    const g = await this.client.groups.create(o.name, { description: o.description ?? '', relays: o.relays, adminPubkeys: o.admins ?? [this.pubkey] });
    this.attach(g);
    return this.handle(g);
  }

  async invite(groupId: string, keyPackage: NostrEvent): Promise<GroupHandle> {
    const g = await this.load(groupId);
    await this.sync(groupId);
    const res = await g.inviteByKeyPackageEvent(keyPackage as never);
    if (!Object.values(res).some((r) => r.ok)) throw new Error(`invite commit not accepted by any relay: ${JSON.stringify(res)}`);
    return this.handle(g);
  }

  async removeMember(groupId: string, pubkey: string): Promise<GroupHandle> {
    const g = await this.load(groupId);
    await this.sync(groupId);
    if (!g.groupData) throw new Error('group has no Marmot metadata');
    // marmot-ts 0.5.1 commit() does not flatten actions that return several proposals (one per leaf of a
    // multi-device member), so resolve the action here and commit the concrete Remove proposals.
    const proposals = await Proposals.proposeRemoveUser(pubkey)({ state: g.state, ciphersuite: g.ciphersuite, groupData: g.groupData });
    if (proposals.length === 0) throw new Error('pubkey is not a member of this group');
    const res = await g.commit({ extraProposals: proposals });
    if (!Object.values(res).some((r) => r.ok)) throw new Error('remove commit not accepted by any relay');
    return this.handle(g);
  }

  async rotate(groupId: string): Promise<GroupHandle> {
    const g = await this.load(groupId);
    await this.sync(groupId);
    const res = await g.selfUpdate();
    if (!Object.values(res).some((r) => r.ok)) throw new Error('self-update commit not accepted by any relay');
    return this.handle(g);
  }

  async send(groupId: string, content: string, tags: string[][] = []): Promise<void> {
    const g = await this.load(groupId);
    const res = await g.sendChatMessage(content, tags);
    if (!Object.values(res).some((r) => r.ok)) throw new Error('group message not accepted by any relay');
  }

  async sync(groupId: string): Promise<GroupMessage[]> {
    const g = await this.load(groupId);
    const relays = g.relays ?? [];
    const events = await this.opts.network.query(relays, [{ kinds: [MARMOT_KINDS.GroupMessage], '#h': [getNostrGroupIdHex(g.state)] }]);
    const seen = this.seen.get(groupId) ?? new Set<string>();
    this.seen.set(groupId, seen);
    const fresh = events.filter((e) => !seen.has(e.id)).sort((a, b) => a.created_at - b.created_at);
    const before = this.inbox.length;
    for await (const r of g.ingest(fresh as never)) {
      if (r.kind === 'processed' || r.kind === 'skipped' || r.kind === 'rejected') seen.add(r.event.id);
    }
    const out = this.inbox.splice(before).filter((m) => m.groupId === g.idStr);
    return out;
  }

  async acceptInvites(): Promise<GroupHandle[]> {
    const relays = await this.opts.network.inboxRelays(this.pubkey);
    const wraps = await this.opts.network.query(relays, [{ kinds: [1059], '#p': [this.pubkey] }]);
    await this.client.invites.ingestEvents(wraps as never);
    await this.client.invites.decryptGiftWraps();
    const joined: GroupHandle[] = [];
    for (const welcome of await this.client.invites.getUnread()) {
      try {
        const { group } = await this.client.joinGroupFromWelcome({ welcomeRumor: welcome as never });
        this.attach(group);
        joined.push(this.handle(group));
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

  async leave(groupId: string): Promise<void> {
    await this.client.groups.leave(groupId);
  }

  async groups(): Promise<GroupHandle[]> {
    const all = await this.client.groups.loadAll();
    all.forEach((g) => this.attach(g));
    return all.map((g) => this.handle(g));
  }

  async group(groupId: string): Promise<GroupHandle> {
    return this.handle(await this.load(groupId));
  }

  close(): void {
    for (const g of this.client.groups.loaded) g.removeAllListeners();
  }
}

