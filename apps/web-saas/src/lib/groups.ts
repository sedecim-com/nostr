import type { ArchivedGroupMessage, MlsSnapshot } from '@sedecim/continuity';
import type { GroupHandle, GroupMessage, GroupSession, GroupStorage } from '@sedecim/marmot-adapter';
import type { EncryptedStore } from '@sedecim/encrypted-store/browser';
import type { RelayPool } from '@sedecim/relay-pool';
import type { DeploymentConfig } from './config';
import type { PersonaSession } from './session';

/**
 * High-security groups in the web (FR025-07): Marmot/MLS through the adapter's public API. The MLS code is
 * loaded lazily (its own chunk) and only when the "Grupos seguros" view opens a session.
 */

/**
 * Where MLS traffic goes. The pinned Buzz rejects Marmot kinds (ADR 0006), so a deployment points
 * `secureRelays` at the secondary secure relay; without it the persona relays are used (self-hosted relays
 * that accept kinds 30443/445/10051).
 */
export function groupRelays(cfg: DeploymentConfig, s: PersonaSession): { relays: string[]; source: 'secure-relay' | 'persona' } {
  return cfg.secureRelays?.length ? { relays: cfg.secureRelays, source: 'secure-relay' } : { relays: s.persona.relays, source: 'persona' };
}

/**
 * The web keeps every persona in one vault, so MLS namespaces are prefixed with the persona id: each
 * persona's group state lives in its own sealed collections (`mls-<persona>-groups`, …) of the vault.
 */
export class PersonaGroupStorage implements GroupStorage {
  constructor(private readonly inner: GroupStorage, private readonly personaId: string) {
    if (!/^[a-z0-9]+$/.test(personaId)) throw new Error('persona id must be [a-z0-9]');
  }
  private ns(ns: string) {
    return `${this.personaId}-${ns}`;
  }
  get(ns: string, key: string) {
    return this.inner.get(this.ns(ns), key);
  }
  put(ns: string, key: string, value: unknown) {
    return this.inner.put(this.ns(ns), key, value);
  }
  delete(ns: string, key: string) {
    return this.inner.delete(this.ns(ns), key);
  }
  keys(ns: string) {
    return this.inner.keys(this.ns(ns));
  }
}

/** Kind of the chat rumor marmot-ts sends inside an MLS application message. */
export const CHAT_KIND = 9;

// One MLS session per open persona session (keyed by its pool, which is closed when the persona switches).
const sessions = new WeakMap<RelayPool, Promise<GroupSession>>();

export function openGroupSession(s: PersonaSession, store: EncryptedStore, cfg: DeploymentConfig): Promise<GroupSession> {
  let p = sessions.get(s.pool);
  if (!p) {
    p = (async () => {
      const m = await import('@sedecim/marmot-adapter');
      const provider = new m.MarmotTsProvider();
      // Fail closed if the provider does not declare forward secrecy and post-compromise security.
      m.assertHighSecurity(provider);
      const storage = new PersonaGroupStorage(new m.EncryptedGroupStorage(store), s.persona.id);
      const history = new GroupHistory(store, s.persona.id);
      // VAULT-03: every chat message this session decrypts or sends is kept here, the only moment it can be.
      const onMessage = (msg: GroupMessage) => (msg.kind === CHAT_KIND ? history.append(msg.groupId, [storedMessage(msg)]).then(() => undefined) : undefined);
      return provider.openSession({ signer: s.signer, network: new m.PoolGroupNetwork(s.pool, groupRelays(cfg, s).relays), storage, deviceId: `web-${s.persona.id}`, onMessage });
    })();
    sessions.set(s.pool, p);
    p.catch(() => sessions.delete(s.pool));
  }
  return p;
}

export interface StoredGroupMessage {
  id: string;
  sender: string;
  content: string;
  createdAt: number;
}

const HISTORY_LIMIT = 500;

const storedMessage = (m: Pick<GroupMessage, 'rumorId' | 'sender' | 'content' | 'createdAt'>): StoredGroupMessage => ({ id: m.rumorId, sender: m.sender, content: m.content, createdAt: m.createdAt });

/**
 * Decrypted group history, sealed in the vault per persona (MLS keys of past epochs are deleted, so
 * already-read messages cannot be decrypted again after a reload).
 */
export class GroupHistory {
  private readonly col;
  constructor(store: EncryptedStore, personaId: string) {
    this.col = store.collection<StoredGroupMessage[]>(`mlsmsg-${personaId}`);
  }
  async list(groupId: string): Promise<StoredGroupMessage[]> {
    return (await this.col.get(groupId)) ?? [];
  }
  async append(groupId: string, msgs: StoredGroupMessage[]): Promise<StoredGroupMessage[]> {
    const current = await this.list(groupId);
    if (msgs.length === 0) return current;
    const byId = new Map(current.map((m) => [m.id, m]));
    for (const m of msgs) byId.set(m.id, m);
    const next = [...byId.values()].sort((a, b) => a.createdAt - b.createdAt).slice(-HISTORY_LIMIT);
    await this.col.put(groupId, next);
    return next;
  }
  forget(groupId: string) {
    return this.col.delete(groupId);
  }
  /** VAULT-03: every group's chat, as the vault archives it. */
  async archived(): Promise<ArchivedGroupMessage[]> {
    return (await this.col.all()).flatMap(({ id: groupId, value }) => value.map((m) => ({ groupId, rumorId: m.id, sender: m.sender, kind: CHAT_KIND, content: m.content, createdAt: m.createdAt })));
  }
  /** VAULT-03: adds the chat messages restored from the vault (other kinds are not shown in the web). */
  async restore(messages: ArchivedGroupMessage[]): Promise<number> {
    const byGroup = new Map<string, StoredGroupMessage[]>();
    for (const m of messages) if (m.kind === CHAT_KIND) byGroup.set(m.groupId, [...(byGroup.get(m.groupId) ?? []), storedMessage(m)]);
    for (const [groupId, msgs] of byGroup) await this.append(groupId, msgs);
    return [...byGroup.values()].reduce((n, msgs) => n + msgs.length, 0);
  }
}

// MLS state is a chain of epochs: two operations on the same session must never interleave (a sync
// racing a commit would fork the local state). Every call from the UI goes through this queue.
const queues = new WeakMap<GroupSession, Promise<unknown>>();

export function exclusive<T>(gs: GroupSession, fn: (gs: GroupSession) => Promise<T>): Promise<T> {
  const run = (queues.get(gs) ?? Promise.resolve()).then(() => fn(gs));
  queues.set(gs, run.catch(() => undefined));
  return run;
}

/**
 * A removed member has no leaf left in the tree, so it cannot publish a self-remove (`leave` fails). Drop
 * the group's local MLS state instead and reopen the session (marmot-ts caches loaded groups in memory).
 * Glue for a missing `GroupSession.forget()` in the adapter's API.
 */
export async function forgetRemovedGroup(s: PersonaSession, store: EncryptedStore, cfg: DeploymentConfig, groupId: string): Promise<GroupSession> {
  const gs = await openGroupSession(s, store, cfg);
  await exclusive(gs, async (g) => {
    const m = await import('@sedecim/marmot-adapter');
    await new PersonaGroupStorage(new m.EncryptedGroupStorage(store), s.persona.id).delete('groups', groupId);
    g.close();
  });
  sessions.delete(s.pool);
  return openGroupSession(s, store, cfg);
}

/** Drops the persona's cached MLS session (closing it): the next `openGroupSession` reads the stored state again. */
export async function dropGroupSession(s: PersonaSession): Promise<void> {
  const p = sessions.get(s.pool);
  sessions.delete(s.pool);
  await p?.then((g) => g.close(), () => undefined);
}

/** VAULT-03: the persona's MLS state by logical namespace, without private key packages (a copy never joins with them). */
export async function groupStateSnapshot(store: EncryptedStore, personaId: string): Promise<MlsSnapshot> {
  const prefix = `mls-${personaId}-`;
  const out: MlsSnapshot = {};
  for (const name of await store.collectionNames(prefix)) {
    const ns = name.slice(prefix.length);
    if (ns !== 'keypackages') out[ns] = await store.collection<unknown>(name).all();
  }
  return out;
}

/** Device id a restored MLS state is owned by: no device, so every group counts as restored until `rejoin`. */
const RESTORED_OWNER = 'vault-restore';

/**
 * VAULT-03: writes the MLS state restored from the vault, only if this persona has no groups in this browser (newer
 * local state is never overwritten). The groups come back as a copy of the other device's leaf: they can be read,
 * and `rejoinRestoredGroup` makes this browser a new leaf before it sends (FR025-06).
 */
export async function restoreGroupState(s: PersonaSession, store: EncryptedStore, namespaces: MlsSnapshot | undefined): Promise<'restored' | 'kept' | 'none'> {
  if (!namespaces?.groups?.length) return 'none';
  const prefix = `mls-${s.persona.id}-`;
  if ((await store.collection<unknown>(`${prefix}groups`).all()).length) return 'kept';
  await dropGroupSession(s);
  for (const [ns, entries] of Object.entries(namespaces)) {
    if (ns === 'keypackages' || !/^[a-z0-9-]+$/.test(ns)) continue;
    const col = store.collection<unknown>(`${prefix}${ns}`);
    for (const e of entries) await col.put(e.id, e.value);
  }
  const m = await import('@sedecim/marmot-adapter');
  await new PersonaGroupStorage(new m.EncryptedGroupStorage(store), s.persona.id).put('device', 'owner', RESTORED_OWNER);
  return 'restored';
}

/** A restored group is a copy of another device's leaf: join it again as a new leaf of this browser. */
export async function rejoinRestoredGroup(gs: GroupSession, groupId: string, relays: string[]): Promise<{ status: 'joined' | 'pending'; group: GroupHandle }> {
  const m = await import('@sedecim/marmot-adapter');
  if (!m.isExtendedGroupSession(gs)) throw new Error('este proveedor MLS no puede volver a entrar en un grupo restaurado');
  return gs.rejoin(groupId, relays);
}
