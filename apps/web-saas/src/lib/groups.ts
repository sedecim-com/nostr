import { ciphertextUploader, downloadFromServers, prepareBlob, type UnsanitizableFileError } from '@sedecim/blossom-client';
import type { ArchivedGroupMessage, MlsSnapshot } from '@sedecim/continuity';
import type { AddDevicesResult, ExtendedGroupSession, FetchedGroupMedia, GroupHandle, GroupMediaAttachment, GroupMediaReference, GroupMessage, GroupProposal, GroupSession, GroupStorage, MediaDownloader, MediaUploader, MemberChange, PendingGroupOperation } from '@sedecim/marmot-adapter';
import type { EncryptedStore } from '@sedecim/encrypted-store/browser';
import { normalizePubkey, type NostrEvent } from '@sedecim/nostr-core';
import type { RelayPool } from '@sedecim/relay-pool';
import { blossomServersOf, unsanitizableMessage, uploadTargets } from './blossom';
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
      // FR025-14: the name this browser announces inside the groups it joins.
      const deviceLabel = await groupDeviceLabel(store, s.persona.id);
      return provider.openSession({ signer: s.signer, network: new m.PoolGroupNetwork(s.pool, groupRelays(cfg, s).relays), storage, deviceId: `web-${s.persona.id}`, ...(deviceLabel ? { deviceLabel } : {}), onMessage });
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
  /** FR025-14: the MIP-04 files the message carries, sent or received (opened later with `fetchGroupFile`). */
  media?: GroupMediaAttachment[];
  /** The rumor's tags and the epoch it was sent in, kept as the sovereign client keeps them (the vault archives them). */
  tags?: string[][];
  epoch?: number;
}

const HISTORY_LIMIT = 500;

const storedMessage = (m: Pick<GroupMessage, 'rumorId' | 'sender' | 'content' | 'createdAt' | 'media' | 'tags' | 'epoch'>): StoredGroupMessage => ({
  id: m.rumorId,
  sender: m.sender,
  content: m.content,
  createdAt: m.createdAt,
  ...(m.media?.length ? { media: m.media } : {}),
  ...(m.tags?.length ? { tags: m.tags } : {}),
  ...(m.epoch !== undefined ? { epoch: m.epoch } : {}),
});

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
  /** VAULT-03: every group's chat, as the vault archives it (with the tags that carry its files, FR025-14). */
  async archived(): Promise<ArchivedGroupMessage[]> {
    return (await this.col.all()).flatMap(({ id: groupId, value }) =>
      value.map((m) => ({ groupId, rumorId: m.id, sender: m.sender, kind: CHAT_KIND, content: m.content, createdAt: m.createdAt, ...(m.tags?.length ? { tags: m.tags } : {}), ...(m.epoch !== undefined ? { epoch: m.epoch } : {}) })),
    );
  }
  /** VAULT-03: adds the chat messages restored from the vault (other kinds are not shown in the web). */
  async restore(messages: ArchivedGroupMessage[]): Promise<number> {
    const byGroup = new Map<string, StoredGroupMessage[]>();
    const parse = messages.some((m) => m.tags?.length) ? (await import('@sedecim/marmot-adapter')).parseMediaAttachments : () => [];
    for (const m of messages) if (m.kind === CHAT_KIND) byGroup.set(m.groupId, [...(byGroup.get(m.groupId) ?? []), storedMessage({ ...m, media: parse(m.tags ?? []) })]);
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
    // FR025-12: what was still waiting for a relay in that group can no longer be sent.
    if (m.isExtendedGroupSession(g)) for (const op of await g.pendingOperations(groupId)) await g.discardPending(op.id);
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

/**
 * FR025-12: syncs the groups with operations that found no relay and sends them again; returns what is still pending
 * (nothing with a provider without an outbox).
 */
export async function retryPendingGroupOperations(gs: GroupSession, groupId?: string): Promise<PendingGroupOperation[]> {
  const m = await import('@sedecim/marmot-adapter');
  return m.isExtendedGroupSession(gs) ? gs.retryPending(groupId) : [];
}

/** FR025-12: forgets a pending group operation (one every relay refused). */
export async function discardPendingGroupOperation(gs: GroupSession, id: string): Promise<void> {
  const m = await import('@sedecim/marmot-adapter');
  if (m.isExtendedGroupSession(gs)) await gs.discardPending(id);
}

/** A restored group is a copy of another device's leaf: join it again as a new leaf of this browser. */
export async function rejoinRestoredGroup(gs: GroupSession, groupId: string, relays: string[]): Promise<{ status: 'joined' | 'pending'; group: GroupHandle }> {
  const m = await import('@sedecim/marmot-adapter');
  if (!m.isExtendedGroupSession(gs)) throw new Error('este proveedor MLS no puede volver a entrar en un grupo restaurado');
  return gs.rejoin(groupId, relays);
}

/*
 * FR025-14: what only the sovereign client did so far, in «Grupos seguros»: several devices per persona, key rotation,
 * proposals and their decision, and encrypted files (MIP-04). The decisions are the adapter's shared flows, the same the
 * CLI runs; the view adds the confirmations and the compartmentalisation checks of the web.
 */

/** The adapter's multi-device, proposal and MIP-04 operations, or a clear refusal with a provider without them. */
async function extended(gs: GroupSession): Promise<ExtendedGroupSession> {
  const m = await import('@sedecim/marmot-adapter');
  if (!m.isExtendedGroupSession(gs)) throw new Error('este proveedor MLS no ofrece dispositivos, propuestas ni archivos cifrados');
  return gs;
}

/**
 * The pubkeys an invitation or a proposal names (npub, nprofile or hex, separated by spaces, commas or lines), once
 * each, leaving out `members` (already in the group). Another persona of this browser is refused, as the sovereign client
 * refuses another identity of its own: every member of the group would see both.
 */
export function parseMembers(entries: string, ownPersonas: readonly string[], members: readonly string[] = []): string[] {
  const own = new Set(ownPersonas);
  const out: string[] = [];
  for (const entry of entries.split(/[\s,]+/).filter(Boolean)) {
    let pubkey: string;
    try {
      pubkey = normalizePubkey(entry);
    } catch {
      throw new Error(`"${entry.length > 80 ? `${entry.slice(0, 80)}…` : entry}" no es una npub válida`);
    }
    if (members.includes(pubkey) || out.includes(pubkey)) continue;
    if (own.has(pubkey)) throw new Error('compartimentación: esa npub es otra de tus personas; no la invites desde esta.');
    out.push(pubkey);
  }
  return out;
}

/**
 * Invites every current device of each of these personas in one commit (one Welcome per persona), as the sovereign
 * client's invite does (FR025-06). Returns who got in and who has no key package on the group relays.
 */
export async function inviteMembers(gs: GroupSession, groupId: string, pubkeys: string[], relays: string[]): Promise<{ added: string[]; missing: string[]; group: GroupHandle }> {
  const ext = await extended(gs);
  await ext.sync(groupId);
  const keyPackages: NostrEvent[] = [];
  const added: string[] = [];
  const missing: string[] = [];
  for (const pubkey of pubkeys) {
    const kps = await ext.missingDeviceKeyPackages(groupId, pubkey, relays);
    if (kps.length) {
      keyPackages.push(...kps);
      added.push(pubkey);
    } else missing.push(pubkey);
  }
  return { added, missing, group: keyPackages.length ? await ext.inviteMany(groupId, keyPackages) : await ext.group(groupId) };
}

/** Where this browser stands in a group: in it, removed with its whole persona, or only this device (its leaf) removed. */
export function membership(handle: GroupHandle | undefined, pubkey: string): 'member' | 'removed' | 'device-removed' {
  if (!handle || !handle.members.includes(pubkey)) return 'removed';
  // Another device of the persona keeps it among the members; this one no longer has a leaf of its own.
  if (handle.devices?.length && !handle.devices.some((d) => d.self)) return 'device-removed';
  return 'member';
}

/** The name this browser announces inside the groups; kept next to the persona in the vault, outside the MLS state. */
const deviceRecord = (store: EncryptedStore, personaId: string) => store.collection<{ label: string }>(`groupdevice-${personaId}`);

export async function groupDeviceLabel(store: EncryptedStore, personaId: string): Promise<string> {
  return (await deviceRecord(store, personaId).get('self'))?.label ?? '';
}

/**
 * Stores the name of this browser in the groups (up to 64 characters, as members keep it; empty: none) and reopens the
 * persona's MLS session with it, after whatever the old one was doing. When members see it: SECURE_GROUP_TEXTS.label.
 */
export async function saveGroupDeviceLabel(s: PersonaSession, store: EncryptedStore, cfg: DeploymentConfig, label: string): Promise<GroupSession> {
  const clean = label.trim().slice(0, 64);
  const gs = await openGroupSession(s, store, cfg);
  await exclusive(gs, async (g) => {
    if (clean) await deviceRecord(store, s.persona.id).put('self', { label: clean });
    else await deviceRecord(store, s.persona.id).delete('self');
    g.close();
  });
  sessions.delete(s.pool);
  return openGroupSession(s, store, cfg);
}

/** Key packages of devices of `pubkey` not in the group yet (never this browser), newest first, to pick from. */
export async function missingDevices(gs: GroupSession, groupId: string, pubkey: string, relays: string[]): Promise<NostrEvent[]> {
  const ext = await extended(gs);
  await ext.sync(groupId);
  return (await ext.missingDeviceKeyPackages(groupId, pubkey, relays)).sort((a, b) => b.created_at - a.created_at);
}

/** Adds the picked devices: an admin commits them, any other member proposes them (`addDevices`, as the CLI's add-device). */
export async function addGroupDevices(gs: GroupSession, groupId: string, keyPackages: NostrEvent[]): Promise<AddDevicesResult> {
  const m = await import('@sedecim/marmot-adapter');
  const ext = await extended(gs);
  await ext.sync(groupId);
  return m.addDevices(ext, groupId, keyPackages);
}

/** Admin: removes one device (leaf) and keeps the rest of that persona's devices. */
export async function removeGroupDevice(gs: GroupSession, groupId: string, leafIndex: number): Promise<GroupHandle> {
  return (await extended(gs)).removeDevice(groupId, leafIndex);
}

export async function pendingProposals(gs: GroupSession, groupId: string): Promise<GroupProposal[]> {
  return (await extended(gs)).pendingProposals(groupId);
}

/** A member proposes adding or removing someone (`proposeMemberChange`, as the CLI's `group propose`). */
export async function proposeChange(gs: GroupSession, groupId: string, change: MemberChange, relays: string[]): Promise<GroupProposal[]> {
  const m = await import('@sedecim/marmot-adapter');
  return m.proposeMemberChange(await extended(gs), groupId, change, relays);
}

/**
 * An admin decides the pending proposals. With some approved, one commit applies them and leaves the rest out, which
 * discards them (a proposal only lives in its epoch). With none approved, the admin rotates its own keys: a commit with
 * no proposal, which discards them all (the CLI's `group rotate`).
 */
export async function decideProposals(gs: GroupSession, groupId: string, approve: string[]): Promise<GroupHandle> {
  const ext = await extended(gs);
  return approve.length ? ext.commitProposals(groupId, { refs: approve }) : ext.rotate(groupId);
}

/**
 * A file as it goes into a group: metadata removed from JPEG, PNG and WebP and, with `stripFileMetadata`, an image whose
 * metadata cannot be removed refused before anything else (UnsanitizableFileError): the rule of every attachment of the
 * web (FR019), and the sovereign client's. Other documents go as they are.
 */
export function prepareGroupFile(bytes: Uint8Array, mimeType: string, stripFileMetadata: boolean): Uint8Array {
  return prepareBlob(bytes, { sanitize: true, requireSanitizable: stripFileMetadata && 'images', mimeType }).data;
}

/**
 * Uploads a group file's ciphertext to every server of the persona's Blossom list that takes encrypted files and to the
 * deployment's blob-store (the web's routing of encrypted attachments, FR018-05), mirrored as the sovereign client does.
 */
export async function groupMediaUploader(s: PersonaSession, cfg: DeploymentConfig): Promise<MediaUploader> {
  const targets = uploadTargets(cfg, await blossomServersOf(s), true);
  if (targets.length === 0) throw new Error('No hay servidor Blossom para archivos cifrados: publica tu lista de servidores o configura el blob-store.');
  return ciphertextUploader(targets, s.signer, { mirror: true });
}

/** Refuses a file name MIP-04 cannot carry (members' clients would drop the file): checked before anything else. */
export async function checkGroupFileName(filename: string): Promise<void> {
  const m = await import('@sedecim/marmot-adapter');
  if (!m.isValidMediaFilename(filename)) throw new Error('Ese nombre de archivo no se puede enviar a un grupo seguro: debe ocupar entre 1 y 255 bytes y no llevar saltos de línea. Cámbiale el nombre.');
}

/**
 * Encrypts the (prepared) file with the group's current epoch, uploads the ciphertext and sends the message that carries
 * it (MIP-04, `imeta`).
 */
export async function sendGroupFile(gs: GroupSession, groupId: string, file: { data: Uint8Array; filename: string; type: string }, upload: MediaUploader, caption = ''): Promise<GroupMediaReference> {
  await checkGroupFileName(file.filename);
  return (await extended(gs)).sendMedia(groupId, { data: file.data, filename: file.filename, type: file.type || 'application/octet-stream' }, upload, caption);
}

/**
 * Fetches a group file's ciphertext by its hash: the URL it was shared with and, if that fails, the sender's Blossom
 * servers (their kind 10063 list, read on the persona's relays). Every candidate is hash-verified before it is used.
 */
export function groupMediaDownloader(s: PersonaSession): MediaDownloader {
  return async (hash, url, sender) => {
    try {
      return (await downloadFromServers(hash, { url, servers: [] }, s.signer)).data;
    } catch (err) {
      const servers = await blossomServersOf(s, sender);
      if (servers.length === 0) throw err;
      return (await downloadFromServers(hash, { servers }, s.signer)).data;
    }
  };
}

/**
 * Opens a file of the group (`fetchGroupMedia`): finding it and decrypting it wait their turn in the session's queue, the
 * download does not, so a slow server does not hold the group. Call it outside `exclusive`.
 */
export async function fetchGroupFile(gs: GroupSession, groupId: string, sha256: string, download: MediaDownloader): Promise<FetchedGroupMedia> {
  const m = await import('@sedecim/marmot-adapter');
  const ext = await extended(gs);
  const queued = {
    mediaReference: (gid: string, sha: string) => exclusive(gs, () => ext.mediaReference(gid, sha)),
    decryptMedia: (gid: string, ciphertext: Uint8Array, attachment: GroupMediaAttachment, epoch: number) => exclusive(gs, () => ext.decryptMedia(gid, ciphertext, attachment, epoch)),
  };
  return m.fetchGroupMedia(queued, groupId, sha256, download);
}

/** A file size as the log shows it; nothing for a size a member's message did not state as a whole number of bytes. */
export function fileSizeLabel(size: number | undefined): string {
  if (size === undefined || !Number.isSafeInteger(size) || size < 0) return '';
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1).replace('.', ',')} KB`;
  return `${(size / (1024 * 1024)).toFixed(1).replace('.', ',')} MB`;
}

/** What a failed group action tells the user: the adapter's refusals in Spanish, anything else as it came. */
export function groupErrorMessage(e: unknown): string {
  const err = (e ?? {}) as Error;
  switch (err.name) {
    case 'PendingProposalsError':
      return 'Hay propuestas sin decidir en el grupo: hasta que un admin las confirme o las rechace no se pueden enviar mensajes ni archivos.';
    case 'NotGroupAdminError':
      return 'Solo un admin del grupo puede hacer eso: propónlo y que un admin lo confirme.';
    case 'RestoredGroupStateError':
      return 'Este grupo se restauró con la copia de otro dispositivo: vuelve a entrar como dispositivo nuevo antes de escribir.';
    case 'MediaKeyUnavailableError':
      return 'Este navegador no tiene la clave de la época en que se envió el archivo: no estaba en el grupo entonces, o esa clave ya caducó.';
    case 'UnsanitizableFileError':
      return unsanitizableMessage(err as UnsanitizableFileError);
  }
  const message = err.message ?? String(e);
  if (/no admissible pending proposal/.test(message)) return 'Ninguna de las propuestas marcadas se puede aplicar.';
  if (/no pending proposals in this epoch/.test(message)) return 'Esas propuestas ya no están pendientes (el grupo cambió de época): quien las hizo tiene que volver a proponerlas.';
  if (/^blob [0-9a-f]+… not available/.test(message)) return 'Ningún servidor entregó el archivo cifrado con el hash que anuncia el mensaje: no se ha descifrado nada.';
  if (/epoch changed (during the upload|before the file went out)/.test(message)) return 'El grupo cambió de época mientras se subía el archivo: vuelve a enviarlo.';
  // A proposal does not wait for a relay as messages and commits do (marmot-ts publishes it or fails).
  if (/Failed to publish proposal event/.test(message)) return 'Sin conexión con el relay de grupos: la propuesta no salió. Vuelve a hacerla cuando haya conexión.';
  if (/^blossom upload failed on every server/.test(message)) return 'Ningún servidor aceptó el archivo cifrado: no se ha enviado nada al grupo.';
  return message;
}
