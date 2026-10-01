import { ArchiveVaultClient, forgetDueArchives, type ArchiveForgetQueue } from '@sedecim/continuity';
import type { OutboxRecord } from '@sedecim/delivery-engine';
import type { EncryptedStore } from '@sedecim/encrypted-store/browser';
import {
  DirectMessenger,
  forgetMessageCopies,
  NotYourMessageError,
  purgeExpiredCopies,
  roundedExpiration,
  unwrappedExpiration,
  type DirectMessage,
  type DmCopies,
  type DmDelivery,
  type DmInbox,
  type DmOperation,
  type ForgottenCopies,
  type WrapOptions,
} from '@sedecim/messaging';
import { hexToBytes, wipe } from '@sedecim/nostr-core';
import { DM_DELETION_TEXTS, MESSAGE_EXPIRATION_TEXTS, PRESETS, expirationDays, resolveMessageExpiration, type ExpirationSource, type MessageExpirationOption } from '@sedecim/profiles';
import type { PersonaSession } from './session';
import type { PersonaRecord } from './vault';

/**
 * PANEL-06 (§12.2): the expiration of direct messages (NIP-40) and the deletion of one's own in the web. What the
 * persona chose for each conversation is sealed in the browser vault next to the rest of its data, as its panel
 * configuration is; so are the deletions it remembers and the vault archives it still has to delete.
 */

/** A conversation's own choices: a DM with one contact, by the contact's pubkey. */
export interface ConversationSettings {
  expiration?: MessageExpirationOption;
}

const conversations = (store: EncryptedStore, personaId: string) => store.collection<ConversationSettings>(`conv-${personaId}`);
/** Messages deleted by their author (messaging's TombstoneStore). */
export const dmTombstones = (store: EncryptedStore, personaId: string) => store.collection<boolean>(`dmdel-${personaId}`);
/** Vault archives this browser still has to delete (continuity's ArchiveForgetQueue). */
export const vaultForgetQueue = (store: EncryptedStore, personaId: string): ArchiveForgetQueue => store.collection<number>(`vdel-${personaId}`);

/** The persona's copies of its DMs in this browser: its sent operations, its outbox and the deletions it remembers. */
export function dmCopies(store: EncryptedStore, s: Pick<PersonaSession, 'persona' | 'engine'>): DmCopies {
  return { operations: store.collection<DmOperation>(`dm-ops-${s.persona.id}`), outbox: s.engine, tombstones: dmTombstones(store, s.persona.id) };
}

/** The profile's default, when the persona still follows a preset (a customized one has none of its own). */
function profileDefault(persona: PersonaRecord): MessageExpirationOption | undefined {
  return persona.preset === 'custom' ? undefined : PRESETS[persona.preset]?.messageExpiration;
}

/** The expiration of the next message to `contact`: the conversation's, else the persona's, else its profile's. */
export async function conversationExpiration(store: EncryptedStore, persona: PersonaRecord, contact: string): Promise<{ option: MessageExpirationOption; source: ExpirationSource; conversation?: MessageExpirationOption }> {
  const own = (await conversations(store, persona.id).get(contact))?.expiration;
  return { ...resolveMessageExpiration({ profile: profileDefault(persona), persona: persona.config.messageExpiration, conversation: own }), ...(own ? { conversation: own } : {}) };
}

/** The shortest expiration the persona uses, its own or a conversation's (to compare with the vault's retention). */
export async function shortestExpiration(store: EncryptedStore, persona: PersonaRecord): Promise<MessageExpirationOption> {
  const own = resolveMessageExpiration({ profile: profileDefault(persona), persona: persona.config.messageExpiration }).option;
  const chosen = [own, ...(await conversations(store, persona.id).all()).map((e) => e.value.expiration)];
  const days = (o: MessageExpirationOption | undefined) => (o ? (expirationDays(o) ?? Infinity) : Infinity);
  return chosen.reduce<MessageExpirationOption>((best, o) => (o && days(o) < days(best) ? o : best), 'off');
}

/** Sets the conversation's own expiration, or clears it (undefined: as the persona). Only later messages take it. */
export async function setConversationExpiration(store: EncryptedStore, persona: PersonaRecord, contact: string, option: MessageExpirationOption | undefined): Promise<void> {
  const col = conversations(store, persona.id);
  if (option === undefined) await col.delete(contact);
  else await col.put(contact, { expiration: option });
}

/** The NIP-40 expiration of a message sent at `nowMs` under `option`, rounded up to a UTC day; none for `off`. */
export function expirationFor(option: MessageExpirationOption, nowMs = Date.now()): number | undefined {
  const days = expirationDays(option);
  return days === undefined ? undefined : roundedExpiration(days, Math.floor(nowMs / 1000));
}

/** Whether the persona's copies can be in the deployment's vault: it is used with the cloud backup on. */
function vaultOf(url: string | undefined, persona: PersonaRecord): string | undefined {
  return url && persona.config.cloudBackup !== 'off' && persona.archiveKeyHex ? url : undefined;
}

/**
 * Deletes from the persona's vault the archives of these events and of the queued ones that are due; what the vault
 * does not confirm stays queued (vaultForgetQueue) for the next run (these events only with `remember`, see
 * forgetDueArchives). Nothing is asked of a vault the persona does not use, and nothing is queued for a persona that
 * cannot have archives in this deployment's vault (no vault, or no archive key in this browser).
 */
export async function forgetInVault(store: EncryptedStore, persona: PersonaRecord, vaultUrl: string | undefined, eventIds: string[], nowMs = Date.now(), opts: { remember?: boolean } = {}) {
  if (!vaultUrl || !persona.archiveKeyHex) return { deleted: 0, queued: 0 };
  const url = vaultOf(vaultUrl, persona);
  const queue = vaultForgetQueue(store, persona.id);
  const now = Math.floor(nowMs / 1000);
  if (!url) return forgetDueArchives(undefined, queue, eventIds, now, opts);
  const key = hexToBytes(persona.archiveKeyHex);
  try {
    return await forgetDueArchives({ client: new ArchiveVaultClient({ baseUrl: url, auth: { archiveKey: key } }), key }, queue, eventIds, now, opts);
  } finally {
    wipe(key);
  }
}

export interface DmPurge extends ForgottenCopies {
  /** Vault archives deleted, and a vault error (the deletions then wait for the next run). */
  vault: number;
  vaultError?: string;
  /** The soonest expiration still ahead in this browser's copies and vault deletions (unix seconds). */
  next?: number;
}

/**
 * PANEL-06: forgets this browser's copies of the messages that expired at `nowMs` (sent operations, outbox records) and
 * deletes their vault archives, with those of `expiredWraps` (e.g. the messages the inbox just dropped). What this
 * browser stored in the vault was queued when stored, so the others are only tried with the vault at hand.
 */
export async function purgeExpiredDms(store: EncryptedStore, s: Pick<PersonaSession, 'persona' | 'engine'>, vaultUrl: string | undefined, expiredWraps: string[] = [], nowMs = Date.now()): Promise<DmPurge> {
  const copies = await purgeExpiredCopies(dmCopies(store, s), Math.floor(nowMs / 1000));
  const vault = await forgetInVault(store, s.persona, vaultUrl, [...copies.wrapIds, ...expiredWraps], nowMs, { remember: false });
  const next = [copies.next, vault.next].filter((x): x is number => x !== undefined);
  return { ...copies, vault: vault.deleted, ...(vault.error ? { vaultError: vault.error } : {}), ...(next.length ? { next: Math.min(...next) } : {}) };
}

/**
 * PANEL-06: messages the inbox dropped because their author deleted them (a contact, or this persona from another
 * device): this browser forgets its copies of them and deletes their vault archives, as for its own deletions.
 */
export async function forgetDeletedDms(store: EncryptedStore, s: Pick<PersonaSession, 'persona' | 'engine'>, vaultUrl: string | undefined, messages: DirectMessage[]) {
  const forgotten = await forgetMessageCopies(dmCopies(store, s), messages.map((m) => ({ rumorId: m.rumor.id, author: m.sender, wrapIds: [m.wrap.id] })));
  return { forgotten, vault: await forgetInVault(store, s.persona, vaultUrl, forgotten.wrapIds) };
}

export interface DmDeletionPlan {
  /** What the user reads before confirming (DM_DELETION_TEXTS and what the vault keeps): nothing is sent before confirm(). */
  notice: string[];
  confirm(): Promise<{ deliveries: Array<DmDelivery<OutboxRecord>>; forgotten: ForgottenCopies; vault: number; vaultError?: string }>;
}

/**
 * PANEL-06: deleting one of the persona's own messages, in two steps: the plan says what deleting does and does not do,
 * and only its confirm() sends the deletion (NIP-17: a kind 5 gift-wrapped to each recipient and to the persona's other
 * devices) and forgets this browser's copies. A message someone else wrote is refused here (NotYourMessageError).
 */
export function planDmDeletion(
  store: EncryptedStore,
  s: Pick<PersonaSession, 'persona' | 'pubkey' | 'signer' | 'pool' | 'engine' | 'dmOperations' | 'dmDiscovery'>,
  m: DirectMessage,
  opts: { inbox?: Pick<DmInbox<OutboxRecord>, 'forget'>; vaultUrl?: string; wrapOptions?: WrapOptions } = {},
): DmDeletionPlan {
  if (m.sender !== s.pubkey || m.rumor.pubkey !== s.pubkey) throw new NotYourMessageError(m.rumor.id);
  return {
    notice: [DM_DELETION_TEXTS.request, DM_DELETION_TEXTS.local, DM_DELETION_TEXTS.copies, MESSAGE_EXPIRATION_TEXTS.vault],
    confirm: async () => {
      const messenger = new DirectMessenger(s.signer, { nip17: true, readReceipts: false }, opts.wrapOptions);
      // One operation per message (FR011-05): deleting it again retries the same request instead of making another.
      const route = { pool: s.pool, outbox: s.engine, operations: s.dmOperations, ownRelays: s.persona.relays, discoveryRelays: s.dmDiscovery, quorum: 1 };
      const { deliveries } = await messenger.deleteDmOnce(`delete:${m.rumor.id}`, { rumor: m.rumor, expiration: unwrappedExpiration(m) }, route);
      opts.inbox?.forget(m.rumor.id, s.pubkey);
      const { forgotten, vault } = await forgetDeletedDms(store, s, opts.vaultUrl, [m]);
      return { deliveries, forgotten, vault: vault.deleted, ...(vault.error ? { vaultError: vault.error } : {}) };
    },
  };
}
