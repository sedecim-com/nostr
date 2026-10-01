/**
 * Group operations the sovereign client and the web both offer, on top of `ExtendedGroupSession`, so that the two decide
 * them the same way: who commits and who proposes a device (FR025-06/09), what a proposal to add or remove someone
 * carries, and how a received MIP-04 file is found, fetched and opened (FR025-05). Relays, Blossom servers and the
 * network policy stay with the caller.
 */
import type { NostrEvent } from '@sedecim/nostr-core';
import { ciphertextHashFromUrl } from './media';
import type { ExtendedGroupSession, GroupHandle, GroupMediaAttachment, GroupProposal } from './types';

/** Why a group operation cannot go ahead, in the words both clients show (`code` tells them apart). */
export class GroupFlowError extends Error {
  constructor(
    readonly code: 'no-new-devices' | 'no-key-packages' | 'unknown-attachment' | 'no-attachment-url',
    message: string,
  ) {
    super(message);
    this.name = 'GroupFlowError';
  }
}

export type AddDevicesResult = { committed: true; group: GroupHandle } | { committed: false; proposals: GroupProposal[] };

/**
 * Adds these devices of one persona (key packages of devices not in the group yet, from `missingDeviceKeyPackages`): an
 * admin commits them all in one commit, with one Welcome; any other member sends Add proposals for an admin to commit
 * (MIP-03: only admins commit). The caller syncs the group first.
 */
export async function addDevices(gs: ExtendedGroupSession, groupId: string, keyPackages: NostrEvent[]): Promise<AddDevicesResult> {
  if (keyPackages.length === 0) throw new GroupFlowError('no-new-devices', 'no hay key packages de dispositivos que no estén ya en el grupo');
  const g = await gs.group(groupId);
  if (g.admins.includes(gs.pubkey)) return { committed: true, group: await gs.inviteMany(groupId, keyPackages) };
  return { committed: false, proposals: await gs.proposeAdd(groupId, keyPackages) };
}

export type MemberChange = { add: string } | { remove: string };

/**
 * A member proposes adding someone (every current device of theirs not in the group) or removing someone (every leaf of
 * theirs). It travels as a kind 445 group message; an admin commits it or leaves it out, and until then nobody can send
 * messages to the group (RFC 9420).
 */
export async function proposeMemberChange(gs: ExtendedGroupSession, groupId: string, change: MemberChange, relays: string[]): Promise<GroupProposal[]> {
  if ('remove' in change) return gs.proposeRemove(groupId, { pubkey: change.remove });
  await gs.sync(groupId);
  const keyPackages = await gs.missingDeviceKeyPackages(groupId, change.add, relays);
  if (keyPackages.length === 0) throw new GroupFlowError('no-key-packages', 'el invitado no tiene key packages de dispositivos fuera del grupo');
  return gs.proposeAdd(groupId, keyPackages);
}

/** Fetches a blob by the SHA-256 of its ciphertext, from the locator it was shared with or the sender's servers. */
export type MediaDownloader = (ciphertextSha256: string, url: string, sender: string) => Promise<Uint8Array>;

export interface FetchedGroupMedia {
  data: Uint8Array;
  attachment: GroupMediaAttachment;
  /** Epoch whose media secret opened it, and the member who sent it. */
  epoch: number;
  sender: string;
}

/**
 * Opens a MIP-04 file received (or sent) in the group, by the SHA-256 of its plaintext. The ciphertext is fetched by its
 * own hash, which the downloader checks, and decrypted with the media secret of the epoch it was sent in, which checks it
 * again (AEAD tag and plaintext SHA-256). Only `mediaReference` and `decryptMedia` use the session, so a caller can queue
 * those two with its other MLS operations and leave the download out of that queue.
 */
export async function fetchGroupMedia(gs: Pick<ExtendedGroupSession, 'mediaReference' | 'decryptMedia'>, groupId: string, sha256: string, download: MediaDownloader): Promise<FetchedGroupMedia> {
  const ref = await gs.mediaReference(groupId, sha256);
  if (!ref) throw new GroupFlowError('unknown-attachment', 'adjunto desconocido en este grupo');
  const url = ref.attachment.url;
  const hash = url ? ciphertextHashFromUrl(url) : undefined;
  if (!url || !hash) throw new GroupFlowError('no-attachment-url', 'el adjunto no tiene una URL Blossom válida');
  const ciphertext = await download(hash, url, ref.sender);
  return { data: await gs.decryptMedia(groupId, ciphertext, ref.attachment, ref.epoch), attachment: ref.attachment, epoch: ref.epoch, sender: ref.sender };
}
