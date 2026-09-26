/**
 * High-security groups (spec §10.3). Marmot = Nostr identity + MLS (RFC 9420). The product depends only on
 * these interfaces; the concrete provider (marmot-ts) lives behind them so it can be swapped for MDK
 * bindings without touching callers. NIP-EE is superseded by Marmot and must not be used.
 */
import type { Filter, NostrEvent, Signer } from '@sedecim/nostr-core';

/** Marmot event kinds used by the pinned implementation (marmot-ts 0.5.1). */
export const MARMOT_KINDS = {
  /** Addressable key package (current). */
  KeyPackage: 30443,
  /** Legacy key package kind still accepted when reading. */
  LegacyKeyPackage: 443,
  /** Welcome rumor, always delivered inside a NIP-59 gift wrap (kind 1059). */
  Welcome: 444,
  /** MLS group message (commits, proposals, application messages). */
  GroupMessage: 445,
  /** Relays where a user publishes key packages / receives Welcomes. */
  KeyPackageRelays: 10051,
} as const;

export interface GroupCryptoProperties {
  forwardSecrecy: boolean;
  postCompromiseSecurity: boolean;
  multiDevice: boolean;
  implementation: string;
  version: string;
  ciphersuite?: string;
}

export interface GroupHandle {
  /** MLS group id (hex). */
  groupId: string;
  /** Public Nostr group id used in the `h` tag of kind 445 events (hex). */
  nostrGroupId: string;
  name: string;
  epoch: number;
  members: string[];
  admins: string[];
  relays: string[];
  /** MLS leaves (one per device; a persona with two devices has two leaves). */
  devices?: GroupDevice[];
  /** Proposals received in this epoch that no admin has committed yet. */
  pendingProposals?: number;
  /**
   * The local MLS state of this group was copied from another device (backup restore). The cloned leaf
   * must not be used to send: run `rejoin` so this device joins as a new leaf and the old one is removed.
   */
  restored?: boolean;
}

/** One MLS leaf of the group. */
export interface GroupDevice {
  pubkey: string;
  leafIndex: number;
  /** Device id announced by the device inside the group (its key package `d` slot is a separate random value). */
  deviceId?: string;
  /** Human label announced by the device (only group members ever see it: it travels inside MLS). */
  label?: string;
  /** This is the local device's leaf. */
  self: boolean;
}

/** MIP-04 (v2, `mip04-v2`) media attachment as carried in an `imeta` tag of a group message. */
export interface GroupMediaAttachment {
  /** Where the ciphertext is stored (Blossom `server/<sha256 of ciphertext>`). */
  url?: string;
  /** SHA-256 of the plaintext (hex, `x`). */
  sha256: string;
  /** Canonical MIME type (`m`). */
  type: string;
  filename: string;
  /** 12-byte ChaCha20-Poly1305 nonce (hex, `n`). */
  nonce: string;
  version: string;
  size?: number;
  dimensions?: string;
  blurhash?: string;
  alt?: string;
}

/** A MIP-04 attachment together with the MLS epoch whose exporter secret encrypts it. */
export interface GroupMediaReference {
  groupId: string;
  epoch: number;
  attachment: GroupMediaAttachment;
  sender: string;
  rumorId: string;
}

export type GroupProposalType = 'add' | 'remove' | 'update' | 'group-context-extensions' | 'other';

export interface GroupProposal {
  /** Proposal reference (base64, as ts-mls keys `unappliedProposals`). */
  ref: string;
  type: GroupProposalType;
  /** Pubkey of the proposing member (undefined for external senders). */
  proposer?: string;
  proposerLeaf?: number;
  /** add: pubkey of the key package; remove: pubkey of the removed leaf. */
  target?: string;
  /** remove: leaf index removed. */
  targetLeaf?: number;
  /** An admin may commit it under this repo's policy (see `docs/marmot.md`). */
  admissible: boolean;
}

export interface GroupSyncReport {
  messages: GroupMessage[];
  /** Proposals newly received in this sync. */
  proposals: number;
  /** Commits processed (epoch advanced). */
  commits: number;
  /** Commits rejected by the MIP-03 admin policy (non-admin commits). */
  rejectedCommits: number;
  /** Events that could not be read (other epochs, garbage, removed from the group). */
  unreadable: number;
}

export interface GroupMessage {
  groupId: string;
  sender: string;
  content: string;
  kind: number;
  createdAt: number;
  rumorId: string;
  /** MLS epoch in which the message was sent (MIP-04: selects the media exporter secret). */
  epoch?: number;
  /** Leaf index of the sending device. */
  senderLeaf?: number;
  tags?: string[][];
  /** Valid MIP-04 attachments (`imeta` tags). */
  media?: GroupMediaAttachment[];
}

/** Transport the provider uses to talk to relays (implemented over our RelayPool). */
export interface GroupNetwork {
  publish(relays: string[], event: NostrEvent): Promise<Array<{ relay: string; ok: boolean; message: string }>>;
  query(relays: string[], filters: Filter[], timeoutMs?: number): Promise<NostrEvent[]>;
  subscribe(relays: string[], filters: Filter[], onEvent: (e: NostrEvent) => void): { close(): void };
  /** Relays where `pubkey` receives invites (kind 10051 / 10050 lookups). */
  inboxRelays(pubkey: string): Promise<string[]>;
}

/** Persistent key/value storage. Implementations MUST encrypt at rest: values hold MLS private keys. */
export interface GroupStorage {
  get(namespace: string, key: string): Promise<unknown | undefined>;
  put(namespace: string, key: string, value: unknown): Promise<void>;
  delete(namespace: string, key: string): Promise<void>;
  keys(namespace: string): Promise<string[]>;
}

export interface SessionOptions {
  signer: Signer;
  network: GroupNetwork;
  storage: GroupStorage;
  /** Stable per-device id (key package `d` slot). Each installation MUST use its own. */
  deviceId: string;
  /** Optional device label, announced only inside the groups (encrypted), never on public relays. */
  deviceLabel?: string;
  /**
   * The storage was restored from another device's backup. When the storage does not record which
   * device owns it (older backups), this marks every existing group as restored (see `rejoin`).
   */
  clonedState?: boolean;
}

/** Per-identity, per-device group session. */
export interface GroupSession {
  readonly pubkey: string;
  /** Publish a key package so others can add this device to groups. */
  publishKeyPackage(relays: string[]): Promise<NostrEvent>;
  /** Find the newest key package of a user on the given relays. */
  findKeyPackage(pubkey: string, relays: string[]): Promise<NostrEvent | undefined>;
  createGroup(opts: { name: string; description?: string; relays: string[]; admins?: string[] }): Promise<GroupHandle>;
  /** Add a member by key package (commit + gift-wrapped Welcome). */
  invite(groupId: string, keyPackage: NostrEvent): Promise<GroupHandle>;
  removeMember(groupId: string, pubkey: string): Promise<GroupHandle>;
  /** Self-update commit: rotates this member's leaf keys (post-compromise security). */
  rotate(groupId: string): Promise<GroupHandle>;
  send(groupId: string, content: string, tags?: string[][]): Promise<void>;
  /** Fetch and process new kind 445 events for a group; returns decrypted application messages. */
  sync(groupId: string): Promise<GroupMessage[]>;
  /** Process pending invites (gift-wrapped Welcomes) and join those groups. */
  acceptInvites(): Promise<GroupHandle[]>;
  leave(groupId: string): Promise<void>;
  groups(): Promise<GroupHandle[]>;
  group(groupId: string): Promise<GroupHandle>;
  close(): void;
}

/** Input for sending a MIP-04 encrypted file. */
export interface GroupMediaInput {
  data: Uint8Array;
  filename: string;
  /** MIME type (canonicalized per MIP-04). */
  type: string;
  alt?: string;
  dimensions?: string;
}

/** Uploads ciphertext (e.g. to the user's Blossom servers) and returns its locator. */
export type MediaUploader = (ciphertext: Uint8Array, ciphertextSha256: string) => Promise<{ url: string }>;

/**
 * Multi-device, proposal and MIP-04 operations (FR025-05/06/09). Separate from `GroupSession` so existing
 * implementations keep compiling; `MarmotTsProvider` sessions implement it (see `isExtendedGroupSession`).
 */
export interface ExtendedGroupSession extends GroupSession {
  readonly deviceId: string;
  /** Current key packages of `pubkey`: the newest per device (`d` slot). */
  findKeyPackages(pubkey: string, relays: string[]): Promise<NostrEvent[]>;
  /**
   * Key packages of `pubkey` whose device is not in the group yet (never the local device). Devices are
   * recognised by their in-group announcement or by the key package's leaf signature key.
   */
  missingDeviceKeyPackages(groupId: string, pubkey: string, relays: string[]): Promise<NostrEvent[]>;
  /** Admin: add several key packages (e.g. every device of a persona) in one commit. */
  inviteMany(groupId: string, keyPackages: NostrEvent[]): Promise<GroupHandle>;
  /** Admin: add every current device of `pubkey` not yet in the group. */
  invitePersona(groupId: string, pubkey: string, relays: string[]): Promise<GroupHandle>;
  /** Admin: remove one leaf (a single device). */
  removeDevice(groupId: string, leafIndex: number): Promise<GroupHandle>;
  devices(groupId: string): Promise<GroupDevice[]>;
  /** Any member: propose adding key packages (Add proposals, kind 445). */
  proposeAdd(groupId: string, keyPackages: NostrEvent[]): Promise<GroupProposal[]>;
  /** Any member: propose removing every leaf of `pubkey` (or one leaf with `leafIndex`). */
  proposeRemove(groupId: string, target: { pubkey: string } | { leafIndex: number }): Promise<GroupProposal[]>;
  pendingProposals(groupId: string): Promise<GroupProposal[]>;
  /** Admin: commit pending proposals (all admissible ones, or only `refs`). */
  commitProposals(groupId: string, opts?: { refs?: string[] }): Promise<GroupHandle>;
  syncWithReport(groupId: string): Promise<GroupSyncReport>;
  /** Groups whose state was restored from another device and still use the cloned leaf. */
  restoredGroups(): Promise<string[]>;
  /**
   * Re-enter a restored group as a new leaf of this device: admins add the new leaf from the cloned one
   * and then remove the cloned leaf; non-admins propose both (Add + Remove) for an admin to commit.
   * Returns `joined` when this device already holds its own new leaf, `pending` otherwise.
   */
  rejoin(groupId: string, relays: string[]): Promise<{ status: 'joined' | 'pending'; group: GroupHandle }>;
  /** MIP-04: encrypt with the current epoch, upload, and send a kind 9 message with the `imeta` tag. */
  sendMedia(groupId: string, file: GroupMediaInput, upload: MediaUploader, caption?: string): Promise<GroupMediaReference>;
  /** MIP-04: decrypt ciphertext of an attachment sent in `epoch` (needs that epoch's media secret). */
  decryptMedia(groupId: string, ciphertext: Uint8Array, attachment: GroupMediaAttachment, epoch: number): Promise<Uint8Array>;
  /** Attachment received (or sent) in this group, by plaintext SHA-256. */
  mediaReference(groupId: string, sha256: string): Promise<GroupMediaReference | undefined>;
}

export function isExtendedGroupSession(s: GroupSession): s is ExtendedGroupSession {
  return typeof (s as Partial<ExtendedGroupSession>).rejoin === 'function' && typeof (s as Partial<ExtendedGroupSession>).sendMedia === 'function';
}

/** The local MLS state of a group is a clone of another device's leaf: sending from it is refused. */
export class RestoredGroupStateError extends Error {
  constructor(readonly groupId: string) {
    super(`group ${groupId.slice(0, 12)}… was restored from another device's backup: run rejoin so this device joins as a new leaf (cloned leaves break forward secrecy)`);
    this.name = 'RestoredGroupStateError';
  }
}

export class NotGroupAdminError extends Error {
  constructor(action: string) {
    super(`only group admins can ${action} (MIP-03): propose it instead and let an admin commit`);
    this.name = 'NotGroupAdminError';
  }
}

/** ts-mls refuses application messages while proposals are pending (RFC 9420: commit them first). */
export class PendingProposalsError extends Error {
  constructor(readonly count: number) {
    super(`${count} pending proposal(s) in this epoch: an admin must commit them before messages can be sent`);
    this.name = 'PendingProposalsError';
  }
}

export class MediaKeyUnavailableError extends Error {
  constructor(epoch: number) {
    super(`no media secret for epoch ${epoch}: this device was not a member then, or the secret expired (MIP-04)`);
    this.name = 'MediaKeyUnavailableError';
  }
}

export interface GroupCryptoProvider {
  readonly properties: GroupCryptoProperties;
  openSession(opts: SessionOptions): Promise<GroupSession>;
}

export class GroupCryptoUnavailableError extends Error {
  constructor() {
    super('No Marmot/MLS provider configured: high-security groups are unavailable (fail closed).');
  }
}
