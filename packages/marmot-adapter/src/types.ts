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
}

export interface GroupMessage {
  groupId: string;
  sender: string;
  content: string;
  kind: number;
  createdAt: number;
  rumorId: string;
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
  /** Stable per-device id (key package `d` slot). */
  deviceId: string;
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

export interface GroupCryptoProvider {
  readonly properties: GroupCryptoProperties;
  openSession(opts: SessionOptions): Promise<GroupSession>;
}

export class GroupCryptoUnavailableError extends Error {
  constructor() {
    super('No Marmot/MLS provider configured: high-security groups are unavailable (fail closed).');
  }
}
