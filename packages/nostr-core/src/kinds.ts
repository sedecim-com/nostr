import type { NostrEvent } from './event';
import { getTagValue } from './event';

export const Kind = {
  Metadata: 0,
  Deletion: 5,
  Reaction: 7,
  GroupChatMessage: 9,
  Seal: 13,
  PrivateDirectMessage: 14,
  FileMessage: 15,
  GiftWrap: 1059,
  DmRelayList: 10050,
  BlossomServerList: 10063,
  RelayList: 10002,
  ClientAuth: 22242,
  NostrConnect: 24133,
  BlossomAuth: 24242,
  HttpAuth: 27235,
  GroupMetadata: 39000,
  GroupAdmins: 39001,
  GroupMembers: 39002,
} as const;

export function isReplaceableKind(kind: number): boolean {
  return kind === 0 || kind === 3 || (kind >= 10000 && kind < 20000);
}

export function isEphemeralKind(kind: number): boolean {
  return kind >= 20000 && kind < 30000;
}

export function isAddressableKind(kind: number): boolean {
  return kind >= 30000 && kind < 40000;
}

export function isRegularKind(kind: number): boolean {
  return !isReplaceableKind(kind) && !isEphemeralKind(kind) && !isAddressableKind(kind);
}

/** Key identifying the "slot" of a replaceable/addressable event, or the id for regular events. */
export function eventAddress(evt: NostrEvent): string {
  if (isReplaceableKind(evt.kind)) return `${evt.kind}:${evt.pubkey}:`;
  if (isAddressableKind(evt.kind)) return `${evt.kind}:${evt.pubkey}:${getTagValue(evt, 'd') ?? ''}`;
  return evt.id;
}

/**
 * NIP-01 head selection: newest created_at wins; on a tie the lowest id (lexical) wins.
 * Returns true if `candidate` should replace `current`.
 */
export function supersedes(candidate: NostrEvent, current: NostrEvent): boolean {
  if (candidate.created_at !== current.created_at) return candidate.created_at > current.created_at;
  return candidate.id < current.id;
}

/** Collapse a set of events to their canonical heads (dedup by id, head selection by address). */
export function selectHeads(events: Iterable<NostrEvent>): NostrEvent[] {
  const byAddress = new Map<string, NostrEvent>();
  for (const evt of events) {
    const addr = eventAddress(evt);
    const cur = byAddress.get(addr);
    if (!cur || supersedes(evt, cur)) byAddress.set(addr, evt);
  }
  return [...byAddress.values()];
}
