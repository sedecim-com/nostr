/**
 * NIP-29 relay-based groups (Buzz channels). Standard collaboration channels: NOT end-to-end encrypted
 * unless content is encrypted client-side before publishing (spec §10.1).
 */
import { getTagValue, getTagValues, type EventTemplate, type NostrEvent } from '@sedecim/nostr-core';

export const NIP29 = {
  ChatMessage: 9,
  Reaction: 7,
  Deletion: 5,
  PutUser: 9000,
  RemoveUser: 9001,
  EditMetadata: 9002,
  DeleteEvent: 9005,
  CreateGroup: 9007,
  DeleteGroup: 9008,
  JoinRequest: 9021,
  LeaveRequest: 9022,
  GroupMetadata: 39000,
  GroupAdmins: 39001,
  GroupMembers: 39002,
} as const;

export function chatMessage(groupId: string, content: string, opts: { replyTo?: { root: string; parent?: string }; previous?: string[] } = {}): EventTemplate {
  const tags: string[][] = [['h', groupId]];
  if (opts.replyTo) {
    tags.push(['e', opts.replyTo.root, '', 'root']);
    if (opts.replyTo.parent && opts.replyTo.parent !== opts.replyTo.root) tags.push(['e', opts.replyTo.parent, '', 'reply']);
  }
  if (opts.previous?.length) tags.push(['previous', ...opts.previous.map((id) => id.slice(0, 8))]);
  return { kind: NIP29.ChatMessage, content, tags };
}

export function reaction(groupId: string, target: NostrEvent, content = '+'): EventTemplate {
  return { kind: NIP29.Reaction, content, tags: [['h', groupId], ['e', target.id], ['p', target.pubkey]] };
}

export function deletion(groupId: string, eventId: string, reason = ''): EventTemplate {
  return { kind: NIP29.Deletion, content: reason, tags: [['h', groupId], ['e', eventId]] };
}

export function createGroup(name: string, visibility: 'open' | 'private' = 'private'): EventTemplate {
  return { kind: NIP29.CreateGroup, content: '', tags: [['name', name], ['visibility', visibility]] };
}

export function joinRequest(groupId: string): EventTemplate {
  return { kind: NIP29.JoinRequest, content: '', tags: [['h', groupId]] };
}

export function channelFilter(groupId: string, since?: number) {
  return { kinds: [NIP29.ChatMessage, NIP29.Reaction, NIP29.Deletion], '#h': [groupId], ...(since !== undefined ? { since } : {}) };
}

export interface GroupMetadata {
  id: string;
  name?: string;
  about?: string;
  private: boolean;
  closed: boolean;
  hidden: boolean;
}

export function parseGroupMetadata(evt: NostrEvent): GroupMetadata | undefined {
  if (evt.kind !== NIP29.GroupMetadata) return undefined;
  const id = getTagValue(evt, 'd');
  if (!id) return undefined;
  const has = (n: string) => evt.tags.some((t) => t[0] === n);
  return { id, name: getTagValue(evt, 'name'), about: getTagValue(evt, 'about'), private: has('private'), closed: has('closed'), hidden: has('hidden') };
}

export function parseGroupMembers(evt: NostrEvent): string[] {
  return evt.kind === NIP29.GroupMembers ? getTagValues(evt, 'p') : [];
}
