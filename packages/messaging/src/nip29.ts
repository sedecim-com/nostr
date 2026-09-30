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

/** Where a reply sits in its thread (NIP-10 `e` markers). */
export interface ThreadRef {
  root: string;
  parent: string;
}

const isEventId = (v: string | undefined): v is string => !!v && /^[0-9a-f]{64}$/.test(v);

/**
 * FR015-04: where a channel message sits in a thread, read as Buzz reads it: a `reply` marker names the parent and a
 * `root` marker the thread's root; a `reply` alone is a direct reply to the root; a `root` alone, or no marker, is a
 * top-level message (Buzz never anchors a reply on a lone `root`). The last valid marker of each kind wins.
 */
export function threadOf(evt: Pick<NostrEvent, 'tags'>): ThreadRef | undefined {
  let root: string | undefined;
  let reply: string | undefined;
  for (const t of evt.tags) {
    if (t[0] !== 'e' || !isEventId(t[1])) continue;
    if (t[3] === 'root') root = t[1];
    else if (t[3] === 'reply') reply = t[1];
  }
  return reply ? { root: root ?? reply, parent: reply } : undefined;
}

/**
 * A channel message (kind 9). `replyTo` makes it a reply: both NIP-10 markers, also for a direct reply (Buzz reads a
 * lone `root` as a top-level message; NIP-10 readers take the `reply` as the parent), and the NIP-C7 `q` tag chat
 * clients quote the parent by.
 */
export function chatMessage(groupId: string, content: string, opts: { replyTo?: { root: string; parent?: string; parentAuthor?: string }; previous?: string[] } = {}): EventTemplate {
  const tags: string[][] = [['h', groupId]];
  if (opts.replyTo) {
    const parent = opts.replyTo.parent ?? opts.replyTo.root;
    tags.push(['e', opts.replyTo.root, '', 'root'], ['e', parent, '', 'reply'], opts.replyTo.parentAuthor ? ['q', parent, '', opts.replyTo.parentAuthor] : ['q', parent]);
  }
  if (opts.previous?.length) tags.push(['previous', ...opts.previous.map((id) => id.slice(0, 8))]);
  return { kind: NIP29.ChatMessage, content, tags };
}

/** FR015-04: a reply to `parent`, in the parent's own thread (Buzz rejects a reply whose root is not the parent's). */
export function replyMessage(groupId: string, content: string, parent: NostrEvent): EventTemplate {
  return chatMessage(groupId, content, { replyTo: { root: threadOf(parent)?.root ?? parent.id, parent: parent.id, parentAuthor: parent.pubkey } });
}

/** NIP-25 reaction (kind 7): `e` names the target (the last `e`, as NIP-25 and Buzz read it), `p` its author, `k` its kind. */
export function reaction(groupId: string, target: NostrEvent, content = '+'): EventTemplate {
  return { kind: NIP29.Reaction, content, tags: [['h', groupId], ['e', target.id], ['p', target.pubkey], ['k', String(target.kind)]] };
}

/**
 * NIP-09 deletion (kind 5) of one of the persona's own events, such as its reaction: what Buzz clients remove a
 * reaction with. One target (Buzz refuses more) and the `h` tag, so that `#h` subscriptions receive it.
 */
export function deletion(groupId: string, target: Pick<NostrEvent, 'id' | 'kind'>, reason = ''): EventTemplate {
  return { kind: NIP29.Deletion, content: reason, tags: [['h', groupId], ['e', target.id], ['k', String(target.kind)]] };
}

/** FR015-04: NIP-29 delete-event (kind 9005): the author of a channel message, or a channel admin, removes it. */
export function deleteEvent(groupId: string, eventId: string): EventTemplate {
  return { kind: NIP29.DeleteEvent, content: '', tags: [['h', groupId], ['e', eventId]] };
}

export function createGroup(name: string, visibility: 'open' | 'private' = 'private'): EventTemplate {
  return { kind: NIP29.CreateGroup, content: '', tags: [['name', name], ['visibility', visibility]] };
}

export function joinRequest(groupId: string): EventTemplate {
  return { kind: NIP29.JoinRequest, content: '', tags: [['h', groupId]] };
}

/** Every kind a channel view reads: messages, reactions and both kinds of deletion. */
export function channelFilter(groupId: string, since?: number) {
  return { kinds: [NIP29.ChatMessage, NIP29.Reaction, NIP29.Deletion, NIP29.DeleteEvent], '#h': [groupId], ...(since !== undefined ? { since } : {}) };
}

/**
 * The subscription of an open channel: its newest messages and, with their own limit (NIP-01 limits each filter), the
 * reactions and deletions around them, so that a busy channel does not show fewer messages.
 */
export function channelFilters(groupId: string, limits: { messages: number; activity: number } = { messages: 100, activity: 500 }) {
  return [
    { kinds: [NIP29.ChatMessage], '#h': [groupId], limit: limits.messages },
    { kinds: [NIP29.Reaction, NIP29.Deletion, NIP29.DeleteEvent], '#h': [groupId], limit: limits.activity },
  ];
}

export interface GroupMetadata {
  id: string;
  name?: string;
  about?: string;
  private: boolean;
  closed: boolean;
  hidden: boolean;
  /** Who signed it: the relay key that signs the group's state. */
  pubkey: string;
}

export function parseGroupMetadata(evt: NostrEvent): GroupMetadata | undefined {
  if (evt.kind !== NIP29.GroupMetadata) return undefined;
  const id = getTagValue(evt, 'd');
  if (!id) return undefined;
  const has = (n: string) => evt.tags.some((t) => t[0] === n);
  return { id, name: getTagValue(evt, 'name'), about: getTagValue(evt, 'about'), private: has('private'), closed: has('closed'), hidden: has('hidden'), pubkey: evt.pubkey };
}

export function parseGroupMembers(evt: NostrEvent): string[] {
  return evt.kind === NIP29.GroupMembers ? getTagValues(evt, 'p') : [];
}

const newest = (events: NostrEvent[]) => events.reduce<NostrEvent | undefined>((a, e) => (!a || e.created_at > a.created_at ? e : a), undefined);

/**
 * FR015-04: the channel's admins: its newest kind 39001 signed by the key that signs its metadata (39000), the relay's.
 * A list signed by anyone else names nobody.
 */
export function groupAdmins(events: NostrEvent[], groupId: string): Set<string> {
  const ofGroup = (kind: number) => events.filter((e) => e.kind === kind && getTagValue(e, 'd') === groupId);
  const meta = newest(ofGroup(NIP29.GroupMetadata));
  const list = meta && newest(ofGroup(NIP29.GroupAdmins).filter((e) => e.pubkey === meta.pubkey));
  return new Set(list ? getTagValues(list, 'p') : []);
}

export interface ReactionSummary {
  content: string;
  /** Authors who reacted with this content (each counted once). */
  count: number;
  /** The persona's own reactions with this content: what removing it deletes. */
  mine: NostrEvent[];
}

export interface ChannelEntry {
  event: NostrEvent;
  thread?: ThreadRef;
  reactions: ReactionSummary[];
}

export interface ChannelView {
  /** The messages shown, oldest first. */
  messages: ChannelEntry[];
  /** Messages and reactions hidden by a deletion the view accepts. */
  deleted: Set<string>;
  /** Every event seen, deleted ones included (to quote the parent of a reply). */
  byId: Map<string, NostrEvent>;
}

/**
 * FR015-04: what an open channel shows, from its subscription's events in any order. Its messages (kind 9), minus the
 * ones deleted by their author (kind 5 or 9005) or by a channel admin (9005 in the same channel), as Buzz and the
 * mirror apply them; and on each message, the reactions (kind 7) whose last `e` names it, counted once per author and
 * content, minus the ones their author deleted (kind 5).
 */
export function channelView(events: Iterable<NostrEvent>, opts: { groupId: string; me: string; admins?: ReadonlySet<string> }): ChannelView {
  const byId = new Map<string, NostrEvent>();
  for (const e of events) byId.set(e.id, e);
  const all = [...byId.values()];
  const admins = opts.admins ?? new Set<string>();
  const deleted = new Set<string>();
  for (const d of all) {
    if (d.kind !== NIP29.Deletion && d.kind !== NIP29.DeleteEvent) continue;
    for (const id of getTagValues(d, 'e')) {
      const target = byId.get(id);
      if (!target) continue;
      const byAuthor = target.pubkey === d.pubkey;
      if (d.kind === NIP29.Deletion ? byAuthor : getTagValue(d, 'h') === opts.groupId && getTagValue(target, 'h') === opts.groupId && (byAuthor || admins.has(d.pubkey))) deleted.add(id);
    }
  }
  const messages = all.filter((e) => e.kind === NIP29.ChatMessage && getTagValue(e, 'h') === opts.groupId && !deleted.has(e.id)).sort((a, b) => a.created_at - b.created_at || (a.id < b.id ? -1 : 1));
  const reactions = new Map(messages.map((m) => [m.id, new Map<string, { authors: Set<string>; mine: NostrEvent[] }>()]));
  for (const r of all) {
    if (r.kind !== NIP29.Reaction || deleted.has(r.id)) continue;
    const onMessage = reactions.get(getTagValues(r, 'e').at(-1) ?? '');
    if (!onMessage) continue;
    const content = r.content || '+';
    const summary = onMessage.get(content) ?? { authors: new Set<string>(), mine: [] };
    summary.authors.add(r.pubkey);
    if (r.pubkey === opts.me) summary.mine.push(r);
    onMessage.set(content, summary);
  }
  return {
    messages: messages.map((event) => {
      const thread = threadOf(event);
      const summaries = [...reactions.get(event.id)!].map(([content, s]) => ({ content, count: s.authors.size, mine: s.mine })).sort((a, b) => b.count - a.count || a.content.localeCompare(b.content));
      return { event, ...(thread ? { thread } : {}), reactions: summaries };
    }),
    deleted,
    byId,
  };
}
