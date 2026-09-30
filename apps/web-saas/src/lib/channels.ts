import type { EventTemplate, NostrEvent } from '@sedecim/nostr-core';
import { deletion, reaction, type ChannelEntry } from '@sedecim/messaging';
import type { PersonaSession } from './session';

/**
 * FR015-04: reactions, replies and deletions in the web's NIP-29 channels. A message is deleted with NIP-29's
 * delete-event (kind 9005), which Buzz accepts from its author and from the channel's owners and admins; the persona's
 * own reaction with NIP-09 (kind 5), as Buzz clients remove one. Everything goes through the outbox like any send.
 */

/** Reactions offered on each message; any other content another client sent is shown as it came. */
export const REACTIONS = ['👍', '❤️', '😂', '🎉'] as const;

/** Whether the persona may delete `message`: its own, or anyone's as an admin of the channel (its relay-signed 39001). */
export function canDelete(message: NostrEvent, me: string, admins: ReadonlySet<string>): boolean {
  return message.pubkey === me || admins.has(me);
}

/**
 * What toggling `content` on a message publishes: a deletion (kind 5) of each of the persona's reactions with that
 * content when there is one (Buzz takes one target per deletion), else one reaction.
 */
export function reactionToggle(groupId: string, entry: ChannelEntry, content: string): EventTemplate[] {
  const mine = entry.reactions.find((r) => r.content === content)?.mine ?? [];
  return mine.length ? mine.map((r) => deletion(groupId, r)) : [reaction(groupId, entry.event, content)];
}

/**
 * Publishes channel events through the persona's outbox (one relay acceptance is enough) and returns them signed, so
 * the view shows them before the relay echoes them. Throws with the relays' reasons when they all refused one.
 */
export async function publishToChannel(s: Pick<PersonaSession, 'engine' | 'persona'>, templates: EventTemplate[]): Promise<NostrEvent[]> {
  const out: NostrEvent[] = [];
  for (const template of templates) {
    const rec = await s.engine.submit({ template }, { relays: s.persona.relays, quorum: 1, wait: true });
    if (rec.state === 'FAILED') throw new Error(`El relay no lo aceptó (${rec.failureReason ?? 'sin motivo'})`);
    if (rec.event) out.push(rec.event);
  }
  return out;
}
