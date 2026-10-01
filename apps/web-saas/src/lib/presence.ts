import type { OutboxRecord } from '@sedecim/delivery-engine';
import { buildStatus, buildStatusClear, statusFilter, statusTemplateProblem, STATUS_MAX_CHARS, type StatusTextProblem, type UserStatus } from '@sedecim/messaging';
import { nowSeconds, type EventTemplate } from '@sedecim/nostr-core';
import { presencePolicy, type SovereigntyConfig } from '@sedecim/profiles';
import type { PersonaSession } from './session';
import { sendBlockedReason } from './workspace';

/*
 * FR015-05: the persona's NIP-38 status in the web. It is published and cleared only when the persona's profile allows
 * presence and its user turned it on (presencePolicy), only from the status card, signed by the persona's own signer
 * through its outbox, on its own relays and over its own pool (never another persona's). The statuses of others come
 * with their profiles (ProfileCache), never in a request of their own. With presence off nothing here sends anything.
 */

/** Presence is off for this persona, or its profile does not allow it: nothing was sent. */
export class PresenceDisabledError extends Error {}

/** What the status card says about a text it cannot publish (StatusTextError). */
export const STATUS_PROBLEM_TEXT: Record<StatusTextProblem, string> = {
  empty: 'Escribe tu estado.',
  'too-long': `El estado admite hasta ${STATUS_MAX_CHARS} caracteres.`,
  link: 'El estado no admite enlaces ni menciones (direcciones web, nostr:, npub…).',
};

/** How long a status lasts, as the card offers it (never more than a day: STATUS_MAX_TTL_SECONDS). */
export const STATUS_DURATIONS: ReadonlyArray<{ seconds: number; label: string }> = [
  { seconds: 1800, label: '30 minutos' },
  { seconds: 3600, label: '1 hora' },
  { seconds: 4 * 3600, label: '4 horas' },
  { seconds: 8 * 3600, label: '8 horas' },
  { seconds: 24 * 3600, label: '24 horas' },
];

function allowed(config: SovereigntyConfig): void {
  const policy = presencePolicy(config);
  if (!policy.use) throw new PresenceDisabledError(policy.statement);
  const blocked = sendBlockedReason(config);
  if (blocked) throw new Error(blocked);
}

/**
 * The persona's own status, from its own relays: asking for its own npub tells them nothing about anyone else. Nothing
 * is asked while presence is not allowed.
 */
export async function loadOwnStatus(s: PersonaSession, config: SovereigntyConfig): Promise<UserStatus | undefined> {
  if (!presencePolicy(config).use || sendBlockedReason(config)) return undefined;
  const events = await s.pool.query(s.persona.relays, [statusFilter([s.pubkey])], 5000);
  s.statuses.receive(events, [s.pubkey]);
  return s.statuses.get(s.pubkey);
}

// NIP-01: of two versions with the same created_at the lowest id wins, so a change made in the same second as the
// previous one (clearing right after publishing) could be dropped by the relays: it is dated one second later.
const nextCreatedAt = (s: PersonaSession) => Math.max(nowSeconds(), (s.statuses.latest(s.pubkey)?.createdAt ?? 0) + 1);

async function submit(s: PersonaSession, template: EventTemplate): Promise<OutboxRecord> {
  const problem = statusTemplateProblem(template);
  if (problem) throw new Error(`estado no válido: ${problem}`);
  const rec = await s.engine.submit({ template }, { relays: s.persona.relays, quorum: 1, wait: true });
  if (rec.state === 'FAILED' || !rec.event) throw new Error(`Los relays rechazaron el estado${rec.failureReason ? `: ${rec.failureReason}` : ''}.`);
  s.statuses.put(rec.event);
  return rec;
}

/**
 * FR015-05: publishes the status the user wrote and confirmed, expiring `ttlSeconds` later (kind 30315 with the
 * `general` slot and a NIP-40 expiration, nothing else). Throws before sending anything when presence is not allowed.
 */
export async function publishStatus(s: PersonaSession, config: SovereigntyConfig, text: string, ttlSeconds: number): Promise<OutboxRecord> {
  allowed(config);
  return submit(s, buildStatus(text, ttlSeconds, nextCreatedAt(s)));
}

/** FR015-05: clears the persona's status: an empty one replaces it and expires an hour later (STATUS_CLEAR_TTL_SECONDS). */
export async function clearStatus(s: PersonaSession, config: SovereigntyConfig): Promise<OutboxRecord> {
  allowed(config);
  return submit(s, buildStatusClear(nextCreatedAt(s)));
}
