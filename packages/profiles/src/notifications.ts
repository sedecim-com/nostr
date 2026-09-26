import type { NotificationsOption, SovereigntyConfig } from './types';
import { PRESETS, type PresetName } from './presets';

/**
 * Mobile/web notification model per profile (ADR 0010, DEC-08). Every push is opaque: it never carries
 * content, sender or a message count. The modes only differ in how much timing they reveal.
 */

/** Transports behind the same interface. Only Web Push exists today; the others are planned. */
export type PushTransport = 'web-push' | 'apns' | 'fcm' | 'unifiedpush';

/** Who can observe what about a push (one list per party). */
export interface NotificationExposure {
  /** Browser/OS push service (Mozilla autopush, Google FCM for Chrome, Apple for Safari). */
  pushProvider: string[];
  /** Operator of services/notification-gateway. */
  gatewayOperator: string[];
  /** Relays the gateway watches for the user's gift wraps. */
  relay: string[];
}

export interface NotificationPolicy {
  mode: NotificationsOption;
  /** Push body: a constant opaque payload, an empty push (wake signal only) or nothing is sent. */
  payload: 'fixed-opaque' | 'empty' | 'none';
  /** Random delay before a push, uniform in [minDelayMs, maxDelayMs] after the first pending activity. */
  minDelayMs: number;
  maxDelayMs: number;
  /** Minimum time between two pushes to the same device: activity in between is coalesced into one push. */
  minIntervalMs: number;
  /** Sends are aligned to this tick so pushes to many devices leave together (harder timing correlation). */
  batchTickMs: number;
  /** Web Push TTL (seconds the push service keeps an undelivered push) and Urgency header. */
  ttlSeconds: number;
  urgency: 'normal' | 'low';
  /** What the client does instead of (or in addition to) push. */
  fallback: string;
  exposes: NotificationExposure;
}

/** The constant plaintext of a 'fixed-opaque' push: identical for every user and every event. */
export const OPAQUE_PUSH_PAYLOAD = '{"v":1}';
/** Web Push `Topic` header: a pending push replaces the previous one at the push service (coalescing). */
export const OPAQUE_PUSH_TOPIC = 'activity';
/** The only text a client may show for a push. */
export const OPAQUE_NOTIFICATION_TEXT = 'Tienes actividad nueva';

const SECOND = 1000;
const MINUTE = 60 * SECOND;

const PROVIDER_COMMON = [
  'Que el dispositivo tiene una suscripción push y la IP del gateway que envía los avisos.',
  'Cuándo se entrega cada aviso (hora ya desplazada por el retardo aleatorio y agrupada).',
  'Tamaño del aviso cifrado (constante) y los headers TTL/Urgency/Topic.',
];
const GATEWAY_COMMON = [
  'Relación npub ↔ endpoint push del dispositivo y el perfil declarado (se guarda solo en memoria).',
  'La IP del cliente al registrarse y los relays que el usuario le pidió vigilar.',
  'Cuándo llega un gift wrap (kind 1059) dirigido a ese npub; nunca el contenido ni el remitente real (van cifrados).',
];
const RELAY_COMMON = [
  'Que el gateway (su IP y, con NIP-42, su identidad de servicio) consulta gift wraps de ese npub.',
  'Lo mismo que ya veía sin push: la llegada de gift wraps para ese npub.',
];

export const NOTIFICATION_MODES: Record<NotificationsOption, NotificationPolicy> = {
  push: {
    mode: 'push',
    payload: 'fixed-opaque',
    minDelayMs: 10 * SECOND,
    maxDelayMs: 60 * SECOND,
    minIntervalMs: 2 * MINUTE,
    batchTickMs: 15 * SECOND,
    ttlSeconds: 3600,
    urgency: 'normal',
    fallback: 'La app consulta los relays mientras está abierta.',
    exposes: { pushProvider: PROVIDER_COMMON, gatewayOperator: GATEWAY_COMMON, relay: RELAY_COMMON },
  },
  'privacy-push': {
    mode: 'privacy-push',
    payload: 'empty',
    minDelayMs: 2 * MINUTE,
    maxDelayMs: 10 * MINUTE,
    minIntervalMs: 15 * MINUTE,
    batchTickMs: MINUTE,
    ttlSeconds: 4 * 3600,
    urgency: 'low',
    fallback: 'La app consulta los relays mientras está abierta.',
    exposes: {
      pushProvider: [...PROVIDER_COMMON.slice(0, 2), 'Un aviso vacío (sin cuerpo cifrado) y los headers TTL/Urgency/Topic.'],
      gatewayOperator: GATEWAY_COMMON,
      relay: RELAY_COMMON,
    },
  },
  none: {
    mode: 'none',
    payload: 'none',
    minDelayMs: 0,
    maxDelayMs: 0,
    minIntervalMs: 0,
    batchTickMs: 0,
    ttlSeconds: 0,
    urgency: 'low',
    fallback: 'Sin push: la app consulta los relays solo mientras está abierta (polling local).',
    exposes: { pushProvider: [], gatewayOperator: [], relay: [] },
  },
};

/** Effective notification policy of a configuration. Tor-only never pushes, whatever the control says. */
export function notificationPolicy(c: SovereigntyConfig): NotificationPolicy {
  return NOTIFICATION_MODES[c.network === 'tor-only' ? 'none' : c.notifications];
}

/** The profile × mode matrix of ADR 0010 (derived from the presets, so it cannot drift). */
export function notificationMatrix(): Array<{ profile: PresetName; policy: NotificationPolicy }> {
  return (Object.keys(PRESETS) as PresetName[]).map((profile) => ({ profile, policy: notificationPolicy({ ...PRESETS[profile] }) }));
}

/**
 * Delay until the next push of a device: a uniform random delay, never sooner than `minIntervalMs` after
 * the previous push, rounded up to the next batch tick (absolute clock) so devices share send instants.
 */
export function nextPushDelayMs(policy: NotificationPolicy, now: number, lastSentAt: number | undefined, random: () => number = Math.random): number {
  const jitter = policy.minDelayMs + Math.floor(random() * (policy.maxDelayMs - policy.minDelayMs + 1));
  const earliest = lastSentAt === undefined ? now : lastSentAt + policy.minIntervalMs;
  let at = Math.max(now + jitter, earliest);
  if (policy.batchTickMs > 0) at = Math.ceil(at / policy.batchTickMs) * policy.batchTickMs;
  return at - now;
}
