import { nip98, type Signer } from '@sedecim/nostr-core';
import { notificationPolicy, type NotificationPolicy, type PresetName, type SovereigntyConfig } from '@sedecim/profiles';
import { normalizeRelayUrl } from '@sedecim/relay-pool';

/**
 * Opt-in opaque push (ADR 0010). The browser subscribes through its push service with the gateway's VAPID
 * key and the gateway is told, with a NIP-98 request signed by the persona, which relays to watch. Each
 * persona uses its own service-worker scope, so two personas of one browser never share a push endpoint.
 */

export type PushAvailability =
  | { state: 'hidden' }
  | { state: 'disabled'; reason: string }
  | { state: 'unsupported'; reason: string }
  | { state: 'available'; policy: NotificationPolicy };

export interface PushEnv {
  serviceWorker?: Pick<ServiceWorkerContainer, 'register' | 'getRegistration'>;
  hasPushManager: boolean;
  hasNotification: boolean;
}

export function browserPushEnv(): PushEnv {
  const nav = typeof navigator === 'undefined' ? undefined : navigator;
  return {
    ...(nav && 'serviceWorker' in nav ? { serviceWorker: nav.serviceWorker } : {}),
    hasPushManager: typeof window !== 'undefined' && 'PushManager' in window,
    hasNotification: typeof window !== 'undefined' && 'Notification' in window,
  };
}

/** Whether the control is shown, and why it cannot be used when it is not. */
export function pushAvailability(gateway: string | undefined, config: SovereigntyConfig | undefined, env: PushEnv): PushAvailability {
  if (!gateway || !config) return { state: 'hidden' };
  const policy = notificationPolicy(config);
  if (policy.mode === 'none') {
    return {
      state: 'disabled',
      reason:
        config.network === 'tor-only'
          ? 'En perfiles Tor no hay notificaciones push: registrar el dispositivo en un servicio push revelaría cuándo tienes actividad. La app consulta los relays solo mientras está abierta.'
          : 'Este perfil no usa notificaciones push: nada se registra en servicios push ni en el gateway. La app consulta los relays solo mientras está abierta.',
    };
  }
  if (!env.serviceWorker || !env.hasPushManager || !env.hasNotification) return { state: 'unsupported', reason: 'Este navegador no admite notificaciones push web.' };
  return { state: 'available', policy };
}

/** OPS-06: which of a persona's relays the gateway can watch, from its `GET /v1/relays`. */
export interface RelayWatch {
  /** The gateway saw, with a canary, a gift wrap for someone else arrive there: it can tell when there is activity. */
  watchable: string[];
  /** The gateway has not checked them yet (it refuses registrations for them until it does). */
  pending: string[];
  /** They deliver gift wraps only to their recipient: the gateway cannot see activity there without reading DMs. */
  unobservable: string[];
  /** This deployment's gateway does not serve them. */
  unserved: string[];
}

/**
 * OPS-06: the gateway only watches relays where it can see activity without reading access to anyone's DMs. The
 * browser asks which before offering push, so a persona whose relays deliver gift wraps only to their recipient
 * (Buzz, the secure relay) is told why there is no push instead of being offered a switch that cannot work.
 */
export async function watchableRelays(gateway: string, relays: string[], doFetch: typeof fetch = fetch): Promise<RelayWatch> {
  const res = await doFetch(`${gateway}/v1/relays`);
  if (!res.ok) throw new Error(`El gateway de notificaciones no respondió (${res.status})`);
  const listed = ((await res.json()) as { relays?: Array<{ relay: string; observable: boolean; checkedAt: number }> }).relays ?? [];
  const known = new Map(listed.map((r) => [r.relay, r]));
  const out: RelayWatch = { watchable: [], pending: [], unobservable: [], unserved: [] };
  for (const url of relays) {
    let r: (typeof listed)[number] | undefined;
    try {
      r = known.get(normalizeRelayUrl(url));
    } catch {
      r = undefined;
    }
    (!r ? out.unserved : r.observable ? out.watchable : r.checkedAt ? out.unobservable : out.pending).push(url);
  }
  return out;
}

export const pushScope = (personaId: string) => `./push/${encodeURIComponent(personaId)}/`;

const prefKey = (personaId: string) => `acceso-nostr:push:${personaId}`;
export function pushPreference(personaId: string): boolean {
  try {
    return localStorage.getItem(prefKey(personaId)) === '1';
  } catch {
    return false;
  }
}
function setPushPreference(personaId: string, on: boolean) {
  try {
    if (on) localStorage.setItem(prefKey(personaId), '1');
    else localStorage.removeItem(prefKey(personaId));
  } catch {
    /* per-browser convenience only */
  }
}

export interface PushPersona {
  id: string;
  preset: PresetName | 'custom';
  relays: string[];
  config: SovereigntyConfig;
}

export interface PushDeps {
  env: PushEnv;
  signer: Signer;
  fetch?: typeof fetch;
}

function base64UrlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

async function signed(deps: PushDeps, url: string, method: string, body: unknown): Promise<Response> {
  const raw = JSON.stringify(body);
  const evt = await deps.signer.signEvent(nip98.buildHttpAuthTemplate(url, method, raw));
  return (deps.fetch ?? fetch)(url, { method, headers: { authorization: nip98.encodeAuthHeader(evt), 'content-type': 'application/json' }, body: raw });
}

/** Subscribes this browser for `persona` and registers it with the gateway. Throws with a user-facing message. */
export async function enablePush(gateway: string, persona: PushPersona, deps: PushDeps): Promise<{ mode: string }> {
  const availability = pushAvailability(gateway, persona.config, deps.env);
  if (availability.state !== 'available') throw new Error(availability.state === 'hidden' ? 'Notificaciones no configuradas' : availability.reason);
  const doFetch = deps.fetch ?? fetch;
  if (typeof Notification !== 'undefined' && Notification.permission !== 'granted' && (await Notification.requestPermission()) !== 'granted') {
    throw new Error('El navegador no concedió permiso para mostrar notificaciones.');
  }
  const vapid = (await (await doFetch(`${gateway}/v1/vapid`)).json()) as { publicKey: string };
  const reg = await deps.env.serviceWorker!.register('./sw.js', { scope: pushScope(persona.id) });
  const sub = (await reg.pushManager.getSubscription()) ?? (await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: base64UrlToBytes(vapid.publicKey) }));
  const res = await signed(deps, `${gateway}/v1/subscriptions`, 'POST', {
    subscription: sub.toJSON(),
    profile: persona.preset,
    mode: availability.policy.mode,
    network: persona.config.network,
    relays: persona.relays,
  });
  if (res.status !== 201) {
    await sub.unsubscribe().catch(() => false);
    const err = ((await res.json().catch(() => ({}))) as { error?: string }).error;
    throw new Error(`El gateway rechazó el registro (${res.status}${err ? `: ${err}` : ''})`);
  }
  setPushPreference(persona.id, true);
  return (await res.json()) as { mode: string };
}

/** Removes the gateway registration and the browser subscription for `persona`. */
export async function disablePush(gateway: string, persona: Pick<PushPersona, 'id'>, deps: PushDeps): Promise<void> {
  setPushPreference(persona.id, false);
  const reg = await deps.env.serviceWorker?.getRegistration(pushScope(persona.id));
  const sub = await reg?.pushManager.getSubscription();
  await signed(deps, `${gateway}/v1/subscriptions`, 'DELETE', sub ? { endpoint: sub.endpoint } : {}).catch(() => undefined);
  await sub?.unsubscribe().catch(() => false);
  await reg?.unregister().catch(() => false);
}
