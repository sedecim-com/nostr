import type { PresenceOption, SovereigntyConfig } from './types';
import { PRESETS, type PresetName } from './presets';

/**
 * FR015-05: the NIP-38 status (kind 30315) of a persona. A status is a public event signed with the persona's npub: the
 * relays it goes to, and whoever can read them, see what it says and when it was published, that is, when the persona
 * was active. So it is off in every preset and the user turns it on in the panel, where the profile allows it: never in
 * Tor-only (Tor hides where an event comes from, not when or what), never with an identity verified by an organization
 * (its policy cannot govern presence, and the institutional model denies what the policy does not govern), and with a
 * warning for a pseudonymous persona. Part of the reviewed copy (disclosureCatalog, docs/disclosures.md); the design is
 * in docs/presence.md.
 */
export const PRESENCE_TEXTS = {
  what: 'Tu estado es un texto corto que escribes tú (NIP-38, kind 30315): se publica firmado con tu npub en los relays de esta persona, y quien pueda leerlos ve lo que dice y cuándo lo publicaste. La web nunca publica un estado por su cuenta: ni «en línea», ni «escribiendo», ni la última vez que te conectaste.',
  limits: 'Cada estado admite hasta 100 caracteres, sin enlaces ni menciones, y caduca (NIP-40) como mucho a las 24 horas: entonces la web deja de mostrarlo y los relays que respetan la expiración dejan de servirlo; los que la ignoran pueden conservarlo.',
  clear: 'Borrar publica en lugar del anterior un estado vacío que caduca en una hora: los relays que respetan los eventos reemplazables dejan de servir el anterior, pero las copias que otros ya guardaron no desaparecen.',
  others: 'Los estados de otras personas solo se piden en la misma consulta que sus perfiles públicos (los autores de tus canales, tus contactos de mensajes directos y los miembros de un grupo cuando pides sus nombres): ninguna consulta aparte pide el estado de otra persona ni queda abierta una suscripción con tu lista de contactos. Se muestran como texto, sin enlaces, hasta que caducan y nunca más de 24 horas.',
  pseudonymous: 'Esta persona es pseudónima: lo que escribas en tu estado y las horas a las que lo cambias pueden relacionarla con otras identidades tuyas o con tu identidad real.',
  torOnly: 'En Tor-only no hay estado de presencia: un estado es un evento público firmado con tu npub que dice cuándo estabas activo, y Tor oculta desde dónde publicas, no cuándo ni qué.',
  organization: 'Con una identidad verificada por una organización no hay estado de presencia: lo verían el operador y los miembros de su relay junto a tu cargo, y la política de la organización todavía no puede decidir sobre él. Lo que la política no gobierna queda denegado.',
  off: 'La presencia está apagada para esta persona: no publica ni pide estados (kind 30315). Se activa en Soberanía y privacidad, si su perfil lo permite.',
} as const;

export type PresencePolicy = { use: true; statement: string } | { use: false; reason: 'off' | 'tor-only' | 'organization'; statement: string };

/** FR015-05: the presence option of a configuration; one stored before FR015-05 has none, which is `off`. */
export function presenceOption(c: Partial<SovereigntyConfig>): PresenceOption {
  return c.presence ?? 'off';
}

/**
 * FR015-05: whether a persona publishes and reads statuses: only when its user turned presence on and its profile
 * allows it. Derived from its controls, like the mirror and notification policies, so a customized persona gets what
 * its controls say; validateConfig refuses the combinations this answers `tor-only` or `organization` to.
 */
export function presencePolicy(c: Pick<SovereigntyConfig, 'network' | 'identity'> & Partial<Pick<SovereigntyConfig, 'presence'>>): PresencePolicy {
  if (c.network === 'tor-only') return { use: false, reason: 'tor-only', statement: PRESENCE_TEXTS.torOnly };
  if (c.identity === 'verified') return { use: false, reason: 'organization', statement: PRESENCE_TEXTS.organization };
  if (presenceOption(c) === 'off') return { use: false, reason: 'off', statement: PRESENCE_TEXTS.off };
  return { use: true, statement: PRESENCE_TEXTS.what };
}

/** The profile × presence matrix once the user turns it on (derived from the presets, so it cannot drift). */
export function presenceMatrix(): Array<{ profile: PresetName; policy: PresencePolicy }> {
  return (Object.keys(PRESETS) as PresetName[]).map((profile) => ({ profile, policy: presencePolicy({ ...PRESETS[profile], presence: 'status' }) }));
}
