import type { SovereigntyConfig } from './types';
import { PRESETS, type PresetName } from './presets';

/**
 * FR014-04: whether a client asks the operator's mirror (services/indexer) for derived channel views: unread counts
 * and search. Every query is signed with the persona key (NIP-98), so the operator learns which channels the persona
 * follows, when, from which address and what it searches for. Only personas whose identity the operator already knows
 * (linked or verified) do it: a pseudonymous persona would hand it that record. Tor-only never does, as the web opens
 * no clearnet connection for it. Part of the reviewed copy (disclosureCatalog, docs/disclosures.md).
 */
export const CHANNEL_MIRROR_TEXTS = {
  uses: 'Los contadores de no leídos y la búsqueda de canales los calcula el mirror del operador. Cada consulta va firmada con tu npub (NIP-98): el operador ve qué canales consultas, cuándo, desde qué dirección IP y el texto que buscas.',
  readState: 'Hasta dónde leíste cada canal se guarda cifrado en este navegador, aparte para cada persona, y no se envía al mirror: el mirror devuelve la hora de los mensajes recientes y los no leídos se cuentan aquí. En otro navegador, cada canal empieza como leído.',
  scope: 'El mirror solo responde por los canales en los que el relay te lista como miembro y, en una organización, por los que su política te deja leer. La búsqueda cubre sus mensajes en claro, nunca los mensajes directos ni los grupos seguros, y puede no llegar a todo el historial.',
  pseudonymous: 'Esta persona es pseudónima: la web no consulta el mirror del operador, así que no hay contadores de no leídos ni búsqueda de canales. Cada consulta iría firmada con tu npub y le diría al operador qué canales lees y qué buscas.',
  torOnly: 'En Tor-only la web no conecta con el mirror del operador, igual que con los relays: no hay contadores de no leídos ni búsqueda de canales.',
} as const;

export type MirrorPolicy = { use: true; statement: string } | { use: false; reason: 'pseudonymous' | 'tor-only'; statement: string };

/** FR014-04: the mirror policy of a configuration (derived from its controls, like the notification policy). */
export function mirrorPolicy(c: Pick<SovereigntyConfig, 'network' | 'identity'>): MirrorPolicy {
  if (c.network === 'tor-only') return { use: false, reason: 'tor-only', statement: CHANNEL_MIRROR_TEXTS.torOnly };
  if (c.identity === 'pseudonymous') return { use: false, reason: 'pseudonymous', statement: CHANNEL_MIRROR_TEXTS.pseudonymous };
  return { use: true, statement: CHANNEL_MIRROR_TEXTS.uses };
}

/** The profile × mirror matrix (derived from the presets, so it cannot drift). */
export function mirrorMatrix(): Array<{ profile: PresetName; policy: MirrorPolicy }> {
  return (Object.keys(PRESETS) as PresetName[]).map((profile) => ({ profile, policy: mirrorPolicy(PRESETS[profile]) }));
}
