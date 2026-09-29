import type { PresetName } from './presets';
import type { SovereigntyConfig } from './types';

/**
 * PANEL-07: how mature each profile and function is, in the one place the web, the CLI, the README and the
 * release notes take it from. Before v1.0 nothing is GA: the external review and pentest (SEC-01, SEC-02) have
 * not happened. `atV1` is what the PRD lets each one declare at v1.0 (docs/backlog/replanteo-2026-09-27.md,
 * «Madurez que declarará v1.0»). deploy/production-gates.json (OPS-20) keeps the same label for the features
 * it gates, checked by the tests.
 */
export type MaturityLevel = 'early-release' | 'beta' | 'preview' | 'experimental';

export const MATURITY_LABELS: Record<MaturityLevel, string> = {
  'early-release': 'Early release',
  beta: 'Beta',
  preview: 'Preview',
  experimental: 'Experimental',
};

/** Lower is less mature: a configuration is as mature as its least mature part. */
const RANK: Record<MaturityLevel, number> = { experimental: 0, preview: 1, beta: 2, 'early-release': 3 };

export type MaturityId = PresetName | 'nip17-dms' | 'marmot-groups' | 'continuity-vault' | 'managed-custody' | 'enclave-custody' | 'push';

export interface MaturityEntry {
  id: MaturityId;
  kind: 'profile' | 'function';
  name: string;
  level: MaturityLevel;
  /** Why it is not further along today. */
  why: string;
  /** What it may declare at v1.0, and on what condition. */
  atV1: string;
}

export const MATURITY: readonly MaturityEntry[] = [
  { id: 'convenience', kind: 'profile', name: 'convenience (SaaS)', level: 'early-release', why: 'Sin revisión externa ni stage en AWS todavía.', atV1: 'GA controlado, con SEC-01, SEC-02, el stage y la release firmada.' },
  {
    id: 'private-resilient',
    kind: 'profile',
    name: 'private-resilient',
    level: 'early-release',
    why: 'Sin revisión externa. Sin Continuity Vault en el despliegue, el historial depende de los relays y el perfil queda en Beta.',
    atV1: 'GA controlado, solo con el Continuity Vault.',
  },
  { id: 'institutional', kind: 'profile', name: 'institutional', level: 'early-release', why: 'Sin pentest sobre stage todavía.', atV1: 'GA controlado, con el pentest sobre stage y la auditoría.' },
  { id: 'sovereign', kind: 'profile', name: 'sovereign (self-hosted)', level: 'early-release', why: 'Todavía no hay una release firmada.', atV1: 'GA técnico, con la release firmada, la instalación reproducible y el restore drill.' },
  {
    id: 'sovereign-tor',
    kind: 'profile',
    name: 'sovereign-tor',
    level: 'experimental',
    why: 'Falla cerrado y tiene pruebas de fugas propias, pero ni el cliente ni sus dependencias tienen revisión independiente.',
    atV1: 'Experimental: nada lo declara apto para alto riesgo sin una auditoría específica y un cliente dedicado.',
  },
  {
    id: 'nip17-dms',
    kind: 'function',
    name: 'DMs NIP-17',
    level: 'early-release',
    why: 'Solo se habilitan con el gate de interoperabilidad contra el Buzz fijado en verde. No ofrecen forward secrecy.',
    atV1: 'Con el perfil que los usa, y siempre detrás del gate de interoperabilidad.',
  },
  { id: 'marmot-groups', kind: 'function', name: 'Grupos Marmot/MLS', level: 'beta', why: 'marmot-ts es alpha y ts-mls está en release candidate.', atV1: 'Beta mientras marmot-ts o ts-mls sean alpha o release candidate.' },
  { id: 'continuity-vault', kind: 'function', name: 'Continuity Vault', level: 'early-release', why: 'Falta aprobar su threat model (VAULT-07) y la revisión externa.', atV1: 'Con private-resilient.' },
  {
    id: 'managed-custody',
    kind: 'function',
    name: 'Custodia gestionada básica',
    level: 'early-release',
    why: 'Espera la aprobación legal (DEC-12) y la validación en AWS; el gate de release no la deja en producción.',
    atV1: 'GA opcional, con la aprobación legal y KMS y Secrets Manager reales.',
  },
  { id: 'enclave-custody', kind: 'function', name: 'Custodia en Nitro Enclave', level: 'preview', why: 'Prototipo: la attestation solo se verificó en local, y va apagada en producción.', atV1: 'Preview: EIF, PCR, attestation y KMS reales más auditoría.' },
  { id: 'push', kind: 'function', name: 'Notificaciones push', level: 'experimental', why: 'Con Buzz y el secure relay, el gateway no puede ver la actividad sin leer DMs, así que no se ofrecen.', atV1: 'Experimental, detrás de un flag.' },
];

export function maturity(id: MaturityId): MaturityEntry {
  const e = MATURITY.find((m) => m.id === id);
  if (!e) throw new Error(`unknown maturity entry: ${id}`);
  return e;
}

export interface ConfigMaturity {
  level: MaturityLevel;
  label: string;
  /** Every entry that applies to the configuration, least mature first. */
  parts: MaturityEntry[];
}

/**
 * The maturity of a persona's configuration: the least mature of what it uses. The base is its profile: Tor-only,
 * private-resilient (continuity required before each send), direct (convenience) or the rest (sovereign). Marmot,
 * managed custody, the enclave and the vault add their own. PANEL-07: private-resilient without a vault in the
 * deployment leaves the history on the relays, so it is never above Beta.
 */
export function configMaturity(config: SovereigntyConfig, ctx: { continuityVault?: boolean } = {}): ConfigMaturity {
  const parts: MaturityEntry[] = [];
  if (config.network === 'tor-only') parts.push(maturity('sovereign-tor'));
  else if (config.continuity === 'required-for-resilient') {
    const resilient = maturity('private-resilient');
    parts.push(ctx.continuityVault ? resilient : { ...resilient, level: 'beta', why: 'Sin Continuity Vault en el despliegue, el historial depende de los relays.' });
  } else parts.push(maturity(config.network === 'direct' ? 'convenience' : 'sovereign'));
  if (config.messaging === 'marmot') parts.push(maturity('marmot-groups'));
  if (config.custody === 'managed-enclave') parts.push(maturity('enclave-custody'));
  else if (config.custody === 'managed') parts.push(maturity('managed-custody'));
  if (config.continuity !== 'off' && ctx.continuityVault) parts.push(maturity('continuity-vault'));
  parts.sort((a, b) => RANK[a.level] - RANK[b.level]);
  const level = parts[0]!.level;
  return { level, label: MATURITY_LABELS[level], parts };
}

/** Markdown table of the catalog (README and release notes, generated by scripts/maturity.ts). */
export function maturityTable(): string {
  const rows = MATURITY.map((m) => `| ${m.name} | ${m.kind === 'profile' ? 'Perfil' : 'Función'} | ${MATURITY_LABELS[m.level]} | ${m.why} | ${m.atV1} |`);
  return ['| Perfil o función | Tipo | Hoy | Por qué | En v1.0 |', '|---|---|---|---|---|', ...rows].join('\n');
}
