import { SENSITIVITY_ORDER, type Rule, type Subject } from '@sedecim/policy-client';
import { parsePubkey } from './signers';

/** Text lists: "a, b" or one per line → ['a','b']. */
export const splitList = (s: string) =>
  s
    .split(/[,\n]/)
    .map((x) => x.trim())
    .filter(Boolean);

/** "clearance=secret\nunit=a|b" → attributes (a `|` makes a multi-valued attribute). */
export function parseAttributes(text: string): Subject['attributes'] {
  const out: Subject['attributes'] = {};
  for (const line of text.split('\n').map((l) => l.trim()).filter(Boolean)) {
    const i = line.indexOf('=');
    if (i <= 0) throw new Error(`atributo inválido: "${line}" (usa clave=valor)`);
    const values = line.slice(i + 1).split('|').map((v) => v.trim()).filter(Boolean);
    out[line.slice(0, i).trim()] = values.length === 1 ? values[0]! : values;
  }
  return out;
}

export const formatAttributes = (a: Subject['attributes']) =>
  Object.entries(a)
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join('|') : v}`)
    .join('\n');

const ACTIONS = ['read', 'publish', 'admin', 'invite'];
const TRUST = ['unverified', 'registered', 'attested'];

/** Rules are edited as JSON; validated here so the API only sees well-formed rules. */
export function parseRules(text: string): Rule[] {
  let v: unknown;
  try {
    v = JSON.parse(text.trim() || '[]');
  } catch {
    throw new Error('las reglas deben ser JSON válido');
  }
  if (!Array.isArray(v)) throw new Error('las reglas deben ser una lista JSON');
  for (const [i, r] of v.entries()) {
    const rule = r as Partial<Rule>;
    if (!rule || typeof rule !== 'object' || !Array.isArray(rule.actions) || rule.actions.length === 0 || !rule.actions.every((a) => ACTIONS.includes(a))) throw new Error(`regla ${i}: "actions" debe listar read, publish, admin o invite`);
    if (rule.anyRole !== undefined && (!Array.isArray(rule.anyRole) || !rule.anyRole.every((x) => typeof x === 'string'))) throw new Error(`regla ${i}: "anyRole" debe ser una lista de roles`);
    if (rule.minDeviceTrust !== undefined && !TRUST.includes(rule.minDeviceTrust)) throw new Error(`regla ${i}: "minDeviceTrust" inválido`);
    if (rule.attributes !== undefined && (typeof rule.attributes !== 'object' || Array.isArray(rule.attributes))) throw new Error(`regla ${i}: "attributes" debe ser un objeto`);
  }
  return v as Rule[];
}

/** Members, one npub/hex per line. Empty: no explicit membership (the field is omitted). */
export function parseMembers(text: string): string[] | undefined {
  const list = splitList(text);
  return list.length ? list.map(parsePubkey) : undefined;
}

export const SENSITIVITIES = SENSITIVITY_ORDER;
