/**
 * Institutional authorization (spec §16): Zero-Trust-like evaluation by user, device, role/attribute
 * and channel context. Default deny.
 */
export type Action = 'read' | 'publish' | 'admin' | 'invite';
export type Sensitivity = 'public' | 'internal' | 'confidential' | 'secret';
export const SENSITIVITY_ORDER: Sensitivity[] = ['public', 'internal', 'confidential', 'secret'];

export interface Subject {
  pubkey: string;
  roles: string[];
  attributes: Record<string, string | string[]>;
  suspended?: boolean;
}

export interface Device {
  id: string;
  ownerPubkey: string;
  trust: 'unverified' | 'registered' | 'attested';
  registeredAt: number;
  revokedAt?: number;
  /** WebAuthn credential id (base64url) bound to the device when it was registered with a passkey. */
  credentialId?: string;
  /** WebAuthn attestation format verified at registration ('packed' | 'none'). */
  attestationFormat?: string;
}

export interface Rule {
  actions: Action[];
  anyRole?: string[];
  /** Every listed attribute must match (value or any of values). */
  attributes?: Record<string, string | string[]>;
  minDeviceTrust?: Device['trust'];
}

export interface Resource {
  id: string;
  kind: 'workspace' | 'channel' | 'group';
  sensitivity: Sensitivity;
  rules: Rule[];
  /** Explicit members (NIP-29 group membership), optional. */
  members?: string[];
}

export interface Decision {
  allow: boolean;
  reasons: string[];
  rule?: number;
}

const TRUST_ORDER: Device['trust'][] = ['unverified', 'registered', 'attested'];

function attrMatches(have: string | string[] | undefined, want: string | string[]): boolean {
  if (have === undefined) return false;
  const h = Array.isArray(have) ? have : [have];
  const w = Array.isArray(want) ? want : [want];
  return w.some((x) => h.includes(x));
}

export function evaluate(input: { subject: Subject; device?: Device; resource: Resource; action: Action; now?: number }): Decision {
  const { subject, device, resource, action } = input;
  const reasons: string[] = [];
  if (subject.suspended) return { allow: false, reasons: ['subject suspended'] };
  if (resource.members && !resource.members.includes(subject.pubkey)) return { allow: false, reasons: ['not a member of resource'] };
  if (device) {
    if (device.ownerPubkey !== subject.pubkey) return { allow: false, reasons: ['device not owned by subject'] };
    if (device.revokedAt !== undefined && device.revokedAt <= (input.now ?? Date.now())) return { allow: false, reasons: ['device revoked'] };
  }
  const sensIdx = SENSITIVITY_ORDER.indexOf(resource.sensitivity);
  if (sensIdx >= SENSITIVITY_ORDER.indexOf('confidential')) {
    const clearance = subject.attributes.clearance;
    const c = typeof clearance === 'string' ? SENSITIVITY_ORDER.indexOf(clearance as Sensitivity) : -1;
    if (c < sensIdx) return { allow: false, reasons: [`clearance below ${resource.sensitivity}`] };
    if (!device || TRUST_ORDER.indexOf(device.trust) < TRUST_ORDER.indexOf('registered')) return { allow: false, reasons: ['sensitive resource requires a registered device'] };
  }
  for (const [i, rule] of resource.rules.entries()) {
    if (!rule.actions.includes(action)) continue;
    if (rule.anyRole && !rule.anyRole.some((r) => subject.roles.includes(r))) {
      reasons.push(`rule ${i}: missing role`);
      continue;
    }
    if (rule.attributes && !Object.entries(rule.attributes).every(([k, v]) => attrMatches(subject.attributes[k], v))) {
      reasons.push(`rule ${i}: attribute mismatch`);
      continue;
    }
    if (rule.minDeviceTrust && (!device || TRUST_ORDER.indexOf(device.trust) < TRUST_ORDER.indexOf(rule.minDeviceTrust))) {
      reasons.push(`rule ${i}: device trust below ${rule.minDeviceTrust}`);
      continue;
    }
    return { allow: true, reasons: [`rule ${i} matched`], rule: i };
  }
  return { allow: false, reasons: reasons.length ? reasons : ['no rule grants this action (default deny)'] };
}
