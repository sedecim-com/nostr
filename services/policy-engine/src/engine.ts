import { randomBytes } from 'node:crypto';
import { evaluate, type Action, type Decision, type Device, type Resource, type Subject } from '@sedecim/policy-client';

export interface RotationRequired {
  at: number;
  resourceId: string;
  reason: string;
  removedPubkey: string;
}

export interface PolicyAuditEntry {
  at: number;
  actor: string;
  action: string;
  target: string;
  details?: Record<string, unknown>;
}

/**
 * Institutional mode core (spec §16). Keeps the Nostr identity: subjects are npubs mapped to roles and
 * attributes only when the organisation decides. Audit never stores message plaintext.
 */
export class PolicyEngine {
  readonly subjects = new Map<string, Subject>();
  readonly devices = new Map<string, Device>();
  readonly resources = new Map<string, Resource>();
  readonly rotations: RotationRequired[] = [];
  readonly audit: PolicyAuditEntry[] = [];
  private readonly sessions = new Map<string, { pubkey: string; deviceId: string; createdAt: number }>();

  constructor(private readonly now: () => number = Date.now) {}

  private log(actor: string, action: string, target: string, details?: Record<string, unknown>) {
    this.audit.push({ at: this.now(), actor, action, target, ...(details ? { details } : {}) });
  }

  upsertSubject(actor: string, s: Subject) {
    this.subjects.set(s.pubkey, s);
    this.log(actor, 'subject.upsert', s.pubkey, { roles: s.roles });
  }

  upsertResource(actor: string, r: Resource) {
    this.resources.set(r.id, r);
    this.log(actor, 'resource.upsert', r.id, { sensitivity: r.sensitivity });
  }

  registerDevice(actor: string, ownerPubkey: string, trust: Device['trust'] = 'registered'): Device {
    const d: Device = { id: randomBytes(8).toString('hex'), ownerPubkey, trust, registeredAt: this.now() };
    this.devices.set(d.id, d);
    this.log(actor, 'device.register', d.id, { owner: ownerPubkey, trust });
    return d;
  }

  openSession(pubkey: string, deviceId: string): string {
    const d = this.devices.get(deviceId);
    if (!d || d.ownerPubkey !== pubkey || d.revokedAt !== undefined) throw new Error('device not usable for a new session');
    const token = randomBytes(24).toString('hex');
    this.sessions.set(token, { pubkey, deviceId, createdAt: this.now() });
    return token;
  }

  sessionValid(token: string): boolean {
    const s = this.sessions.get(token);
    if (!s) return false;
    const d = this.devices.get(s.deviceId);
    return !!d && d.revokedAt === undefined;
  }

  /**
   * FR-024: revoking a device blocks new sessions, invalidates existing ones and — when the owner has no
   * other trusted device — flags every group they belong to for key rotation (MLS commit / credential rotation).
   */
  revokeDevice(actor: string, deviceId: string, reason = 'revoked'): RotationRequired[] {
    const d = this.devices.get(deviceId);
    if (!d) throw new Error('unknown device');
    d.revokedAt = this.now();
    for (const [t, s] of this.sessions) if (s.deviceId === deviceId) this.sessions.delete(t);
    this.log(actor, 'device.revoke', deviceId, { reason });
    const out: RotationRequired[] = [];
    for (const r of this.resources.values()) {
      if (r.kind === 'group' && r.members?.includes(d.ownerPubkey)) {
        const rot = { at: this.now(), resourceId: r.id, reason: `device ${deviceId} revoked`, removedPubkey: d.ownerPubkey };
        this.rotations.push(rot);
        out.push(rot);
      }
    }
    return out;
  }

  revokeSubject(actor: string, pubkey: string): RotationRequired[] {
    const s = this.subjects.get(pubkey);
    if (s) s.suspended = true;
    const rots: RotationRequired[] = [];
    for (const d of this.devices.values()) if (d.ownerPubkey === pubkey && d.revokedAt === undefined) rots.push(...this.revokeDevice(actor, d.id, 'subject revoked'));
    for (const r of this.resources.values()) if (r.members) r.members = r.members.filter((m) => m !== pubkey);
    this.log(actor, 'subject.revoke', pubkey);
    return rots;
  }

  evaluate(input: { pubkey: string; deviceId?: string; resourceId: string; action: Action }): Decision {
    const subject = this.subjects.get(input.pubkey);
    const resource = this.resources.get(input.resourceId);
    if (!subject) return { allow: false, reasons: ['unknown subject'] };
    if (!resource) return { allow: false, reasons: ['unknown resource'] };
    const device = input.deviceId ? this.devices.get(input.deviceId) : undefined;
    if (input.deviceId && !device) return { allow: false, reasons: ['unknown device'] };
    const decision = evaluate({ subject, device, resource, action: input.action, now: this.now() });
    this.log(input.pubkey, 'policy.evaluate', input.resourceId, { action: input.action, allow: decision.allow });
    return decision;
  }

  /** NIP-42 allowlist for the relay: active subjects with at least one non-revoked device. */
  relayAllowlist(): string[] {
    return [...this.subjects.values()]
      .filter((s) => !s.suspended && [...this.devices.values()].some((d) => d.ownerPubkey === s.pubkey && d.revokedAt === undefined))
      .map((s) => s.pubkey)
      .sort();
  }
}
