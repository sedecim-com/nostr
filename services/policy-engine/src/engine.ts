import { createHash, randomBytes } from 'node:crypto';
import {
  evaluate,
  type Action,
  type Decision,
  type Device,
  type DirectoryEntry,
  type PolicyAuditEntry,
  type Resource,
  type RetentionPolicy,
  type Rotation,
  type Subject,
} from '@sedecim/policy-client';
import { MemoryPolicyRepository, type PolicyRepository, type StoredDevice } from './repository';
import { creationOptions, newChallenge, verifyRegistration, WebAuthnError, type RegistrationCredentialJSON } from './webauthn';

/** @deprecated use Rotation from @sedecim/policy-client. */
export type RotationRequired = Rotation;
export type { PolicyAuditEntry };

/** FR023-08: shown with every retention policy (API field and docs). */
export const RETENTION_NOTICE =
  'La retención y el borrado solo eliminan la copia del mirror/indexer de esta organización. No borran las copias ya replicadas en otros relays ni las que guardan los clientes y dispositivos de los participantes.';

export interface WebAuthnConfig {
  rpId: string;
  rpName: string;
  origins: string[];
  /** Accept `fmt: none` (most synced passkeys). Default true; false requires a verified `packed` attestation. */
  allowNone?: boolean;
  challengeTtlMs?: number;
}

export class NotFoundError extends Error {}
export class ConflictError extends Error {}

const hashToken = (t: string) => createHash('sha256').update(t).digest('hex');
/** Strips the stored WebAuthn public key and counter: the API only returns the public Device. */
const publicDevice = ({ credentialPublicKey: _k, signCount: _c, ...d }: StoredDevice): Device => d;

/**
 * Institutional mode core (spec §16). Keeps the Nostr identity: subjects are npubs mapped to roles and
 * attributes only when the organisation decides. Audit never stores message plaintext.
 * State lives in a PolicyRepository (Postgres with DATABASE_URL, memory otherwise).
 */
export class PolicyEngine {
  constructor(
    readonly repo: PolicyRepository = new MemoryPolicyRepository(),
    private readonly now: () => number = Date.now,
    private readonly webauthn: WebAuthnConfig = { rpId: 'localhost', rpName: 'Acceso Nostr', origins: ['http://localhost:8080'] },
  ) {}

  private log(actor: string, action: string, target: string, details?: Record<string, unknown>) {
    return this.repo.appendAudit({ at: this.now(), actor, action, target, ...(details ? { details } : {}) });
  }

  async upsertSubject(actor: string, s: Subject) {
    await this.repo.putSubject(s);
    await this.log(actor, 'subject.upsert', s.pubkey, { roles: s.roles });
  }

  async upsertResource(actor: string, r: Resource) {
    await this.repo.putResource(r);
    await this.log(actor, 'resource.upsert', r.id, { sensitivity: r.sensitivity });
  }

  listSubjects() {
    return this.repo.listSubjects();
  }
  listResources() {
    return this.repo.listResources();
  }
  async listDevices(owner?: string): Promise<Device[]> {
    return (await this.repo.listDevices(owner)).map(publicDevice);
  }
  async getDevice(id: string): Promise<Device | undefined> {
    const d = await this.repo.getDevice(id);
    return d && publicDevice(d);
  }
  listRotations(status?: Rotation['status']) {
    return this.repo.listRotations(status);
  }
  listAudit(q: { limit?: number; before?: number } = {}) {
    return this.repo.listAudit({ limit: Math.min(Math.max(q.limit ?? 100, 1), 1000), ...(q.before !== undefined ? { before: q.before } : {}) });
  }

  async registerDevice(actor: string, ownerPubkey: string, trust: Device['trust'] = 'registered'): Promise<Device> {
    // 'attested' is only earned through a verified WebAuthn registration (FR023-07).
    if (trust === 'attested') throw new ConflictError('attested trust requires WebAuthn registration');
    const d: Device = { id: randomBytes(8).toString('hex'), ownerPubkey, trust, registeredAt: this.now() };
    await this.repo.putDevice(d);
    await this.log(actor, 'device.register', d.id, { owner: ownerPubkey, trust });
    return d;
  }

  async openSession(pubkey: string, deviceId: string): Promise<string> {
    const d = await this.repo.getDevice(deviceId);
    if (!d || d.ownerPubkey !== pubkey || d.revokedAt !== undefined) throw new Error('device not usable for a new session');
    const token = randomBytes(24).toString('hex');
    await this.repo.putSession(hashToken(token), { pubkey, deviceId, createdAt: this.now() });
    return token;
  }

  async sessionValid(token: string): Promise<boolean> {
    const s = await this.repo.getSession(hashToken(token));
    if (!s) return false;
    const d = await this.repo.getDevice(s.deviceId);
    return !!d && d.revokedAt === undefined;
  }

  /**
   * FR-024: revoking a device blocks new sessions, invalidates existing ones and flags every group the
   * owner belongs to for key rotation (MLS commit / credential rotation).
   */
  async revokeDevice(actor: string, deviceId: string, reason = 'revoked'): Promise<Rotation[]> {
    const d = await this.repo.getDevice(deviceId);
    if (!d) throw new NotFoundError('unknown device');
    d.revokedAt = this.now();
    await this.repo.putDevice(d);
    await this.repo.deleteSessionsOfDevice(deviceId);
    await this.log(actor, 'device.revoke', deviceId, { reason });
    const out: Rotation[] = [];
    for (const r of await this.repo.listResources()) {
      if (r.kind === 'group' && r.members?.includes(d.ownerPubkey)) {
        const rot: Rotation = { id: randomBytes(8).toString('hex'), at: this.now(), resourceId: r.id, reason: `device ${deviceId} revoked`, removedPubkey: d.ownerPubkey, status: 'pending' };
        await this.repo.addRotation(rot);
        out.push(rot);
      }
    }
    return out;
  }

  async revokeSubject(actor: string, pubkey: string): Promise<Rotation[]> {
    const s = await this.repo.getSubject(pubkey);
    if (s) await this.repo.putSubject({ ...s, suspended: true });
    const rots: Rotation[] = [];
    for (const d of await this.repo.listDevices(pubkey)) if (d.revokedAt === undefined) rots.push(...(await this.revokeDevice(actor, d.id, 'subject revoked')));
    for (const r of await this.repo.listResources()) if (r.members?.includes(pubkey)) await this.repo.putResource({ ...r, members: r.members.filter((m) => m !== pubkey) });
    await this.log(actor, 'subject.revoke', pubkey);
    return rots;
  }

  async markRotationDone(actor: string, id: string): Promise<Rotation> {
    const r = await this.repo.markRotationDone(id, this.now());
    if (!r) throw new NotFoundError('unknown rotation');
    await this.log(actor, 'rotation.done', id, { resourceId: r.resourceId });
    return r;
  }

  async evaluate(input: { pubkey: string; deviceId?: string; resourceId: string; action: Action }): Promise<Decision> {
    const subject = await this.repo.getSubject(input.pubkey);
    const resource = await this.repo.getResource(input.resourceId);
    if (!subject) return { allow: false, reasons: ['unknown subject'] };
    if (!resource) return { allow: false, reasons: ['unknown resource'] };
    const device = input.deviceId ? await this.repo.getDevice(input.deviceId) : undefined;
    if (input.deviceId && !device) return { allow: false, reasons: ['unknown device'] };
    const decision = evaluate({ subject, device, resource, action: input.action, now: this.now() });
    await this.log(input.pubkey, 'policy.evaluate', input.resourceId, { action: input.action, allow: decision.allow });
    return decision;
  }

  /** NIP-42 allowlist for the relay: active subjects with at least one non-revoked device. */
  async relayAllowlist(): Promise<string[]> {
    const owners = new Set((await this.repo.listDevices()).filter((d) => d.revokedAt === undefined).map((d) => d.ownerPubkey));
    return (await this.repo.listSubjects())
      .filter((s) => !s.suspended && owners.has(s.pubkey))
      .map((s) => s.pubkey)
      .sort();
  }

  // FR023-06: organisational directory (admin-only; never published).
  listDirectory() {
    return this.repo.listDirectory();
  }
  async putDirectoryEntry(actor: string, e: DirectoryEntry) {
    await this.repo.putDirectoryEntry(e);
    await this.log(actor, 'directory.upsert', e.pubkey);
  }
  async deleteDirectoryEntry(actor: string, pubkey: string) {
    if (!(await this.repo.deleteDirectoryEntry(pubkey))) throw new NotFoundError('unknown directory entry');
    await this.log(actor, 'directory.delete', pubkey);
  }

  // FR023-08: retention of the mirror copy per workspace/channel.
  listRetention() {
    return this.repo.listRetention();
  }
  async putRetention(actor: string, p: RetentionPolicy) {
    if (!(await this.repo.getResource(p.resourceId))) throw new NotFoundError('unknown resource');
    await this.repo.putRetention(p);
    await this.log(actor, 'retention.set', p.resourceId, { days: p.days, legalHold: p.legalHold });
  }

  // FR023-07: device trust through WebAuthn. The challenge is single use and short-lived.
  async webauthnOptions(deviceId: string) {
    const d = await this.usableDevice(deviceId);
    const challenge = newChallenge();
    await this.repo.putChallenge(d.id, challenge, this.now() + (this.webauthn.challengeTtlMs ?? 300_000));
    const others = (await this.repo.listDevices(d.ownerPubkey)).map((x) => x.credentialId).filter((c): c is string => !!c);
    return creationOptions({ rpId: this.webauthn.rpId, rpName: this.webauthn.rpName, userId: Buffer.from(d.ownerPubkey, 'hex'), userName: d.ownerPubkey, challenge, excludeCredentials: others });
  }

  async webauthnRegister(actor: string, deviceId: string, credential: RegistrationCredentialJSON): Promise<Device> {
    const d = await this.usableDevice(deviceId);
    const pending = await this.repo.takeChallenge(d.id);
    if (!pending || pending.expiresAt < this.now()) throw new WebAuthnError('no pending challenge (request options first)');
    const v = verifyRegistration(credential, { challenge: pending.challenge, origins: this.webauthn.origins, rpId: this.webauthn.rpId, allowNone: this.webauthn.allowNone ?? true });
    const updated: StoredDevice = { ...d, trust: 'attested', credentialId: v.credentialId, attestationFormat: v.fmt, credentialPublicKey: v.publicKey, signCount: v.signCount };
    try {
      await this.repo.putDevice(updated);
    } catch (e) {
      throw new ConflictError((e as Error).message);
    }
    await this.log(actor, 'device.attest', d.id, { fmt: v.fmt, userVerified: v.userVerified });
    return publicDevice(updated);
  }

  private async usableDevice(deviceId: string): Promise<StoredDevice> {
    const d = await this.repo.getDevice(deviceId);
    if (!d) throw new NotFoundError('unknown device');
    if (d.revokedAt !== undefined) throw new ConflictError('device revoked');
    return d;
  }
}
