import { createHash, randomBytes } from 'node:crypto';
import {
  evaluate,
  type Action,
  type Decision,
  type Device,
  type DirectoryEntry,
  type PolicyAuditEntry,
  type RelayGrant,
  type Resource,
  type RevocationPage,
  type RetentionPolicy,
  type Rotation,
  type Subject,
} from '@sedecim/policy-client';
import { MemoryPolicyRepository, type PolicyRepository, type StoredDevice } from './repository';
import {
  creationOptions,
  newChallenge,
  requestOptions,
  verifyAssertion,
  verifyRegistration,
  WebAuthnError,
  type AssertionCredentialJSON,
  type RegistrationCredentialJSON,
  type VerifiedAssertion,
} from './webauthn';

/** @deprecated use Rotation from @sedecim/policy-client. */
export type RotationRequired = Rotation;
export type { PolicyAuditEntry };

/** FR023-12: how long access decisions are kept by default (ACCESS_LOG_RETENTION_DAYS). */
export const DEFAULT_ACCESS_LOG_RETENTION_DAYS = 90;

/** FR023-12: why an MLS group resource takes no retention policy (see putRetention). */
export const GROUP_RETENTION_REFUSED =
  'retention and legal hold do not apply to MLS groups: the organisation keeps no copy of their content (end-to-end encryption with forward secrecy)';

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
  /** FR023-11 (WEBAUTHN_REQUIRE_UV): registrations and assertions must carry user verification (PIN, biometrics). */
  requireUserVerification?: boolean;
  /**
   * FR023-11 (SESSION_REQUIRE_ASSERTION): every session asks for a passkey assertion, also for owners without a passkey
   * (refused until they register one). Default: only owners who registered a passkey (see `passkeyBound`).
   */
  sessionRequireAssertion?: boolean;
}

export class NotFoundError extends Error {}
export class ConflictError extends Error {}
/** FR023-11: a session was not opened. Its message is what the caller sees; what went wrong with an assertion is only audited. */
export class SessionDeniedError extends Error {}

/** FR023-11: the one answer to a failed assertion, so that a caller learns nothing about the credential or the check. */
export const ASSERTION_REJECTED = 'WebAuthn assertion rejected';

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

  /** Sets roles and attributes. Never changes the revocation (FR023-09): lifting it is `reactivateSubject`. */
  async upsertSubject(actor: string, s: Subject) {
    const prev = await this.repo.getSubject(s.pubkey);
    const { suspended: _ignored, ...fields } = s;
    await this.repo.putSubject({ ...fields, ...(prev?.suspended ? { suspended: true } : {}) });
    await this.log(actor, 'subject.upsert', s.pubkey, { roles: s.roles });
  }

  /**
   * FR023-09: lifting a revocation is an explicit action with its own audit entry. Devices revoked with the
   * subject stay revoked and resource memberships are not restored, so the person needs a new device (and
   * to be added back to groups) before a relay lets it in again.
   */
  async reactivateSubject(actor: string, pubkey: string) {
    const s = await this.repo.getSubject(pubkey);
    if (!s) throw new NotFoundError('unknown subject');
    if (!s.suspended) throw new ConflictError('subject is not revoked');
    const { suspended: _lifted, ...active } = s;
    await this.repo.putSubject(active);
    await this.log(actor, 'subject.reactivate', pubkey);
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

  /**
   * Opens a session of `pubkey` (the NIP-98 signer) on one of its devices. FR023-11: an owner who registered a passkey
   * (every owner with SESSION_REQUIRE_ASSERTION) opens it only with an assertion of that device's passkey, on the
   * single-use challenge of `webauthnAssertionOptions`; the session then records the device and the credential.
   */
  async openSession(pubkey: string, deviceId: string, assertion?: AssertionCredentialJSON): Promise<string> {
    const d = await this.repo.getDevice(deviceId);
    if (!d || d.ownerPubkey !== pubkey || d.revokedAt !== undefined) throw new SessionDeniedError('device not usable for a new session');
    let credentialId: string | undefined;
    if (assertion !== undefined) credentialId = await this.checkSessionAssertion(pubkey, d, assertion);
    else if (await this.assertionRequired(pubkey)) {
      throw new SessionDeniedError(
        (await this.passkeyBound(pubkey))
          ? 'this owner registered a passkey: every session requires its WebAuthn assertion (POST /v1/devices/:id/webauthn/assert/options first)'
          : 'every session requires a WebAuthn assertion (SESSION_REQUIRE_ASSERTION): register a passkey on this device first',
      );
    }
    const token = randomBytes(24).toString('hex');
    await this.repo.putSession(hashToken(token), { pubkey, deviceId, createdAt: this.now(), ...(credentialId ? { credentialId } : {}) });
    return token;
  }

  /**
   * A session is valid while its device is not revoked. FR023-11: one opened with a passkey, while the device keeps that
   * passkey (registering another one on it ends it); one opened without, only while its owner needs none: once the
   * owner registers a passkey (or with SESSION_REQUIRE_ASSERTION), it no longer counts.
   */
  async sessionValid(token: string): Promise<boolean> {
    const s = await this.repo.getSession(hashToken(token));
    if (!s) return false;
    const d = await this.repo.getDevice(s.deviceId);
    if (!d || d.revokedAt !== undefined || d.ownerPubkey !== s.pubkey) return false;
    if (s.credentialId !== undefined) return d.credentialId === s.credentialId;
    return !(await this.assertionRequired(s.pubkey));
  }

  /**
   * FR023-11: whether the owner ever registered a passkey on one of their devices, revoked ones included. It never goes
   * back: revoking the device that holds the passkey must not bring back sessions without one, nor let whoever holds
   * only the owner's Nostr key enroll an authenticator of their own (only an admin registers another passkey).
   */
  async passkeyBound(pubkey: string): Promise<boolean> {
    return (await this.repo.listDevices(pubkey)).some((d) => !!d.credentialId);
  }

  private async assertionRequired(pubkey: string): Promise<boolean> {
    return !!this.webauthn.sessionRequireAssertion || (await this.passkeyBound(pubkey));
  }

  /**
   * FR023-11: the assertion of a session, on the device's pending challenge, which it consumes whatever the outcome. A
   * failure is audited as `session.assert` with its reason (never the challenge, the credential or the signature) and
   * the caller only gets ASSERTION_REJECTED. A success is not audited: when someone opens sessions is usage metadata,
   * which the append-only audit would keep forever (FR023-12 keeps the access decisions out of it for the same reason).
   * Returns the credential that signed.
   */
  private async checkSessionAssertion(pubkey: string, d: StoredDevice, assertion: AssertionCredentialJSON): Promise<string> {
    const pending = await this.repo.takeChallenge(d.id, 'assert');
    const reject = async (reason: string, details: Record<string, unknown> = {}) => {
      await this.log(pubkey, 'session.assert', d.id, { ok: false, reason, ...details });
      return new SessionDeniedError(ASSERTION_REJECTED);
    };
    if (d.trust !== 'attested' || !d.credentialId || !d.credentialPublicKey) throw await reject('device has no passkey');
    if (!pending || pending.expiresAt < this.now()) throw await reject(pending ? 'challenge expired' : 'no pending challenge');
    let v: VerifiedAssertion;
    try {
      v = verifyAssertion(assertion, {
        challenge: pending.challenge,
        origins: this.webauthn.origins,
        rpId: this.webauthn.rpId,
        credentialId: d.credentialId,
        publicKey: d.credentialPublicKey,
        userHandle: Buffer.from(d.ownerPubkey, 'hex'),
        requireUserVerification: !!this.webauthn.requireUserVerification,
      });
    } catch (e) {
      if (e instanceof WebAuthnError) throw await reject(e.message);
      throw e;
    }
    // A counter that does not go up means two authenticators hold the same key (WebAuthn §6.1.1): refused and audited.
    if (!(await this.repo.advanceSignCount(d.id, d.credentialId, v.signCount))) {
      const now = await this.repo.getDevice(d.id);
      if (!now || now.revokedAt !== undefined || now.credentialId !== d.credentialId) throw await reject('device revoked or given another passkey meanwhile');
      throw await reject('signature counter did not increase: possible cloned authenticator', { signCount: v.signCount });
    }
    return d.credentialId;
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

  /**
   * FR024-04: device revocations after `after` (an audit id), oldest first. They come straight from the
   * audit, filtered by action, so no amount of other audit traffic can push one out of a page.
   */
  async listRevocations(q: { after?: number; limit?: number } = {}): Promise<RevocationPage> {
    const entries = await this.repo.listAuditByAction({ action: 'device.revoke', after: q.after ?? 0, limit: Math.min(Math.max(q.limit ?? 100, 1), 1000) });
    return {
      revocations: entries.map((e) => ({ cursor: e.id, at: e.at, deviceId: e.target, ...(typeof e.details?.reason === 'string' ? { reason: e.details.reason } : {}) })),
      // Read after the page, so that it is never older than what the page holds.
      latest: await this.repo.lastAuditId('device.revoke'),
      now: this.now(),
    };
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
    // FR023-12: in the access log, not the audit: it has a retention of its own (pruneAccessLog).
    await this.repo.appendAccess({ at: this.now(), pubkey: input.pubkey, ...(input.deviceId ? { deviceId: input.deviceId } : {}), resourceId: input.resourceId, action: input.action, allow: decision.allow });
    return decision;
  }

  /** FR023-12: access decisions, newest first (admin). */
  listAccessLog(q: { limit?: number; before?: number; resourceId?: string } = {}) {
    return this.repo.listAccess({ limit: Math.min(Math.max(q.limit ?? 100, 1), 1000), ...(q.before !== undefined ? { before: q.before } : {}), ...(q.resourceId !== undefined ? { resourceId: q.resourceId } : {}) });
  }

  /**
   * FR023-12: the access log keeps `days` days. The decisions on a resource under legal hold are kept while the hold
   * lasts. A hold on a workspace covers all of its channels, and the engine cannot tell which channels those are: while
   * one lasts, nothing is pruned. Returns how many were deleted.
   */
  async pruneAccessLog(days: number): Promise<number> {
    const held = (await this.retentionWithKinds()).filter((p) => p.legalHold);
    if (held.some((p) => p.kind === 'workspace')) return 0;
    return this.repo.purgeAccess({ before: this.now() - days * 86_400_000, exceptResources: held.map((p) => p.resourceId) });
  }

  /** NIP-42 allowlist for the relay: active subjects with at least one non-revoked device. */
  async relayAllowlist(): Promise<string[]> {
    const owners = new Set((await this.repo.listDevices()).filter((d) => d.revokedAt === undefined).map((d) => d.ownerPubkey));
    return (await this.repo.listSubjects())
      .filter((s) => !s.suspended && owners.has(s.pubkey))
      .map((s) => s.pubkey)
      .sort();
  }

  /**
   * FR023-10: who may publish in each channel (NIP-29) and group (Marmot) resource, for the relays. Only people of the
   * allowlist (active, with a device not revoked), each allowed when `evaluate` lets one of their devices publish: a
   * relay knows the NIP-42 pubkey of a session, not its device. Computed with the pure `evaluate`: these are not
   * access decisions and stay out of the access log.
   */
  async relayPublishGrants(): Promise<RelayGrant[]> {
    const devices = new Map<string, Device[]>();
    for (const d of await this.repo.listDevices()) if (d.revokedAt === undefined) devices.set(d.ownerPubkey, [...(devices.get(d.ownerPubkey) ?? []), d]);
    const subjects = (await this.repo.listSubjects()).filter((s) => !s.suspended && devices.has(s.pubkey));
    const now = this.now();
    const grants: RelayGrant[] = [];
    for (const resource of await this.repo.listResources()) {
      if (resource.kind !== 'channel' && resource.kind !== 'group') continue;
      const pubkeys = subjects.filter((subject) => devices.get(subject.pubkey)!.some((device) => evaluate({ subject, device, resource, action: 'publish', now }).allow)).map((s) => s.pubkey);
      grants.push({ resourceId: resource.id, kind: resource.kind, pubkeys: pubkeys.sort() });
    }
    return grants.sort((a, b) => (a.resourceId < b.resourceId ? -1 : a.resourceId > b.resourceId ? 1 : 0));
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
  async listRetention(): Promise<RetentionPolicy[]> {
    return (await this.retentionWithKinds()).map(({ kind: _kind, ...p }) => p);
  }
  /**
   * FR023-12: a policy left on an MLS group (set before groups were refused, or on a resource whose kind changed since)
   * applies to nothing. The kind of a resource that no longer exists is unknown.
   */
  private async retentionWithKinds(): Promise<Array<RetentionPolicy & { kind?: Resource['kind'] }>> {
    const [policies, resources] = await Promise.all([this.repo.listRetention(), this.repo.listResources()]);
    const kinds = new Map(resources.map((r) => [r.id, r.kind]));
    return policies.flatMap((p) => {
      const kind = kinds.get(p.resourceId);
      return kind === 'group' ? [] : [{ ...p, ...(kind ? { kind } : {}) }];
    });
  }
  async putRetention(actor: string, p: RetentionPolicy) {
    const resource = await this.repo.getResource(p.resourceId);
    if (!resource) throw new NotFoundError('unknown resource');
    // FR023-12: retention and legal hold act on the organisation's mirror copy. An MLS group has none: its content is
    // end-to-end encrypted with forward secrecy, so a hold on it would promise evidence nobody can keep.
    if (resource.kind === 'group') throw new ConflictError(GROUP_RETENTION_REFUSED);
    await this.repo.putRetention(p);
    await this.log(actor, 'retention.set', p.resourceId, { days: p.days, legalHold: p.legalHold });
  }

  // FR023-07: device trust through WebAuthn. The challenge is single use and short-lived.
  async webauthnOptions(deviceId: string) {
    const d = await this.usableDevice(deviceId);
    const challenge = newChallenge();
    await this.repo.putChallenge(d.id, challenge, this.now() + (this.webauthn.challengeTtlMs ?? 300_000), 'register');
    const others = (await this.repo.listDevices(d.ownerPubkey)).map((x) => x.credentialId).filter((c): c is string => !!c);
    return creationOptions({ rpId: this.webauthn.rpId, rpName: this.webauthn.rpName, userId: Buffer.from(d.ownerPubkey, 'hex'), userName: d.ownerPubkey, challenge, excludeCredentials: others, userVerification: this.userVerification() });
  }

  /**
   * FR023-11: registering a passkey ends the device's sessions (those of a passkey it replaces) and deletes the owner's
   * sessions opened without one, which no longer count anyway (see `sessionValid`).
   */
  async webauthnRegister(actor: string, deviceId: string, credential: RegistrationCredentialJSON): Promise<Device> {
    const d = await this.usableDevice(deviceId);
    const pending = await this.repo.takeChallenge(d.id, 'register');
    if (!pending || pending.expiresAt < this.now()) throw new WebAuthnError('no pending challenge (request options first)');
    const v = verifyRegistration(credential, { challenge: pending.challenge, origins: this.webauthn.origins, rpId: this.webauthn.rpId, allowNone: this.webauthn.allowNone ?? true });
    if (this.webauthn.requireUserVerification && !v.userVerified) throw new WebAuthnError('user verification required');
    const updated: StoredDevice = { ...d, trust: 'attested', credentialId: v.credentialId, attestationFormat: v.fmt, credentialPublicKey: v.publicKey, signCount: v.signCount };
    try {
      await this.repo.putDevice(updated);
    } catch (e) {
      throw new ConflictError((e as Error).message);
    }
    await this.repo.deleteSessionsOfDevice(d.id);
    await this.repo.deleteUnassertedSessions(d.ownerPubkey);
    await this.log(actor, 'device.attest', d.id, { fmt: v.fmt, userVerified: v.userVerified });
    return publicDevice(updated);
  }

  /**
   * FR023-11: request options for an assertion of the passkey of one of the owner's devices, with a single-use challenge
   * of their own (5 minutes; asking again replaces it). To anyone but its owner the device does not exist.
   */
  async webauthnAssertionOptions(pubkey: string, deviceId: string) {
    const d = await this.repo.getDevice(deviceId);
    if (!d || d.ownerPubkey !== pubkey) throw new NotFoundError('unknown device');
    if (d.revokedAt !== undefined) throw new ConflictError('device revoked');
    if (d.trust !== 'attested' || !d.credentialId) throw new ConflictError('device has no passkey: register one first');
    const challenge = newChallenge();
    await this.repo.putChallenge(d.id, challenge, this.now() + (this.webauthn.challengeTtlMs ?? 300_000), 'assert');
    return requestOptions({ rpId: this.webauthn.rpId, challenge, allowCredentials: [d.credentialId], userVerification: this.userVerification() });
  }

  private userVerification() {
    return this.webauthn.requireUserVerification ? ('required' as const) : ('preferred' as const);
  }

  private async usableDevice(deviceId: string): Promise<StoredDevice> {
    const d = await this.repo.getDevice(deviceId);
    if (!d) throw new NotFoundError('unknown device');
    if (d.revokedAt !== undefined) throw new ConflictError('device revoked');
    return d;
  }
}
