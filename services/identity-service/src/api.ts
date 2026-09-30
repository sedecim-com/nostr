import { randomBytes } from 'node:crypto';
import { getTagValue, nip98, verifyEvent } from '@sedecim/nostr-core';
import { Service, HttpError, isHex64, requireFields, CognitoTokenError, type CognitoVerifier, type ServiceOptions, type Req } from '@sedecim/service-kit';
import { BackupEnvelopeError, MAX_VAULT_BACKUP_BYTES, validateBackupEnvelope, type VaultBackupMeta } from '@sedecim/identity/backup-vault';
import { ExternalLoginTakenError, type BackupMetaRow, type IdentityRepository, type PersonaRow, type Visibility } from './repository';

const CUSTODY = ['local', 'offline', 'external', 'encrypted-backup', 'managed', 'managed-enclave'];
const VIS: Visibility[] = ['private', 'selective', 'public'];
const FORBIDDEN_KEY_FIELDS = /(nsec|secret|seed|private|mnemonic|password)/i;
const id = () => randomBytes(12).toString('hex');
/** IR-2026-09-19: free-text fields have their own limit, not just the body limit. */
const TEXT_MAX = 200;
function text(v: unknown, field: string): string | undefined {
  if (v === undefined || v === null || v === '') return undefined;
  if (typeof v !== 'string' || v.length > TEXT_MAX) throw new HttpError(400, `${field} must be a string of up to ${TEXT_MAX} chars`);
  return v;
}

export interface BackupVaultOptions {
  /** Max size of one stored envelope (default 512 KiB). */
  maxBytes?: number;
  /** Versions kept per account; older ones are pruned (default 5). */
  keep?: number;
}

const backupMeta = (b: BackupMetaRow): VaultBackupMeta => ({
  id: b.backupId,
  format: b.format as VaultBackupMeta['format'],
  format_version: b.formatVersion,
  size: b.size,
  sha256: b.sha256,
  ...(b.npub ? { npub: b.npub } : {}),
  created_at: b.createdAt,
});

/**
 * Identity service (spec §5.1): relates an application account with the npubs the user CHOOSES to
 * register. It never knows an nsec. Personas the user keeps unlinked are simply never registered.
 */
export function createIdentityApi(repo: IdentityRepository, opts: ServiceOptions & { cognito?: CognitoVerifier; backupVault?: BackupVaultOptions }) {
  const maxBackup = opts.backupVault?.maxBytes ?? MAX_VAULT_BACKUP_BYTES;
  const keepBackups = opts.backupVault?.keep ?? 5;
  const svc = new Service({ ...opts, maxBodyBytes: Math.max(opts.maxBodyBytes ?? 1_000_000, maxBackup + 1024) });
  const base = () => opts.publicBaseUrl ?? svc.baseUrl;

  const me = async (req: Req) => {
    const p = await repo.personaByPubkey(req.pubkey!);
    if (!p) throw new HttpError(404, 'no account for this pubkey');
    return p;
  };

  svc.get('/health', () => ({ ok: true }), 'none', { rateClass: 'none' });

  svc.post(
    '/v1/accounts',
    async (req) => {
      const body = req.json<{ custody_mode?: string; label?: string }>();
      const custody = body.custody_mode ?? 'local';
      if (!CUSTODY.includes(custody)) throw new HttpError(400, 'invalid custody_mode');
      if (await repo.personaByPubkey(req.pubkey!)) throw new HttpError(409, 'pubkey already registered');
      const accountId = id();
      const label = text(body.label, 'label');
      const persona: PersonaRow = { personaId: id(), accountId, pubkey: req.pubkey!, custodyMode: custody, linkageVisibility: 'private', ...(label ? { label } : {}) };
      await repo.createAccount(accountId, persona);
      await repo.audit(accountId, req.pubkey!, 'account.created', { persona: persona.personaId, custody });
      return { status: 201, body: { account_id: accountId, persona } };
    },
    'nip98',
    { rateClass: 'auth' },
  );

  svc.get(
    '/v1/accounts/me',
    async (req) => {
      const p = await me(req);
      const personas = await repo.personasOf(p.accountId);
      const links = await repo.linksOf(personas.map((x) => x.personaId));
      return { account_id: p.accountId, personas, links };
    },
    'nip98',
  );

  svc.post(
    '/v1/accounts/me/personas',
    async (req) => {
      const current = await me(req);
      const body = req.json<{ pubkey: string; custody_mode?: string; label?: string; proof: unknown }>();
      requireFields(body, ['pubkey', 'proof']);
      if (!isHex64(body.pubkey)) throw new HttpError(400, 'invalid pubkey');
      const custody = body.custody_mode ?? 'local';
      if (!CUSTODY.includes(custody)) throw new HttpError(400, 'invalid custody_mode');
      // Proof of control of the new key: a fresh event signed by it, bound to this account and URL.
      const proof = body.proof;
      const now = Math.floor(Date.now() / 1000);
      if (
        !verifyEvent(proof) ||
        proof.pubkey !== body.pubkey ||
        proof.kind !== nip98.HTTP_AUTH_KIND ||
        getTagValue(proof, 'account') !== current.accountId ||
        getTagValue(proof, 'u') !== `${base()}/v1/accounts/me/personas` ||
        Math.abs(now - proof.created_at) > 120
      ) {
        throw new HttpError(400, 'invalid proof of key control');
      }
      if (await repo.personaByPubkey(body.pubkey)) throw new HttpError(409, 'pubkey already registered');
      const label = text(body.label, 'label');
      const persona: PersonaRow = { personaId: id(), accountId: current.accountId, pubkey: body.pubkey, custodyMode: custody, linkageVisibility: 'private', ...(label ? { label } : {}) };
      await repo.addPersona(persona);
      await repo.audit(current.accountId, req.pubkey!, 'persona.registered', { persona: persona.personaId, custody });
      return { status: 201, body: { persona } };
    },
    'nip98',
  );

  svc.delete(
    '/v1/accounts/me/personas/:pubkey',
    async (req) => {
      const current = await me(req);
      if (!(await repo.removePersona(current.accountId, req.params.pubkey!))) throw new HttpError(404, 'persona not found');
      await repo.audit(current.accountId, req.pubkey!, 'persona.unregistered', { pubkey: req.params.pubkey });
      return { ok: true };
    },
    'nip98',
  );

  svc.post(
    '/v1/links',
    async (req) => {
      const current = await me(req);
      const body = req.json<{ from: string; to: string; visibility: Visibility; audience?: string[]; confirm?: boolean }>();
      requireFields(body, ['from', 'to', 'visibility']);
      if (body.confirm !== true) throw new HttpError(400, 'linking identities requires explicit confirmation (confirm: true)');
      if (!VIS.includes(body.visibility)) throw new HttpError(400, 'invalid visibility');
      if (body.visibility === 'selective' && !(body.audience ?? []).every(isHex64)) throw new HttpError(400, 'audience must be hex pubkeys');
      if (body.visibility === 'selective' && !body.audience?.length) throw new HttpError(400, 'selective links need an audience');
      const personas = await repo.personasOf(current.accountId);
      const from = personas.find((p) => p.pubkey === body.from);
      const to = personas.find((p) => p.pubkey === body.to);
      if (!from || !to || from.personaId === to.personaId) throw new HttpError(400, 'both personas must belong to your account');
      const link = { linkId: id(), fromPersona: from.personaId, toPersona: to.personaId, visibility: body.visibility, audience: body.audience ?? [] };
      await repo.addLink(link);
      await repo.audit(current.accountId, req.pubkey!, 'link.created', { from: from.personaId, to: to.personaId, visibility: body.visibility });
      return { status: 201, body: { link } };
    },
    'nip98',
  );

  // FR007-06: only the account that owns both personas can remove their link; anyone else gets the same 404 as
  // for a link that does not exist, so the id reveals nothing.
  svc.delete(
    '/v1/links/:linkId',
    async (req) => {
      const current = await me(req);
      const link = await repo.removeLink(current.accountId, req.params.linkId!);
      if (!link) throw new HttpError(404, 'link not found');
      await repo.audit(current.accountId, req.pubkey!, 'link.removed', { link: link.linkId, from: link.fromPersona, to: link.toPersona, visibility: link.visibility });
      return { ok: true };
    },
    'nip98',
  );

  const resolveLinks = async (pubkey: string, viewer?: string) => {
    const p = await repo.personaByPubkey(pubkey);
    if (!p) return [];
    const personas = await repo.personasOf(p.accountId);
    const byId = new Map(personas.map((x) => [x.personaId, x.pubkey]));
    return (await repo.linksOf([p.personaId]))
      .filter((l) => l.visibility === 'public' || (l.visibility === 'selective' && viewer !== undefined && l.audience.includes(viewer)))
      .map((l) => ({ from: byId.get(l.fromPersona), to: byId.get(l.toPersona), visibility: l.visibility }));
  };

  svc.get('/v1/links/public/:pubkey', async (req) => ({ links: await resolveLinks(req.params.pubkey!) }));
  svc.get('/v1/links/visible/:pubkey', async (req) => ({ links: await resolveLinks(req.params.pubkey!, req.pubkey) }), 'nip98');

  svc.put(
    '/v1/personas/:pubkey/key-metadata',
    async (req) => {
      const current = await me(req);
      const body = req.json<Record<string, unknown>>();
      for (const k of Object.keys(body)) if (FORBIDDEN_KEY_FIELDS.test(k)) throw new HttpError(400, `field "${k}" not allowed: key metadata must never contain secrets`);
      requireFields(body, ['key_id', 'provider']);
      const version = Number(body.version ?? 1);
      if (!Number.isInteger(version) || version < 0 || version > 2_147_483_647) throw new HttpError(400, 'version must be a non-negative 32-bit integer');
      const lastUsed = text(typeof body.last_used === 'number' ? String(body.last_used) : body.last_used, 'last_used');
      const persona = (await repo.personasOf(current.accountId)).find((p) => p.pubkey === req.params.pubkey);
      if (!persona) throw new HttpError(404, 'persona not found');
      await repo.upsertKeyMetadata({
        keyId: text(String(body.key_id), 'key_id')!,
        personaId: persona.personaId,
        provider: text(String(body.provider), 'provider')!,
        version,
        ...(lastUsed ? { lastUsed } : {}),
        recoveryState: text(String(body.recovery_state ?? 'none'), 'recovery_state')!,
      });
      await repo.audit(current.accountId, req.pubkey!, 'key_metadata.updated', { persona: persona.personaId, key_id: body.key_id });
      return { ok: true, key_metadata: await repo.keyMetadataOf(persona.personaId) };
    },
    'nip98',
  );

  // Acceso (Cognito) login attached to the account (ADR 0008). The npub stays the identity: the Cognito
  // token only proves which Acceso user controls this account, and is never stored.
  svc.post(
    '/v1/accounts/me/external-logins',
    async (req) => {
      const current = await me(req);
      const body = req.json<{ provider?: string; token?: string }>();
      requireFields(body, ['provider', 'token']);
      if (body.provider !== 'cognito' || !opts.cognito) throw new HttpError(400, 'unsupported provider');
      let who;
      try {
        who = await opts.cognito.verify(String(body.token));
      } catch (e) {
        if (e instanceof CognitoTokenError) throw new HttpError(401, `invalid cognito token: ${e.message}`);
        throw e;
      }
      try {
        await repo.linkExternalLogin({ accountId: current.accountId, provider: 'cognito', issuer: who.issuer, subject: who.subject, ...(who.username ? { username: who.username } : {}) });
      } catch (e) {
        if (e instanceof ExternalLoginTakenError) throw new HttpError(409, e.message);
        throw e;
      }
      await repo.audit(current.accountId, req.pubkey!, 'external_login.linked', { provider: 'cognito', subject: who.subject });
      return { status: 201, body: { external_logins: await repo.externalLoginsOf(current.accountId) } };
    },
    'nip98',
    { rateClass: 'auth' },
  );
  svc.get('/v1/accounts/me/external-logins', async (req) => ({ external_logins: await repo.externalLoginsOf((await me(req)).accountId) }), 'nip98');
  svc.delete(
    '/v1/accounts/me/external-logins/:provider',
    async (req) => {
      const current = await me(req);
      if (!(await repo.unlinkExternalLogin(current.accountId, req.params.provider!))) throw new HttpError(404, 'external login not found');
      await repo.audit(current.accountId, req.pubkey!, 'external_login.unlinked', { provider: req.params.provider });
      return { ok: true };
    },
    'nip98',
  );

  // FR027-03: encrypted backup vault. Owner = identity account, proven by NIP-98 (any registered persona)
  // or, in SaaS mode, by the Acceso (Cognito) token of a login linked to the account, so a new device
  // can restore with the Acceso login plus the backup password. Contents are opaque and never logged.
  const backupOwner = async (req: Req): Promise<{ accountId: string; actor: string }> => {
    if (req.token === undefined) return { accountId: (await me(req)).accountId, actor: req.pubkey! };
    if (!opts.cognito) throw new HttpError(401, 'bearer tokens are not accepted by this deployment');
    let who;
    try {
      who = await opts.cognito.verify(req.token);
    } catch (e) {
      if (e instanceof CognitoTokenError) throw new HttpError(401, `invalid cognito token: ${e.message}`);
      throw e;
    }
    req.limitPrincipal(`cognito:${who.issuer}#${who.subject}`);
    const accountId = await repo.accountByExternalLogin('cognito', who.issuer, who.subject);
    if (!accountId) throw new HttpError(404, 'no account linked to this Acceso login');
    return { accountId, actor: `cognito:${who.subject}` };
  };

  svc.post(
    '/v1/backups',
    async (req) => {
      const owner = await backupOwner(req);
      let v;
      try {
        v = validateBackupEnvelope(req.rawBody, maxBackup);
      } catch (e) {
        if (e instanceof BackupEnvelopeError) throw new HttpError(e.message.startsWith('backup too large') ? 413 : 400, e.message);
        throw e;
      }
      const row = { backupId: id(), accountId: owner.accountId, format: v.format, formatVersion: v.formatVersion, size: v.size, sha256: nip98.payloadHash(req.rawBody), ...(v.npub ? { npub: v.npub } : {}), createdAt: new Date().toISOString(), envelope: req.rawBody };
      await repo.putBackup(row, keepBackups);
      await repo.audit(owner.accountId, owner.actor, 'backup.stored', { backup: row.backupId, format: v.format, size: v.size });
      const { envelope: _e, ...meta } = row;
      return { status: 201, body: { backup: backupMeta(meta) } };
    },
    'nip98-or-token',
  );
  svc.get('/v1/backups', async (req) => ({ backups: (await repo.backupsOf((await backupOwner(req)).accountId)).map(backupMeta) }), 'nip98-or-token');
  svc.get(
    '/v1/backups/:id',
    async (req) => {
      const owner = await backupOwner(req);
      const b = await repo.getBackup(owner.accountId, req.params.id!);
      if (!b) throw new HttpError(404, 'backup not found');
      await repo.audit(owner.accountId, owner.actor, 'backup.downloaded', { backup: b.backupId });
      const { envelope, ...meta } = b;
      return { backup: backupMeta(meta), envelope };
    },
    'nip98-or-token',
    // A stolen token must not allow bulk downloads of envelopes to attack offline.
    { rateClass: 'auth' },
  );
  const deleteBackups = async (req: Req) => {
    const owner = await backupOwner(req);
    const deleted = await repo.deleteBackups(owner.accountId, req.params.id);
    if (req.params.id && !deleted) throw new HttpError(404, 'backup not found');
    await repo.audit(owner.accountId, owner.actor, 'backup.deleted', { backup: req.params.id ?? 'all', count: deleted });
    return { deleted };
  };
  svc.delete('/v1/backups', deleteBackups, 'nip98-or-token');
  svc.delete('/v1/backups/:id', deleteBackups, 'nip98-or-token');

  svc.get('/v1/accounts/me/audit', async (req) => ({ audit: await repo.auditOf((await me(req)).accountId) }), 'nip98');
  return svc;
}
