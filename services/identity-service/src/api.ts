import { randomBytes } from 'node:crypto';
import { getTagValue, nip98, verifyEvent } from '@sedecim/nostr-core';
import { Service, HttpError, isHex64, requireFields, CognitoTokenError, type CognitoVerifier, type ServiceOptions, type Req } from '@sedecim/service-kit';
import { ExternalLoginTakenError, type IdentityRepository, type PersonaRow, type Visibility } from './repository';

const CUSTODY = ['local', 'offline', 'external', 'encrypted-backup', 'managed', 'managed-enclave'];
const VIS: Visibility[] = ['private', 'selective', 'public'];
const FORBIDDEN_KEY_FIELDS = /(nsec|secret|seed|private|mnemonic|password)/i;
const id = () => randomBytes(12).toString('hex');

/**
 * Identity service (spec §5.1): relates an application account with the npubs the user CHOOSES to
 * register. It never knows an nsec. Personas the user keeps unlinked are simply never registered.
 */
export function createIdentityApi(repo: IdentityRepository, opts: ServiceOptions & { cognito?: CognitoVerifier }) {
  const svc = new Service(opts);
  const base = () => opts.publicBaseUrl ?? svc.baseUrl;

  const me = async (req: Req) => {
    const p = await repo.personaByPubkey(req.pubkey!);
    if (!p) throw new HttpError(404, 'no account for this pubkey');
    return p;
  };

  svc.get('/health', () => ({ ok: true }));

  svc.post(
    '/v1/accounts',
    async (req) => {
      const body = req.json<{ custody_mode?: string; label?: string }>();
      const custody = body.custody_mode ?? 'local';
      if (!CUSTODY.includes(custody)) throw new HttpError(400, 'invalid custody_mode');
      if (await repo.personaByPubkey(req.pubkey!)) throw new HttpError(409, 'pubkey already registered');
      const accountId = id();
      const persona: PersonaRow = { personaId: id(), accountId, pubkey: req.pubkey!, custodyMode: custody, linkageVisibility: 'private', ...(body.label ? { label: body.label } : {}) };
      await repo.createAccount(accountId, persona);
      await repo.audit(accountId, req.pubkey!, 'account.created', { persona: persona.personaId, custody });
      return { status: 201, body: { account_id: accountId, persona } };
    },
    'nip98',
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
      const persona: PersonaRow = { personaId: id(), accountId: current.accountId, pubkey: body.pubkey, custodyMode: custody, linkageVisibility: 'private', ...(body.label ? { label: body.label } : {}) };
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
      const persona = (await repo.personasOf(current.accountId)).find((p) => p.pubkey === req.params.pubkey);
      if (!persona) throw new HttpError(404, 'persona not found');
      await repo.upsertKeyMetadata({
        keyId: String(body.key_id),
        personaId: persona.personaId,
        provider: String(body.provider),
        version: Number(body.version ?? 1),
        ...(body.last_used ? { lastUsed: String(body.last_used) } : {}),
        recoveryState: String(body.recovery_state ?? 'none'),
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

  svc.get('/v1/accounts/me/audit', async (req) => ({ audit: await repo.auditOf((await me(req)).accountId) }), 'nip98');
  return svc;
}
