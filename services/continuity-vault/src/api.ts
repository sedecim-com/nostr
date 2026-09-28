import { createHash } from 'node:crypto';
import { ArchiveEnvelopeError, isArchiveId, MAX_ARCHIVE_ENVELOPE_BYTES, validateArchiveEnvelope, type ArchiveMeta } from '@sedecim/continuity';
import { CognitoTokenError, HttpError, isHex64, Service, type CognitoVerifier, type Req, type ServiceOptions } from '@sedecim/service-kit';
import { newObjectKey, type ObjectStore } from './objects';
import { QuotaExceededError, type ArchiveRepository, type ArchiveRow } from './repository';

/** Who may open a vault account with NIP-98 (ADR 0011). Acceso logins are accepted whenever `cognito` is set. */
export type Nip98Policy = 'open' | 'allowlist' | 'off';

export interface VaultLimits {
  /** One envelope, in bytes (default 1 MiB). */
  maxEnvelopeBytes: number;
  /** Archives per account (default 100 000). */
  maxArchives: number;
  /** Stored bytes per account (default 256 MiB). */
  maxBytes: number;
}

export const DEFAULT_VAULT_LIMITS: VaultLimits = { maxEnvelopeBytes: MAX_ARCHIVE_ENVELOPE_BYTES, maxArchives: 100_000, maxBytes: 256 * 1024 * 1024 };

export interface ContinuityVaultOptions extends ServiceOptions {
  /** SaaS: accept Acceso (Cognito) tokens; the account is the Acceso user. */
  cognito?: CognitoVerifier;
  /** Default 'open': any Nostr key can hold an account (the client derives a vault-only key from its archive key). */
  nip98?: Nip98Policy;
  /** Hex pubkeys allowed when `nip98` is 'allowlist'. */
  allowedPubkeys?: string[];
  limits?: Partial<VaultLimits>;
}

const sha256 = (text: string) => createHash('sha256').update(text, 'utf8').digest('hex');

const meta = (r: ArchiveRow): ArchiveMeta => ({ id: r.archiveId, key_id: r.keyId, size: r.size, sha256: r.sha256, created_at: r.createdAt, updated_at: r.updatedAt });

/**
 * Continuity Vault (ADR 0011, VAULT-01): stores client-sealed archive envelopes per account and nothing
 * else. It never sees a key or a plaintext, it is not the indexer (it cannot read, index or serve events),
 * and it needs no identity account: the account is whoever authenticates, a Nostr key (NIP-98) or an Acceso
 * login. Envelope contents and archive ids are never logged.
 */
export function createContinuityVaultApi(repo: ArchiveRepository, objects: ObjectStore, opts: ContinuityVaultOptions) {
  const limits: VaultLimits = { ...DEFAULT_VAULT_LIMITS, ...opts.limits };
  for (const [k, v] of Object.entries(limits)) if (!Number.isSafeInteger(v) || v <= 0) throw new Error(`vault limit ${k} must be a positive integer`);
  const nip98 = opts.nip98 ?? 'open';
  const allowed = new Set(opts.allowedPubkeys ?? []);
  for (const pk of allowed) if (!isHex64(pk)) throw new Error('allowedPubkeys must be hex pubkeys');
  if (nip98 === 'allowlist' && !allowed.size) throw new Error("nip98 'allowlist' needs at least one allowed pubkey");
  if (nip98 === 'off' && !opts.cognito) throw new Error('a vault without NIP-98 needs Acceso (cognito) logins');

  const svc = new Service({ ...opts, maxBodyBytes: limits.maxEnvelopeBytes });
  const quota = { maxArchives: limits.maxArchives, maxBytes: limits.maxBytes };

  const owner = async (req: Req): Promise<string> => {
    if (req.token !== undefined) {
      if (!opts.cognito) throw new HttpError(401, 'bearer tokens are not accepted by this deployment');
      let who;
      try {
        who = await opts.cognito.verify(req.token);
      } catch (e) {
        if (e instanceof CognitoTokenError) throw new HttpError(401, `invalid cognito token: ${e.message}`);
        throw e;
      }
      const account = `acceso:${who.issuer}#${who.subject}`;
      req.limitPrincipal(account);
      return account;
    }
    if (nip98 === 'off') throw new HttpError(403, 'this vault only accepts Acceso logins');
    if (nip98 === 'allowlist' && !allowed.has(req.pubkey!)) throw new HttpError(403, 'this key is not allowed to use this vault');
    return `nostr:${req.pubkey}`;
  };

  const archiveParam = (req: Req): string => {
    const id = req.params.id!;
    if (!isArchiveId(id)) throw new HttpError(400, 'archive id must be 64 hex characters');
    return id;
  };

  // Best effort: an object that cannot be deleted stays orphaned (no row points to it) until a sweep.
  const discard = async (keys: string[]) => {
    let failed = 0;
    for (let i = 0; i < keys.length; i += 32)
      await Promise.all(
        keys.slice(i, i + 32).map((k) =>
          objects.delete(k).catch(() => {
            failed++;
          }),
        ),
      );
    if (failed) svc.logger.warn('vault objects left orphaned', { count: failed });
  };

  svc.get('/health', () => ({ ok: true }), 'none', { rateClass: 'none' });

  svc.put(
    '/v1/archives/:id',
    async (req) => {
      const account = await owner(req);
      const id = archiveParam(req);
      let v;
      try {
        v = validateArchiveEnvelope(req.rawBody, limits.maxEnvelopeBytes);
      } catch (e) {
        if (e instanceof ArchiveEnvelopeError) throw new HttpError(e.message.startsWith('archive too large') ? 413 : 400, e.message);
        throw e;
      }
      // The object is written first: a row never points to an object that is not there.
      const objectKey = newObjectKey();
      await objects.put(objectKey, new TextEncoder().encode(req.rawBody));
      let stored;
      try {
        stored = await repo.upsert({ owner: account, archiveId: id, keyId: v.keyId, size: v.size, sha256: sha256(req.rawBody), objectKey }, quota, new Date().toISOString());
      } catch (e) {
        await discard([objectKey]);
        if (e instanceof QuotaExceededError) throw new HttpError(507, 'vault quota exceeded: delete archives or ask the operator for more space');
        throw e;
      }
      if (stored.replacedObject) await discard([stored.replacedObject]);
      return { status: stored.created ? 201 : 200, body: { archive: meta(stored.row) } };
    },
    'nip98-or-token',
  );

  svc.get(
    '/v1/archives',
    async (req) => {
      const account = await owner(req);
      const after = req.query.get('after') ?? undefined;
      if (after !== undefined && !isArchiveId(after)) throw new HttpError(400, 'after must be an archive id');
      const limitParam = req.query.get('limit');
      const limit = limitParam === null ? 100 : Number(limitParam);
      if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw new HttpError(400, 'limit must be an integer from 1 to 1000');
      const rows = await repo.list(account, after, limit + 1);
      const page = rows.slice(0, limit);
      return { archives: page.map(meta), ...(rows.length > limit ? { next: page[page.length - 1]!.archiveId } : {}) };
    },
    'nip98-or-token',
  );

  svc.get(
    '/v1/archives/:id',
    async (req) => {
      const account = await owner(req);
      const id = archiveParam(req);
      // A concurrent replace may delete the object between the two reads: look the row up again once.
      for (let attempt = 0; attempt < 2; attempt++) {
        const row = await repo.get(account, id);
        if (!row) break;
        const data = await objects.get(row.objectKey);
        if (!data) continue;
        const envelope = new TextDecoder().decode(data);
        if (sha256(envelope) !== row.sha256) {
          svc.logger.error('vault object does not match its checksum');
          throw new HttpError(500, 'archive content unavailable');
        }
        return { archive: meta(row), envelope };
      }
      const row = await repo.get(account, id);
      if (!row) throw new HttpError(404, 'archive not found');
      svc.logger.error('vault object missing');
      throw new HttpError(500, 'archive content unavailable');
    },
    'nip98-or-token',
  );

  const remove = async (req: Req) => {
    const account = await owner(req);
    const id = req.params.id === undefined ? undefined : archiveParam(req);
    const keys = await repo.delete(account, id);
    if (id !== undefined && !keys.length) throw new HttpError(404, 'archive not found');
    await discard(keys);
    return { deleted: keys.length };
  };
  svc.delete('/v1/archives', remove, 'nip98-or-token');
  svc.delete('/v1/archives/:id', remove, 'nip98-or-token');

  svc.get(
    '/v1/usage',
    async (req) => ({ ...(await repo.usage(await owner(req))), limits: { max_archives: limits.maxArchives, max_bytes: limits.maxBytes, max_envelope_bytes: limits.maxEnvelopeBytes } }),
    'nip98-or-token',
  );

  return svc;
}
