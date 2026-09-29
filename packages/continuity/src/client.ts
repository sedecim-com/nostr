import { finalizeEvent, getPublicKey, nip98, toUnsigned, type EventTemplate, type NostrEvent } from '@sedecim/nostr-core';
import { ArchiveEnvelopeError, isArchiveId, validateArchiveEnvelope, type ArchiveEnvelope, type ArchiveMeta } from './envelope';
import { archiveAuthKey } from './seal';

/**
 * Which vault account the client uses (ADR 0011):
 * - `archiveKey`: NIP-98 signed with the key derived from the archive key (the default for personas);
 * - `signer`: NIP-98 with any other signer;
 * - `token`: an Acceso (Cognito) token, in SaaS deployments that accept it.
 */
export type ArchiveVaultAuth = { archiveKey: Uint8Array } | { signer: { signEvent(template: EventTemplate): Promise<NostrEvent> } } | { token: () => Promise<string> };

export interface ArchiveVaultOptions {
  /** continuity-vault base URL */
  baseUrl: string;
  auth: ArchiveVaultAuth;
  fetch?: typeof fetch;
}

/**
 * VAULT-05: how long the account's archives are kept since their last write. `days` is the account's choice (null:
 * the operator's maximum), `max_days` the operator's, `effective_days` what applies (null: kept until deleted).
 */
export interface ArchiveRetention {
  days: number | null;
  max_days: number | null;
  effective_days: number | null;
}

export interface ArchiveUsage {
  archives: number;
  bytes: number;
  limits: { max_archives: number; max_bytes: number; max_envelope_bytes: number };
  /** Absent on vaults older than VAULT-05. */
  retention?: ArchiveRetention;
}

export class ArchiveVaultError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ArchiveVaultError';
  }
}

/** Client of the Continuity Vault. Validates envelopes before uploading and checks sha256 on download. */
export class ArchiveVaultClient {
  private readonly base: string;
  private readonly fetch: typeof fetch;

  constructor(private readonly opts: ArchiveVaultOptions) {
    this.base = opts.baseUrl.replace(/\/$/, '');
    this.fetch = opts.fetch ?? ((...a) => globalThis.fetch(...a));
  }

  private async authorization(url: string, method: string, body?: string): Promise<string> {
    const auth = this.opts.auth;
    if ('token' in auth) return `Bearer ${await auth.token()}`;
    const template = nip98.buildHttpAuthTemplate(url, method, body);
    if ('signer' in auth) return nip98.encodeAuthHeader(await auth.signer.signEvent(template));
    const sk = archiveAuthKey(auth.archiveKey);
    try {
      return nip98.encodeAuthHeader(finalizeEvent(toUnsigned(template, getPublicKey(sk)), sk));
    } finally {
      sk.fill(0);
    }
  }

  private async request<T>(path: string, method = 'GET', body?: string): Promise<{ status: number; json: T }> {
    const url = `${this.base}${path}`;
    const authorization = await this.authorization(url, method, body);
    const res = await this.fetch(url, { method, headers: { authorization, 'content-type': 'application/json' }, ...(body !== undefined ? { body } : {}) });
    const text = await res.text();
    let json: unknown;
    try {
      json = text ? JSON.parse(text) : undefined;
    } catch {
      json = undefined;
    }
    if (!res.ok) throw new ArchiveVaultError(res.status, (json as { error?: string } | undefined)?.error ?? `HTTP ${res.status}`);
    return { status: res.status, json: json as T };
  }

  /** Stores (or replaces) the envelope under `id`. Idempotent: retrying an upload never duplicates it. */
  async put(id: string, envelope: ArchiveEnvelope | string): Promise<{ archive: ArchiveMeta; created: boolean }> {
    if (!isArchiveId(id)) throw new ArchiveEnvelopeError('archive id must be 64 hex characters');
    const text = typeof envelope === 'string' ? envelope : JSON.stringify(envelope);
    validateArchiveEnvelope(text, Infinity);
    const r = await this.request<{ archive: ArchiveMeta }>(`/v1/archives/${id}`, 'PUT', text);
    return { archive: r.json.archive, created: r.status === 201 };
  }

  /** One page of archive metadata, ordered by id; pass `next` back as `after` for the following page. */
  async list(opts: { after?: string; limit?: number } = {}): Promise<{ archives: ArchiveMeta[]; next?: string }> {
    const q = new URLSearchParams();
    if (opts.after) q.set('after', opts.after);
    if (opts.limit) q.set('limit', String(opts.limit));
    const qs = q.toString();
    return (await this.request<{ archives: ArchiveMeta[]; next?: string }>(`/v1/archives${qs ? `?${qs}` : ''}`)).json;
  }

  /** Every archive of the account (follows the pages). */
  async listAll(): Promise<ArchiveMeta[]> {
    const all: ArchiveMeta[] = [];
    let after: string | undefined;
    do {
      const page = await this.list({ ...(after ? { after } : {}), limit: 1000 });
      all.push(...page.archives);
      after = page.next;
    } while (after);
    return all;
  }

  /** Downloads the exact envelope text that was stored under `id`. */
  async get(id: string): Promise<{ meta: ArchiveMeta; envelope: string }> {
    if (!isArchiveId(id)) throw new ArchiveEnvelopeError('archive id must be 64 hex characters');
    const { json } = await this.request<{ archive: ArchiveMeta; envelope: string }>(`/v1/archives/${id}`);
    if (json.archive.id !== id || nip98.payloadHash(json.envelope) !== json.archive.sha256) throw new ArchiveEnvelopeError('downloaded archive does not match its metadata');
    validateArchiveEnvelope(json.envelope, Infinity);
    return { meta: json.archive, envelope: json.envelope };
  }

  /** Deletes one archive, or every archive of the account when no id is given. Returns how many. */
  async remove(id?: string): Promise<number> {
    if (id !== undefined && !isArchiveId(id)) throw new ArchiveEnvelopeError('archive id must be 64 hex characters');
    return (await this.request<{ deleted: number }>(id ? `/v1/archives/${id}` : '/v1/archives', 'DELETE')).json.deleted;
  }

  /** What the account uses and the limits of this vault. */
  async usage(): Promise<ArchiveUsage> {
    return (await this.request<ArchiveUsage>('/v1/usage')).json;
  }

  /** VAULT-05: keep the account's archives `days` since their last write (null: the operator's maximum). */
  async setRetention(days: number | null): Promise<ArchiveRetention> {
    return (await this.request<{ retention: ArchiveRetention }>('/v1/retention', 'PUT', JSON.stringify({ days }))).json.retention;
  }
}
