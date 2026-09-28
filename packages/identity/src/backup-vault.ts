/**
 * FR027-03: cloud vault for encrypted backups. The vault (identity-service `/v1/backups`) only ever
 * stores the backup envelope as produced by the client: the key (NIP-49) and the sealed contents are
 * encrypted with the user's backup password, which never leaves the device.
 *
 * `validateBackupEnvelope` is shared by client and server: it accepts only the known encrypted
 * formats with an exact field allowlist, so a plaintext key (nsec, hex) or a clear persona can never be
 * uploaded by mistake. Browser-safe: only nostr-core primitives.
 */
import { nip19, nip98, type Signer } from '@sedecim/nostr-core';

export type VaultBackupFormat = 'sedecim-identity-backup' | 'acceso-nostr-key-backup';

export interface VaultBackupMeta {
  id: string;
  format: VaultBackupFormat;
  format_version: number;
  /** Size of the stored envelope in bytes (UTF-8). */
  size: number;
  /** sha256 (hex) of the stored envelope text. */
  sha256: string;
  /** npub declared in clear by the envelope itself (acceso-nostr-key-backup), if any. */
  npub?: string;
  created_at: string;
}

export class BackupEnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BackupEnvelopeError';
  }
}

/** Default cap on the stored envelope (v2 backups carry the encrypted MLS state). */
export const MAX_VAULT_BACKUP_BYTES = 512 * 1024;

const NCRYPTSEC = /^ncryptsec1[023456789acdefghjklmnpqrstuvwxyz]{152}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
// Defense in depth over the raw text: a bech32 nsec or a 32-byte hex string never belongs in an envelope.
const NSEC = /nsec1[023456789acdefghjklmnpqrstuvwxyz]{58}/i;
// Any run of >= 64 hex digits (a key glued to other hex digits must not slip through: found by SEC-03 fuzz).
const HEX64 = /[0-9a-f]{64}/i;
const FIELDS: Record<string, Record<number, { required: string[]; optional: string[] }>> = {
  'sedecim-identity-backup': { 2: { required: ['format', 'version', 'contentKey', 'sealed', 'createdAt'], optional: ['ncryptsec'] } },
  'acceso-nostr-key-backup': {
    1: { required: ['format', 'version', 'npub', 'ncryptsec'], optional: [] },
    // VAULT-02: the archive key; the persona key is absent for a persona whose key lives in a signer.
    2: { required: ['format', 'version', 'npub'], optional: ['ncryptsec', 'archiveKey'] },
  },
};

/**
 * Checks that `text` is a well-formed ENCRYPTED backup envelope (without decrypting it) and returns its
 * metadata. Throws BackupEnvelopeError with a reason that never echoes the content.
 */
export function validateBackupEnvelope(text: string, maxBytes = MAX_VAULT_BACKUP_BYTES): { format: VaultBackupFormat; formatVersion: number; size: number; npub?: string } {
  if (typeof text !== 'string') throw new BackupEnvelopeError('backup must be JSON text');
  const size = new TextEncoder().encode(text).length;
  if (size > maxBytes) throw new BackupEnvelopeError(`backup too large (${size} > ${maxBytes} bytes)`);
  if (NSEC.test(text)) throw new BackupEnvelopeError('backup contains a plaintext nsec');
  if (HEX64.test(text)) throw new BackupEnvelopeError('backup contains a 32-byte hex value (possible plaintext key)');
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw new BackupEnvelopeError('backup is not valid JSON');
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new BackupEnvelopeError('backup must be a JSON object');
  const o = v as Record<string, unknown>;
  const specs = typeof o.format === 'string' && Object.hasOwn(FIELDS, o.format) ? FIELDS[o.format] : undefined;
  if (!specs) throw new BackupEnvelopeError('unsupported backup format (only encrypted backups are accepted)');
  const spec = typeof o.version === 'number' && Object.hasOwn(specs, o.version) ? specs[o.version] : undefined;
  if (!spec) throw new BackupEnvelopeError(`unsupported ${String(o.format)} version`);
  for (const k of Object.keys(o)) if (!spec.required.includes(k) && !spec.optional.includes(k)) throw new BackupEnvelopeError(`field "${k}" not allowed in an encrypted backup`);
  for (const k of spec.required) if (o[k] === undefined) throw new BackupEnvelopeError(`missing field: ${k}`);
  if (o.ncryptsec !== undefined && (typeof o.ncryptsec !== 'string' || !NCRYPTSEC.test(o.ncryptsec))) throw new BackupEnvelopeError('ncryptsec is not a NIP-49 string');
  if (o.archiveKey !== undefined && (typeof o.archiveKey !== 'string' || !NCRYPTSEC.test(o.archiveKey))) throw new BackupEnvelopeError('archiveKey is not a NIP-49 string');
  if (o.format === 'acceso-nostr-key-backup' && o.ncryptsec === undefined && o.archiveKey === undefined) throw new BackupEnvelopeError('backup has neither a key nor an archive key');
  let npub: string | undefined;
  if (o.format === 'sedecim-identity-backup') {
    if (typeof o.contentKey !== 'string' || !NCRYPTSEC.test(o.contentKey)) throw new BackupEnvelopeError('contentKey is not a NIP-49 string');
    if (typeof o.createdAt !== 'number' || !Number.isFinite(o.createdAt) || o.createdAt < 0) throw new BackupEnvelopeError('invalid createdAt');
    // nonce (24) + Poly1305 tag (16) + at least a minimal JSON payload.
    if (typeof o.sealed !== 'string' || !BASE64.test(o.sealed) || (o.sealed.length / 4) * 3 < 24 + 16 + 2) throw new BackupEnvelopeError('sealed is not an XChaCha20-Poly1305 payload');
  } else {
    try {
      const d = nip19.decode(String(o.npub));
      if (d.type !== 'npub') throw new Error();
      npub = String(o.npub);
    } catch {
      throw new BackupEnvelopeError('npub is not a valid npub');
    }
  }
  return { format: o.format as VaultBackupFormat, formatVersion: o.version as number, size, ...(npub ? { npub } : {}) };
}

/** How the client proves who owns the backups: its Nostr key (NIP-98) or an Acceso token (SaaS). */
export type BackupVaultAuth = { signer: Signer } | { token: () => Promise<string> };

export interface BackupVaultOptions {
  /** identity-service base URL */
  baseUrl: string;
  auth: BackupVaultAuth;
  fetch?: typeof fetch;
}

/** Client for the encrypted backup vault. Validates locally before uploading and verifies sha256 on download. */
export class BackupVaultClient {
  private readonly base: string;
  private readonly fetch: typeof fetch;

  constructor(private readonly opts: BackupVaultOptions) {
    this.base = opts.baseUrl.replace(/\/$/, '');
    this.fetch = opts.fetch ?? ((...a) => globalThis.fetch(...a));
  }

  private async request<T>(path: string, method = 'GET', body?: string): Promise<T> {
    const url = `${this.base}${path}`;
    const auth = this.opts.auth;
    const authorization = 'signer' in auth ? nip98.encodeAuthHeader(await auth.signer.signEvent(nip98.buildHttpAuthTemplate(url, method, body))) : `Bearer ${await auth.token()}`;
    const res = await this.fetch(url, { method, headers: { authorization, 'content-type': 'application/json' }, ...(body !== undefined ? { body } : {}) });
    const text = await res.text();
    const json = text ? JSON.parse(text) : undefined;
    if (!res.ok) throw new BackupVaultError(res.status, json?.error ?? `HTTP ${res.status}`);
    return json as T;
  }

  /** Uploads an encrypted backup envelope (object or JSON text); the server keeps the last few versions. */
  async upload(envelope: unknown): Promise<VaultBackupMeta> {
    const text = typeof envelope === 'string' ? envelope : JSON.stringify(envelope);
    validateBackupEnvelope(text);
    return (await this.request<{ backup: VaultBackupMeta }>('/v1/backups', 'POST', text)).backup;
  }

  async list(): Promise<VaultBackupMeta[]> {
    return (await this.request<{ backups: VaultBackupMeta[] }>('/v1/backups')).backups;
  }

  /** Downloads one backup (default: the newest) as the exact envelope text that was uploaded. */
  async download(id = 'latest'): Promise<{ meta: VaultBackupMeta; envelope: string }> {
    const r = await this.request<{ backup: VaultBackupMeta; envelope: string }>(`/v1/backups/${encodeURIComponent(id)}`);
    if (nip98.payloadHash(r.envelope) !== r.backup.sha256) throw new BackupEnvelopeError('downloaded backup does not match its sha256');
    validateBackupEnvelope(r.envelope, Infinity);
    return { meta: r.backup, envelope: r.envelope };
  }

  /** Deletes one version, or every backup of the account when no id is given. */
  async remove(id?: string): Promise<number> {
    return (await this.request<{ deleted: number }>(id ? `/v1/backups/${encodeURIComponent(id)}` : '/v1/backups', 'DELETE')).deleted;
  }
}

export class BackupVaultError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'BackupVaultError';
  }
}

/** Convenience wrappers (FR027-03). */
export const uploadBackup = (opts: BackupVaultOptions, envelope: unknown) => new BackupVaultClient(opts).upload(envelope);
export const downloadBackup = (opts: BackupVaultOptions, id?: string) => new BackupVaultClient(opts).download(id);
