import { spawn } from 'node:child_process';
import { createCipheriv, createDecipheriv, createHash, generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto';
import { generateSecretKey, getPublicKey, isHex, nip49, selfTestKey, wipe, type EventTemplate } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { decodeCoseSign1 } from './attestation';
import { decodeCbor } from './cbor';
import { decryptEnvelopedData } from './cms';
import type { EnclaveKms } from './kms';
import { UserProofError, type UserProofVerifier } from './proof';
import type { AwsCredentials, EnclaveRequest, EnclaveResponse, RequestHandler } from './protocol';

/** Nitro Secure Module: produces attestation documents signed by the Nitro hypervisor. */
export interface Nsm {
  attest(req: { publicKey?: Uint8Array; nonce?: Uint8Array; userData?: Uint8Array }): Promise<Uint8Array>;
}

/**
 * NSM through an external helper built from aws-nitro-enclaves-nsm-api (Node cannot issue the /dev/nsm
 * ioctl). Contract: JSON `{public_key, nonce, user_data}` (base64, optional) on stdin, base64 CBOR document
 * on stdout. Not exercised here: it needs a real enclave (docs/managed-enclave.md).
 */
export class ExecNsm implements Nsm {
  constructor(private readonly helper: string) {}
  attest(req: { publicKey?: Uint8Array; nonce?: Uint8Array; userData?: Uint8Array }): Promise<Uint8Array> {
    const b64 = (b?: Uint8Array) => (b ? Buffer.from(b).toString('base64') : undefined);
    return new Promise((resolve, reject) => {
      const p = spawn(this.helper, [], { stdio: ['pipe', 'pipe', 'inherit'] });
      let out = '';
      p.stdout.setEncoding('utf8').on('data', (d: string) => (out += d));
      p.on('error', reject);
      p.on('close', (code) => (code === 0 ? resolve(new Uint8Array(Buffer.from(out.trim(), 'base64'))) : reject(new Error(`nsm helper exited with ${code}`))));
      p.stdin.end(JSON.stringify({ public_key: b64(req.publicKey), nonce: b64(req.nonce), user_data: b64(req.userData) }));
    });
  }
}

interface Sealed {
  /** 1: bound to the pubkey only (readable, never exportable); 2: also bound to its owner (FR005-09). */
  v: 1 | 2;
  alg: 'AES-256-GCM';
  /** KMS CiphertextBlob of the data key (only an attested enclave can get it back). */
  edk: string;
  iv: string;
  ct: string;
  tag: string;
  /** v2: `ownerTag` of the key owner, inside the KMS encryption context and the GCM AAD. */
  ot?: string;
}

export interface EnclaveSignerOptions {
  nsm: Nsm;
  kms: EnclaveKms;
  /** KMS key whose policy is conditioned on this enclave's measurements. */
  kmsKeyId: string;
  /**
   * FR-026 export (password-encrypted ncryptsec). Off unless explicitly enabled, and even then only against a proof of
   * the key owner (`proof`): without a verifier the enclave refuses every export (IR-2026-09-01, FR005-09).
   */
  allowExport?: boolean;
  /** Verifier of the owner's Acceso token, with the user pool's signing keys pinned in the image. */
  proof?: UserProofVerifier;
  /** How many accepted proofs the enclave remembers at once (default 10000); when full, it refuses rather than forget one. */
  maxRememberedProofs?: number;
}

/** A request the enclave turns down for what it is, not for a failure of its own: the parent relays the status. */
export class EnclaveRefusal extends Error {
  constructor(readonly status: 400 | 401 | 403, message: string) {
    super(message);
  }
}

/** Same cap as the parent (service.ts): scrypt memory must fit in the enclave. */
const MAX_IMPORT_LOG_N = 18;
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));
const context = (pubkey: string, ot?: string) => ({ app: 'acceso-nostr', purpose: 'enclave-key', pubkey, ...(ot ? { owner_tag: ot } : {}) });
const aad = (pubkey: string, ot?: string) => Buffer.from(`acceso-nostr/enclave-key/${pubkey}${ot ? `/${ot}` : ''}`);
/**
 * What binds a sealed key to its owner. A hash, not the owner: the encryption context is written in clear to CloudTrail,
 * which already sees the pubkey, and must not also name the Acceso account behind it.
 */
export const ownerTag = (owner: string) => createHash('sha256').update(`acceso-nostr/owner/v1|${owner}`).digest('hex');
const OWNER_MAX = 512;
const OWNER_TAG = /^[0-9a-f]{64}$/;
/** Proofs accepted and not yet expired; bounded, and full means refuse (never forget a token that could be replayed). */
const DEFAULT_REMEMBERED_PROOFS = 10_000;

function checkTemplate(t: unknown): asserts t is EventTemplate {
  const x = t as EventTemplate;
  if (!x || !Number.isInteger(x.kind) || x.kind < 0 || typeof x.content !== 'string' || (x.tags !== undefined && !Array.isArray(x.tags))) throw new Error('invalid event template');
}

function checkOwner(owner: unknown): string {
  if (typeof owner !== 'string' || owner.length === 0 || owner.length > OWNER_MAX) throw new EnclaveRefusal(400, 'owner is required');
  return owner;
}

function parseSealed(sealedB64: string): Sealed {
  let s: Sealed;
  try {
    s = JSON.parse(Buffer.from(sealedB64, 'base64').toString('utf8')) as Sealed;
  } catch {
    throw new Error('unsupported sealed key');
  }
  const text = (v: unknown) => typeof v === 'string' && v.length > 0;
  if (!s || (s.v !== 1 && s.v !== 2) || s.alg !== 'AES-256-GCM' || !text(s.edk) || !text(s.iv) || !text(s.ct) || !text(s.tag)) throw new Error('unsupported sealed key');
  if (s.v === 2 ? typeof s.ot !== 'string' || !OWNER_TAG.test(s.ot) : s.ot !== undefined) throw new Error('unsupported sealed key');
  return s;
}

/**
 * Signing program that runs inside the Nitro Enclave. Nostr secrets exist only here, in memory, for the
 * duration of one operation: they are sealed with AES-256-GCM under a KMS data key that KMS only releases
 * encrypted to this enclave's ephemeral RSA key, bound to its attestation (PCRs).
 */
export class EnclaveSigner implements RequestHandler {
  private readonly rsa: { publicKey: KeyObject; privateKey: KeyObject };
  private readonly spki: Uint8Array;
  /** `jti` -> expiry (seconds) of the proofs already used: one token lets one key out once. Memory only. */
  private readonly usedProofs = new Map<string, number>();

  constructor(private readonly opts: EnclaveSignerOptions) {
    // Ephemeral per boot: never leaves the enclave; its public half goes into every attestation document.
    this.rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    this.spki = new Uint8Array(this.rsa.publicKey.export({ type: 'spki', format: 'der' }));
  }

  private attestation(nonce?: Uint8Array) {
    return this.opts.nsm.attest({ publicKey: this.spki, ...(nonce ? { nonce } : {}) });
  }

  /**
   * The enclave's clock: the timestamp of a document its own NSM just produced. The parent supplies no time and cannot
   * bend this one (an enclave has no clock of its own to trust), so a stolen token cannot be aged back into validity.
   */
  private async trustedNow(): Promise<number> {
    const { payload } = decodeCoseSign1(await this.attestation());
    const body = decodeCbor(payload);
    const ts = body instanceof Map ? body.get('timestamp') : undefined;
    if (typeof ts !== 'number' || !Number.isFinite(ts) || ts <= 0) throw new Error('NSM document carries no timestamp');
    return ts;
  }

  private async seal(sk: Uint8Array, pubkey: string, owner: string, credentials?: AwsCredentials): Promise<string> {
    const ot = ownerTag(owner);
    const attestationDocument = await this.attestation();
    const dk = await this.opts.kms.generateDataKey({ keyId: this.opts.kmsKeyId, context: context(pubkey, ot), attestationDocument, ...(credentials ? { credentials } : {}) });
    const key = decryptEnvelopedData(dk.ciphertextForRecipient, this.rsa.privateKey);
    try {
      if (key.length !== 32) throw new Error('unexpected data key size');
      const iv = randomBytes(12);
      const c = createCipheriv('aes-256-gcm', key, iv);
      c.setAAD(aad(pubkey, ot));
      const ct = Buffer.concat([c.update(sk), c.final()]);
      const sealed: Sealed = { v: 2, alg: 'AES-256-GCM', edk: b64(dk.ciphertextBlob), iv: b64(iv), ct: b64(ct), tag: b64(c.getAuthTag()), ot };
      return b64(Buffer.from(JSON.stringify(sealed)));
    } finally {
      key.fill(0);
    }
  }

  private async unseal(s: Sealed, pubkey: string, credentials?: AwsCredentials): Promise<Uint8Array> {
    if (!isHex(pubkey, 32)) throw new Error('invalid pubkey');
    const attestationDocument = await this.attestation();
    const out = await this.opts.kms.decrypt({ keyId: this.opts.kmsKeyId, ciphertextBlob: unb64(s.edk), context: context(pubkey, s.ot), attestationDocument, ...(credentials ? { credentials } : {}) });
    const key = decryptEnvelopedData(out.ciphertextForRecipient, this.rsa.privateKey);
    let sk: Uint8Array | undefined;
    try {
      const d = createDecipheriv('aes-256-gcm', key, unb64(s.iv), { authTagLength: 16 });
      d.setAAD(aad(pubkey, s.ot));
      d.setAuthTag(unb64(s.tag));
      sk = new Uint8Array(Buffer.concat([d.update(unb64(s.ct)), d.final()]));
    } finally {
      key.fill(0);
    }
    // Binds the blob to the pubkey the parent claims (the KMS context already does; defense in depth).
    if (getPublicKey(sk) !== pubkey) {
      wipe(sk);
      throw new Error('sealed key does not match pubkey');
    }
    return sk;
  }

  private async withSigner<T>(sealed: string, pubkey: string, credentials: AwsCredentials | undefined, fn: (s: LocalSigner) => Promise<T>): Promise<T> {
    const sk = await this.unseal(parseSealed(sealed), pubkey, credentials);
    const signer = new LocalSigner(sk, 'managed-enclave');
    wipe(sk);
    try {
      return await fn(signer);
    } finally {
      signer.destroy();
    }
  }

  private async store(sk: Uint8Array, owner: string, credentials?: AwsCredentials) {
    try {
      if (!selfTestKey(sk).ok) throw new Error('key self-test failed');
      const pubkey = getPublicKey(sk);
      return { pubkey, sealed: await this.seal(sk, pubkey, owner, credentials) };
    } finally {
      wipe(sk);
    }
  }

  /**
   * FR005-09: the export proof. The owner's Acceso token is verified here, against keys pinned in the image and the
   * enclave's own clock, and has to be that of the owner the key was sealed for. Nothing the parent can relay or
   * fabricate passes: a token of another user, an expired or stale sign-in, or one that was already used.
   */
  private async checkExportProof(token: unknown, sealed: Sealed): Promise<void> {
    const verifier = this.opts.proof;
    if (!verifier) throw new EnclaveRefusal(403, 'export needs a proof of the key owner and this enclave has no verifier configured');
    if (typeof token !== 'string' || !token) throw new EnclaveRefusal(401, 'export needs the owner\'s Acceso token as proof');
    const nowMs = await this.trustedNow();
    let proof;
    try {
      proof = verifier.verify(token, nowMs);
    } catch (err) {
      if (err instanceof UserProofError) throw new EnclaveRefusal(401, err.message);
      throw err;
    }
    // A v1 blob names no owner: nothing ties it to whoever holds a valid token, so it cannot leave.
    if (sealed.v !== 2 || !sealed.ot) throw new EnclaveRefusal(403, 'this sealed key has no owner binding: it cannot be exported');
    if (sealed.ot !== ownerTag(proof.owner)) throw new EnclaveRefusal(403, 'the proof is not from the owner of this key');
    // Consumed here, after the checks that can fail for reasons of the request, and before anything that touches KMS.
    const nowS = Math.floor(nowMs / 1000);
    for (const [jti, exp] of this.usedProofs) if (exp <= nowS) this.usedProofs.delete(jti);
    if (this.usedProofs.has(proof.jti)) throw new EnclaveRefusal(401, 'proof: this token was already used: sign in again');
    if (this.usedProofs.size >= (this.opts.maxRememberedProofs ?? DEFAULT_REMEMBERED_PROOFS)) throw new EnclaveRefusal(403, 'proof: too many proofs in flight, try again later');
    this.usedProofs.set(proof.jti, proof.expiresAt);
  }

  async handle(req: EnclaveRequest): Promise<EnclaveResponse> {
    try {
      const creds = 'credentials' in req ? req.credentials : undefined;
      switch (req.op) {
        case 'attest': {
          const nonce = unb64(req.nonce);
          if (nonce.length < 16 || nonce.length > 64) throw new Error('nonce must be 16-64 bytes');
          return { ok: true, document: b64(await this.attestation(nonce)) };
        }
        case 'generate': {
          const owner = checkOwner(req.owner);
          return { ok: true, ...(await this.store(generateSecretKey(), owner, creds)) };
        }
        case 'import': {
          const owner = checkOwner(req.owner);
          let secretKey: Uint8Array;
          try {
            ({ secretKey } = await nip49.decryptKeyAsync(req.ncryptsec, req.password, { maxLogN: MAX_IMPORT_LOG_N }));
          } catch {
            throw new EnclaveRefusal(400, 'cannot decrypt ncryptsec (wrong password or corrupted payload)');
          }
          return { ok: true, ...(await this.store(secretKey, owner, creds)) };
        }
        case 'sign': {
          checkTemplate(req.template);
          const t = req.template;
          const event = await this.withSigner(req.sealed, req.pubkey, creds, (s) => s.signEvent({ kind: t.kind, content: t.content, tags: t.tags ?? [], created_at: t.created_at }));
          return { ok: true, event };
        }
        case 'nip44': {
          if (!isHex(req.peer, 32)) throw new Error('invalid peer pubkey');
          const result = await this.withSigner(req.sealed, req.pubkey, creds, (s) => (req.mode === 'encrypt' ? s.nip44Encrypt(req.peer, req.data) : s.nip44Decrypt(req.peer, req.data)));
          return { ok: true, result };
        }
        case 'export': {
          if (this.opts.allowExport !== true) throw new EnclaveRefusal(403, 'export disabled');
          if (typeof req.password !== 'string' || req.password.length < 12) throw new EnclaveRefusal(400, 'export password must be at least 12 characters');
          if (!Number.isInteger(req.logN) || req.logN < 1 || req.logN > 22) throw new EnclaveRefusal(400, 'invalid logN');
          const sealed = parseSealed(req.sealed);
          await this.checkExportProof(req.proof, sealed);
          const sk = await this.unseal(sealed, req.pubkey, creds);
          try {
            return { ok: true, ncryptsec: await nip49.encryptKeyAsync(sk, req.password, req.logN, 0x00) };
          } finally {
            wipe(sk);
          }
        }
        default:
          throw new Error('unknown op');
      }
    } catch (err) {
      return { ok: false, error: (err as Error).message, ...(err instanceof EnclaveRefusal ? { status: err.status } : {}) };
    }
  }
}
