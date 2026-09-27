import { spawn } from 'node:child_process';
import { createCipheriv, createDecipheriv, generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto';
import { generateSecretKey, getPublicKey, isHex, nip49, selfTestKey, wipe, type EventTemplate } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { decryptEnvelopedData } from './cms';
import type { EnclaveKms } from './kms';
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
  v: 1;
  alg: 'AES-256-GCM';
  /** KMS CiphertextBlob of the data key (only an attested enclave can get it back). */
  edk: string;
  iv: string;
  ct: string;
  tag: string;
}

export interface EnclaveSignerOptions {
  nsm: Nsm;
  kms: EnclaveKms;
  /** KMS key whose policy is conditioned on this enclave's measurements. */
  kmsKeyId: string;
  /**
   * FR-026 export (password-encrypted ncryptsec). Off unless explicitly enabled: the password comes from the
   * parent, so with export on a compromised backend can exfiltrate every sealed key (IR-2026-09-01).
   */
  allowExport?: boolean;
}

/** Same cap as the parent (service.ts): scrypt memory must fit in the enclave. */
const MAX_IMPORT_LOG_N = 18;
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));
const context = (pubkey: string) => ({ app: 'acceso-nostr', purpose: 'enclave-key', pubkey });
const aad = (pubkey: string) => Buffer.from(`acceso-nostr/enclave-key/${pubkey}`);

function checkTemplate(t: unknown): asserts t is EventTemplate {
  const x = t as EventTemplate;
  if (!x || !Number.isInteger(x.kind) || x.kind < 0 || typeof x.content !== 'string' || (x.tags !== undefined && !Array.isArray(x.tags))) throw new Error('invalid event template');
}

/**
 * Signing program that runs inside the Nitro Enclave. Nostr secrets exist only here, in memory, for the
 * duration of one operation: they are sealed with AES-256-GCM under a KMS data key that KMS only releases
 * encrypted to this enclave's ephemeral RSA key, bound to its attestation (PCRs).
 */
export class EnclaveSigner implements RequestHandler {
  private readonly rsa: { publicKey: KeyObject; privateKey: KeyObject };
  private readonly spki: Uint8Array;

  constructor(private readonly opts: EnclaveSignerOptions) {
    // Ephemeral per boot: never leaves the enclave; its public half goes into every attestation document.
    this.rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    this.spki = new Uint8Array(this.rsa.publicKey.export({ type: 'spki', format: 'der' }));
  }

  private attestation(nonce?: Uint8Array) {
    return this.opts.nsm.attest({ publicKey: this.spki, ...(nonce ? { nonce } : {}) });
  }

  private async seal(sk: Uint8Array, pubkey: string, credentials?: AwsCredentials): Promise<string> {
    const attestationDocument = await this.attestation();
    const dk = await this.opts.kms.generateDataKey({ keyId: this.opts.kmsKeyId, context: context(pubkey), attestationDocument, ...(credentials ? { credentials } : {}) });
    const key = decryptEnvelopedData(dk.ciphertextForRecipient, this.rsa.privateKey);
    try {
      if (key.length !== 32) throw new Error('unexpected data key size');
      const iv = randomBytes(12);
      const c = createCipheriv('aes-256-gcm', key, iv);
      c.setAAD(aad(pubkey));
      const ct = Buffer.concat([c.update(sk), c.final()]);
      const sealed: Sealed = { v: 1, alg: 'AES-256-GCM', edk: b64(dk.ciphertextBlob), iv: b64(iv), ct: b64(ct), tag: b64(c.getAuthTag()) };
      return b64(Buffer.from(JSON.stringify(sealed)));
    } finally {
      key.fill(0);
    }
  }

  private async unseal(sealedB64: string, pubkey: string, credentials?: AwsCredentials): Promise<Uint8Array> {
    if (!isHex(pubkey, 32)) throw new Error('invalid pubkey');
    const s = JSON.parse(Buffer.from(sealedB64, 'base64').toString('utf8')) as Sealed;
    if (s.v !== 1 || s.alg !== 'AES-256-GCM') throw new Error('unsupported sealed key');
    const attestationDocument = await this.attestation();
    const out = await this.opts.kms.decrypt({ keyId: this.opts.kmsKeyId, ciphertextBlob: unb64(s.edk), context: context(pubkey), attestationDocument, ...(credentials ? { credentials } : {}) });
    const key = decryptEnvelopedData(out.ciphertextForRecipient, this.rsa.privateKey);
    let sk: Uint8Array | undefined;
    try {
      const d = createDecipheriv('aes-256-gcm', key, unb64(s.iv), { authTagLength: 16 });
      d.setAAD(aad(pubkey));
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
    const sk = await this.unseal(sealed, pubkey, credentials);
    const signer = new LocalSigner(sk, 'managed-enclave');
    wipe(sk);
    try {
      return await fn(signer);
    } finally {
      signer.destroy();
    }
  }

  private async store(sk: Uint8Array, credentials?: AwsCredentials) {
    try {
      if (!selfTestKey(sk).ok) throw new Error('key self-test failed');
      const pubkey = getPublicKey(sk);
      return { pubkey, sealed: await this.seal(sk, pubkey, credentials) };
    } finally {
      wipe(sk);
    }
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
        case 'generate':
          return { ok: true, ...(await this.store(generateSecretKey(), creds)) };
        case 'import': {
          const { secretKey } = await nip49.decryptKeyAsync(req.ncryptsec, req.password, { maxLogN: MAX_IMPORT_LOG_N });
          return { ok: true, ...(await this.store(secretKey, creds)) };
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
          if (this.opts.allowExport !== true) throw new Error('export disabled');
          if (typeof req.password !== 'string' || req.password.length < 12) throw new Error('export password must be at least 12 characters');
          if (!Number.isInteger(req.logN) || req.logN < 1 || req.logN > 22) throw new Error('invalid logN');
          const sk = await this.unseal(req.sealed, req.pubkey, creds);
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
      return { ok: false, error: (err as Error).message };
    }
  }
}
