import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp } from 'node:fs/promises';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bytesToHex, finalizeEvent, generateSecretKey, getPublicKey, nip49, toUnsigned, verifyEvent } from '@sedecim/nostr-core';
import { createTestCognito } from '@sedecim/service-kit';
import { LocalSigner } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import {
  AttestationError,
  awsEnclaveKms,
  createManagedSignerApi,
  createSimulatedEnclave,
  EnclaveClient,
  EnclaveSigner,
  enclaveBackendFromEnv,
  inProcessTransport,
  ManagedSigner,
  MemoryVault,
  serveEnclave,
  simulatedPcrs,
  socketTransport,
} from '../src/index';

describe('enclave signer over a local socket (vsock stand-in)', () => {
  const sim = createSimulatedEnclave();
  let server: Server;
  let client: EnclaveClient;

  beforeAll(async () => {
    const path = join(await mkdtemp(join(tmpdir(), 'enclave-')), 'signer.sock');
    server = await serveEnclave(sim.enclave, { path });
    client = new EnclaveClient({ transport: socketTransport({ path }), attestation: sim.policy });
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));

  it('verifies the enclave attestation with a fresh nonce', async () => {
    const att = await client.verify();
    expect(att.pcrs[0]).toBe(sim.pcrs[0]);
    expect(att.nonce).toHaveLength(32);
    expect(att.publicKey?.length).toBeGreaterThan(200);
  });

  it('generates a key inside the enclave and signs: the parent only gets a pubkey, a sealed blob and events', async () => {
    const { pubkey, sealed } = await client.generate();
    expect(pubkey).toMatch(/^[0-9a-f]{64}$/);
    const blob = JSON.parse(Buffer.from(Buffer.from(sealed).toString('utf8'), 'base64').toString('utf8')) as Record<string, string>;
    expect(Object.keys(blob).sort()).toEqual(['alg', 'ct', 'edk', 'iv', 'tag', 'v']);
    const signer = client.signer(sealed, pubkey);
    expect(signer.custody).toBe('managed-enclave');
    const evt = await signer.signEvent({ kind: 1, content: 'firmado en el enclave', tags: [['t', 'x']] });
    expect(verifyEvent(evt)).toBe(true);
    expect(evt.pubkey).toBe(pubkey);

    const peer = new LocalSigner(generateSecretKey());
    const ct = await signer.nip44Encrypt(await peer.getPublicKey(), 'hola');
    expect(await peer.nip44Decrypt(pubkey, ct)).toBe('hola');
    expect(await signer.nip44Decrypt(await peer.getPublicKey(), await peer.nip44Encrypt(pubkey, 'de vuelta'))).toBe('de vuelta');
    // Every unseal went through KMS with a verified attestation document.
    expect(sim.kms.calls.every((c) => c.ok)).toBe(true);
    expect(sim.kms.calls.filter((c) => c.op === 'decrypt').length).toBeGreaterThanOrEqual(3);
  });

  it('imports an ncryptsec without the plaintext reaching the sealed blob, and exports for FR-026', async () => {
    const sk = generateSecretKey();
    const { pubkey, sealed } = await client.importNcryptsec(nip49.encryptKey(sk, 'contraseña larga 123', 4), 'contraseña larga 123');
    expect(pubkey).toBe(getPublicKey(sk));
    const raw = Buffer.from(Buffer.from(Buffer.from(sealed).toString('utf8'), 'base64'));
    expect(raw.includes(Buffer.from(sk))).toBe(false);
    expect(raw.toString('utf8')).not.toContain(bytesToHex(sk));
    const exported = await client.exportNcryptsec(sealed, pubkey, 'otra contraseña larga', 4);
    expect(bytesToHex(nip49.decryptKey(exported, 'otra contraseña larga').secretKey)).toBe(bytesToHex(sk));
  });

  it('keeps FR-026 export off unless explicitly enabled (IR-2026-09-01)', async () => {
    const sim = createSimulatedEnclave();
    // Same NSM/KMS, but an enclave built with the production default.
    const locked = new EnclaveClient({ transport: inProcessTransport(new EnclaveSigner({ nsm: sim.nsm, kms: sim.kms, kmsKeyId: 'alias/simulated-enclave' })), attestation: sim.policy });
    const { pubkey, sealed } = await locked.generate();
    await expect(locked.exportNcryptsec(sealed, pubkey, 'una contraseña larga', 4)).rejects.toThrow(/export disabled/);
  });

  it('refuses a sealed blob presented with another pubkey (KMS context + enclave check)', async () => {
    const a = await client.generate();
    const b = await client.generate();
    await expect(client.signer(a.sealed, b.pubkey).signEvent({ kind: 1, content: 'x' })).rejects.toThrow(/enclave:/);
  });

  it('KMS denies the parent: no Recipient attestation, no data key', async () => {
    const { sealed, pubkey } = await client.generate();
    const blob = JSON.parse(Buffer.from(Buffer.from(sealed).toString('utf8'), 'base64').toString('utf8')) as { edk: string };
    await expect(
      sim.kms.decrypt({ keyId: 'alias/simulated-enclave', ciphertextBlob: Buffer.from(blob.edk, 'base64'), context: { app: 'acceso-nostr', purpose: 'enclave-key', pubkey }, attestationDocument: new Uint8Array() }),
    ).rejects.toThrow(/RecipientAttestation/);
  });
});

describe('attestation-conditioned KMS and parent checks', () => {
  it('an enclave image with other measurements cannot obtain data keys', async () => {
    const sim = createSimulatedEnclave({ pcrs: simulatedPcrs('tampered-image') });
    // The parent is configured with the tampered PCRs, so only KMS stands in the way.
    const client = new EnclaveClient({ transport: inProcessTransport(sim.enclave), attestation: { ...sim.policy, expectedPcrs: { 0: sim.pcrs[0] } } });
    await expect(client.generate()).rejects.toThrow(/PCR0 does not match/);
    expect(sim.kms.calls).toEqual([{ op: 'generateDataKey', ok: false }]);
  });

  it('the parent refuses an enclave whose PCRs differ from the expected ones', async () => {
    const sim = createSimulatedEnclave();
    const client = new EnclaveClient({ transport: inProcessTransport(sim.enclave), attestation: { ...sim.policy, expectedPcrs: { 2: simulatedPcrs('other')[2] } } });
    await expect(client.verify()).rejects.toBeInstanceOf(AttestationError);
    await expect(client.generate()).rejects.toThrow(/PCR2/);
  });

  it('the parent rejects forged events from a compromised channel', async () => {
    const sim = createSimulatedEnclave();
    const { pubkey, sealed } = await new EnclaveClient({ transport: inProcessTransport(sim.enclave), attestation: sim.policy }).generate();
    const forger = generateSecretKey();
    const transport = inProcessTransport({
      handle: async (req) => (req.op === 'sign' ? { ok: true, event: finalizeEvent(toUnsigned({ kind: 1, content: 'x' }, getPublicKey(forger)), forger) } : sim.enclave.handle(req)),
    });
    const client = new EnclaveClient({ transport, attestation: sim.policy });
    await expect(client.signer(sealed, pubkey).signEvent({ kind: 1, content: 'x' })).rejects.toThrow(/invalid event/);
  });
});

describe('managed-signer with MANAGED_SIGNER_BACKEND=enclave (simulated)', () => {
  const acceso = createTestCognito();
  const token = () => acceso.token({ sub: 'user-e' });
  let api: ReturnType<typeof createManagedSignerApi>;
  let base: string;
  const vault = new MemoryVault();
  const puts: Uint8Array[] = [];
  const put = vault.put.bind(vault);
  vault.put = async (k, s) => (puts.push(new Uint8Array(s)), put(k, s));

  const call = (path: string, method = 'GET', body?: unknown) =>
    fetch(`${base}${path}`, { method, headers: { authorization: `Bearer ${token()}`, 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) }).then(async (r) => ({ status: r.status, json: await r.json() }));

  beforeAll(async () => {
    const warnings: string[] = [];
    const backend = enclaveBackendFromEnv({ MANAGED_SIGNER_BACKEND: 'enclave', MANAGED_SIGNER_ENCLAVE_SIMULATED: '1' }, (m) => warnings.push(m));
    expect(backend?.simulated).toBe(true);
    expect(warnings.join()).toMatch(/NOT SECURE/);
    const core = new ManagedSigner(vault, { sealedKeys: backend!.client, retentionDays: 0 });
    api = createManagedSignerApi(core, { name: 'managed-signer-enclave-test', cognito: acceso.verifier(), logger: createLogger({ write: () => {} }) });
    base = await api.listen();
  });
  afterAll(() => api.close());

  it('creates, signs, imports and migrates keys through the API while the vault only holds sealed blobs', async () => {
    const created = await call('/v1/keys', 'POST', { consent_version: 'textos test' });
    expect(created.status).toBe(201);
    expect(created.json.custody).toBe('managed-enclave');
    expect(created.json.custodial).toBe(true);
    expect(created.json.provider).toBe('simulated-enclave+memory');
    const keyId = created.json.keyId as string;
    const signed = await call(`/v1/keys/${keyId}/sign`, 'POST', { template: { kind: 1, content: 'hola desde el enclave' } });
    expect(signed.status).toBe(200);
    expect(verifyEvent(signed.json.event)).toBe(true);
    expect(signed.json.event.pubkey).toBe(created.json.pubkey);

    const sk = generateSecretKey();
    const imported = await call('/v1/keys/import', 'POST', { ncryptsec: nip49.encryptKey(sk, 'contraseña larga 123', 4), password: 'contraseña larga 123', consent_version: 'textos test' });
    expect(imported.status).toBe(201);
    expect(imported.json.pubkey).toBe(getPublicKey(sk));
    for (const p of puts) {
      expect(Buffer.from(p).includes(Buffer.from(sk))).toBe(false);
      expect(p.length).toBeGreaterThan(100); // sealed JSON, never a 32-byte secret
    }
  });

  it('exports through the enclave and completes the FR-026 migration', async () => {
    const created = await call('/v1/keys', 'POST', { consent_version: 'textos test' });
    const keyId = created.json.keyId as string;
    const exp = await call(`/v1/keys/${keyId}/export`, 'POST', { password: 'contraseña suficientemente larga' });
    expect(exp.status).toBe(200);
    const { secretKey } = await nip49.decryptKeyAsync(exp.json.ncryptsec, 'contraseña suficientemente larga');
    expect(getPublicKey(secretKey)).toBe(created.json.pubkey);
    const proof = finalizeEvent(toUnsigned({ kind: 27235, content: '', tags: [['challenge', exp.json.challenge]] }, getPublicKey(secretKey)), secretKey);
    expect((await call(`/v1/keys/${keyId}/confirm-migration`, 'POST', { proof })).json.state).toBe('migrated');
  });
});

describe('enclaveBackendFromEnv', () => {
  const pcr = (c: string) => c.repeat(96);
  it('defaults to the in-process backend', () => {
    expect(enclaveBackendFromEnv({})).toBeUndefined();
    expect(enclaveBackendFromEnv({ MANAGED_SIGNER_BACKEND: 'local' })).toBeUndefined();
  });
  it('validates the configuration', () => {
    expect(() => enclaveBackendFromEnv({ MANAGED_SIGNER_BACKEND: 'hsm' })).toThrow(/local' or 'enclave/);
    expect(() => enclaveBackendFromEnv({ MANAGED_SIGNER_BACKEND: 'enclave' })).toThrow(/SOCKET/);
    expect(() => enclaveBackendFromEnv({ MANAGED_SIGNER_BACKEND: 'enclave', MANAGED_SIGNER_ENCLAVE_SOCKET: '/run/x.sock', MANAGED_SIGNER_ENCLAVE_PCR0: pcr('a') })).toThrow(/PCR1/);
    expect(() =>
      enclaveBackendFromEnv({ MANAGED_SIGNER_BACKEND: 'enclave', MANAGED_SIGNER_ENCLAVE_SOCKET: '/run/x.sock', MANAGED_SIGNER_ENCLAVE_PCR0: pcr('a'), MANAGED_SIGNER_ENCLAVE_PCR1: pcr('b'), MANAGED_SIGNER_ENCLAVE_PCR2: 'zz' }),
    ).toThrow(/96 hex/);
    expect(() => enclaveBackendFromEnv({ MANAGED_SIGNER_BACKEND: 'enclave', MANAGED_SIGNER_ENCLAVE_SIMULATED: '1', NODE_ENV: 'production' })).toThrow(/refused/);
    const real = enclaveBackendFromEnv({ MANAGED_SIGNER_BACKEND: 'enclave', MANAGED_SIGNER_ENCLAVE_SOCKET: '127.0.0.1:5005', MANAGED_SIGNER_ENCLAVE_PCR0: pcr('a'), MANAGED_SIGNER_ENCLAVE_PCR1: pcr('b'), MANAGED_SIGNER_ENCLAVE_PCR2: pcr('c') });
    expect(real?.simulated).toBe(false);
    expect(real?.client.provider).toBe('nitro-enclave');
  });
});

describe('awsEnclaveKms (SDK adapter)', () => {
  it('sends the attestation document as Recipient and never accepts plaintext', async () => {
    const seen: Array<{ target: string; body: Record<string, unknown> }> = [];
    let reply: Record<string, unknown> = {};
    const srv = createServer((req, res) => {
      let data = '';
      req.on('data', (d) => (data += d)).on('end', () => {
        seen.push({ target: String(req.headers['x-amz-target']), body: JSON.parse(data) as Record<string, unknown> });
        res.setHeader('content-type', 'application/x-amz-json-1.1');
        res.end(JSON.stringify(reply));
      });
    });
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
    const kms = awsEnclaveKms({ region: 'us-east-1', endpoint: `http://127.0.0.1:${(srv.address() as AddressInfo).port}` });
    const credentials = { accessKeyId: 'AKIDTEST', secretAccessKey: 'secret', sessionToken: 'tok' };
    const doc = new Uint8Array([1, 2, 3]);
    try {
      reply = { KeyId: 'k', CiphertextBlob: 'AQID', CiphertextForRecipient: 'BAUG' };
      const dk = await kms.generateDataKey({ keyId: 'alias/k', context: { pubkey: 'p' }, attestationDocument: doc, credentials });
      expect(dk.ciphertextForRecipient).toEqual(new Uint8Array([4, 5, 6]));
      reply = { KeyId: 'k', CiphertextForRecipient: 'BwgJ' };
      expect((await kms.decrypt({ keyId: 'alias/k', ciphertextBlob: new Uint8Array([1]), context: { pubkey: 'p' }, attestationDocument: doc, credentials })).ciphertextForRecipient).toEqual(new Uint8Array([7, 8, 9]));
      expect(seen.map((s) => s.target)).toEqual(['TrentService.GenerateDataKey', 'TrentService.Decrypt']);
      for (const s of seen) {
        expect(s.body.Recipient).toEqual({ KeyEncryptionAlgorithm: 'RSAES_OAEP_SHA_256', AttestationDocument: 'AQID' });
        expect(s.body.EncryptionContext).toEqual({ pubkey: 'p' });
      }
      reply = { KeyId: 'k', Plaintext: 'AQID' };
      await expect(kms.decrypt({ keyId: 'alias/k', ciphertextBlob: new Uint8Array([1]), context: {}, attestationDocument: doc, credentials })).rejects.toThrow(/Recipient was ignored/);
    } finally {
      srv.close();
    }
  });
});
