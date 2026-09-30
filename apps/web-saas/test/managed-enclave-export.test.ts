/**
 * FR005-10: exporting a managed key from the web when the deployment names the managed-signer's enclave
 * (`managedEnclave` in config.json): this browser checks the enclave's attestation and seals the export password to it,
 * so the password never reaches the managed-signer in clear. Without it, the export works as before.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { EncryptedStore, MemoryBackend, type Vault } from '@sedecim/encrypted-store';
import { createManagedSignerApi, createSimulatedEnclave, EnclaveClient, inProcessTransport, ManagedSigner, MemoryVault, PinnedJwksProofVerifier, simulatedPcrs, type SimulatedEnclave } from '@sedecim/managed-signer';
import { bytesToHex, generateSecretKey, getPublicKey, hexToBytes } from '@sedecim/nostr-core';
import { preset } from '@sedecim/profiles';
import { createTestCognito } from '@sedecim/service-kit';
import { ManagedSignerClient, type EnclaveTrust } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import { enclaveTrust, loadConfig } from '../src/lib/config';
import { managedCancellationBackup, migrateManagedToLocal } from '../src/lib/session';
import { PersonaBook, type PersonaRecord } from '../src/lib/vault';

const newBook = () => new PersonaBook({ store: EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(6)) } as unknown as Vault);
const PASSWORD = 'Export-Password-webapp-51';
const pcr = (c: string) => c.repeat(96);

describe('exporting a managed key from the web with the enclave named in config.json', () => {
  const acceso = createTestCognito();
  // The enclave takes the owner's Acceso token as its proof: one of its own (jti) for every request, as Cognito's are.
  const token = () => acceso.token({ sub: 'ana', jti: randomUUID(), iat: Math.floor(Date.now() / 1000) });
  let sim: SimulatedEnclave;
  let api: ReturnType<typeof createManagedSignerApi>;
  let base = '';
  /** The request bodies this browser sent. One connection per request: the export's scrypt blocks the test server. */
  const bodies: string[] = [];
  const recording: typeof fetch = (input, init) => {
    if (typeof init?.body === 'string') bodies.push(`${init.method ?? 'GET'} ${new URL(String(input)).pathname} ${init.body}`);
    return fetch(input, { ...init, headers: { ...(init?.headers as Record<string, string>), connection: 'close' } });
  };
  const conn = () => ({ baseUrl: base, token: async () => token(), fetch: recording });
  /** What the deployment's managedEnclave gives, plus the root of the simulated enclave (the real one is AWS's). */
  const trustOf = (pcrs: Record<number, string>): EnclaveTrust => ({ ...enclaveTrust({ managedEnclave: { pcr0: pcrs[0]!, pcr1: pcrs[1]!, pcr2: pcrs[2]! } })!, rootFingerprints: [sim.pki.fingerprint] });

  beforeAll(async () => {
    const jwks = (await (await acceso.jwksFetch('jwks')).json()) as { keys: Array<Record<string, unknown>> };
    sim = createSimulatedEnclave({ proof: new PinnedJwksProofVerifier({ issuer: acceso.issuer, clientId: acceso.cfg.clientId, jwks }) });
    const core = new ManagedSigner(new MemoryVault(), { sealedKeys: new EnclaveClient({ transport: inProcessTransport(sim.enclave), attestation: sim.policy, provider: 'simulated-enclave' }), retentionDays: 30 });
    api = createManagedSignerApi(core, { name: 'ms-enclave-web-test', cognito: acceso.verifier(), logger: createLogger({ write: () => {} }) });
    base = await api.listen();
  });
  afterAll(() => api.close());

  const managedPersona = async (book: PersonaBook): Promise<{ persona: PersonaRecord; client: ManagedSignerClient }> => {
    const key = await ManagedSignerClient.createKey(conn(), { consentVersion: 'textos test' });
    const persona: PersonaRecord = { id: `p-${key.keyId}`, label: 'Gestionada', pubkey: key.pubkey, custody: 'managed', managedKeyId: key.keyId, archiveKeyHex: bytesToHex(generateSecretKey()), relays: [], preset: 'convenience', config: { ...preset('convenience'), custody: 'managed' }, createdAt: Date.now() };
    await book.save(persona);
    return { persona, client: new ManagedSignerClient({ ...conn(), keyId: key.keyId }) };
  };

  it('FR005-10: the migration to local custody seals the export password in this browser: it never goes to the managed-signer in clear', async () => {
    const book = newBook();
    const { persona, client } = await managedPersona(book);
    bodies.length = 0;
    const res = await migrateManagedToLocal(book, persona, client, PASSWORD, trustOf(sim.pcrs));
    expect(res.persona.custody).toBe('local');
    expect(getPublicKey(hexToBytes(res.persona.secretHex!))).toBe(persona.pubkey);
    expect(bodies.some((b) => b.includes('/export') && b.includes('"sealed_password":"ae1.'))).toBe(true);
    expect(bodies.filter((b) => b.includes(PASSWORD))).toEqual([]);
  }, 60_000);

  it('FR005-10: so does the backup before cancelling: what this browser posts is the sealed password, never the password', async () => {
    const book = newBook();
    const { persona } = await managedPersona(book);
    // The attestation comes from the enclave; the export is answered here: what is posted is all this case needs to see
    // (the migration above runs the whole way, with the enclave's scrypt).
    const sent: string[] = [];
    const answering: typeof fetch = async (input, init) => {
      sent.push(`${init?.method ?? 'GET'} ${new URL(String(input)).pathname} ${typeof init?.body === 'string' ? init.body : ''}`);
      if (new URL(String(input)).pathname.endsWith('/export')) return new Response(JSON.stringify({ error: 'answered by the test' }), { status: 503 });
      return recording(input, init);
    };
    const client = new ManagedSignerClient({ ...conn(), fetch: answering, keyId: persona.managedKeyId! });
    await expect(managedCancellationBackup(persona, client, PASSWORD, trustOf(sim.pcrs))).rejects.toThrow(/answered by the test/);
    expect(sent.map((s) => s.split(' ').slice(0, 2).join(' '))).toEqual([`GET /v1/keys/${persona.managedKeyId}`, 'GET /v1/enclave/attestation', `POST /v1/keys/${persona.managedKeyId}/export`]);
    expect(sent[2]).toMatch(/^POST \S+ \{"sealed_password":"ae1\.[A-Za-z0-9_.-]+"\}$/);
    expect(sent.filter((s) => s.includes(PASSWORD))).toEqual([]);
  });

  it('FR005-10: an enclave that is not the one named (other measurements) stops the export, and the password is not sent', async () => {
    const book = newBook();
    const { persona, client } = await managedPersona(book);
    bodies.length = 0;
    await expect(migrateManagedToLocal(book, persona, client, PASSWORD, trustOf(simulatedPcrs('another-image')))).rejects.toThrow(/no se pudo verificar el enclave de la plataforma .*PCR0 does not match.*: la contraseña no se envió/);
    expect(bodies).toEqual([]);
    expect((await book.get(persona.id))?.custody).toBe('managed');
  });

  it('FR005-10: without managedEnclave the export goes as before, with the password in the request and no attestation asked for', async () => {
    const book = newBook();
    const { persona } = await managedPersona(book);
    // What this browser sends is all this case needs to see: the export itself is answered here, without running scrypt.
    const sent: string[] = [];
    const answering: typeof fetch = async (input, init) => {
      sent.push(`${init?.method ?? 'GET'} ${new URL(String(input)).pathname} ${typeof init?.body === 'string' ? init.body : ''}`);
      if (new URL(String(input)).pathname.endsWith('/export')) return new Response(JSON.stringify({ error: 'answered by the test' }), { status: 503 });
      return recording(input, init);
    };
    const client = new ManagedSignerClient({ ...conn(), fetch: answering, keyId: persona.managedKeyId! });
    await expect(managedCancellationBackup(persona, client, PASSWORD)).rejects.toThrow(/answered by the test/);
    expect(sent).toEqual([`POST /v1/keys/${persona.managedKeyId}/export ${JSON.stringify({ password: PASSWORD })}`]);
  });

  it('FR005-10: managedEnclave in config.json takes PCR0-2 (and PCR8), and malformed values stop the app', async () => {
    expect(enclaveTrust({})).toBeUndefined();
    expect(enclaveTrust({ managedEnclave: { pcr0: pcr('a'), pcr1: pcr('b'), pcr2: pcr('c') } })).toEqual({ pcrs: { 0: pcr('a'), 1: pcr('b'), 2: pcr('c') } });
    expect(enclaveTrust({ managedEnclave: { pcr0: pcr('a'), pcr1: pcr('b'), pcr2: pcr('c'), pcr8: pcr('d') } })?.pcrs[8]).toBe(pcr('d'));
    for (const bad of [{ pcr0: pcr('a'), pcr1: pcr('b') }, { pcr0: pcr('a'), pcr1: pcr('b'), pcr2: 'c' }, { pcr0: pcr('a'), pcr1: pcr('b'), pcr2: pcr('c'), pcr8: 'd' }, null]) {
      expect(() => enclaveTrust({ managedEnclave: bad as never })).toThrow(/managedEnclave/);
    }
    vi.stubGlobal('fetch', async () => new Response(JSON.stringify({ managedEnclave: { pcr0: pcr('a') } })));
    try {
      await expect(loadConfig()).rejects.toThrow(/managedEnclave/);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
