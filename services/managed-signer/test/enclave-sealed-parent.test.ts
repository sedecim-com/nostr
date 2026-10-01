/**
 * FR005-10: what a compromised parent sees. Everything that crosses the managed-signer API (requests and responses),
 * the channel to the enclave (the frames, byte for byte), the service's logs and what it writes to the vault is captured
 * during an import and an export done with the real client and `enclave`: neither the passwords, nor the imported
 * ncryptsec, nor the nsec appear there in clear, hex or base64. And a parent that swaps the attestation document makes
 * the client stop before it sends anything.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { generateSecretKey, getPublicKey, nip19, nip49 } from '@sedecim/nostr-core';
import { ManagedSignerClient, NitroAttestationError, type EnclaveTrust, type ManagedSignerConnection } from '@sedecim/signer';
import { createLogger } from '@sedecim/telemetry-policy';
import { bech32 } from '@scure/base';
import { createAccesoPool } from './acceso-pool';
import {
  buildAttestationDocument,
  buildCertificate,
  createManagedSignerApi,
  createSimulatedEnclave,
  createTestPki,
  decodeCbor,
  EnclaveClient,
  encodeCbor,
  encodeFrame,
  inProcessTransport,
  ManagedSigner,
  MemoryVault,
  PinnedJwksProofVerifier,
  SimulatedNsm,
  simulatedPcrs,
  type EnclaveTransport,
} from '../src/index';

const acceso = createAccesoPool();
const verifier = new PinnedJwksProofVerifier({ issuer: acceso.issuer, clientId: acceso.clientId, jwks: acceso.jwks });
// ASCII: one UTF-8 form each to look for.
const IMPORT_PASSWORD = 'Import-Password-7d41c9';
const EXPORT_PASSWORD = 'Export-Password-e02b55';

/** Everything the parent handles, as bytes. */
const seen: Buffer[] = [];
const sim = createSimulatedEnclave({ proof: verifier });
const inner = inProcessTransport(sim.enclave);
const transport: EnclaveTransport = {
  request: async (req) => {
    seen.push(encodeFrame(req));
    const res = await inner.request(req);
    seen.push(encodeFrame(res));
    return res;
  },
};
const vault = new MemoryVault();
const put = vault.put.bind(vault);
vault.put = async (k, v) => (seen.push(Buffer.from(v)), put(k, v));
const core = new ManagedSigner(vault, { sealedKeys: new EnclaveClient({ transport, attestation: sim.policy, provider: 'simulated-enclave' }), retentionDays: 0 });
/** The service's log lines, also kept apart. */
const logLines: string[] = [];
const api = createManagedSignerApi(core, {
  name: 'managed-signer-parent-test',
  cognito: acceso.verifier(),
  logger: createLogger({ level: 'debug', write: (r) => (logLines.push(JSON.stringify(r)), seen.push(Buffer.from(JSON.stringify(r)))) }),
});

/** The client's fetch, recording both directions; one connection per request (an export's scrypt blocks the server). */
const recording: typeof fetch = async (input, init) => {
  seen.push(Buffer.from(`${init?.method ?? 'GET'} ${String(input)}\n${JSON.stringify(init?.headers ?? {})}\n${typeof init?.body === 'string' ? init.body : ''}`));
  const res = await fetch(input, { ...init, headers: { ...(init?.headers as Record<string, string>), connection: 'close' } });
  seen.push(Buffer.from(await res.clone().text()));
  return res;
};
const trust: EnclaveTrust = { pcrs: { 0: sim.pcrs[0]!, 1: sim.pcrs[1]!, 2: sim.pcrs[2]! }, rootFingerprints: [sim.pki.fingerprint] };
let base = '';
const conn = (f: typeof fetch = recording): ManagedSignerConnection => ({ baseUrl: base, token: async () => acceso.token({ sub: 'ana' }), fetch: f });

/** The secret in every form it could travel in: as is, hex (both cases), and base64/base64url at any byte alignment. */
function forms(secret: Uint8Array): Buffer[] {
  const b = Buffer.from(secret);
  const out = [b, Buffer.from(b.toString('hex')), Buffer.from(b.toString('hex').toUpperCase())];
  for (const shift of [0, 1, 2]) {
    for (const enc of ['base64', 'base64url'] as const) {
      // Only the 4-character groups that encode the secret's bytes alone, whatever comes before or after it.
      const s = Buffer.concat([Buffer.alloc(shift), b]).toString(enc).replace(/=+$/, '');
      out.push(Buffer.from(s.slice(shift ? 4 : 0, Math.floor(s.length / 4) * 4 - 4)));
    }
  }
  return out;
}
function leaks(secrets: Record<string, Uint8Array>): string[] {
  const all = Buffer.concat(seen);
  return Object.entries(secrets).flatMap(([name, secret]) => (forms(secret).some((f) => f.length >= 8 && all.includes(f)) ? [name] : []));
}
const text = (s: string) => new TextEncoder().encode(s);
const payloadOf = (ncryptsec: string) => new Uint8Array(bech32.fromWords(bech32.decode(ncryptsec as `ncryptsec1${string}`, 5000).words));

beforeAll(async () => {
  base = await api.listen();
});
afterAll(() => api.close());

describe('what the parent sees of a sealed import and export', () => {
  it('FR005-10: neither the passwords, nor the ncryptsec imported, nor the nsec cross the API, the enclave channel, the logs or the vault', async () => {
    seen.length = 0;
    const sk = generateSecretKey();
    const ncryptsec = nip49.encryptKey(sk, IMPORT_PASSWORD, 4);
    const key = await ManagedSignerClient.importEncrypted(conn(), ncryptsec, IMPORT_PASSWORD, { consentVersion: 'textos test', enclave: trust });
    expect(key.pubkey).toBe(getPublicKey(sk));
    const exported = await new ManagedSignerClient({ ...conn(), keyId: key.keyId }).exportForMigration(EXPORT_PASSWORD, { enclave: trust });
    expect(getPublicKey(nip49.decryptKey(exported.ncryptsec, EXPORT_PASSWORD).secretKey)).toBe(key.pubkey);

    // The capture did see both operations, through the API and down to the enclave.
    const all = Buffer.concat(seen).toString('utf8');
    for (const field of ['"sealed_secrets":"ae1.', '"sealed_password":"ae1.', '"op":"import"', '"op":"export"', '"sealedSecrets":"ae1.', '"sealedPassword":"ae1.']) expect(all).toContain(field);
    // The exported ncryptsec is the answer the parent relays: without the password it is ciphertext.
    expect(all).toContain(exported.ncryptsec);
    // The service logs the requests, never the envelopes it relays.
    expect(logLines.length).toBeGreaterThan(0);
    expect(logLines.filter((l) => l.includes('ae1.'))).toEqual([]);
    expect(leaks({ importPassword: text(IMPORT_PASSWORD), exportPassword: text(EXPORT_PASSWORD), importedNcryptsec: text(ncryptsec), importedNcryptsecPayload: payloadOf(ncryptsec), nsec: text(nip19.nsecEncode(sk)), secretKey: sk })).toEqual([]);
  });

  it('FR005-10: the same capture does see a password sent in clear (control)', async () => {
    const created = await ManagedSignerClient.createKey(conn(), { consentVersion: 'textos test' });
    seen.length = 0;
    // Refused for an old sign-in, so no scrypt runs: the request, with its body, has already crossed the API.
    const stale: ManagedSignerConnection = { ...conn(), token: async () => acceso.token({ sub: 'ana', auth_time: Math.floor(Date.now() / 1000) - 3600 }) };
    await expect(new ManagedSignerClient({ ...stale, keyId: created.keyId }).exportForMigration(EXPORT_PASSWORD)).rejects.toThrow(/sign-in/);
    expect(leaks({ exportPassword: text(EXPORT_PASSWORD) })).toEqual(['exportPassword']);
  });
});

describe('a parent that swaps the attestation document', () => {
  const evilRsa = new Uint8Array(generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ type: 'spki', format: 'der' }));
  const evilLeaf = generateKeyPairSync('ec', { namedCurve: 'P-384' });
  /** A fetch that answers the attestation itself; `sent` lists every request that did reach the service. */
  const swapping = (swap: (nonce: Uint8Array) => Promise<Uint8Array>) => {
    const sent: string[] = [];
    const f: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      if (url.pathname === '/v1/enclave/attestation') {
        const doc = await swap(new Uint8Array(Buffer.from(url.searchParams.get('nonce')!, 'base64url')));
        return new Response(JSON.stringify({ document: Buffer.from(doc).toString('base64') }), { status: 200, headers: { 'content-type': 'application/json' } });
      }
      sent.push(`${init?.method ?? 'GET'} ${url.pathname}`);
      return recording(input, init);
    };
    return { f, sent };
  };
  const nsm = (o: { pcrs?: Record<number, string>; now?: () => number }) => new SimulatedNsm({ pki: sim.pki, pcrs: o.pcrs ?? sim.pcrs, ...(o.now ? { now: o.now } : {}) });
  const rogue = createTestPki();
  const rogueDoc = (nonce: Uint8Array) => {
    const certificate = buildCertificate({ subject: 'i-rogue-enc', issuer: 'simulated.intermediate', publicKey: evilLeaf.publicKey, issuerKey: rogue.intermediate.key, notBefore: new Date(Date.now() - 60_000), notAfter: new Date(Date.now() + 3_600_000), ca: false });
    return buildAttestationDocument({ timestamp: Date.now(), pcrs: sim.pcrs, certificate, cabundle: [rogue.root.cert, rogue.intermediate.cert], publicKey: evilRsa, nonce }, evilLeaf.privateKey);
  };
  const withOwnKey = async (nonce: Uint8Array) => {
    const [p, u, payload, s] = decodeCbor(await core.enclaveAttestation(nonce)) as [Uint8Array, unknown, Uint8Array, Uint8Array];
    const m = decodeCbor(payload) as Map<string, unknown>;
    m.set('public_key', evilRsa);
    return encodeCbor([p, u, encodeCbor(m), s]);
  };
  const CASES: Array<[string, (nonce: Uint8Array) => Promise<Uint8Array>, string]> = [
    ['the enclave\'s document with an RSA key of its own in it', withOwnKey, 'bad-signature'],
    ['a document of its own, under a PKI of its own, with its RSA key', async (n) => rogueDoc(n), 'untrusted-root'],
    ['the document of an enclave image of its own (other PCRs) on a real Nitro host', (n) => nsm({ pcrs: simulatedPcrs('image-of-the-parent') }).attest({ publicKey: evilRsa, nonce: n }), 'pcr-mismatch'],
    ['the document of a debug-mode enclave', (n) => nsm({ pcrs: { 0: '00'.repeat(48), 1: '00'.repeat(48), 2: '00'.repeat(48) } }).attest({ publicKey: evilRsa, nonce: n }), 'debug-enclave'],
    ['an old document', (n) => nsm({ now: () => Date.now() - 10 * 60_000 }).attest({ publicKey: evilRsa, nonce: n }), 'stale'],
    ['a genuine document for another nonce', () => core.enclaveAttestation(randomBytes(32)), 'nonce-mismatch'],
  ];

  it.each(CASES)('FR005-10: %s: the client stops before it sends the import', async (_what, swap, code) => {
    const { f, sent } = swapping(swap);
    const err = await ManagedSignerClient.importEncrypted(conn(f), nip49.encryptKey(generateSecretKey(), IMPORT_PASSWORD, 4), IMPORT_PASSWORD, { consentVersion: 'textos test', enclave: trust }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NitroAttestationError);
    expect((err as NitroAttestationError).code).toBe(code);
    expect(sent).toEqual([]);
  });

  it.each(CASES)('FR005-10: %s: the client stops before it sends the export password', async (_what, swap, code) => {
    const created = await ManagedSignerClient.createKey(conn(), { consentVersion: 'textos test' });
    const { f, sent } = swapping(swap);
    const err = await new ManagedSignerClient({ ...conn(f), keyId: created.keyId }).exportForMigration(EXPORT_PASSWORD, { enclave: trust }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NitroAttestationError);
    expect((err as NitroAttestationError).code).toBe(code);
    // Only the key's description was asked for; nothing was posted.
    expect(sent).toEqual([`GET /v1/keys/${created.keyId}`]);
  });
});
