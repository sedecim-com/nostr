/**
 * FR005-10: the secrets of an import (ncryptsec and password) and the password of an export reach the enclave sealed by
 * the client to the RSA key of an attestation document the client verified itself: RSA-OAEP-SHA256 of an AES-256-GCM
 * key, the purpose, owner tag and pubkey in the AAD, and the attestation's timestamp checked against the enclave's clock.
 * The parent relays an opaque string.
 */
import { describe, expect, it } from 'vitest';
import { constants, createCipheriv, createHash, createPublicKey, publicEncrypt, randomBytes } from 'node:crypto';
import { generateSecretKey, getPublicKey, nip49 } from '@sedecim/nostr-core';
import { envelopeAad, MAX_ENVELOPE_CHARS, ownerTag as sharedOwnerTag, sealToEnclave, toBase64Url, verifyNitroAttestation } from '@sedecim/signer';
import { bech32 } from '@scure/base';
import { createAccesoPool } from './acceso-pool';
import { AttestationError, createSimulatedEnclave, EnclaveClient, EnclaveError, EnclaveSigner, flagFromEnv, inProcessTransport, openSealedSecret, ownerTag, PinnedJwksProofVerifier, SEALED_DOES_NOT_OPEN, simulatedPcrs, type SimulatedEnclave } from '../src/index';

const pool = createAccesoPool();
const verifier = () => new PinnedJwksProofVerifier({ issuer: pool.issuer, clientId: pool.clientId, jwks: pool.jwks });
const ownerOf = (sub: string) => `${pool.issuer}#${sub}`;
const IMPORT_PASSWORD = 'contraseña de importación';
const EXPORT_PASSWORD = 'contraseña de exportación larga';

const setup = (opts: Parameters<typeof createSimulatedEnclave>[0] = {}) => {
  const sim = createSimulatedEnclave({ proof: verifier(), ...opts });
  return { sim, client: new EnclaveClient({ transport: inProcessTransport(sim.enclave), attestation: sim.policy }) };
};

/** What a client does before sealing: a nonce of its own, the document checked with the portable verifier. */
async function attested(sim: SimulatedEnclave, client: EnclaveClient) {
  const nonce = randomBytes(32);
  const att = verifyNitroAttestation(await client.attest(nonce), { trustedRootFingerprints: sim.policy.trustedRootFingerprints, expectedPcrs: sim.policy.expectedPcrs, expectedNonce: nonce, requirePublicKey: true });
  return { spki: att.publicKey!, at: att.timestamp };
}
const sealImport = async (sim: SimulatedEnclave, client: EnclaveClient, owner: string, ncryptsec: string, password = IMPORT_PASSWORD) => {
  const { spki, at } = await attested(sim, client);
  return sealToEnclave(spki, { purpose: 'import', ownerTag: ownerTag(owner), at, ncryptsec, password });
};
const sealExport = async (sim: SimulatedEnclave, client: EnclaveClient, owner: string, pubkey: string, password = EXPORT_PASSWORD) => {
  const { spki, at } = await attested(sim, client);
  return sealToEnclave(spki, { purpose: 'export', ownerTag: ownerTag(owner), pubkey, at, password });
};
/** The same format built with node:crypto, with any content: interop, and contents a well-behaved client never sends. */
const rawSeal = (spki: Uint8Array, aad: Uint8Array, content: unknown) => {
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(typeof content === 'string' ? content : JSON.stringify(content)), c.final(), c.getAuthTag()]);
  const ek = publicEncrypt({ key: createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' }), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, key);
  return `ae1.${toBase64Url(ek)}.${toBase64Url(iv)}.${toBase64Url(ct)}`;
};
const refusal = async (p: Promise<unknown>) => {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(EnclaveError);
  return err as EnclaveError;
};
/** Changes one byte of part `i` (1 ek, 2 iv, 3 ct) of an envelope, `at` counted from its end when negative. */
const bend = (envelope: string, part: number, at: number) => {
  const parts = envelope.split('.');
  const b = Buffer.from(parts[part]!, 'base64url');
  b[at < 0 ? b.length + at : at]! ^= 0x01;
  parts[part] = toBase64Url(b);
  return parts.join('.');
};
const blob = (sealed: Uint8Array) => JSON.parse(Buffer.from(Buffer.from(sealed).toString('utf8'), 'base64').toString('utf8')) as { ot?: string };
const withLogN = (ncryptsec: string, logN: number) => {
  const { words } = bech32.decode(ncryptsec as `ncryptsec1${string}`, 5000);
  const b = new Uint8Array(bech32.fromWords(words));
  b[1] = logN;
  return bech32.encode('ncryptsec', bech32.toWords(b), 5000);
};

describe('secrets sealed to the enclave', () => {
  it('FR005-10: the owner tag the client binds is the one the enclave seals keys with (unchanged format)', () => {
    const owner = ownerOf('ana');
    expect(sharedOwnerTag(owner)).toBe(ownerTag(owner));
    expect(ownerTag(owner)).toBe(createHash('sha256').update(`acceso-nostr/owner/v1|${owner}`).digest('hex'));
  });

  it('FR005-10: an import sealed with WebCrypto opens in the enclave, and the key is sealed for the owner of the envelope', async () => {
    const { sim, client } = setup();
    const sk = generateSecretKey();
    const envelope = await sealImport(sim, client, ownerOf('ana'), nip49.encryptKey(sk, IMPORT_PASSWORD, 4));
    expect(envelope).toMatch(/^ae1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/);
    expect(envelope.length).toBeLessThanOrEqual(MAX_ENVELOPE_CHARS);
    const { pubkey, sealed } = await client.importSealed(ownerOf('ana'), envelope);
    expect(pubkey).toBe(getPublicKey(sk));
    expect(blob(sealed).ot).toBe(ownerTag(ownerOf('ana')));
  });

  it('FR005-10: the parent cannot import it for another owner: the owner is in the AAD, and nothing is sealed', async () => {
    const { sim, client } = setup();
    const envelope = await sealImport(sim, client, ownerOf('ana'), nip49.encryptKey(generateSecretKey(), IMPORT_PASSWORD, 4));
    const before = sim.kms.calls.length;
    const err = await refusal(client.importSealed(ownerOf('mallory'), envelope));
    expect(err.status).toBe(400);
    expect(err.message).toContain(SEALED_DOES_NOT_OPEN);
    expect(sim.kms.calls.length).toBe(before);
  });

  it('FR005-10: an envelope sealed with node:crypto opens as well (the format, not one library)', async () => {
    const { sim, client } = setup();
    const { spki, at } = await attested(sim, client);
    const sk = generateSecretKey();
    const envelope = rawSeal(spki, envelopeAad('import', ownerTag(ownerOf('ana'))), { ncryptsec: nip49.encryptKey(sk, IMPORT_PASSWORD, 4), password: IMPORT_PASSWORD, at });
    expect((await client.importSealed(ownerOf('ana'), envelope)).pubkey).toBe(getPublicKey(sk));
  });

  it('FR005-10: a sealed export password: the ncryptsec opens with it and with nothing else', async () => {
    const { sim, client } = setup();
    const { pubkey, sealed } = await client.generate(ownerOf('ana'));
    const envelope = await sealExport(sim, client, ownerOf('ana'), pubkey);
    const ncryptsec = await client.exportSealed(sealed, pubkey, envelope, 4, pool.token({ sub: 'ana' }));
    expect(getPublicKey(nip49.decryptKey(ncryptsec, EXPORT_PASSWORD).secretKey)).toBe(pubkey);
    expect(() => nip49.decryptKey(ncryptsec, 'otra contraseña cualquiera')).toThrow();
  });

  it('FR005-10: sealed for another purpose, owner or key, or to another enclave key, it does not open', async () => {
    const { sim, client } = setup();
    const a = await client.generate(ownerOf('ana'));
    const b = await client.generate(ownerOf('ana'));
    const ncryptsec = nip49.encryptKey(generateSecretKey(), IMPORT_PASSWORD, 4);
    const token = () => pool.token({ sub: 'ana' });
    // An export envelope reused for an import, and an import envelope reused for an export.
    const exportEnvelope = await sealExport(sim, client, ownerOf('ana'), a.pubkey);
    expect((await refusal(client.importSealed(ownerOf('ana'), exportEnvelope))).message).toContain(SEALED_DOES_NOT_OPEN);
    const importEnvelope = await sealImport(sim, client, ownerOf('ana'), ncryptsec);
    expect((await refusal(client.exportSealed(a.sealed, a.pubkey, importEnvelope, 4, token()))).message).toContain(SEALED_DOES_NOT_OPEN);
    // The password sealed for key A presented for key B of the same owner.
    expect((await refusal(client.exportSealed(b.sealed, b.pubkey, exportEnvelope, 4, token()))).message).toContain(SEALED_DOES_NOT_OPEN);
    // Sealed for another owner's tag.
    const forBeto = await sealExport(sim, client, ownerOf('beto'), a.pubkey);
    expect((await refusal(client.exportSealed(a.sealed, a.pubkey, forBeto, 4, token()))).message).toContain(SEALED_DOES_NOT_OPEN);
    // The enclave restarted: a new ephemeral RSA key, and the envelope sealed to the old one no longer opens.
    const rebooted = new EnclaveClient({ transport: inProcessTransport(new EnclaveSigner({ nsm: sim.nsm, kms: sim.kms, kmsKeyId: 'alias/simulated-enclave', allowExport: true, proof: verifier() })), attestation: sim.policy });
    const err = await refusal(rebooted.importSealed(ownerOf('ana'), importEnvelope));
    expect(err.status).toBe(400);
    expect(err.message).toMatch(/fetch a new attestation and seal again/);
    // All of them were the caller's error (400), none an enclave failure, and the right one still works.
    expect((await client.importSealed(ownerOf('ana'), importEnvelope)).pubkey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('FR005-10: a change to any byte of the key, the IV, the ciphertext or the tag is refused with the same answer', async () => {
    const { sim, client } = setup();
    const envelope = await sealImport(sim, client, ownerOf('ana'), nip49.encryptKey(generateSecretKey(), IMPORT_PASSWORD, 4));
    for (const [part, at] of [[1, 0], [1, 100], [1, -1], [2, 0], [2, -1], [3, 0], [3, 20], [3, -17], [3, -16], [3, -1]] as const) {
      const err = await refusal(client.importSealed(ownerOf('ana'), bend(envelope, part, at)));
      expect(err.status).toBe(400);
      expect(err.message).toBe(`enclave: ${SEALED_DOES_NOT_OPEN}`);
    }
  });

  it('FR005-10: the attestation it was sealed for must be recent by the enclave\'s clock: not older than 5 minutes nor over 60 s ahead', async () => {
    const { sim, client } = setup();
    const { spki } = await attested(sim, client);
    const aad = envelopeAad('import', ownerTag(ownerOf('ana')));
    const content = (at: number) => ({ ncryptsec: nip49.encryptKey(generateSecretKey(), IMPORT_PASSWORD, 4), password: IMPORT_PASSWORD, at });
    const old = await refusal(client.importSealed(ownerOf('ana'), rawSeal(spki, aad, content(Date.now() - 6 * 60_000))));
    expect(old.status).toBe(400);
    expect(old.message).toMatch(/older than 300 s/);
    const ahead = await refusal(client.importSealed(ownerOf('ana'), rawSeal(spki, aad, content(Date.now() + 2 * 60_000))));
    expect(ahead.message).toMatch(/from the future/);
    expect((await client.importSealed(ownerOf('ana'), rawSeal(spki, aad, content(Date.now() - 4 * 60_000)))).pubkey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('FR005-10: what is not an envelope is refused before anything is decrypted: too large, malformed, the wrong content', async () => {
    const { sim, client } = setup();
    const { spki, at } = await attested(sim, client);
    const good = await sealImport(sim, client, ownerOf('ana'), nip49.encryptKey(generateSecretKey(), IMPORT_PASSWORD, 4));
    const [, ek, iv, ct] = good.split('.') as [string, string, string, string];
    // 256 bytes take 342 characters and leave 4 spare bits in the last one, which a canonical encoding keeps at zero.
    const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const ekSpareBit = ek.slice(0, -1) + B64[B64.indexOf(ek.slice(-1)) | 1];
    const cases: Array<[unknown, RegExp]> = [
      [`${good}.${'A'.repeat(MAX_ENVELOPE_CHARS)}`, /longer than 4096 characters/],
      [42, /must be a string/],
      [`ae2.${ek}.${iv}.${ct}`, /not an ae1 envelope/],
      [`ae1.${ek}.${iv}`, /not an ae1 envelope/],
      [`ae1.${ek}.${iv}.${ct}.x`, /not an ae1 envelope/],
      [`ae1.${ek}.${iv}.${ct}=`, /invalid base64url/],
      [`ae1.${ek}.${iv}.${ct.slice(0, -1)}+`, /invalid base64url/],
      [`ae1.${ekSpareBit}.${iv}.${ct}`, /invalid base64url/], // the same bytes, not canonically encoded
      [`ae1.${ek}.${toBase64Url(randomBytes(11))}.${ct}`, /wrong part sizes/],
      [`ae1.${ek}.${iv}.${toBase64Url(randomBytes(16))}`, /wrong part sizes/],
      [`ae1..${iv}.${ct}`, /wrong part sizes/],
    ];
    for (const [envelope, why] of cases) {
      const err = await refusal(client.importSealed(ownerOf('ana'), envelope as string));
      expect(err.status).toBe(400);
      expect(err.message).toMatch(why);
    }
    // The size limit applies before the RSA step: openSealedSecret never gets to the key.
    expect(() => openSealedSecret(undefined as never, 'x'.repeat(MAX_ENVELOPE_CHARS + 1), 'import', ownerTag(ownerOf('ana')), '', Date.now())).toThrow(/longer than 4096/);
    const aad = envelopeAad('import', ownerTag(ownerOf('ana')));
    for (const [content, why] of [
      ['not json', /not JSON/],
      [[1, 2], /not an object/],
      [{ ncryptsec: 'x', password: 'y' }, /exactly at,ncryptsec,password/],
      [{ ncryptsec: 'x', password: 'y', at, extra: 1 }, /exactly at,ncryptsec,password/],
      [{ ncryptsec: 'x', password: 'y', at: String(at) }, /timestamp in ms/],
      [{ ncryptsec: 'x', password: 7, at }, /password must be a string/],
      [{ ncryptsec: null, password: 'y', at }, /ncryptsec must be a string/],
    ] as Array<[unknown, RegExp]>) {
      const err = await refusal(client.importSealed(ownerOf('ana'), rawSeal(spki, aad, content)));
      expect(err.status).toBe(400);
      expect(err.message).toMatch(why);
    }
  });

  it('FR005-10: a sealed import keeps the limits: the scrypt cost cap and a wrong password are 400s', async () => {
    const { sim, client } = setup();
    const ncryptsec = nip49.encryptKey(generateSecretKey(), IMPORT_PASSWORD, 4);
    const costly = await refusal(client.importSealed(ownerOf('ana'), await sealImport(sim, client, ownerOf('ana'), withLogN(ncryptsec, 20))));
    expect(costly.status).toBe(400);
    expect(costly.message).toMatch(/logN 20 is above 18/);
    const wrong = await refusal(client.importSealed(ownerOf('ana'), await sealImport(sim, client, ownerOf('ana'), ncryptsec, 'otra contraseña')));
    expect(wrong.status).toBe(400);
    expect(wrong.message).toMatch(/cannot decrypt ncryptsec/);
  });

  it('FR005-10: a sealed export keeps the password rule, and an envelope that fails does not spend the owner\'s proof', async () => {
    const { sim, client } = setup();
    const { pubkey, sealed } = await client.generate(ownerOf('ana'));
    const token = pool.token({ sub: 'ana' });
    const short = await refusal(client.exportSealed(sealed, pubkey, await sealExport(sim, client, ownerOf('ana'), pubkey, 'corta'), 4, token));
    expect(short.status).toBe(400);
    expect(short.message).toMatch(/at least 12 characters/);
    await refusal(client.exportSealed(sealed, pubkey, 'ae1.AAAA.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAA', 4, token));
    // The same token still works: it was only spent by the export that went through.
    const ncryptsec = await client.exportSealed(sealed, pubkey, await sealExport(sim, client, ownerOf('ana'), pubkey), 4, token);
    expect(getPublicKey(nip49.decryptKey(ncryptsec, EXPORT_PASSWORD).secretKey)).toBe(pubkey);
    expect((await refusal(client.exportSealed(sealed, pubkey, await sealExport(sim, client, ownerOf('ana'), pubkey), 4, token))).message).toMatch(/already used/);
  });

  it('FR005-10: in clear or sealed, never both and never neither', async () => {
    const { sim, client } = setup();
    const ncryptsec = nip49.encryptKey(generateSecretKey(), IMPORT_PASSWORD, 4);
    const envelope = await sealImport(sim, client, ownerOf('ana'), ncryptsec);
    const owner = ownerOf('ana');
    expect(await sim.enclave.handle({ op: 'import', owner, ncryptsec, password: IMPORT_PASSWORD, sealedSecrets: envelope })).toMatchObject({ ok: false, status: 400, error: expect.stringMatching(/not both/) });
    expect(await sim.enclave.handle({ op: 'import', owner, sealedSecrets: envelope, password: IMPORT_PASSWORD })).toMatchObject({ ok: false, status: 400 });
    expect(await sim.enclave.handle({ op: 'import', owner })).toMatchObject({ ok: false, status: 400, error: expect.stringMatching(/needs ncryptsec and password, or sealedSecrets/) });
    const { pubkey, sealed } = await client.generate(owner);
    const sealedText = Buffer.from(sealed).toString('utf8');
    const exportEnvelope = await sealExport(sim, client, owner, pubkey);
    const both = await sim.enclave.handle({ op: 'export', sealed: sealedText, pubkey, password: EXPORT_PASSWORD, sealedPassword: exportEnvelope, logN: 4, proof: pool.token({ sub: 'ana' }) });
    expect(both).toMatchObject({ ok: false, status: 400, error: expect.stringMatching(/not both/) });
    const neither = await sim.enclave.handle({ op: 'export', sealed: sealedText, pubkey, logN: 4, proof: pool.token({ sub: 'ana' }) });
    expect(neither).toMatchObject({ ok: false, status: 400, error: expect.stringMatching(/at least 12 characters/) });
  });

  it('FR005-10: with ENCLAVE_REQUIRE_SEALED_SECRETS the enclave refuses secrets in clear (403) and still takes sealed ones', async () => {
    const { sim, client } = setup({ requireSealedSecrets: true });
    const owner = ownerOf('ana');
    const sk = generateSecretKey();
    const ncryptsec = nip49.encryptKey(sk, IMPORT_PASSWORD, 4);
    const clearImport = await refusal(client.importNcryptsec(owner, ncryptsec, IMPORT_PASSWORD));
    expect(clearImport.status).toBe(403);
    expect(clearImport.message).toMatch(/ENCLAVE_REQUIRE_SEALED_SECRETS/);
    const { pubkey, sealed } = await client.importSealed(owner, await sealImport(sim, client, owner, ncryptsec));
    expect(pubkey).toBe(getPublicKey(sk));
    const clearExport = await refusal(client.exportNcryptsec(sealed, pubkey, EXPORT_PASSWORD, 4, pool.token({ sub: 'ana' })));
    expect(clearExport.status).toBe(403);
    const ncryptsecOut = await client.exportSealed(sealed, pubkey, await sealExport(sim, client, owner, pubkey), 4, pool.token({ sub: 'ana' }));
    expect(getPublicKey(nip49.decryptKey(ncryptsecOut, EXPORT_PASSWORD).secretKey)).toBe(pubkey);
    // Without the flag, secrets in clear keep working as before.
    const legacy = setup();
    expect((await legacy.client.importNcryptsec(owner, nip49.encryptKey(generateSecretKey(), IMPORT_PASSWORD, 4), IMPORT_PASSWORD)).pubkey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('FR005-10: the parent relays only documents that pass its own policy (a document for the client\'s nonce from an enclave it would not use fails there)', async () => {
    const sim = createSimulatedEnclave({ pcrs: simulatedPcrs('image-the-parent-does-not-expect') });
    const parent = new EnclaveClient({ transport: inProcessTransport(sim.enclave), attestation: { ...sim.policy, expectedPcrs: { 0: simulatedPcrs()[0] } } });
    await expect(parent.attest(randomBytes(32))).rejects.toBeInstanceOf(AttestationError);
    await expect(parent.attest(randomBytes(8))).rejects.toThrow(/16-64 bytes/);
    const ok = setup();
    expect((await ok.client.attest(randomBytes(32))).length).toBeGreaterThan(1000);
  });

  it('FR005-10: the switches are 1 or off, and a typo is a configuration error, not a silent off', () => {
    expect(flagFromEnv({ ENCLAVE_REQUIRE_SEALED_SECRETS: '1' }, 'ENCLAVE_REQUIRE_SEALED_SECRETS')).toBe(true);
    for (const off of [undefined, '', '0']) expect(flagFromEnv({ ENCLAVE_REQUIRE_SEALED_SECRETS: off }, 'ENCLAVE_REQUIRE_SEALED_SECRETS')).toBe(false);
    for (const typo of ['true', 'yes', ' 1']) expect(() => flagFromEnv({ ENCLAVE_REQUIRE_SEALED_SECRETS: typo }, 'ENCLAVE_REQUIRE_SEALED_SECRETS')).toThrow(/must be 1/);
  });
});
