import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { CreateKeyCommand, KMSClient } from '@aws-sdk/client-kms';
import { DescribeSecretCommand, GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { bytesToHex, finalizeEvent, generateSecretKey, nip49, toUnsigned, verifyEvent } from '@sedecim/nostr-core';
import { awsKms, awsSecretsManager, ManagedSigner, SecretsManagerVault, type KmsLike, type SecretsManagerLike } from '../src/index';

const keyId = () => randomBytes(16).toString('hex');

/** Fake KMS: data keys are "wrapped" by an in-memory table bound to the encryption context. */
function fakeKms() {
  const wrapped = new Map<string, { key: Buffer; ctx: string; kmsKeyId: string }>();
  const issued: Uint8Array[] = [];
  const returned: Uint8Array[] = [];
  const kms: KmsLike = {
    async generateDataKey(kmsKeyId, context) {
      const key = randomBytes(32);
      const handle = randomBytes(16);
      wrapped.set(handle.toString('hex'), { key: Buffer.from(key), ctx: JSON.stringify(context), kmsKeyId });
      issued.push(key);
      return { plaintext: key, ciphertext: handle };
    },
    async decrypt(kmsKeyId, ciphertext, context) {
      const w = wrapped.get(Buffer.from(ciphertext).toString('hex'));
      if (!w || w.ctx !== JSON.stringify(context) || w.kmsKeyId !== kmsKeyId) throw new Error('InvalidCiphertextException');
      const out = new Uint8Array(w.key);
      returned.push(out);
      return out;
    },
  };
  return { kms, issued, returned };
}

function fakeSecretsManager() {
  const secrets = new Map<string, { value: string; recoveryWindowDays?: number }>();
  const sm: SecretsManagerLike = {
    async createSecret(name, value) {
      if (secrets.has(name)) throw new Error('ResourceExistsException');
      secrets.set(name, { value });
    },
    async getSecretString(name) {
      const s = secrets.get(name);
      return s && s.recoveryWindowDays === undefined ? s.value : undefined;
    },
    async deleteSecret(name, recoveryWindowDays) {
      const s = secrets.get(name);
      if (s) s.recoveryWindowDays = recoveryWindowDays;
    },
  };
  return { sm, secrets };
}

describe('SecretsManagerVault (unit, FR005-02)', () => {
  it('stores only AES-GCM ciphertext and a KMS-wrapped data key under the prefix, and zeroes key buffers', async () => {
    const { kms, issued, returned } = fakeKms();
    const { sm, secrets } = fakeSecretsManager();
    const vault = new SecretsManagerVault(sm, kms, { kmsKeyId: 'alias/acceso-nostr', prefix: 'test/keys/' });
    const id = keyId();
    const secret = generateSecretKey();
    await vault.put(id, secret);
    const stored = secrets.get(`test/keys/${id}`)!.value;
    expect(stored).not.toContain(bytesToHex(secret));
    expect(JSON.parse(stored)).toMatchObject({ v: 1, alg: 'AES-256-GCM', kms_key_id: 'alias/acceso-nostr' });
    expect(issued[0]!.every((b) => b === 0)).toBe(true);
    expect(await vault.get(id)).toEqual(secret);
    expect(returned[0]!.every((b) => b === 0)).toBe(true);
    expect(await vault.get(keyId())).toBeUndefined();
    await expect(vault.put('../etc', secret)).rejects.toThrow(/invalid key id/);
  });

  it('binds each sealed secret to its key id (encryption context + AAD)', async () => {
    const { kms } = fakeKms();
    const { sm, secrets } = fakeSecretsManager();
    const vault = new SecretsManagerVault(sm, kms, { kmsKeyId: 'k' });
    const [a, b] = [keyId(), keyId()];
    await vault.put(a, generateSecretKey());
    await vault.put(b, generateSecretKey());
    secrets.get(vault.name(b))!.value = secrets.get(vault.name(a))!.value;
    await expect(vault.get(b)).rejects.toThrow();
    const sealed = JSON.parse(secrets.get(vault.name(a))!.value);
    sealed.ct = Buffer.from(Buffer.from(sealed.ct, 'base64').map((x) => x ^ 1)).toString('base64');
    secrets.get(vault.name(a))!.value = JSON.stringify(sealed);
    await expect(vault.get(a)).rejects.toThrow();
  });

  it('schedules deletion with the retention window clamped to 7..30 days (DEC-09)', async () => {
    const { kms } = fakeKms();
    const { sm, secrets } = fakeSecretsManager();
    expect(new SecretsManagerVault(sm, kms, { kmsKeyId: 'k' }).recoveryWindowDays).toBe(30);
    expect(new SecretsManagerVault(sm, kms, { kmsKeyId: 'k', retentionDays: 0 }).recoveryWindowDays).toBe(7);
    expect(new SecretsManagerVault(sm, kms, { kmsKeyId: 'k', retentionDays: 90 }).recoveryWindowDays).toBe(30);
    const vault = new SecretsManagerVault(sm, kms, { kmsKeyId: 'k', retentionDays: 14 });
    const id = keyId();
    await vault.put(id, generateSecretKey());
    await vault.delete(id);
    expect(secrets.get(vault.name(id))!.recoveryWindowDays).toBe(14);
    expect(await vault.get(id)).toBeUndefined();
  });
});

const MOTO = process.env.MOTO_ENDPOINT;
describe.skipIf(!MOTO)('SecretsManagerVault against moto (AWS SDK v3)', () => {
  const aws = { region: 'us-east-1', endpoint: MOTO, credentials: { accessKeyId: 'testing', secretAccessKey: 'testing' } };
  const prefix = `acceso-nostr-test/${Date.now()}/`;
  const setup = async () => {
    const { KeyMetadata } = await new KMSClient(aws).send(new CreateKeyCommand({ Description: 'acceso-nostr managed keys (test)' }));
    return new SecretsManagerVault(awsSecretsManager(aws), awsKms(aws), { kmsKeyId: KeyMetadata!.KeyId!, prefix, retentionDays: 30 });
  };

  it('round-trips through KMS + Secrets Manager and schedules deletion with the recovery window', async () => {
    const vault = await setup();
    const sm = new SecretsManagerClient(aws);
    const id = keyId();
    const secret = generateSecretKey();
    await vault.put(id, secret);
    const raw = (await sm.send(new GetSecretValueCommand({ SecretId: `${prefix}${id}` }))).SecretString!;
    expect(raw).not.toContain(bytesToHex(secret));
    expect(await vault.get(id)).toEqual(secret);
    expect(await vault.get(keyId())).toBeUndefined();

    await vault.delete(id);
    const d = await sm.send(new DescribeSecretCommand({ SecretId: `${prefix}${id}` }));
    expect(d.DeletedDate).toBeInstanceOf(Date);
    expect(await vault.get(id)).toBeUndefined();
    await vault.delete(keyId());
  });

  it('rejects material copied under another key id (KMS encryption context + AAD)', async () => {
    const vault = await setup();
    const sm = awsSecretsManager(aws);
    const [a, b] = [keyId(), keyId()];
    await vault.put(a, generateSecretKey());
    await sm.createSecret(`${prefix}${b}`, (await sm.getSecretString(`${prefix}${a}`))!);
    await expect(vault.get(b)).rejects.toThrow();
    const kms = awsKms(aws);
    const kmsKeyId = (await new KMSClient(aws).send(new CreateKeyCommand({}))).KeyMetadata!.KeyId!;
    const dk = await kms.generateDataKey(kmsKeyId, { key_id: a });
    await expect(kms.decrypt(kmsKeyId, dk.ciphertext, { key_id: b })).rejects.toThrow();
    expect(await kms.decrypt(kmsKeyId, dk.ciphertext, { key_id: a })).toEqual(dk.plaintext);
  });

  it('backs the managed signer end to end (create, sign, migrate, delete)', async () => {
    const vault = await setup();
    const core = new ManagedSigner(vault, { retentionDays: 30 });
    const k = await core.create('o', 'p');
    expect(k.provider).toBe('aws-secrets-manager');
    expect(verifyEvent(await core.sign(k.keyId, 'o', 'p', { kind: 1, content: 'desde KMS' }))).toBe(true);
    const exp = await core.export(k.keyId, 'o', 'p', 'contraseña suficientemente larga', 4);
    const sk = nip49.decryptKey(exp.ncryptsec, 'contraseña suficientemente larga').secretKey;
    await core.confirmMigration(k.keyId, 'o', 'p', finalizeEvent(toUnsigned({ kind: 27235, content: '', tags: [['challenge', exp.challenge]] }, k.pubkey), sk));
    await core.delete(k.keyId, 'o', 'p');
    // Secrets Manager holds it in the recovery window: unreadable now, destroyed by AWS after 30 days.
    expect(await vault.get(k.keyId)).toBeUndefined();
  });
});
