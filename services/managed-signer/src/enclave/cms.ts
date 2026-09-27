import { constants, createCipheriv, createDecipheriv, privateDecrypt, publicEncrypt, randomBytes, type KeyObject } from 'node:crypto';
import { ctx, decodeOid, der, derChildren, int, octets, oid, parseDer, seq, set, TAG, type DerNode } from './der';

/**
 * CMS EnvelopedData (RFC 5652) as returned by KMS in CiphertextForRecipient: one KeyTransRecipientInfo
 * (RSAES-OAEP with SHA-256 to the enclave's ephemeral key) and AES-256-CBC content encryption.
 */
const OID = {
  envelopedData: '1.2.840.113549.1.7.3',
  data: '1.2.840.113549.1.7.1',
  rsaesOaep: '1.2.840.113549.1.1.7',
  mgf1: '1.2.840.113549.1.1.8',
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
  aes256Cbc: '2.16.840.1.101.3.4.1.42',
} as const;

const HASHES: Record<string, string> = { [OID.sha1]: 'sha1', [OID.sha256]: 'sha256' };

function expect(node: DerNode | undefined, tag: number, what: string): DerNode {
  if (!node || node.tag !== tag) throw new Error(`cms: malformed ${what}`);
  return node;
}

/** OAEP hash from RSAES-OAEP-params (RFC 4055): absent hashAlgorithm means SHA-1. */
function oaepHash(params: DerNode | undefined): string {
  if (!params || params.tag === TAG.NULL) return 'sha1';
  const fields = derChildren(expect(params, TAG.SEQUENCE, 'OAEP params'));
  const h = fields.find((f) => f.tag === 0xa0);
  if (!h) return 'sha1';
  const alg = derChildren(expect(derChildren(h)[0], TAG.SEQUENCE, 'OAEP hash'))[0]!;
  const name = HASHES[decodeOid(expect(alg, TAG.OID, 'OAEP hash OID').value)];
  if (!name) throw new Error('cms: unsupported OAEP hash');
  return name;
}

/** Decrypts CiphertextForRecipient with the enclave's RSA private key; returns the plaintext (e.g. a data key). */
export function decryptEnvelopedData(cms: Uint8Array, privateKey: KeyObject): Uint8Array {
  const top = derChildren(expect(parseDer(cms), TAG.SEQUENCE, 'ContentInfo'));
  if (decodeOid(expect(top[0], TAG.OID, 'contentType').value) !== OID.envelopedData) throw new Error('cms: not EnvelopedData');
  const env = derChildren(expect(derChildren(expect(top[1], 0xa0, 'content'))[0], TAG.SEQUENCE, 'EnvelopedData'));
  let i = 1; // version
  if (env[i]?.tag === 0xa0) i++; // originatorInfo
  const recipients = derChildren(expect(env[i++], TAG.SET, 'recipientInfos'));
  const eci = derChildren(expect(env[i], TAG.SEQUENCE, 'encryptedContentInfo'));

  const ktri = recipients.map((r) => derChildren(r)).find((r) => r[0]?.tag === TAG.INTEGER && r.length === 4);
  if (!ktri) throw new Error('cms: no KeyTransRecipientInfo');
  const kea = derChildren(expect(ktri[2], TAG.SEQUENCE, 'keyEncryptionAlgorithm'));
  if (decodeOid(expect(kea[0], TAG.OID, 'key encryption OID').value) !== OID.rsaesOaep) throw new Error('cms: key encryption must be RSAES-OAEP');
  const cek = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: oaepHash(kea[1]) }, expect(ktri[3], TAG.OCTET_STRING, 'encryptedKey').value);

  try {
    const cea = derChildren(expect(eci[1], TAG.SEQUENCE, 'contentEncryptionAlgorithm'));
    if (decodeOid(expect(cea[0], TAG.OID, 'content encryption OID').value) !== OID.aes256Cbc) throw new Error('cms: content encryption must be AES-256-CBC');
    const iv = expect(cea[1], TAG.OCTET_STRING, 'IV').value;
    // encryptedContent [0] IMPLICIT OCTET STRING, primitive or constructed (BER chunks).
    const ec = eci[2];
    let ct: Uint8Array;
    if (ec?.tag === 0x80) ct = ec.value;
    else if (ec?.tag === 0xa0) ct = Buffer.concat(derChildren(ec).map((c) => expect(c, TAG.OCTET_STRING, 'encryptedContent chunk').value));
    else throw new Error('cms: encryptedContent missing');
    const d = createDecipheriv('aes-256-cbc', cek, iv);
    return new Uint8Array(Buffer.concat([d.update(ct), d.final()]));
  } finally {
    cek.fill(0);
  }
}

/** Builds EnvelopedData the way KMS does for a Recipient (used by the simulated KMS and tests). */
export function encryptEnvelopedData(plaintext: Uint8Array, recipientPublicKey: KeyObject): Uint8Array {
  const cek = randomBytes(32);
  const iv = randomBytes(16);
  const c = createCipheriv('aes-256-cbc', cek, iv);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  const ek = publicEncrypt({ key: recipientPublicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, cek);
  cek.fill(0);
  const sha256Alg = seq(oid(OID.sha256));
  const oaepParams = seq(ctx(0, true, sha256Alg), ctx(1, true, seq(oid(OID.mgf1), sha256Alg)));
  // rid: subjectKeyIdentifier [0]; KMS recipients are identified by the key itself, the value is opaque here.
  const ktri = seq(int(2), ctx(0, false, randomBytes(20)), seq(oid(OID.rsaesOaep), oaepParams), octets(ek));
  const eci = seq(oid(OID.data), seq(oid(OID.aes256Cbc), octets(iv)), der(0x80, ct));
  return seq(oid(OID.envelopedData), ctx(0, true, seq(int(2), set(ktri), eci)));
}
