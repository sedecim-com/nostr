// Exportable crypto vectors (SEC-07, ADR 0004): NIP-49 and NIP-59 cases built from fixed inputs, so a client
// in another language can check what it produces as well as what it reads. NIP-44 uses the official file
// (nip44.vectors.json, checked by nip44-vectors.test.ts).
//   npx tsx packages/nostr-core/test/vectors/generate.ts          (write)
//   npx tsx packages/nostr-core/test/vectors/generate.ts --check  (exit 1 if a committed file is stale)
// Everything below is built with @noble primitives, not with the SDK functions under test, so the tests that
// read these files cross-check the SDK against an independent construction.
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { schnorr } from '@noble/curves/secp256k1.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { scrypt } from '@noble/hashes/scrypt';
import { sha256 } from '@noble/hashes/sha256';
import { bech32 } from '@scure/base';
import { bytesToHex, concatBytes, getEventHash, getPublicKey, hexToBytes, nip44, utf8ToBytes, type NostrEvent, type UnsignedEvent } from '../../src/index';

/** Every "random" input is sha256 of a label, so the files are reproducible. */
const derive = (label: string) => sha256(utf8ToBytes(`acceso-nostr/vectors/${label}`));
const secret = (name: string) => derive(`key/${name}`);
const hex = bytesToHex;

// ------------------------------------------------------------------ NIP-49
function ncryptsec(logN: number, salt: Uint8Array, nonce: Uint8Array, keySecurity: number, ciphertext: Uint8Array): string {
  const bytes = concatBytes(new Uint8Array([0x02, logN]), salt, nonce, new Uint8Array([keySecurity]), ciphertext);
  return bech32.encode('ncryptsec', bech32.toWords(bytes), 5000);
}

function encryptNip49(sec: Uint8Array, password: string, logN: number, keySecurity: number, label: string) {
  const salt = derive(`nip49/${label}/salt`).slice(0, 16);
  const nonce = derive(`nip49/${label}/nonce`).slice(0, 24);
  const key = scrypt(utf8ToBytes(password.normalize('NFKC')), salt, { N: 2 ** logN, r: 8, p: 1, dkLen: 32 });
  const ciphertext = xchacha20poly1305(key, nonce, new Uint8Array([keySecurity])).encrypt(sec);
  return { salt, nonce, ciphertext, ncryptsec: ncryptsec(logN, salt, nonce, keySecurity, ciphertext) };
}

export function nip49Vectors() {
  const cases = [
    { label: 'ascii', sec: secret('nip49/ascii'), password: 'nostr', logN: 16, keySecurity: 0x02, note: 'Default cost (log_n 16) and key security unknown' },
    { label: 'unicode', sec: secret('nip49/unicode'), password: 'contraseña 🔑 ñ', logN: 12, keySecurity: 0x01, note: 'Non-ASCII password; key known not to have been handled insecurely' },
    { label: 'nfkc', sec: secret('nip49/nfkc'), password: 'ÅΩẛ̣', logN: 8, keySecurity: 0x00, note: 'Password that NFKC changes: the normalized form opens it too' },
  ];
  const valid = cases.map((c) => {
    const e = encryptNip49(c.sec, c.password, c.logN, c.keySecurity, c.label);
    return {
      note: c.note,
      sec: hex(c.sec),
      password: c.password,
      password_nfkc_utf8: hex(utf8ToBytes(c.password.normalize('NFKC'))),
      log_n: c.logN,
      key_security: c.keySecurity,
      salt: hex(e.salt),
      nonce: hex(e.nonce),
      ncryptsec: e.ncryptsec,
    };
  });
  const base = encryptNip49(cases[0]!.sec, cases[0]!.password, cases[0]!.logN, cases[0]!.keySecurity, cases[0]!.label);
  const flipped = (b: Uint8Array, i: number) => Uint8Array.from(b, (x, j) => (j === i ? x ^ 0x01 : x));
  const invalid = [
    { note: 'Wrong password', ncryptsec: base.ncryptsec, password: 'Nostr' },
    { note: 'Ciphertext changed', ncryptsec: ncryptsec(16, base.salt, base.nonce, 0x02, flipped(base.ciphertext, 0)), password: 'nostr' },
    { note: 'Key security byte changed (it is the AAD)', ncryptsec: ncryptsec(16, base.salt, base.nonce, 0x01, base.ciphertext), password: 'nostr' },
    {
      note: 'Unsupported version 0x01',
      ncryptsec: bech32.encode('ncryptsec', bech32.toWords(concatBytes(new Uint8Array([0x01, 16]), base.salt, base.nonce, new Uint8Array([0x02]), base.ciphertext)), 5000),
      password: 'nostr',
    },
    { note: 'log_n above what the reader accepts: reject before running scrypt', ncryptsec: base.ncryptsec, password: 'nostr', max_log_n: 15 },
  ];
  return {
    description: 'NIP-49 (ncryptsec) vectors of Acceso Nostr. See README.md in this folder.',
    official: [
      {
        note: 'Test vector published in NIP-49',
        ncryptsec: 'ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p',
        password: 'nostr',
        log_n: 16,
        sec: '3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683',
      },
    ],
    normalization: [{ note: 'NIP-49 example: passwords are NFKC-normalized before scrypt', password_utf8: 'e284abe284a6e1ba9bcca3', password_nfkc_utf8: 'c385cea9e1b9a9' }],
    valid,
    invalid,
  };
}

// ------------------------------------------------------------------ NIP-59
const T0 = 1790640000; // 2026-09-29T00:00:00Z

function sign(unsigned: UnsignedEvent, sec: Uint8Array, label: string): NostrEvent {
  const id = getEventHash(unsigned);
  return { ...unsigned, id, sig: hex(schnorr.sign(hexToBytes(id), sec, derive(`nip59/${label}/aux`))) };
}

/** NIP-44 v2 payload with a fixed nonce (the SDK's `encrypt` takes the nonce for exactly this). */
const seal44 = (from: Uint8Array, toPub: string, plaintext: string, label: string) =>
  nip44.encrypt(plaintext, nip44.getConversationKey(from, toPub), derive(`nip59/${label}/nonce`));

function rumor(author: Uint8Array, kind: number, content: string, tags: string[][], createdAt: number) {
  const unsigned: UnsignedEvent = { pubkey: getPublicKey(author), created_at: createdAt, kind, tags, content };
  return { ...unsigned, id: getEventHash(unsigned) };
}

function giftWrap(opts: { author: Uint8Array; recipientPub: string; rumor: object; sealKind?: number; label: string }) {
  const seal = sign(
    { pubkey: getPublicKey(opts.author), created_at: T0 - 3600, kind: opts.sealKind ?? 13, tags: [], content: seal44(opts.author, opts.recipientPub, JSON.stringify(opts.rumor), `${opts.label}/seal`) },
    opts.author,
    `${opts.label}/seal`,
  );
  const ephemeral = secret(`nip59/${opts.label}/ephemeral`);
  const wrap = sign(
    { pubkey: getPublicKey(ephemeral), created_at: T0 - 7200, kind: 1059, tags: [['p', opts.recipientPub]], content: seal44(ephemeral, opts.recipientPub, JSON.stringify(seal), `${opts.label}/wrap`) },
    ephemeral,
    `${opts.label}/wrap`,
  );
  return { seal, wrap, ephemeral };
}

export function nip59Vectors() {
  const [alice, bob, carol, mallory] = ['alice', 'bob', 'carol', 'mallory'].map((n) => secret(`nip59/${n}`)) as [Uint8Array, Uint8Array, Uint8Array, Uint8Array];
  const [alicePub, bobPub] = [getPublicKey(alice), getPublicKey(bob)];
  const dm = rumor(alice, 14, 'Hola, Bob. ¿Nos vemos a las 18:00?', [['p', bobPub]], T0);
  const toBob = giftWrap({ author: alice, recipientPub: bobPub, rumor: dm, label: 'dm-to-bob' });
  const toSelf = giftWrap({ author: alice, recipientPub: alicePub, rumor: dm, label: 'dm-copy-to-alice' });
  const valid = [
    { note: 'Kind 14 DM from Alice to Bob', wrap: toBob, recipient: bob },
    { note: 'The copy of the same DM that Alice wraps to herself', wrap: toSelf, recipient: alice },
  ].map(({ note, wrap, recipient }) => ({
    note,
    recipient_sec: hex(recipient),
    sender_pub: alicePub,
    wrap_conversation_key: hex(nip44.getConversationKey(recipient, wrap.wrap.pubkey)),
    seal_conversation_key: hex(nip44.getConversationKey(recipient, alicePub)),
    wrap: wrap.wrap,
    seal: wrap.seal,
    rumor: dm,
  }));

  const tampered = { ...toBob.wrap, content: toBob.wrap.content.slice(0, -4) + (toBob.wrap.content.endsWith('AAAA') ? 'BBBB' : 'AAAA') };
  const notASeal = giftWrap({ author: alice, recipientPub: bobPub, rumor: dm, sealKind: 1, label: 'kind-1-seal' });
  // Mallory seals a rumor that claims to be written by Alice.
  const forged = giftWrap({ author: mallory, recipientPub: bobPub, rumor: dm, label: 'impersonation' });
  const edited = giftWrap({ author: alice, recipientPub: bobPub, rumor: { ...dm, content: 'Mejor a las 20:00' }, label: 'edited-rumor' });
  const invalid = [
    { note: 'Wrong recipient: the wrap does not decrypt', recipient_sec: hex(carol), wrap: toBob.wrap },
    { note: 'Wrap content changed: its signature no longer verifies', recipient_sec: hex(bob), wrap: tampered },
    { note: 'The sealed event is kind 1, not 13', recipient_sec: hex(bob), wrap: notASeal.wrap },
    { note: 'Seal signed by someone other than the rumor author (impersonation)', recipient_sec: hex(bob), wrap: forged.wrap },
    { note: 'Rumor content edited after its id was computed', recipient_sec: hex(bob), wrap: edited.wrap },
  ];
  return { description: 'NIP-59 gift wrap vectors of Acceso Nostr. See README.md in this folder.', valid, invalid };
}

// ------------------------------------------------------------------ files
const dir = fileURLToPath(new URL('.', import.meta.url));
export const FILES = { 'nip49.vectors.json': nip49Vectors, 'nip59.vectors.json': nip59Vectors } as const;
export const render = (build: () => object) => JSON.stringify(build(), null, 2) + '\n';

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const check = process.argv.includes('--check');
  let stale = false;
  for (const [name, build] of Object.entries(FILES)) {
    const path = `${dir}${name}`;
    const next = render(build);
    if (!check) writeFileSync(path, next);
    else if (readFileSync(path, 'utf8') !== next) {
      console.error(`${name} is stale: run npx tsx packages/nostr-core/test/vectors/generate.ts`);
      stale = true;
    }
  }
  if (stale) process.exit(1);
  console.log(check ? 'vectors ok' : `wrote ${Object.keys(FILES).join(', ')}`);
}
