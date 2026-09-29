import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../src/utils';
import { getPublicKey } from '../src/keys';
import { nip44 } from '../src/index';

// Official NIP-44 v2 vectors (github.com/paulmillr/nip44, nip44.vectors.json). The NIP publishes the
// file's SHA-256, checked first so an edited copy cannot pass.
const raw = readFileSync(new URL('./vectors/nip44.vectors.json', import.meta.url));
const V = JSON.parse(raw.toString()).v2;
const hex = (b: Uint8Array) => bytesToHex(b);
const pub = (sec: string) => getPublicKey(hexToBytes(sec));

describe('NIP-44 v2 official vectors', () => {
  it('uses the published vectors file', () => {
    expect(hex(sha256(raw))).toBe('269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040');
  });

  it('valid.get_conversation_key', () => {
    for (const v of V.valid.get_conversation_key) expect(hex(nip44.getConversationKey(hexToBytes(v.sec1), v.pub2)), v.sec1).toBe(v.conversation_key);
  });

  it('valid.get_message_keys', () => {
    const ck = hexToBytes(V.valid.get_message_keys.conversation_key);
    for (const k of V.valid.get_message_keys.keys) {
      const m = nip44.getMessageKeys(ck, hexToBytes(k.nonce));
      expect([hex(m.chachaKey), hex(m.chachaNonce), hex(m.hmacKey)]).toEqual([k.chacha_key, k.chacha_nonce, k.hmac_key]);
    }
  });

  it('valid.calc_padded_len', () => {
    for (const [len, padded] of V.valid.calc_padded_len) expect(nip44.calcPaddedLen(len), String(len)).toBe(padded);
  });

  it('valid.encrypt_decrypt (both directions)', () => {
    for (const v of V.valid.encrypt_decrypt) {
      const ck = nip44.getConversationKey(hexToBytes(v.sec1), pub(v.sec2));
      expect(hex(ck)).toBe(v.conversation_key);
      expect(hex(nip44.getConversationKey(hexToBytes(v.sec2), pub(v.sec1)))).toBe(v.conversation_key);
      expect(nip44.encrypt(v.plaintext, ck, hexToBytes(v.nonce))).toBe(v.payload);
      expect(nip44.decrypt(v.payload, ck)).toBe(v.plaintext);
    }
  });

  it('valid.encrypt_decrypt_long_msg', () => {
    for (const v of V.valid.encrypt_decrypt_long_msg) {
      const plaintext = v.pattern.repeat(v.repeat);
      expect(hex(sha256(utf8ToBytes(plaintext)))).toBe(v.plaintext_sha256);
      const ck = hexToBytes(v.conversation_key);
      const payload = nip44.encrypt(plaintext, ck, hexToBytes(v.nonce));
      expect(hex(sha256(utf8ToBytes(payload)))).toBe(v.payload_sha256);
      expect(nip44.decrypt(payload, ck)).toBe(plaintext);
    }
  });

  it('invalid.encrypt_msg_lengths', () => {
    const ck = new Uint8Array(32).fill(1);
    for (const len of V.invalid.encrypt_msg_lengths) expect(() => nip44.encrypt('x'.repeat(len), ck), String(len)).toThrow();
  });

  it('invalid.get_conversation_key', () => {
    for (const v of V.invalid.get_conversation_key) expect(() => nip44.getConversationKey(hexToBytes(v.sec1), v.pub2), v.note).toThrow();
  });

  it('invalid.decrypt', () => {
    for (const v of V.invalid.decrypt) expect(() => nip44.decrypt(v.payload, hexToBytes(v.conversation_key)), v.note).toThrow();
  });
});
