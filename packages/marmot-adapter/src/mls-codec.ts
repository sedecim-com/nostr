import { encode, keyPackageDecoder, keyPackageEncoder, mlsMessageDecoder, mlsMessageEncoder, type Decoder, type KeyPackage, type MlsMessage } from 'ts-mls';

const MAX_INPUT = 1_000_000;

/**
 * Strict decode: the whole input must be one object. ts-mls `decode()` ignores trailing bytes, so two
 * different byte strings can decode to the same object; this wrapper rejects that (found by SEC-03 fuzz).
 */
function strict<T>(dec: Decoder<T>, bytes: Uint8Array): T | undefined {
  if (bytes.length > MAX_INPUT) return undefined;
  const r = dec(bytes, 0);
  return r && r[1] === bytes.length ? r[0] : undefined;
}

/**
 * TLS presentation-language codec of MLS wire objects (RFC 9420 §6), as used by ts-mls. Decoders
 * return undefined on malformed input (ts-mls may also throw a CodecError); used for validation and
 * by the fuzz tests.
 */
export const mlsCodec = {
  decodeMessage: (bytes: Uint8Array): MlsMessage | undefined => strict(mlsMessageDecoder, bytes),
  encodeMessage: (msg: MlsMessage): Uint8Array => encode(mlsMessageEncoder, msg),
  decodeKeyPackage: (bytes: Uint8Array): KeyPackage | undefined => strict(keyPackageDecoder, bytes),
  encodeKeyPackage: (kp: KeyPackage): Uint8Array => encode(keyPackageEncoder, kp),
};
