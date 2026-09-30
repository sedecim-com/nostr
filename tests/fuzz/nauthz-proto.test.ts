/**
 * Internal review 2026-09: the hand-written protobuf codec of the nauthz admission server in the
 * policy-engine allowlist sync (nostr-rs-relay `[grpc] event_admission_server`). The relay's requests must
 * decode or be rejected with an Error; the reply must decode back to the same decision and message.
 */
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { AdmissionServer, decodeEventRequest, encodeEventReply } from '@sedecim/policy-engine';
import { runs, throwsCleanly } from './arbitraries';

// Minimal reference encoder/decoder for the test (proto3 wire format).
const varint = (n: number): number[] => {
  const out: number[] = [];
  for (; n > 0x7f; n = Math.floor(n / 128)) out.push((n % 128) | 0x80);
  out.push(n);
  return out;
};
const lenField = (f: number, b: Uint8Array) => [...varint((f << 3) | 2), ...varint(b.length), ...b];
const intField = (f: number, v: number) => [...varint(f << 3), ...varint(v)];

/**
 * nauthz EventRequest { event = 1 (Event { id = 1, pubkey = 2, created_at = 3, kind = 4, content = 5, tags = 6 (TagEntry {
 * values = 1 }) }), ip_addr = 2, origin = 3, user_agent = 4, auth_pubkey = 5 }.
 */
function encodeEventRequest(r: { eventPubkey: Uint8Array; kind: number; createdAt: number; authPubkey?: Uint8Array; ip?: string; tags?: string[][] }) {
  const tags = (r.tags ?? []).flatMap((t) => lenField(6, new Uint8Array(t.flatMap((v) => lenField(1, new TextEncoder().encode(v))))));
  const event = new Uint8Array([...lenField(1, new Uint8Array(32)), ...lenField(2, r.eventPubkey), ...intField(3, r.createdAt), ...intField(4, r.kind), ...lenField(5, new TextEncoder().encode('hola')), ...tags]);
  return new Uint8Array([...lenField(1, event), ...(r.ip ? lenField(2, new TextEncoder().encode(r.ip)) : []), ...(r.authPubkey ? lenField(5, r.authPubkey) : [])]);
}

function decodeReply(b: Uint8Array): { decision?: number; message?: string } {
  const out: { decision?: number; message?: string } = {};
  let o = 0;
  const rv = () => {
    let v = 0;
    for (let s = 0; ; s += 7) {
      const x = b[o++]!;
      v += (x & 0x7f) * 2 ** s;
      if (!(x & 0x80)) return v;
    }
  };
  while (o < b.length) {
    const key = rv();
    if (key === 0x08) out.decision = rv();
    else if (key === 0x12) {
      const n = rv();
      out.message = new TextDecoder().decode(b.subarray(o, o + n));
      o += n;
    } else throw new Error(`unexpected key ${key}`);
  }
  return out;
}

const key32 = fc.uint8Array({ minLength: 32, maxLength: 32 });
// FR023-10: tags, `h` ones among them (the channel or group an event is for).
const tag = fc.oneof(fc.tuple(fc.constant('h'), fc.string({ maxLength: 64 })).map((t) => [...t]), fc.array(fc.string({ maxLength: 20 }), { maxLength: 4 }));
const request = fc.record({
  eventPubkey: key32,
  kind: fc.nat({ max: 65535 }),
  createdAt: fc.nat({ max: 2 ** 40 }),
  authPubkey: fc.option(key32, { nil: undefined }),
  ip: fc.option(fc.ipV4(), { nil: undefined }),
  tags: fc.array(tag, { maxLength: 6 }),
});

describe('nauthz protobuf codec (fuzz)', () => {
  it('decodes what a relay encodes', () => {
    fc.assert(
      fc.property(request, (r) => {
        const d = decodeEventRequest(encodeEventRequest(r));
        expect(d.eventPubkey).toBe(Buffer.from(r.eventPubkey).toString('hex'));
        expect(d.kind).toBe(r.kind);
        expect(d.authPubkey).toBe(r.authPubkey ? Buffer.from(r.authPubkey).toString('hex') : undefined);
        const h = r.tags.filter((t) => t[0] === 'h' && t[1] !== undefined).map((t) => t[1]);
        expect(d.h).toEqual(h.length ? h : undefined);
      }),
      runs(500),
    );
  });

  it('random and mutated requests decode or throw an Error (bounded work)', () => {
    const mutated = fc.tuple(request, fc.array(fc.tuple(fc.nat(), fc.integer({ min: 1, max: 255 })), { minLength: 1, maxLength: 4 })).map(([r, f]) => {
      const b = encodeEventRequest(r);
      for (const [i, x] of f) b[i % b.length]! ^= x;
      return b;
    });
    fc.assert(fc.property(fc.oneof(fc.uint8Array({ maxLength: 200 }), mutated), (b) => void throwsCleanly(() => decodeEventRequest(b))), runs(2000));
  });

  it('a request is only permitted for an allowlisted, correctly decoded auth pubkey', () => {
    const allowed = new Uint8Array(32).fill(0xab);
    const server = new AdmissionServer();
    server.set([Buffer.from(allowed).toString('hex')]);
    // No channel registered: an `h` is left to the allowlist (FR023-10).
    server.setGrants([]);
    fc.assert(
      fc.property(request, (r) => {
        const d = server.decide(decodeEventRequest(encodeEventRequest(r)));
        expect(d.permit).toBe(false); // random auth keys are never the allowlisted one
        expect(server.decide(decodeEventRequest(encodeEventRequest({ ...r, authPubkey: allowed }))).permit).toBe(true);
      }),
      runs(300),
    );
  });

  it('regressions: overlong varints, lengths past the end, unsupported wire types', () => {
    for (const b of [
      Uint8Array.of(0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f),
      Uint8Array.of(0x0a, 0x05, 0x01),
      Uint8Array.of(0x0b),
      Uint8Array.of(0x09, 0x01, 0x02),
      Uint8Array.of(0x80),
    ]) expect(throwsCleanly(() => decodeEventRequest(b))).toBe(true);
  });

  it('EventReply encodes decision and message exactly', () => {
    fc.assert(
      fc.property(fc.boolean(), fc.option(fc.string({ minLength: 1, maxLength: 300 }), { nil: undefined }), (permit, message) => {
        expect(decodeReply(encodeEventReply(permit, message))).toEqual({ decision: permit ? 1 : 2, ...(message ? { message } : {}) });
      }),
      runs(500),
    );
  });
});
