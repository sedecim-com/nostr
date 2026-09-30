/**
 * The NIP-77 client's messages against Negentropy Protocol V1 as the appendix of NIP-77 writes it (version byte 0x61,
 * 32-byte ids, varints, bounds, range modes, fingerprints, frame size limit). The expected bytes come from the grammar
 * of the specification, decoded by an independent reader (negentropy-spec.ts); none is taken from an implementation.
 * This is not interoperability with any particular relay.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { nip77 } from 'nostr-tools';
import { bytesToHex, finalizeEvent, generateSecretKey, getPublicKey, hexToBytes, randomBytes, toUnsigned, type Filter } from '@sedecim/nostr-core';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { NegentropyResponder, TestRelay, type NegLogEntry } from '@sedecim/test-relay';
import { NegentropySync, syncHistory, type SyncStrategy } from '../src/index';
import { INFINITY, MODE, PROTOCOL_V1, compareBounds, decodeMessage, encodeVarint, fingerprint, itemsPerRange, sortItems, type SpecItem, type SpecMessage } from './negentropy-spec';

const factory = (url: string) => new WebSocket(url) as unknown as WebSocketLike;
const HEX = /^(?:[0-9a-f]{2})+$/;
const randomItem = (timestamp: number): SpecItem => ({ timestamp, id: bytesToHex(randomBytes(32)) });

function storage(items: SpecItem[]) {
  const s = new nip77.NegentropyStorageVector();
  for (const it of items) s.insert(it.timestamp, it.id);
  s.seal();
  return s;
}

/**
 * Checks one message against the spec for the sender's items; returns what each range held, and whether it was cut by
 * `frameLimit` in the way the reference implementations cut (see below).
 */
function checkMessage(msg: SpecMessage, items: SpecItem[], frameLimit?: number) {
  expect(msg.version).toBe(PROTOCOL_V1);
  expect(msg.minimalVarints).toBe(true);
  for (let i = 1; i < msg.ranges.length; i++) expect(compareBounds(msg.ranges[i - 1]!.upper, msg.ranges[i]!.upper)).toBeLessThan(0);
  // "adjacent Skip ranges should be coalesced into a single Skip range"
  for (let i = 1; i < msg.ranges.length; i++) expect(msg.ranges[i - 1]!.mode === MODE.Skip && msg.ranges[i]!.mode === MODE.Skip).toBe(false);
  const per = itemsPerRange(msg, items);
  let cut = false;
  msg.ranges.forEach((r, i) => {
    const ids = per[i]!.map((x) => x.id);
    if (r.mode === MODE.IdList) expect([...r.ids!].sort()).toEqual([...ids].sort());
    if (r.mode !== MODE.Fingerprint) return;
    const got = bytesToHex(r.fingerprint!);
    const closing = i === msg.ranges.length - 1 && r.upper.timestamp === INFINITY;
    if (got !== bytesToHex(fingerprint(ids)) && closing && frameLimit !== undefined && msg.byteLength > frameLimit - 1_200) {
      // A message cut by the frame size limit closes with one Fingerprint range to infinity. The reference
      // implementations (hoytech/negentropy, C++ and JavaScript; nostr-tools ports the latter) fill it with the
      // fingerprint of the items after the range where they stopped, not of the whole range the spec's text describes:
      // the receiver sees a mismatch and splits the range, so the skipped part is reconciled in a later round.
      let suffix = false;
      for (let k = 1; k <= ids.length && !suffix; k++) suffix = bytesToHex(fingerprint(ids.slice(k))) === got;
      expect(suffix).toBe(true);
      cut = true;
    } else expect(got).toBe(bytesToHex(fingerprint(ids)));
  });
  return { per, cut };
}

describe('Negentropy V1 messages of the NIP-77 client (FR013-05)', () => {
  const relay = new TestRelay({ supportsNegentropy: true });
  let pool: RelayPool;
  beforeAll(async () => {
    await relay.start();
    pool = new RelayPool({ webSocketFactory: factory });
  });
  afterAll(async () => {
    pool.close();
    await relay.stop();
  });

  /** Runs one NIP-77 session of the client with `local` against the test relay; returns what the client sent in it. */
  async function session(filter: Filter, local: SpecItem[]): Promise<{ sent: NegLogEntry[]; n: NegentropySync }> {
    const from = relay.negLog.length;
    const n = new NegentropySync(pool, { detect: 'nip11', local: () => local.map((x) => ({ id: x.id, created_at: x.timestamp })) });
    await n.run(relay.url, filter, () => undefined);
    const open = relay.negLog.slice(from).find((m) => m.type === 'NEG-OPEN')!;
    // The NEG-CLOSE goes out as the session ends: wait until the relay has it.
    for (let i = 0; i < 100 && !relay.negLog.some((m) => m.type === 'NEG-CLOSE' && m.subId === open.subId); i++) await new Promise((r) => setTimeout(r, 10));
    return { sent: relay.negLog.slice(from).filter((m) => m.subId === open.subId), n };
  }

  it('writes varints and bound timestamps as the grammar says (FR013-05)', () => {
    const neg = new nip77.Negentropy(storage([]));
    const bound = (timestamp: number, prefix: number[] = [], fresh = true) => {
      if (fresh) neg.lastTimestampOut = 0;
      return bytesToHex(neg.encodeBound({ timestamp, id: Uint8Array.from(prefix) }).unwrap());
    };
    // encodedTimestamp = 1 + offset, as a varint (base 128, most significant digit first); then the prefix length.
    expect(bound(0)).toBe('0100');
    expect(bound(126)).toBe('7f00');
    expect(bound(127)).toBe('810000');
    expect(bound(299)).toBe('822c00');
    expect(bound(16_383)).toBe('81800000');
    expect(bound(5, [0xab, 0xcd])).toBe('0602abcd');
    // The offset is from the previously encoded timestamp; infinity is 0.
    bound(1_000);
    expect(bound(1_005, [], false)).toBe('0600');
    expect(bound(Number.MAX_VALUE)).toBe('0000');
    expect(bytesToHex(encodeVarint(16_384))).toBe('818000');
  });

  it('opens with version 0x61 and one IdList range up to infinity carrying whole 32-byte ids (FR013-05)', async () => {
    const filter = { kinds: [1], authors: [getPublicKey(generateSecretKey())] };
    const empty = await session(filter, []);
    expect(empty.sent[0]).toMatchObject({ type: 'NEG-OPEN', filter });
    // 0x61, bound {encodedTimestamp 0 = infinity, idPrefix length 0}, mode 2 = IdList, 0 ids
    expect(empty.sent[0]!.message).toBe('6100000200');

    const one = randomItem(1_700_000_000);
    const single = await session(filter, [one]);
    expect(single.sent[0]!.message).toBe(`6100000201${one.id}`);
    const decoded = decodeMessage(single.sent[0]!.message!);
    expect(decoded.ranges).toHaveLength(1);
    expect(decoded.ranges[0]).toMatchObject({ mode: MODE.IdList, ids: [one.id], upper: { timestamp: INFINITY } });
    expect(decoded.byteLength).toBe(1 + 2 + 1 + 1 + 32);
  });

  it('splits 32 or more items into ascending ranges with minimal bounds and spec fingerprints (FR013-05)', async () => {
    // Groups of items share a timestamp, so some bounds need an id prefix.
    const items = Array.from({ length: 100 }, (_, i) => randomItem(1_700_000_000 + Math.floor(i / 7) * 60));
    const { sent } = await session({ kinds: [1], authors: [getPublicKey(generateSecretKey())] }, items);
    const msg = decodeMessage(sent[0]!.message!);
    const { per } = checkMessage(msg, items);
    expect(msg.ranges.length).toBeGreaterThan(1);
    expect(msg.ranges.at(-1)!.upper).toEqual({ timestamp: INFINITY, idPrefix: new Uint8Array(0) });
    expect(per.flat()).toHaveLength(100);
    const sorted = sortItems(items);
    let seen = 0;
    for (const [i, r] of msg.ranges.slice(0, -1).entries()) {
      seen += per[i]!.length;
      const prev = sorted[seen - 1]!;
      const next = sorted[seen]!;
      const { timestamp, idPrefix } = r.upper;
      // "If these records' timestamps differ, then the length should be 0, otherwise ... their common ID-prefix plus 1."
      if (prev.timestamp !== next.timestamp) expect([timestamp, idPrefix.length]).toEqual([next.timestamp, 0]);
      else {
        const [a, b] = [hexToBytes(prev.id), hexToBytes(next.id)];
        let common = 0;
        while (a[common] === b[common]) common++;
        expect(timestamp).toBe(next.timestamp);
        expect(bytesToHex(idPrefix)).toBe(bytesToHex(b.subarray(0, common + 1)));
      }
    }
  });

  it('answers each round with its own items, delta timestamps restarting in every message, and ends with NEG-CLOSE (FR013-05)', async () => {
    const sk = generateSecretKey();
    const pk = getPublicKey(sk);
    const events = Array.from({ length: 700 }, (_, i) => finalizeEvent(toUnsigned({ kind: 1, content: `r${i}`, created_at: 1_700_000_000 + Math.floor(i / 3) * 60 }, pk), sk));
    events.slice(0, 550).forEach((e) => relay.inject(e));
    const local = events.slice(150).map((e) => ({ id: e.id, timestamp: e.created_at }));
    const { sent, n } = await session({ kinds: [1], authors: [pk] }, local);
    const msgs = sent.filter((m) => m.type !== 'NEG-CLOSE');
    expect(msgs.length).toBeGreaterThan(1);
    for (const m of msgs) {
      expect(m.message).toMatch(HEX);
      // A reply that would be empty (only the version byte) is never sent: the client closes instead.
      expect(m.message).not.toBe('61');
      checkMessage(decodeMessage(m.message!), local);
    }
    expect(sent.at(-1)).toMatchObject({ type: 'NEG-CLOSE', subId: sent[0]!.subId });
    expect(new Set(sent.map((m) => m.subId)).size).toBe(1);
    expect(n.stats.get(relay.url)).toMatchObject({ need: 150, have: 150 });

    const other = await session({ kinds: [1], authors: [pk] }, local.slice(0, 10));
    expect(other.sent[0]!.subId).not.toBe(sent[0]!.subId);
  });

  it('stops and lets the next strategy run when a relay answers with another protocol version (FR013-05)', async () => {
    const listeners = new Set<(m: unknown[]) => void>();
    const conn = {
      onRawMessage: (fn: (m: unknown[]) => void) => (listeners.add(fn), () => listeners.delete(fn)),
      // The probe (a filter that matches nothing) is answered as V1; the real session gets a single V0 byte back, which
      // is how a server says which version it speaks.
      sendMessage: async (msg: unknown[]) => {
        if (msg[0] === 'NEG-OPEN') {
          const probe = JSON.stringify(msg[2]).includes('0'.repeat(64));
          queueMicrotask(() => listeners.forEach((l) => l(['NEG-MSG', msg[1], probe ? '61' : '60'])));
        }
        return true;
      },
      health: () => ({ authenticatedAs: [] }),
      canAuthenticate: false,
      authenticate: async () => false,
    };
    const fake = { ensureRelay: () => conn } as unknown as RelayPool;
    const n = new NegentropySync(fake, { detect: 'probe', timeoutMs: 1_000 });
    await expect(n.run('wss://relay.invalid', { kinds: [1] }, () => undefined)).rejects.toThrow(/invalid: .*version/);
    const fallback: SyncStrategy = { name: 'fallback', supported: async () => true, run: async () => undefined };
    const report = await syncHistory(['wss://relay.invalid'], { kinds: [1] }, [n, fallback]);
    expect(report.perRelay['wss://relay.invalid']).toMatchObject({ strategy: 'fallback' });
    expect(report.perRelay['wss://relay.invalid']!.attempts[0]).toMatchObject({ strategy: 'nip77-negentropy', supported: true });
  });

  it('keeps every message within the frame size limit, a cut one closing with one Fingerprint range to infinity (FR013-05)', () => {
    const reconcile = (clientItems: SpecItem[], serverItems: SpecItem[], frameSizeLimit?: number) => {
      const client = new nip77.Negentropy(storage(clientItems), frameSizeLimit);
      const server = new NegentropyResponder(serverItems.map((x) => ({ id: x.id, created_at: x.timestamp })));
      const need = new Set<string>();
      const have = new Set<string>();
      const sent: string[] = [];
      for (let msg: string | null = client.initiate(); msg !== null; msg = client.reconcile(server.respond(msg), (id) => have.add(id), (id) => need.add(id))) sent.push(msg);
      return { need, have, sent };
    };
    // Interleaved, disjoint sets: the client must list many small ranges, far more than one frame holds.
    const all = Array.from({ length: 6_000 }, (_, i) => randomItem(1_700_000_000 + i));
    const clientItems = all.filter((_, i) => i % 2 === 0);
    const serverItems = all.filter((_, i) => i % 2 === 1);
    expect(() => new nip77.Negentropy(storage([]), 4095)).toThrow(/too small/);

    for (const limit of [4_096, undefined]) {
      const { need, have, sent } = reconcile(clientItems, serverItems, limit);
      const max = limit ?? 60_000;
      const decoded = sent.map(decodeMessage);
      expect(Math.max(...decoded.map((m) => m.byteLength))).toBeLessThanOrEqual(max);
      // The limit was reached: those messages close with the coalesced Fingerprint range (see checkMessage), and every
      // other range of every message follows the spec. The reconciliation still finds every difference.
      const cut = decoded.filter((m) => checkMessage(m, clientItems, max).cut);
      expect(cut.length).toBeGreaterThan(0);
      for (const m of cut) expect([m.ranges.at(-1)!.mode, m.ranges.at(-1)!.upper.timestamp]).toEqual([MODE.Fingerprint, INFINITY]);
      expect([...need].sort()).toEqual(serverItems.map((x) => x.id).sort());
      expect([...have].sort()).toEqual(clientItems.map((x) => x.id).sort());
      // strfry's default strfry.conf accepts websocket frames of up to 131072 bytes: a NEG-MSG hex-encodes the message.
      expect(Math.max(...sent.map((m) => JSON.stringify(['NEG-MSG', 'neg999999', m]).length))).toBeLessThan(131_072);
    }
  });
});
