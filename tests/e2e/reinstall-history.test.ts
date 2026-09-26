/**
 * FR013-03 E2E: reinstall on a clean device. Device A creates an identity, joins NIP-29 channels, sends
 * channel messages and DMs and has a pending outbox item; it exports the v2 backup. Device B (empty data
 * dir) restores the backup, syncs history (NIP-77 on one relay, REQ fallback on the other) and ends
 * with the same channels, DMs and outbox/delivery states as A. NFR008-02: the history exports as JSONL
 * that nostr-tools verifies and another persona can import.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyEvent as ntVerifyEvent } from 'nostr-tools';
import { BUZZ_PINNED_ADAPTER } from '@sedecim/messaging';
import type { OutboxRecord } from '@sedecim/delivery-engine';
import { TestRelay } from '@sedecim/test-relay';
import { SovereignClient } from '@sedecim/sovereign-client';

const opts = (dataDir: string) => ({
  dataDir,
  passphrase: 'device-pass',
  scryptLogN: 4,
  retry: { baseMs: 60_000, maxMs: 60_000 },
  // full NIP-59 timestamp jitter (0–2 days): the rebuild must still find every wrap
  relayAdapter: { ...BUZZ_PINNED_ADAPTER, wrap: {} },
});

/** Delivery state as seen by the user: what was sent where, and what is still pending. */
const ledger = (records: OutboxRecord[]) =>
  records
    .map((r) => ({
      opId: r.opId,
      state: r.state,
      eventId: r.event?.id,
      kind: r.event?.kind,
      groupId: r.groupId,
      recipient: r.meta?.recipient,
      accepted: Object.values(r.relayStatus).filter((s) => s.acceptedAt).map((s) => s.relay).sort(),
    }))
    .sort((a, b) => (a.opId < b.opId ? -1 : 1));

describe('reinstall and rebuild history on a clean device (FR013-03)', () => {
  // Buzz-like relays: NIP-42 + p-gated gift wraps. Only the first one speaks NIP-77.
  const r1 = new TestRelay({ requireAuth: true, pGatedKinds: [1059], supportsNegentropy: true });
  const r2 = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  const r3 = new TestRelay();
  let deviceA: SovereignClient;
  let deviceB: SovereignClient;
  let bobDevice: SovereignClient;

  beforeAll(async () => {
    await Promise.all([r1.start(), r2.start(), r3.start()]);
    const tmp = () => mkdtemp(join(tmpdir(), 'reinstall-'));
    deviceA = new SovereignClient(opts(await tmp()));
    deviceB = new SovereignClient(opts(await tmp()));
    bobDevice = new SovereignClient(opts(await tmp()));
  });
  afterAll(async () => {
    deviceA.close();
    deviceB.close();
    bobDevice.close();
    await Promise.all([r1.stop(), r2.stop(), r3.stop()]);
  });

  it('restores the backup and reconstructs channels, DMs and outbox states equal to device A', async () => {
    // --- device A: normal use -------------------------------------------------------------------
    const alice = await deviceA.createPersona({ label: 'Alice', relays: [r1.url, r2.url] });
    const bob = await bobDevice.createPersona({ label: 'Bob', relays: [r1.url, r2.url] });
    expect((await deviceA.joinChannel(alice.id, 'general')).state).toBe('REPLICATED');
    await deviceA.sendChannel(alice.id, 'general', 'hola general');
    await bobDevice.sendChannel(bob.id, 'general', 'hola Alice, soy Bob');
    await deviceA.sendChannel(alice.id, 'general', 'segundo mensaje');
    await deviceA.sendChannel(alice.id, 'random', 'otro canal');
    await bobDevice.sendChannel(bob.id, 'ajeno', 'canal donde Alice no está');
    expect((await deviceA.sendDm(alice.id, bob.pubkey, 'DM para Bob')).every((r) => r.state === 'REPLICATED')).toBe(true);
    await bobDevice.sendDm(bob.id, alice.pubkey, 'DM para Alice');
    // Both relays overloaded: this message stays in the outbox (retry scheduled far in the future).
    r1.faults.rejectReason = r2.faults.rejectReason = 'error: overloaded, try later';
    const pending = await deviceA.sendChannel(alice.id, 'general', 'mensaje pendiente');
    r1.faults.rejectReason = r2.faults.rejectReason = null;
    expect(pending.state).toBe('QUEUED');

    const aChannels = {
      general: (await deviceA.readChannel(alice.id, 'general')).map((e) => e.id).sort(),
      random: (await deviceA.readChannel(alice.id, 'random')).map((e) => e.id).sort(),
    };
    const dmView = (ms: Array<{ rumor: { id: string; content: string }; sender: string }>) => ms.map((m) => ({ id: m.rumor.id, from: m.sender, text: m.rumor.content })).sort((a, b) => (a.id < b.id ? -1 : 1));
    const aDms = dmView(await deviceA.inbox(alice.id));
    expect(aDms.map((m) => m.text).sort()).toEqual(['DM para Alice', 'DM para Bob']);
    const aLedger = ledger(await deviceA.outbox(alice.id));
    const pkg = await deviceA.exportBackup(alice.id, 'backup-pw', { scryptLogN: 4 });
    deviceA.close(); // the phone is lost

    // --- device B: clean install, restore, sync ------------------------------------------------
    expect(await (await deviceB.identities()).list()).toEqual([]);
    const restored = await deviceB.restoreBackup(JSON.parse(JSON.stringify(pkg)), 'backup-pw');
    expect(restored.pubkey).toBe(alice.pubkey);
    expect(restored.relays).toEqual([r1.url, r2.url]);
    const r = await deviceB.syncHistory(restored.id);

    expect(r.strategies).toEqual({ [r1.url]: 'nip77-negentropy', [r2.url]: 'req-window' });
    expect(r1.negStats.open).toBeGreaterThan(0);
    expect(Object.keys(r.channels).sort()).toEqual(['general', 'random']); // discovered from Alice's own events
    expect({ general: r.channels.general!.map((e) => e.id).sort(), random: r.channels.random!.map((e) => e.id).sort() }).toEqual(aChannels);
    expect(r.channels.general!.map((e) => e.content)).toContain('hola Alice, soy Bob');
    expect(dmView(r.dms)).toEqual(aDms);
    expect(ledger(r.outbox)).toEqual(aLedger);
    expect(r.outbox.find((o) => o.opId === pending.opId)!.state).toBe('QUEUED');

    // The pending message is delivered from device B with the same signed event (no duplicate).
    const resumed = (await deviceB.resume(restored.id)).find((o) => o.opId === pending.opId)!;
    expect(resumed.state).toBe('REPLICATED');
    expect(resumed.event!.id).toBe(pending.event!.id);
    expect(r1.events.has(pending.event!.id) && r2.events.has(pending.event!.id)).toBe(true);
    const again = await deviceB.syncHistory(restored.id);
    expect(again.channels.general!.filter((e) => e.content === 'mensaje pendiente')).toHaveLength(1);
  });

  it('exports the rebuilt history as verifiable JSONL that another client/persona imports (NFR008-02)', async () => {
    const [alice] = await (await deviceB.identities()).list();
    const jsonl = await deviceB.exportHistory(alice!.id);
    const lines = jsonl.trimEnd().split('\n').map((l) => JSON.parse(l));
    expect(lines.length).toBeGreaterThanOrEqual(8); // join + 4 own channel msgs + Bob's + DM wraps
    expect(lines.every((e) => ntVerifyEvent(e))).toBe(true);
    expect(lines.some((e) => e.kind === 1059) && lines.some((e) => e.kind === 9021)).toBe(true);

    const archive = await deviceB.createPersona({ label: 'Archivo', relays: [r3.url] });
    const dry = await deviceB.importHistory(archive.id, `${jsonl}garbage\n`, { dryRun: true });
    expect(dry).toMatchObject({ valid: lines.length, published: 0, invalid: [{ line: lines.length + 1, reason: 'malformed JSON' }] });
    const res = await deviceB.importHistory(archive.id, jsonl);
    expect(res).toMatchObject({ valid: lines.length, published: lines.length, rejected: 0 });
    expect(lines.every((e) => r3.events.has(e.id))).toBe(true);
  });
});
