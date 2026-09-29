/**
 * VAULT-03: the persona's history in the Continuity Vault. A push seals canonical events, decrypted group messages
 * and the ledger/MLS snapshots; a restore with nothing but the archive key gets exactly that back, and nothing that
 * does not verify, does not open or belongs to another persona.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { finalizeEvent, generateSecretKey, getPublicKey, toUnsigned, type NostrEvent } from '@sedecim/nostr-core';
import { ArchiveVaultClient, archiveEvent, archiveHistory, archiveId, belongsOnPersonaRelays, eventLabel, generateArchiveKey, LEDGER_LABEL, restoreHistory, sealArchive, type ArchivedGroupMessage } from '@sedecim/continuity';
import { createContinuityVaultApi, MemoryArchiveRepository, MemoryObjectStore } from '../src/index';

const persona = generateSecretKey();
const pubkey = getPublicKey(persona);
const other = generateSecretKey();
const ev = (sk: Uint8Array, kind: number, content: string, tags: string[][] = []): NostrEvent => finalizeEvent(toUnsigned({ kind, content, tags }, getPublicKey(sk)), sk);

describe('persona history in the Continuity Vault (VAULT-03)', () => {
  const repo = new MemoryArchiveRepository();
  const objects = new MemoryObjectStore();
  const api = createContinuityVaultApi(repo, objects, { name: 'vault-history' });
  let base: string;
  const key = generateArchiveKey();
  const client = () => new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: key } });

  const channel = ev(persona, 9, 'hola canal secreto', [['h', 'general']]);
  const reply = ev(other, 9, 'respuesta de otra persona', [['h', 'general']]);
  const state = ev(other, 39000, '', [['d', 'general'], ['name', 'General']]);
  const wrap = ev(generateSecretKey(), 1059, 'ciphertext-de-un-gift-wrap', [['p', pubkey]]);
  const messages: ArchivedGroupMessage[] = [
    { groupId: 'g1', rumorId: 'r1', sender: getPublicKey(other), kind: 9, content: 'mensaje de grupo recibido', createdAt: 1_700_000_000, epoch: 3 },
    { groupId: 'g1', rumorId: 'r2', sender: pubkey, kind: 9, content: 'mensaje de grupo propio', createdAt: 1_700_000_100, epoch: 3 },
  ];
  const ledger = [{ id: 'op-1', state: 'REPLICATED', event: channel }];
  const mls = { groups: [{ id: 'g1', value: { epoch: 3 } }], device: [{ id: 'owner', value: 'cli-device' }] };

  beforeAll(async () => {
    base = await api.listen();
  });
  afterAll(() => api.close());

  it('seals events, group messages and snapshots, and a clean device restores exactly them with the archive key', async () => {
    const pushed = await archiveHistory(client(), key, { pubkey, events: [channel, reply, state, wrap, channel], groupMessages: messages, ledger, mls });
    expect(pushed).toEqual({ events: { uploaded: 4, kept: 0, invalid: 0 }, groupMessages: { uploaded: 2, kept: 0 }, snapshots: ['ledger', 'mls'] });

    // The operator holds only envelopes: no text, event id, npub or label.
    let held = JSON.stringify(repo.rows());
    for await (const k of objects.list()) held += new TextDecoder().decode((await objects.get(k))!);
    for (const t of ['hola canal secreto', 'mensaje de grupo', channel.id, wrap.id, pubkey, 'general', 'REPLICATED', 'cli-device', 'event:']) expect(held).not.toContain(t);

    // A new device: only the archive key (from the persona's backup).
    const restored = await restoreHistory(new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: new Uint8Array(key) } }), key, { pubkey });
    expect(restored.archives).toBe(8);
    expect(restored.skipped).toBe(0);
    expect(new Set(restored.events.map((e) => e.id))).toEqual(new Set([channel.id, reply.id, state.id, wrap.id]));
    expect(restored.events.find((e) => e.id === wrap.id)).toEqual(wrap);
    expect(restored.groupMessages).toEqual(messages);
    expect(restored.ledger?.outbox).toEqual(JSON.parse(JSON.stringify(ledger)));
    expect(restored.mls?.namespaces).toEqual(mls);
    expect(restored.missing).toBe(0);
  });

  it('a second push only replaces the snapshots, and a forged signature is never archived', async () => {
    const forged = { ...ev(other, 9, 'falso', [['h', 'general']]), content: 'alterado' };
    const again = await archiveHistory(client(), key, { pubkey, events: [channel, reply, state, wrap, forged], groupMessages: messages, ledger: [...ledger, { id: 'op-2' }] });
    expect(again).toEqual({ events: { uploaded: 0, kept: 4, invalid: 1 }, groupMessages: { uploaded: 0, kept: 2 }, snapshots: ['ledger'] });
    const restored = await restoreHistory(client(), key, { pubkey });
    expect(restored.ledger?.outbox).toHaveLength(2);
    expect(restored.mls?.namespaces).toEqual(mls); // not pushed this time: the previous snapshot stays
  });

  it('skips what does not belong: another persona, or content stored under an id it does not imply', async () => {
    const c = client();
    // A snapshot of another persona (same archive key by mistake) and an event sealed under the ledger's id.
    const strayId = archiveId(key, 'ledger-of-someone-else');
    await c.put(strayId, sealArchive(key, strayId, JSON.stringify({ type: 'ledger', version: 1, pubkey: getPublicKey(other), at: 1, outbox: [] })));
    const misplaced = archiveId(key, eventLabel('not-this-event'));
    await c.put(misplaced, sealArchive(key, misplaced, JSON.stringify({ type: 'event', version: 1, event: reply })));
    const restored = await restoreHistory(c, key, { pubkey });
    expect(restored.skipped).toBe(2);
    expect(restored.events).toHaveLength(4);
    expect(restored.ledger?.outbox).toHaveLength(2);
    expect(archiveId(key, LEDGER_LABEL)).not.toBe(strayId);
  });

  it('an archive deleted after the last push is reported missing, with the date of that copy', async () => {
    const c = client();
    await archiveHistory(c, key, { pubkey, events: [channel], ledger }, { now: () => 1_750_000_000_000 });
    const before = await restoreHistory(c, key, { pubkey });
    expect(before).toMatchObject({ missing: 0, ledger: { at: 1_750_000_000_000 } });
    // The operator (or a lost object) drops the channel message's archive.
    await c.remove(archiveId(key, eventLabel(channel.id)));
    const after = await restoreHistory(c, key, { pubkey });
    expect(after.missing).toBe(1);
    expect(after.events.map((e) => e.id)).not.toContain(channel.id);
  });

  it('VAULT-04: one sent event lands on the archive a push would write, and a restore keeps others’ gift wraps off the persona’s relays', async () => {
    const k = generateArchiveKey();
    const c = new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: k } });
    const sent = ev(persona, 9, 'enviado y copiado al momento', [['h', 'general']]);
    const toOther = ev(generateSecretKey(), 1059, 'wrap-para-otra-persona', [['p', getPublicKey(other)]]);
    await archiveEvent(c, k, sent);
    await archiveEvent(c, k, sent); // idempotent: the same archive again
    await archiveEvent(c, k, toOther);
    await expect(archiveEvent(c, k, { ...sent, content: 'alterado' })).rejects.toThrow(/invalid signature/);
    // A later push finds them already there.
    expect((await archiveHistory(c, k, { pubkey, events: [sent, toOther] })).events).toEqual({ uploaded: 0, kept: 2, invalid: 0 });
    const restored = await restoreHistory(c, k, { pubkey });
    expect(new Set(restored.events.map((e) => e.id))).toEqual(new Set([sent.id, toOther.id]));
    expect(restored.events.filter((e) => belongsOnPersonaRelays(e, pubkey)).map((e) => e.id)).toEqual([sent.id]);
    expect(belongsOnPersonaRelays(wrap, pubkey)).toBe(true); // a wrap addressed to the persona does go back
  });

  it('another archive key is another vault account: it sees none of these archives', async () => {
    const stranger = generateArchiveKey();
    const restored = await restoreHistory(new ArchiveVaultClient({ baseUrl: base, auth: { archiveKey: stranger } }), stranger, { pubkey });
    expect(restored).toEqual({ events: [], groupMessages: [], archives: 0, skipped: 0, missing: 0 });
  });
});
