/**
 * PANEL-06 (§12.2): in the sovereign CLI, the expiration of DMs (--expire for one message, else the conversation's,
 * else the persona's), the purge of what expired when the persona opens, and `dm delete`: the deletion goes to the
 * recipients and the persona's other devices, this device forgets its copies and their vault archives, and someone
 * else's message is refused. The test relay does not honour NIP-40; the vault is the repo's in-memory one.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ArchiveVaultClient, archiveId, eventLabel } from '@sedecim/continuity';
import { createContinuityVaultApi, MemoryArchiveRepository, MemoryObjectStore } from '@sedecim/continuity-vault';
import { NotYourMessageError, roundedExpiration } from '@sedecim/messaging';
import { eventExpiration, generateSecretKey, getPublicKey, getTagValue } from '@sedecim/nostr-core';
import type { EventCache } from '@sedecim/sync';
import { createLogger } from '@sedecim/telemetry-policy';
import { TestRelay } from '@sedecim/test-relay';
import { SovereignClient } from '../src/index';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const DAY = 86_400;

function cli(env: NodeJS.ProcessEnv, ...args: string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--import', 'tsx', CLI, ...args], { env: { ...process.env, ...env } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

describe('sovereign client: expiration and deletion of DMs (PANEL-06)', () => {
  const relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  const vault = createContinuityVaultApi(new MemoryArchiveRepository(), new MemoryObjectStore(), { name: 'vault-cli-expiration', logger: createLogger({ write: () => {} }) });
  let vaultUrl: string;
  let dataDir: string;
  let client: SovereignClient;
  beforeAll(async () => {
    await relay.start();
    vaultUrl = await vault.listen();
    dataDir = await mkdtemp(join(tmpdir(), 'sovereign-expiration-'));
    client = new SovereignClient({ dataDir, passphrase: 'pass', scryptLogN: 4, retry: { baseMs: 20, maxMs: 50 }, vaultUrl });
  });
  afterAll(async () => {
    client.close();
    await vault.close();
    await relay.stop();
  });
  const holds = async (personaId: string, eventId: string) => {
    const key = await (await client.identities()).archiveKey(personaId);
    return (await new ArchiveVaultClient({ baseUrl: vaultUrl, auth: { archiveKey: key } }).listAll()).some((a) => a.id === archiveId(key, eventLabel(eventId)));
  };

  it('PANEL-06: --expire for one message, else the conversation’s, else the persona’s; the wraps carry it rounded to a UTC day', async () => {
    const alice = await client.createPersona({ label: 'Alice', relays: [relay.url] });
    const bob = await client.createPersona({ label: 'Bob', relays: [relay.url] });
    expect((await client.profile(alice.id)).messageExpiration).toBe('off');
    await client.setMessageExpiration(alice.id, '30d');
    expect((await client.profile(alice.id)).messageExpiration).toBe('30d');
    expect(await client.conversationExpiration(alice.id, bob.pubkey)).toEqual({ option: '30d', source: 'persona' });
    await client.setConversationExpiration(alice.id, bob.pubkey, '7d');
    expect(await client.conversationExpiration(alice.id, bob.pubkey)).toEqual({ option: '7d', source: 'conversation', conversation: '7d' });
    expect(await client.shortestExpiration(alice.id)).toBe('7d');

    /** The one expiration every wrap of a send carries, and what it should be (a send may cross midnight UTC). */
    const sendWith = async (text: string, days: number | undefined, expire?: '1d' | 'off') => {
      const before = Math.floor(Date.now() / 1000);
      const recs = await client.sendDm(alice.id, bob.pubkey, text, expire ? { expire } : {});
      const after = Math.floor(Date.now() / 1000);
      const carried = [...new Set(recs.map((r) => eventExpiration(r.event!)))];
      expect(carried).toHaveLength(1);
      expect(recs).toHaveLength(2); // Bob's wrap and the sender's own copy
      if (days === undefined) expect(carried[0]).toBeUndefined();
      else expect([roundedExpiration(days, before), roundedExpiration(days, after)]).toContain(carried[0]);
    };
    await sendWith('por la conversación', 7);
    await sendWith('solo este', 1, '1d');
    await sendWith('sin caducidad', undefined, 'off');
    // Cleared: the conversation follows the persona again.
    await client.setConversationExpiration(alice.id, bob.pubkey, undefined);
    await sendWith('por la persona', 30);
    expect((await client.inbox(bob.id)).map((m) => m.rumor.content)).toEqual(expect.arrayContaining(['por la conversación', 'solo este', 'sin caducidad', 'por la persona']));
  });

  it('PANEL-06: what expired is purged when its time comes: sent operation, outbox and vault archives; nothing without expiration', async () => {
    const alice = await client.createPersona({ label: 'Alice purga', relays: [relay.url] });
    const bob = await client.createPersona({ label: 'Bob purga', relays: [relay.url] });
    await client.setContinuity(alice.id, 'best-effort'); // each send is copied to the vault
    const fleeting = await client.sendDm(alice.id, bob.pubkey, 'efímero', { expire: '1d' });
    const lasting = await client.sendDm(alice.id, bob.pubkey, 'permanente');
    const at = eventExpiration(fleeting[0]!.event!)!;
    for (const r of [...fleeting, ...lasting]) expect(await holds(alice.id, r.event!.id)).toBe(true);
    const s = await client.session(alice.id);
    expect(await client.purgeExpiredDms(s, at - 60)).toMatchObject({ operations: 0, outbox: 0, vault: 0, next: at });
    expect(await client.purgeExpiredDms(s, at)).toMatchObject({ operations: 1, outbox: 2, vault: 2, vaultQueued: 0 });
    for (const r of fleeting) expect(await holds(alice.id, r.event!.id)).toBe(false);
    expect((await client.outbox(alice.id)).map((r) => r.opId).sort()).toEqual(lasting.map((r) => r.opId).sort());
    // Negative control: years later, the message without expiration is still here and in the vault.
    expect(await client.purgeExpiredDms(s, at + 3650 * DAY)).toMatchObject({ operations: 0, outbox: 0, vault: 0 });
    for (const r of lasting) expect(await holds(alice.id, r.event!.id)).toBe(true);
  });

  it('PANEL-06: dm delete sends the deletion, forgets this device’s copies and their vault archives, and Bob no longer sees it; someone else’s message is refused', async () => {
    const alice = await client.createPersona({ label: 'Alice borra', relays: [relay.url] });
    const bob = await client.createPersona({ label: 'Bob borra', relays: [relay.url] });
    await client.setContinuity(alice.id, 'best-effort');
    const recs = await client.sendDm(alice.id, bob.pubkey, 'me arrepiento');
    const rumorId = recs[0]!.groupId!;
    expect((await client.inbox(bob.id)).map((m) => m.rumor.id)).toContain(rumorId);

    await expect(client.deleteDm(alice.id, 'abc')).rejects.toThrow(/al menos 8/);
    const r = await client.deleteDm(alice.id, rumorId.slice(0, 12));
    expect(r).toMatchObject({ rumorId, operations: 1, outbox: 2, vault: 2, vaultQueued: 0 });
    expect(r.deliveries.map((d) => d.meta?.recipient).sort()).toEqual([alice.pubkey, bob.pubkey].sort());
    for (const d of recs) expect(await holds(alice.id, d.event!.id)).toBe(false);
    expect((await client.inbox(bob.id)).map((m) => m.rumor.id)).not.toContain(rumorId);
    expect((await client.inbox(alice.id)).map((m) => m.rumor.id)).not.toContain(rumorId);

    // Bob's message to Alice: Alice cannot delete it, and nothing is sent.
    const theirs = await client.sendDm(bob.id, alice.pubkey, 'lo escribí yo');
    const before = relay.received.length;
    await expect(client.deleteDm(alice.id, theirs[0]!.groupId!)).rejects.toBeInstanceOf(NotYourMessageError);
    expect(relay.received.length).toBe(before);
  });

  it('PANEL-06: the event cache: a deleted DM leaves it and stays out when a relay serves it again; dm inbox --offline shows neither the deleted nor the expired', async () => {
    const alice = await client.createPersona({ label: 'Alice caché', relays: [relay.url] });
    const bob = await client.createPersona({ label: 'Bob caché', relays: [relay.url] });
    await client.sendDm(alice.id, bob.pubkey, 'se queda');
    const regret = await client.sendDm(alice.id, bob.pubkey, 'lo borraré');
    const fleeting = await client.sendDm(alice.id, bob.pubkey, 'efímero', { expire: '1d' });
    const at = eventExpiration(fleeting[0]!.event!)!;
    const bobWrap = regret.find((r) => r.meta?.recipient === bob.pubkey)!.event!;
    const cacheOf = async (id: string) => (await (client as unknown as { eventCache(id: string): Promise<EventCache | undefined> }).eventCache(id))!;
    const offline = async (c: SovereignClient) => (await c.inbox(bob.id, {}, { offline: true })).map((m) => m.rumor.content).sort();
    // Bob reads online: the gift wraps stay in his event cache, and he reads them offline too.
    expect((await client.inbox(bob.id)).map((m) => m.rumor.content).sort()).toEqual(['efímero', 'lo borraré', 'se queda']);
    expect((await cacheOf(bob.id)).has(bobWrap.id)).toBe(true);
    expect(await offline(client)).toEqual(['efímero', 'lo borraré', 'se queda']);

    await client.deleteDm(alice.id, regret[0]!.groupId!);
    // Bob's next read applies the deletion, whichever arrives first, and his cache forgets that wrap.
    expect((await client.inbox(bob.id)).map((m) => m.rumor.content).sort()).toEqual(['efímero', 'se queda']);
    expect((await cacheOf(bob.id)).has(bobWrap.id)).toBe(false);
    expect(await offline(client)).toEqual(['efímero', 'se queda']);
    // The relay still serves it: a history sync brings it again, and neither its result nor the cache keeps it.
    const synced = await client.syncHistory(bob.id);
    expect(synced.dms.map((m) => m.rumor.content)).not.toContain('lo borraré');
    expect(synced.history.wraps.map((w) => w.id)).not.toContain(bobWrap.id);
    expect((await cacheOf(bob.id)).has(bobWrap.id)).toBe(false);

    // Once its expiration passes (a cache clock past it), dm inbox --offline does not show the expiring message.
    const later = new SovereignClient({ dataDir, passphrase: 'pass', scryptLogN: 4, eventCache: { now: () => at } });
    try {
      expect(await offline(later)).toEqual(['se queda']);
    } finally {
      later.close();
    }
  });
});

describe('sovereign CLI: expiration and deletion of DMs (PANEL-06)', () => {
  it('PANEL-06: dm delete without --yes only says what deleting does not undo, and opens nothing', async () => {
    const r = await cli({ SOVEREIGN_DATA_DIR: join(tmpdir(), 'no-such-dir-panel-06'), SOVEREIGN_PASSPHRASE: '' }, 'dm', 'delete', '--persona', 'p', '--id', 'ab'.repeat(32));
    expect(r.status).toBe(1);
    const notice = r.stderr.split('\n').filter((l) => l.startsWith('aviso: '));
    expect(notice.join('\n')).toMatch(/aviso: Borrar no retira las copias que ya circularon: las copias replicadas pueden seguir existiendo/);
    expect(notice.join('\n')).toMatch(/petición de borrado, cifrada como un mensaje más \(NIP-17\)/);
    expect(r.stderr).toMatch(/no se ha borrado nada: para borrar el mensaje, repite la orden con --yes/);
  }, 60_000);

  it('PANEL-06: persona expiration, dm expiration, dm send --expire and dm delete --yes in real CLI processes', async () => {
    const relay = new TestRelay({ host: '127.0.0.1' });
    await relay.start();
    try {
      const env = { SOVEREIGN_DATA_DIR: await mkdtemp(join(tmpdir(), 'sovereign-expire-cli-')), SOVEREIGN_PASSPHRASE: 'expiration-test' };
      const created = await cli(env, 'persona', 'create', '--label', 'Caduca', '--relay', relay.url);
      expect(created.status, created.stderr).toBe(0);
      const id = (JSON.parse(created.stdout) as { id: string }).id;
      const bob = getPublicKey(generateSecretKey());

      const persona = await cli(env, 'persona', 'expiration', '--persona', id, '7d');
      expect(persona.status, persona.stderr).toBe(0);
      expect(persona.stdout).toMatch(/caducidad de los mensajes directos nuevos de esta persona: 7 días/);
      expect(persona.stderr).toMatch(/aviso: Los mensajes directos nuevos piden caducar a los 7 días \(NIP-40\)/);
      expect(persona.stderr).toMatch(/aviso: Cambiar la caducidad solo afecta a los mensajes nuevos/);

      const conversation = await cli(env, 'dm', 'expiration', '--persona', id, '--to', bob, '1d');
      expect(conversation.status, conversation.stderr).toBe(0);
      expect(conversation.stdout).toMatch(/caducidad de esta conversación: 1 día \(la suya\)/);
      expect(conversation.stderr).toMatch(/aviso: La caducidad es una petición \(NIP-40\)/);

      const sent = await cli(env, 'dm', 'send', '--persona', id, '--to', bob, '--expire', '30d', 'hasta dentro de un mes');
      expect(sent.status, sent.stderr).toBe(0);
      const iso = /^caduca: (\d{4}-\d{2}-\d{2}T00:00:00\.000Z) \(NIP-40\)$/m.exec(sent.stdout)?.[1];
      expect(iso).toBeDefined();
      const at = Date.parse(iso!) / 1000;
      const wraps = relay.received.filter((e) => e.kind === 1059);
      expect(wraps).toHaveLength(2);
      for (const w of wraps) expect(eventExpiration(w)).toBe(at);
      expect(at - Math.floor(Date.now() / 1000)).toBeGreaterThan(29 * DAY);

      // The persona's own copy shows up in its inbox with its id and its expiration; dm delete --yes takes that id.
      const inbox = await cli(env, 'dm', 'inbox', '--persona', id);
      expect(inbox.status, inbox.stderr).toBe(0);
      const line = inbox.stdout.split('\n').find((l) => l.includes(`, caduca ${iso}): hasta dentro de un mes`));
      const prefix = /\(id ([0-9a-f]{16}), caduca /.exec(line ?? '')?.[1];
      expect(prefix).toBeDefined();
      const deleted = await cli(env, 'dm', 'delete', '--persona', id, '--id', prefix!, '--yes');
      expect(deleted.status, deleted.stderr).toBe(0);
      expect(deleted.stderr).toMatch(/aviso: Borrar no retira las copias que ya circularon/);
      expect(deleted.stdout).toContain(`petición de borrado de ${prefix}`);
      expect(deleted.stdout).toMatch(/1 mensaje\(s\) enviado\(s\) y 2 registro\(s\) de entrega olvidados/);
      const deletion = relay.received.filter((e) => e.kind === 1059).slice(2);
      expect(deletion).toHaveLength(2);
      // The deletion asks to expire with the message, and goes to Bob and to the persona's other devices.
      for (const w of deletion) expect(eventExpiration(w)).toBe(at);
      expect(deletion.map((w) => getTagValue(w, 'p'))).toContain(bob);
      expect((await cli(env, 'dm', 'inbox', '--persona', id)).stdout).not.toContain('hasta dentro de un mes');
    } finally {
      await relay.stop();
    }
  }, 180_000);
});
