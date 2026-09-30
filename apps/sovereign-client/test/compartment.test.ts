/**
 * FR006-07 (spec §14.1): before a persona uses a contact or a file that another persona of this device already used,
 * the sovereign client says what would cross and goes ahead only with an explicit confirmation (the CLI's
 * --confirm-reuse); until then nothing leaves this persona, not even a relay connection. Inviting another of your own
 * high-risk identities into a group stays refused.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fileDigest, ReuseNotConfirmedError, type ReuseWarning } from '@sedecim/identity';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { TestBlossomServer, TestRelay } from '@sedecim/test-relay';
import { SovereignClient } from '../src/index';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

function cli(dataDir: string, ...args: string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--import', 'tsx', CLI, ...args], { env: { ...process.env, SOVEREIGN_DATA_DIR: dataDir, SOVEREIGN_PASSPHRASE: 'compartment-test', SOVEREIGN_FLAGS: '/nonexistent' } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

const kinds = (ws: ReuseWarning[]) => ws.map((w) => `${w.kind}:${w.label}`);

describe('sovereign client: reusing a contact or a file across personas (FR006-07)', () => {
  const relay = new TestRelay({ requireAuth: true, pGatedKinds: [1059] });
  const blobs = new TestBlossomServer();
  beforeAll(async () => {
    await relay.start();
    await blobs.start();
  });
  afterAll(async () => {
    await relay.stop();
    await blobs.stop();
  });

  it('DMs, invitations and group files: refused with what would cross, then sent once confirmed (FR006-07)', async () => {
    const confirmed: ReuseWarning[] = [];
    const client = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-compartment-')), passphrase: 'pass', scryptLogN: 4, blobStore: blobs.url, onConfirmedReuse: (w) => confirmed.push(...w) });
    const outside = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-compartment-dave-')), passphrase: 'pass', scryptLogN: 4 });
    try {
      const alice = await client.createPersona({ label: 'Alice', relays: [relay.url] });
      const bob = await client.createPersona({ label: 'Bob', relays: [relay.url] });
      const dave = await outside.createPersona({ label: 'Dave', relays: [relay.url] });
      await outside.groupPublishKeyPackage(dave.id);

      // Alice writes to Dave, invites him and sends a file to the group: first uses, nothing to confirm.
      await client.sendDm(alice.id, dave.pubkey, 'hola dave');
      const g1 = await client.groupCreate(alice.id, 'de alice');
      await client.groupInvite(alice.id, g1.groupId, dave.pubkey);
      const photo = new TextEncoder().encode('acta firmada');
      await client.groupSendFile(alice.id, g1.groupId, { data: photo, filename: 'acta.txt', mimeType: 'text/plain' });
      expect(confirmed).toEqual([]);

      // Bob, another persona of the same device: every use of Dave or of that file is refused before Bob even connects.
      const received = relay.received.length;
      const uploaded = blobs.blobs.size;
      const dm = await client.sendDm(bob.id, dave.pubkey, 'hola dave, soy bob').catch((e: Error) => e);
      expect(dm).toBeInstanceOf(ReuseNotConfirmedError);
      expect(kinds((dm as ReuseNotConfirmedError).warnings)).toEqual(['contact:Alice']);
      expect((dm as Error).message).toMatch(/^compartimentación: Ya escribiste o invitaste a este contacto desde tu persona "Alice".* No se ha enviado nada/);
      for (const attempt of [
        () => client.groupInvite(bob.id, g1.groupId, dave.pubkey),
        () => client.groupPropose(bob.id, g1.groupId, { add: dave.pubkey }),
        () => client.groupAddDevice(bob.id, g1.groupId, dave.pubkey),
        () => client.groupSendFile(bob.id, g1.groupId, { data: photo, filename: 'copia.txt', mimeType: 'text/plain' }),
      ]) {
        const err = await attempt().catch((e: Error) => e);
        expect(err).toBeInstanceOf(ReuseNotConfirmedError);
      }
      expect(kinds(await (await client.identities()).reuseCheck(bob.id, { contact: dave.pubkey }))).toEqual(['contact:Alice']);
      expect(relay.received.length).toBe(received);
      expect(relay.authedPubkeys).not.toContain(bob.pubkey);
      expect(blobs.blobs.size).toBe(uploaded);

      // Confirmed: it goes out, the warnings are reported, and the same crossing is not asked again.
      const sent = await client.sendDm(bob.id, dave.pubkey, 'hola dave, soy bob', { confirmReuse: true });
      expect(sent.every((r) => r.state === 'REPLICATED')).toBe(true);
      expect(kinds(confirmed)).toEqual(['contact:Alice']);
      await client.sendDm(bob.id, dave.pubkey, 'otra vez');
      const g2 = await client.groupCreate(bob.id, 'de bob');
      expect((await client.groupInvite(bob.id, g2.groupId, dave.pubkey)).members).toContain(dave.pubkey);
      await expect(client.groupSendFile(bob.id, g2.groupId, { data: photo, filename: 'copia.txt', mimeType: 'text/plain' })).rejects.toBeInstanceOf(ReuseNotConfirmedError);
      const copy = await client.groupSendFile(bob.id, g2.groupId, { data: photo, filename: 'copia.txt', mimeType: 'text/plain' }, { confirmReuse: true });
      expect(copy.attachment.filename).toBe('copia.txt');
      expect(blobs.blobs.size).toBe(uploaded + 1);
      expect(kinds(confirmed)).toEqual(['contact:Alice', 'file:Alice']);
    } finally {
      client.close();
      outside.close();
    }
  }, 120_000);

  it('inviting another of your own high-risk identities stays refused, confirmed or not (FR006-07)', async () => {
    const client = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-compartment-risk-')), passphrase: 'pass', scryptLogN: 4 });
    try {
      const onion = 'ws://compartmentrelayabcdefghijklmnopqrstuvwxyz234567abcdefghij.onion';
      const x = await client.createPersona({ label: 'Riesgo X', relays: [onion], highRisk: true });
      const y = await client.createPersona({ label: 'Riesgo Y', relays: [onion], highRisk: true });
      for (const opts of [{}, { confirmReuse: true }]) await expect(client.groupInvite(x.id, 'cualquiera', y.pubkey, opts)).rejects.toThrow(/^compartimentación: El contacto es otra de tus identidades \("Riesgo Y"\).*No se puede invitar a un grupo/);
      // A DM between them is a warning the user can confirm.
      const dm = await client.sendDm(x.id, y.pubkey, 'nota').catch((e: Error) => e);
      expect(kinds((dm as ReuseNotConfirmedError).warnings)).toEqual(['identity:Riesgo Y']);
    } finally {
      client.close();
    }
  });

  it('the CLI refuses the reuse, says how to confirm it, and sends with --confirm-reuse (FR006-07)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'sovereign-compartment-cli-'));
    const create = async (label: string) => {
      const r = await cli(dir, 'persona', 'create', '--label', label, '--relay', relay.url);
      expect(r.status, r.stderr).toBe(0);
      return JSON.parse(r.stdout) as { id: string; pubkey: string };
    };
    const [work, home] = [await create('Trabajo'), await create('Casa')];
    const contact = getPublicKey(generateSecretKey());
    const first = await cli(dir, 'dm', 'send', '--persona', work.id, '--to', contact, 'desde el trabajo');
    expect(first.status, first.stderr).toBe(0);

    const wraps = () => relay.received.filter((e) => e.kind === 1059).length;
    const before = wraps();
    const refused = await cli(dir, 'dm', 'send', '--persona', home.id, '--to', contact, 'desde casa');
    expect(refused.status).toBe(1);
    expect(refused.stderr).toMatch(/^error: compartimentación: Ya escribiste o invitaste a este contacto desde tu persona "Trabajo"/m);
    expect(refused.stderr).toMatch(/^para usarlo también desde esta persona, repite el comando con --confirm-reuse$/m);
    expect(wraps()).toBe(before);

    // The flag goes anywhere, even right before the text.
    const sent = await cli(dir, 'dm', 'send', '--persona', home.id, '--to', contact, '--confirm-reuse', 'desde casa');
    expect(sent.status, sent.stderr).toBe(0);
    expect(sent.stderr).toMatch(/^aviso: compartimentación \(confirmado con --confirm-reuse\): Ya escribiste o invitaste a este contacto desde tu persona "Trabajo"/m);
    expect(sent.stdout).toMatch(/REPLICATED/);
    expect(wraps()).toBe(before + 2);
    const reader = new SovereignClient({ dataDir: dir, passphrase: 'compartment-test' });
    try {
      expect((await reader.inbox(home.id)).map((m) => m.rumor.content)).toContain('desde casa');
    } finally {
      reader.close();
    }

    // A file another persona already sent: send-file is refused before anything else; with the flag it goes on.
    const file = join(dir, 'acta.txt');
    await writeFile(file, 'acta');
    const lib = new SovereignClient({ dataDir: dir, passphrase: 'compartment-test' });
    try {
      await (await lib.identities()).recordUsage(work.id, { fileHash: await fileDigest(new TextEncoder().encode('acta')) });
    } finally {
      lib.close();
    }
    const refusedFile = await cli(dir, 'group', 'send-file', '--persona', home.id, '--group', 'g', '--file', file);
    expect(refusedFile.status).toBe(1);
    expect(refusedFile.stderr).toMatch(/^error: compartimentación: Ya enviaste este mismo archivo desde tu persona "Trabajo"/m);
    expect(refusedFile.stderr).toMatch(/--confirm-reuse$/m);
    // Confirmed, it passes the check and stops further on (this installation has no Blossom server configured).
    const goesOn = await cli(dir, 'group', 'send-file', '--persona', home.id, '--group', 'g', '--file', file, '--confirm-reuse');
    expect(goesOn.stderr).toMatch(/^aviso: compartimentación \(confirmado con --confirm-reuse\): Ya enviaste este mismo archivo/m);
    expect(goesOn.stderr).not.toMatch(/^error: compartimentación/m);
  }, 240_000);
});
