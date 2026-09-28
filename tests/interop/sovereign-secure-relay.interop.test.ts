/**
 * FR025-11 (G1): the sovereign CLI's own code path against the real secure relay (nostr-rs-relay with
 * nip42_auth and nip42_dms, at MARMOT_RELAY_URL in the CI stack job). The client keeps its on-demand NIP-42:
 * invitations (Welcome inside a gift wrap) and NIP-17 DMs only arrive because it authenticates before asking
 * for kind 1059, which that relay otherwise drops without a CLOSED or NOTICE.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SovereignClient } from '@sedecim/sovereign-client';

const MARMOT_URL = process.env.MARMOT_RELAY_URL;

describe.skipIf(!MARMOT_URL)('sovereign CLI on the real secure relay (FR025-11)', () => {
  let client: SovereignClient;
  const persona = (label: string) => client.createPersona({ label, relays: [MARMOT_URL!] });

  beforeAll(async () => {
    client = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-secure-relay-')), passphrase: 'interop', scryptLogN: 4 });
  });
  afterAll(() => client.close());

  it('create → invite → accept → message → remove', async () => {
    const [alice, bob, carol] = [await persona('Alice'), await persona('Bob'), await persona('Carol')];
    await client.groupPublishKeyPackage(bob.id);
    await client.groupPublishKeyPackage(carol.id);
    const g = await client.groupCreate(alice.id, 'G1 secure relay');
    await client.groupInvite(alice.id, g.groupId, bob.pubkey);
    await client.groupInvite(alice.id, g.groupId, carol.pubkey);
    expect((await client.groupAccept(bob.id)).map((x) => x.groupId)).toEqual([g.groupId]);
    expect((await client.groupAccept(carol.id)).map((x) => x.groupId)).toEqual([g.groupId]);

    await client.groupSend(alice.id, g.groupId, 'hola por el secure relay');
    expect((await client.groupSync(bob.id, g.groupId)).map((m) => m.content)).toContain('hola por el secure relay');
    expect((await client.groupSync(carol.id, g.groupId)).map((m) => m.content)).toContain('hola por el secure relay');

    await client.groupRemove(alice.id, g.groupId, bob.pubkey);
    await client.groupSend(alice.id, g.groupId, 'ya sin bob');
    expect((await client.groupSync(carol.id, g.groupId)).map((m) => m.content)).toContain('ya sin bob');
    expect((await client.groupSync(bob.id, g.groupId).catch(() => [])).map((m) => m.content)).not.toContain('ya sin bob');
  }, 90_000);

  it('NIP-17 DM read back by its recipient', async () => {
    const [sender, recipient] = [await persona('Emisor'), await persona('Destinatario')];
    const text = `dm por el secure relay ${Date.now()}`;
    await client.sendDm(sender.id, recipient.pubkey, text);
    expect((await client.inbox(recipient.id)).map((m) => m.rumor.content)).toContain(text);
  }, 30_000);
});
