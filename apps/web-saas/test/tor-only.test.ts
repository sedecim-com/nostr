/**
 * PANEL-05: a browser cannot guarantee Tor-only, so the web opens no relay connection for a Tor-only persona
 * (one created before the web refused them): no reads, no kind 10050, no DM discovery. Control: the same persona
 * on a direct network does connect.
 */
import { describe, expect, it } from 'vitest';
import type { AddressInfo } from 'node:net';
import { WebSocketServer } from 'ws';
import { bytesToHex, generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { preset } from '@sedecim/profiles';
import { openPersona, publishDmRelays } from '../src/lib/session';
import type { PersonaBook, PersonaRecord } from '../src/lib/vault';

describe('Tor-only persona in the web (PANEL-05)', () => {
  it('never connects to a relay: reads come back empty and the 10050 is held with the reason', async () => {
    const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
    await new Promise((r) => wss.once('listening', r));
    let connections = 0;
    wss.on('connection', (ws) => {
      connections++;
      ws.on('message', (raw) => {
        const [type, sub] = JSON.parse(raw.toString()) as [string, string];
        if (type === 'REQ') ws.send(JSON.stringify(['EOSE', sub]));
      });
    });
    const url = `ws://127.0.0.1:${(wss.address() as AddressInfo).port}`;
    const sk = generateSecretKey();
    const persona = (network: 'tor-only' | 'private-relay'): PersonaRecord => ({ id: network, label: network, pubkey: getPublicKey(sk), custody: 'local', secretHex: bytesToHex(sk), relays: [url], preset: 'custom', config: { ...preset('sovereign-tor'), network }, createdAt: 0 });
    const book = { store: EncryptedStore.withKey(new MemoryBackend(), new Uint8Array(32).fill(7)) } as unknown as PersonaBook;
    try {
      const tor = await openPersona(book, persona('tor-only'));
      try {
        expect(await tor.pool.query([url], [{ kinds: [10050] }], 1000)).toEqual([]);
        await publishDmRelays(tor);
        let held;
        for (let i = 0; i < 50 && !held; i++) {
          await new Promise((r) => setTimeout(r, 50));
          held = (await tor.engine.list()).find((r) => r.blockedReason);
        }
        expect(held?.blockedReason).toMatch(/Tor-only/);
        expect(held?.state).not.toBe('REPLICATED');
        expect(connections).toBe(0);
      } finally {
        tor.close();
      }

      const direct = await openPersona(book, persona('private-relay'));
      try {
        await direct.pool.query([url], [{ kinds: [10050] }], 1000);
        expect(connections).toBeGreaterThan(0);
      } finally {
        direct.close();
      }
    } finally {
      wss.close();
    }
  }, 30_000);
});
