/**
 * FR004-08: personas of the sovereign client whose key lives in a NIP-46 signer (bunker:// or nostrconnect://), or
 * imported from an nsec or an ncryptsec, each declaring the custody of its real key. In Tor mode the signer is reached
 * through Tor with the persona's own SOCKS credentials, and without Tor nothing is signed or sent.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { mkdtemp, writeFile } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';
import { bech32 } from '@scure/base';
import { generateSecretKey, getPublicKey, nip19, nip49, type EventTemplate, type NostrEvent, type Signer } from '@sedecim/nostr-core';
import { NetworkBlockedError, RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { formatBunkerUrl, LocalSigner, Nip46Bunker, NOSTR_CONNECT_KIND, parseNostrConnect, SOVEREIGN_NIP46_PERMISSIONS, SOVEREIGN_SIGNED_KINDS, type Nip46Method } from '@sedecim/signer';
import { TestBlossomServer, TestRelay, TestSocksServer, tinyPng } from '@sedecim/test-relay';
import { PRIVACY_NETWORK_UNAVAILABLE } from '@sedecim/tor-network';
import { SovereignClient } from '../src/index';

const onion = (prefix: string) => `${prefix}${'a'.repeat(56 - prefix.length)}.onion`;
const RELAY_ONION = onion('personarelay');
const SIGNER_ONION = onion('signerrelay');
const BLOSSOM_ONION = onion('blossommedia');
const POLICY_ONION = onion('policyengine');
const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const npub = (pubkey: string) => nip19.npubEncode(pubkey);

/** The user's key behind the bunker, recording every kind it is asked to sign (as the web's permission test does). */
class RecordingSigner implements Signer {
  readonly custody = 'local' as const;
  readonly kinds = new Set<number>();
  private readonly inner = new LocalSigner(generateSecretKey());
  getPublicKey() {
    return this.inner.getPublicKey();
  }
  signEvent(t: EventTemplate): Promise<NostrEvent> {
    this.kinds.add(t.kind);
    return this.inner.signEvent(t);
  }
  nip44Encrypt(peer: string, plaintext: string) {
    return this.inner.nip44Encrypt(peer, plaintext);
  }
  nip44Decrypt(peer: string, ciphertext: string) {
    return this.inner.nip44Decrypt(peer, ciphertext);
  }
}

/** The same ncryptsec declaring another scrypt cost (the cost check comes before scrypt, so it never runs). */
function withLogN(ncryptsec: string, logN: number): string {
  const { words } = bech32.decode(ncryptsec as `ncryptsec1${string}`, 5000);
  const bytes = new Uint8Array(bech32.fromWords(words));
  bytes[1] = logN;
  return bech32.encode('ncryptsec', bech32.toWords(bytes), 5000);
}

/** Runs the CLI; `onStderr` sees its stderr as it arrives (e.g. to answer the nostrconnect:// offer it prints). */
function run(args: string[], env: NodeJS.ProcessEnv, onStderr?: (text: string) => void): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--import', 'tsx', CLI, ...args], { env });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => {
      stderr += d;
      onStderr?.(stderr);
    });
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

describe('sovereign client with a NIP-46 signer or an imported key, in Tor profiles (FR004-08)', () => {
  // Both relays ask for NIP-42: the persona's relay gets it signed by the signer, the signer's relay by the client key.
  // Every host is an onion behind the SOCKS stub.
  const relay = new TestRelay({ publicUrl: `ws://${RELAY_ONION}`, requireAuth: true, pGatedKinds: [1059] });
  const signerRelay = new TestRelay({ publicUrl: `ws://${SIGNER_ONION}`, requireAuth: true });
  const blossom = new TestBlossomServer();
  const nip98: NostrEvent[] = [];
  let policy: Server;
  let socks: TestSocksServer;
  let bunkerPool: RelayPool;
  const user = new RecordingSigner();
  const requests: Array<{ method: Nip46Method; kind?: number; allowed: boolean }> = [];
  let bunker: Nip46Bunker;
  let userPk: string;
  let client: SovereignClient;
  let dir: string;
  const retry = { baseMs: 60_000, maxMs: 60_000 };

  beforeAll(async () => {
    await relay.start();
    await signerRelay.start();
    await blossom.start();
    blossom.publicUrl = `http://${BLOSSOM_ONION}`;
    // A policy-engine with nothing to rotate: what matters is the NIP-98 header the worker signs.
    policy = createServer((req, res) => {
      const auth = req.headers.authorization;
      if (auth?.startsWith('Nostr ')) nip98.push(JSON.parse(Buffer.from(auth.slice(6), 'base64').toString('utf8')) as NostrEvent);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ rotations: [] }));
    });
    await new Promise<void>((r) => policy.listen(0, '127.0.0.1', () => r()));
    const port = (s: { port: number } | Server) => ('port' in s ? s.port : (s.address() as AddressInfo).port);
    const local = (p: number) => ({ host: '127.0.0.1', port: p });
    // Like Tor with IsolateSOCKSAuth on a port that requires credentials.
    socks = new TestSocksServer(
      { [RELAY_ONION]: local(port(relay)), [SIGNER_ONION]: local(port(signerRelay)), [BLOSSOM_ONION]: local(Number(new URL(blossom.url).port)), [POLICY_ONION]: local(port(policy)) },
      { requireAuth: true },
    );
    await socks.start();
    // The signer side (a phone, another machine) reaches its relay however it likes: here, directly.
    bunkerPool = new RelayPool({ signer: new LocalSigner(generateSecretKey()), webSocketFactory: (u) => new WebSocket(u.replace(`ws://${SIGNER_ONION}`, `ws://127.0.0.1:${signerRelay.port}`)) as unknown as WebSocketLike });
    bunker = new Nip46Bunker(user, bunkerPool, [`ws://${SIGNER_ONION}`], { allowedKinds: [...SOVEREIGN_SIGNED_KINDS], onRequest: (i) => requests.push(i) });
    await bunker.start();
    userPk = await user.getPublicKey();
    dir = await mkdtemp(join(tmpdir(), 'sovereign-nip46-'));
    client = new SovereignClient({ dataDir: dir, passphrase: 'pass', scryptLogN: 4, socksPort: socks.port, retry });
  });
  afterAll(async () => {
    client.close();
    bunker.stop();
    bunkerPool.close();
    await socks.stop();
    await new Promise<void>((r) => policy.close(() => r()));
    await blossom.stop();
    await signerRelay.stop();
    await relay.stop();
  });

  const personaOf = async (label: string) => (await (await client.identities()).list()).find((p) => p.label === label)!;

  it('a Tor persona signs through its NIP-46 signer over Tor with its own SOCKS credentials, and declares external custody (FR004-08)', async () => {
    // With --npub, a signer that holds another key creates nothing.
    await expect(client.connectSigner({ label: 'Otra llave', relays: [`ws://${RELAY_ONION}`], tor: true, bunker: formatBunkerUrl(await bunker.pointer()), npub: npub(getPublicKey(generateSecretKey())) })).rejects.toThrow(/el signer tiene otra llave/);
    expect(await (await client.identities()).list()).toEqual([]);
    const before = socks.requests.length;
    const p = await client.connectSigner({ label: 'Fuente con signer', relays: [`ws://${RELAY_ONION}`], tor: true, bunker: formatBunkerUrl(await bunker.pointer()), npub: npub(userPk) });
    const connected = socks.requests.length;
    expect(p).toMatchObject({ pubkey: userPk, custody: 'external', network: 'tor-only' });
    // Only the signer's address is kept, never the bunker secret; and no key of the user is on this device.
    expect(p.bunker).toBe(formatBunkerUrl({ remoteSignerPubkey: (await bunker.pointer()).remoteSignerPubkey, relays: [`ws://${SIGNER_ONION}`] }));
    await expect((await client.identities()).unlock(p.id, 'pass')).rejects.toThrow(/custody is external/);

    // The custody declared is the real one: an external signer, not the preset's offline key nor a key on this device.
    expect(client.profileFor(p).custody).toBe('external');
    expect((await client.disclosures(p.id)).find((d) => d.control === 'custody')!.statement).toMatch(/^Un signer externo \(NIP-46\/NIP-07\) firma por ti; este cliente nunca ve la nsec\. El signer ve lo que firma/);
    expect(await (await client.identities()).sendingAs(p.id)).toContain(' · signer externo (NIP-46) · Tor-only · sin vínculo');
    const warnings = client.warningsFor(p).join(' ');
    expect(warnings).toMatch(/auditoría independiente/);
    expect(warnings).not.toMatch(/está en este dispositivo/);

    const rec = await client.sendChannel(p.id, 'sala', 'firmado por el signer');
    expect(rec.state).toBe('REPLICATED');
    expect(rec.event!.pubkey).toBe(userPk);
    expect([...user.kinds]).toEqual(expect.arrayContaining([9, 22242])); // the message and the NIP-42 AUTH, both by the signer
    expect(relay.authedPubkeys).toContain(userPk);
    // On the signer's relay, NIP-42 authenticates this device's client key: never the persona.
    expect(signerRelay.authedPubkeys.length).toBeGreaterThan(0);
    expect(signerRelay.authedPubkeys).not.toContain(userPk);

    // Everything went through the SOCKS port by name. After it exists, all the persona's traffic (its relay and its
    // signer) carries its id; while connecting, before the persona existed, credentials of their own that no persona uses.
    const used = socks.requests.slice(before);
    expect(used.every((r) => r.addressType === 'domain' && [RELAY_ONION, SIGNER_ONION].includes(r.host))).toBe(true);
    expect(socks.requests.slice(connected).filter((r) => r.host === SIGNER_ONION).length).toBeGreaterThan(0);
    expect(new Set(socks.requests.slice(connected).map((r) => r.username))).toEqual(new Set([p.id]));
    const handshake = socks.requests.slice(before, connected);
    expect(handshake.length).toBeGreaterThan(0);
    expect(handshake.every((r) => r.host === SIGNER_ONION && /^[0-9a-f]{16}$/.test(r.username ?? '') && r.username !== p.id)).toBe(true);
  });

  it('asks the signer for exactly the kinds the CLI signs: every signing path works with a bunker that allows only those (FR004-08)', async () => {
    const p = await personaOf('Fuente con signer');
    const other = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-nip46-bob-')), passphrase: 'bob', scryptLogN: 4, socksPort: socks.port, retry });
    try {
      const bob = await other.createPersona({ label: 'Bob', relays: [`ws://${RELAY_ONION}`], tor: true });
      await other.publishDmRelays(bob.id);
      expect((await client.publishDmRelays(p.id)).state).toBe('REPLICATED');
      expect((await client.joinChannel(p.id, 'sala')).state).toBe('REPLICATED');

      // DMs both ways: the seal is signed and the DMs decrypted by the signer (NIP-44), never with a key here.
      expect((await client.sendDm(p.id, bob.pubkey, 'hola Bob')).every((r) => r.state === 'REPLICATED')).toBe(true);
      expect((await other.inbox(bob.id)).map((m) => m.rumor.content)).toContain('hola Bob');
      await other.sendDm(bob.id, p.pubkey, 'hola');
      expect((await client.inbox(p.id)).map((m) => m.rumor.content)).toContain('hola');
      expect(requests.some((r) => r.method === 'nip44_decrypt' && r.allowed)).toBe(true);

      // Marmot groups: key package, invitations both ways, a message and encrypted media on an onion Blossom.
      await other.groupPublishKeyPackage(bob.id);
      await client.groupPublishKeyPackage(p.id);
      const g = await client.groupCreate(p.id, 'celda');
      await client.groupInvite(p.id, g.groupId, bob.pubkey);
      expect((await other.groupAccept(bob.id)).map((x) => x.groupId)).toEqual([g.groupId]);
      await client.groupSend(p.id, g.groupId, 'hola grupo');
      expect((await other.groupSync(bob.id, g.groupId)).map((m) => m.content)).toContain('hola grupo');
      const h = await other.groupCreate(bob.id, 'otra celda');
      await other.groupInvite(bob.id, h.groupId, p.pubkey);
      expect((await client.groupAccept(p.id)).map((x) => x.groupId)).toEqual([h.groupId]);
      const sent = await client.groupSendFile(p.id, g.groupId, { data: tinyPng(), filename: 'acta.png', mimeType: 'image/png' }, { servers: [`http://${BLOSSOM_ONION}`] });
      expect(sent.attachment.url!.startsWith(`http://${BLOSSOM_ONION}/`)).toBe(true);
      expect([...blossom.blobs.values()].map((b) => b.uploader)).toContain(userPk);

      // The revocation worker authenticates to the policy-engine with NIP-98, signed by the signer.
      const { worker } = await client.revocationWorker(p.id, { policyUrl: `http://${POLICY_ONION}` });
      expect(await worker.runOnce()).toEqual([]);
      expect(nip98.at(-1)).toMatchObject({ kind: 27235, pubkey: userPk });

      // Both ways: nothing asked outside the permissions (the bunker would have refused it) and none of them unused.
      expect(requests.filter((r) => !r.allowed)).toEqual([]);
      expect([...user.kinds].sort((x, y) => x - y)).toEqual([...SOVEREIGN_SIGNED_KINDS].sort((x, y) => x - y));
      expect(socks.requests.filter((r) => r.username === p.id).every((r) => [RELAY_ONION, SIGNER_ONION, BLOSSOM_ONION, POLICY_ONION].includes(r.host))).toBe(true);
    } finally {
      other.close();
    }
  }, 120_000);

  it('without Tor nothing reaches the signer or the relays: connecting and sending fail closed, and the message goes out once Tor is back (FR004-08)', async () => {
    const p = await personaOf('Fuente con signer');
    const peer = getPublicKey(generateSecretKey());
    const offline = new SovereignClient({ dataDir: dir, passphrase: 'pass', scryptLogN: 4, socksPort: 1, retry });
    const seen = { requests: requests.length, relay: relay.received.length, signer: signerRelay.received.length, personas: (await (await client.identities()).list()).length };
    try {
      const refused = await offline.sendChannel(p.id, 'sala', 'sin tor').then(() => undefined, (e: unknown) => e);
      expect(refused).toBeInstanceOf(NetworkBlockedError);
      expect((refused as Error).message).toBe(PRIVACY_NETWORK_UNAVAILABLE);
      // A DM cannot even be sealed: its operation is kept, for a retry under the same --op.
      await expect(offline.sendDm(p.id, peer, 'dm sin tor', { opId: 'dm-sin-tor' })).rejects.toThrow(PRIVACY_NETWORK_UNAVAILABLE);
      await expect(offline.connectSigner({ label: 'Sin tor', relays: [`ws://${RELAY_ONION}`], tor: true, bunker: formatBunkerUrl(await bunker.pointer()) })).rejects.toThrow(PRIVACY_NETWORK_UNAVAILABLE);
      expect(await (await offline.identities()).list()).toHaveLength(seen.personas);
    } finally {
      offline.close();
    }
    expect(requests).toHaveLength(seen.requests);
    expect(relay.received).toHaveLength(seen.relay);
    expect(signerRelay.received).toHaveLength(seen.signer);
    // Tor is back: the message was kept, and the next command that opens the persona has it signed and published.
    const back = new SovereignClient({ dataDir: dir, passphrase: 'pass', scryptLogN: 4, socksPort: socks.port, retry });
    try {
      await back.outbox(p.id);
      await back.settle();
      expect((await back.outbox(p.id)).find((r) => r.template?.content === 'sin tor')).toMatchObject({ state: 'REPLICATED', event: { pubkey: userPk, content: 'sin tor' } });
      const dm = await back.sendDm(p.id, peer, 'dm sin tor', { opId: 'dm-sin-tor' });
      expect(dm.map((r) => [r.meta?.recipient, r.state])).toEqual([
        [peer, 'REPLICATED'],
        [userPk, 'REPLICATED'],
      ]);
    } finally {
      back.close();
    }
    expect([...relay.events.values()].filter((e) => e.content === 'sin tor').map((e) => e.pubkey)).toEqual([userPk]);
  });

  it('connects through a nostrconnect:// offer that asks for the same permissions, answered by the signer over Tor (FR004-08)', async () => {
    const second = new RecordingSigner();
    const phone = new Nip46Bunker(second, bunkerPool, [`ws://${SIGNER_ONION}`], { allowedKinds: [...SOVEREIGN_SIGNED_KINDS] });
    await phone.start();
    const offers: string[] = [];
    try {
      const p = await client.connectSigner({
        label: 'Con nostrconnect',
        relays: [`ws://${RELAY_ONION}`],
        tor: true,
        npub: npub(await second.getPublicKey()),
        nostrconnect: { relays: [`ws://${SIGNER_ONION}`], timeoutMs: 10_000, onOffer: (uri) => (offers.push(uri), void phone.acceptNostrConnect(uri)) },
      });
      expect(offers).toHaveLength(1);
      expect(parseNostrConnect(offers[0]!)).toMatchObject({ relays: [`ws://${SIGNER_ONION}`], permissions: SOVEREIGN_NIP46_PERMISSIONS });
      expect(p).toMatchObject({ pubkey: await second.getPublicKey(), custody: 'external' });
      expect((await client.sendChannel(p.id, 'sala', 'vía nostrconnect')).event!.pubkey).toBe(await second.getPublicKey());
    } finally {
      phone.stop();
    }
  });

  it('shows the page where the signer asks for approval (auth_url), with the persona network, and keeps waiting (FR004-08)', async () => {
    // A signer that first asks for approval in a web page, then answers.
    const transport = new LocalSigner(generateSecretKey());
    const transportPk = await transport.getPublicKey();
    const approved = getPublicKey(generateSecretKey());
    let sub: { close(): void } | undefined;
    await new Promise<void>((live) => {
      sub = bunkerPool.subscribe([`ws://${SIGNER_ONION}`], [{ kinds: [NOSTR_CONNECT_KIND], '#p': [transportPk] }], {
        oneose: live,
        onevent: async (evt) => {
          const req = JSON.parse(await transport.nip44Decrypt(evt.pubkey, evt.content)) as { id: string; method: string };
          const answer = async (body: object) =>
            bunkerPool.publish(await transport.signEvent({ kind: NOSTR_CONNECT_KIND, content: await transport.nip44Encrypt(evt.pubkey, JSON.stringify({ id: req.id, ...body })), tags: [['p', evt.pubkey]] }), [`ws://${SIGNER_ONION}`]);
          if (req.method === 'connect') {
            await answer({ result: 'auth_url', error: 'https://signer.example/approve/1' });
            await answer({ result: 'ack' });
          } else if (req.method === 'get_public_key') await answer({ result: approved });
        },
      });
    });
    const pages: Array<[string, string]> = [];
    const approving = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-nip46-approval-')), passphrase: 'ap', scryptLogN: 4, socksPort: socks.port, retry, onSignerAuthUrl: (url, p) => pages.push([url, p.network]) });
    try {
      const p = await approving.connectSigner({ label: 'Con aprobación', relays: [`ws://${RELAY_ONION}`], tor: true, bunker: formatBunkerUrl({ remoteSignerPubkey: transportPk, relays: [`ws://${SIGNER_ONION}`] }) });
      expect(pages).toEqual([['https://signer.example/approve/1', 'tor-only']]);
      expect(p).toMatchObject({ pubkey: approved, custody: 'external' });
    } finally {
      sub?.close();
      approving.close();
    }
  });

  it('refuses a clearnet signer relay for an onion-only persona before any connection (FR004-08)', async () => {
    const before = socks.requests.length;
    const clearnet = formatBunkerUrl({ remoteSignerPubkey: getPublicKey(generateSecretKey()), relays: ['wss://signer.example'], secret: 'x' });
    await expect(client.connectSigner({ label: 'Solo onion', relays: [`ws://${RELAY_ONION}`], onionOnly: true, bunker: clearnet })).rejects.toThrow('onion-only: every relay of the signer must be a .onion address (1 of 1 are not)');
    await expect(client.connectSigner({ label: 'Solo onion', relays: [`ws://${RELAY_ONION}`], onionOnly: true, nostrconnect: { relays: ['wss://signer.example'], onOffer: () => undefined } })).rejects.toThrow(/every relay of the signer must be a \.onion/);
    expect(socks.requests).toHaveLength(before);
  });

  it('imports an nsec or an ncryptsec only as the declared npub, sealed here as local custody (FR004-08)', async () => {
    const input = { relays: [`ws://${RELAY_ONION}`], tor: true };
    const sk = generateSecretKey();
    const pk = getPublicKey(sk);
    await expect(client.importKey(nip19.nsecEncode(sk), { ...input, label: 'Otra', npub: npub(getPublicKey(generateSecretKey())) })).rejects.toThrow(/does not match/);
    const a = await client.importKey(`${nip19.nsecEncode(sk)}\n`, { ...input, label: 'Desde nsec', npub: npub(pk) });
    expect(a).toMatchObject({ pubkey: pk, custody: 'local', network: 'tor-only' });
    expect(await (await (await client.identities()).unlock(a.id, 'pass')).getPublicKey()).toBe(pk);
    // Declared as what it is: a key sealed on this device, which may have been imported; the Tor profile says so.
    expect(client.profileFor(a).custody).toBe('local');
    expect((await client.disclosures(a.id)).find((d) => d.control === 'custody')!.statement).toMatch(/^La llave se guarda cifrada en este dispositivo, creada aquí o importada/);
    expect(client.warningsFor(a).join(' ')).toMatch(/La llave de esta persona está en este dispositivo, cifrada con tu passphrase/);
    await expect(client.importKey(nip19.nsecEncode(sk), { ...input, label: 'Repetida', npub: npub(pk) })).rejects.toThrow(/already exists/);

    const sk2 = generateSecretKey();
    const pk2 = getPublicKey(sk2);
    const ncryptsec = nip49.encryptKey(sk2, 'contraseña de la llave', 4);
    await expect(client.importKey(ncryptsec, { ...input, label: 'Sin contraseña', npub: npub(pk2) })).rejects.toThrow(/necesita su contraseña/);
    await expect(client.importKey(ncryptsec, { ...input, label: 'Mala', npub: npub(pk2), password: 'otra' })).rejects.toThrow(/contraseña incorrecta/);
    await expect(client.importKey(withLogN(ncryptsec, 30), { ...input, label: 'Costosa', npub: npub(pk2), password: 'x' })).rejects.toThrow(/2\^30; el máximo es 2\^20/);
    await expect(client.importKey(npub(pk2), { ...input, label: 'Nada', npub: npub(pk2) })).rejects.toThrow(/se esperaba una llave nsec1… o ncryptsec1…/);
    const b = await client.importKey(ncryptsec, { ...input, label: 'Desde ncryptsec', npub: npub(pk2), password: 'contraseña de la llave' });
    expect(b).toMatchObject({ pubkey: pk2, custody: 'local' });
    expect((await client.sendChannel(b.id, 'sala', 'con llave importada')).event!.pubkey).toBe(pk2);
  });

  it('a persona restored from a backup pairs again with its signer, and only with one that holds its npub (FR004-08)', async () => {
    const p = await personaOf('Fuente con signer');
    const pkg = await client.exportBackup(p.id, 'contraseña del backup', { scryptLogN: 4 });
    expect(pkg.ncryptsec).toBeUndefined(); // there is no key here to back up
    const other = new SovereignClient({ dataDir: await mkdtemp(join(tmpdir(), 'sovereign-nip46-restored-')), passphrase: 'otra', scryptLogN: 4, socksPort: socks.port, retry });
    const stranger = new Nip46Bunker(new RecordingSigner(), bunkerPool, [`ws://${SIGNER_ONION}`]);
    await stranger.start();
    try {
      const restored = await other.restoreBackup(pkg, 'contraseña del backup');
      expect(restored).toMatchObject({ id: p.id, custody: 'external', pubkey: userPk });
      // The backup never carries this device's pairing: nothing can be signed until the signer approves this device.
      await expect(other.sendChannel(p.id, 'sala', 'antes de emparejar')).rejects.toThrow(/no está emparejado con el signer NIP-46/);
      await expect(other.reconnectSigner(p.id, { bunker: formatBunkerUrl(await stranger.pointer()) })).rejects.toThrow(/el signer tiene otra llave/);
      await other.reconnectSigner(p.id, { bunker: formatBunkerUrl(await bunker.pointer()) });
      expect((await other.sendChannel(p.id, 'sala', 'emparejado de nuevo')).event!.pubkey).toBe(userPk);
      await expect(other.reconnectSigner((await other.createPersona({ label: 'Local', relays: [`ws://${RELAY_ONION}`], tor: true })).id, { bunker: formatBunkerUrl(await bunker.pointer()) })).rejects.toThrow(/no hay signer que emparejar/);
    } finally {
      stranger.stop();
      other.close();
    }
  });

  it('the CLI lists what the signer is asked for, connects it and imports an nsec from a file, through Tor (FR004-08)', async () => {
    const cliDir = await mkdtemp(join(tmpdir(), 'sovereign-nip46-cli-'));
    const env = { ...process.env, SOVEREIGN_DATA_DIR: join(cliDir, 'data'), SOVEREIGN_PASSPHRASE: 'cli-pass', TOR_SOCKS: `127.0.0.1:${socks.port}` };
    const bunkerFile = join(cliDir, 'bunker.txt');
    await writeFile(bunkerFile, `${formatBunkerUrl(await bunker.pointer())}\n`, { mode: 0o600 });
    const connected = await run(['persona', 'connect', '--bunker-file', bunkerFile, '--label', 'Cli con signer', '--relay', `ws://${RELAY_ONION}`, '--tor', '--npub', npub(userPk)], env);
    expect(connected.status, connected.stderr).toBe(0);
    expect(connected.stderr).toContain('permiso pedido al signer: Firmar: Mensajes de canal (NIP-29) (sign_event:9)');
    expect(connected.stderr).toContain('permiso pedido al signer: Descifrar mensajes directos (NIP-44) (nip44_decrypt)');
    expect(connected.stderr).toMatch(/^relays de DM \(kind 10050\): REPLICATED$/m);
    const p = JSON.parse(connected.stdout) as { id: string; custody: string; pubkey: string };
    expect(p).toMatchObject({ custody: 'external', pubkey: userPk });
    const sent = await run(['channel', 'send', '--persona', p.id, '--group', 'sala', 'desde el CLI'], env);
    expect(sent.status, sent.stderr).toBe(0);
    expect(sent.stderr).toMatch(/^Enviando como Cli con signer \(npub1.*\) · signer externo \(NIP-46\) · Tor-only · sin vínculo$/m);
    expect(sent.stdout).toMatch(/^REPLICATED/m);
    // Its backup says what it carries: no key, which is in the signer, and no pairing of this device.
    const pw = join(cliDir, 'pw');
    await writeFile(pw, 'contraseña del backup\n', { mode: 0o600 });
    const backup = await run(['backup', 'export', '--persona', p.id, '--out', join(cliDir, 'backup.json'), '--password-file', pw], env);
    expect(backup.status, backup.stderr).toBe(0);
    expect(backup.stdout).toMatch(/^backup cifrado \(relays, panel, grupos MLS\) escrito en /m);
    expect(backup.stderr).toMatch(/^aviso: la llave de esta persona está en su signer NIP-46 y no va en el backup, ni el emparejamiento de este dispositivo/m);

    const sk = generateSecretKey();
    const keyFile = join(cliDir, 'nsec.txt');
    await writeFile(keyFile, `${nip19.nsecEncode(sk)}\n`, { mode: 0o600 });
    const noNpub = await run(['persona', 'import', '--key-file', keyFile, '--label', 'Cli nsec', '--relay', `ws://${RELAY_ONION}`, '--tor'], env);
    expect(noNpub.status).toBe(1);
    expect(noNpub.stderr).toMatch(/--npub NPUB required/);
    const imported = await run(['persona', 'import', '--key-file', keyFile, '--npub', npub(getPublicKey(sk)), '--label', 'Cli nsec', '--relay', `ws://${RELAY_ONION}`, '--tor'], env);
    expect(imported.status, imported.stderr).toBe(0);
    expect(JSON.parse(imported.stdout)).toMatchObject({ custody: 'local', pubkey: getPublicKey(sk) });
    expect(imported.stderr).toMatch(/^aviso: La llave de esta persona está en este dispositivo/m);
    const whoami = await run(['whoami', '--persona', (JSON.parse(imported.stdout) as { id: string }).id], env);
    expect(whoami.stdout).toMatch(/ · llave cifrada en este dispositivo · Tor-only · sin vínculo$/m);
  }, 120_000);

  it('the CLI pairs a restored persona again with its signer, and connects one through the nostrconnect:// offer it prints (FR004-08)', async () => {
    const cliDir = await mkdtemp(join(tmpdir(), 'sovereign-nip46-cli-restore-'));
    const env = { ...process.env, SOVEREIGN_DATA_DIR: join(cliDir, 'data'), SOVEREIGN_PASSPHRASE: 'cli-pass-2', TOR_SOCKS: `127.0.0.1:${socks.port}` };
    const p = await personaOf('Fuente con signer');
    const file = join(cliDir, 'backup.json');
    await writeFile(file, JSON.stringify(await client.exportBackup(p.id, 'contraseña del backup', { scryptLogN: 4 })), { mode: 0o600 });
    const pw = join(cliDir, 'pw');
    await writeFile(pw, 'contraseña del backup\n', { mode: 0o600 });
    const restored = await run(['backup', 'restore', file, '--password-file', pw], env);
    expect(restored.status, restored.stderr).toBe(0);
    const unpaired = await run(['channel', 'send', '--persona', p.id, '--group', 'sala', 'sin emparejar'], env);
    expect(unpaired.status).toBe(1);
    expect(unpaired.stderr).toMatch(/no está emparejado con el signer NIP-46 .*sovereign persona connect --persona /);
    const bunkerFile = join(cliDir, 'bunker.txt');
    await writeFile(bunkerFile, formatBunkerUrl(await bunker.pointer()), { mode: 0o600 });
    const paired = await run(['persona', 'connect', '--persona', p.id, '--bunker-file', bunkerFile], env);
    expect(paired.status, paired.stderr).toBe(0);
    expect(JSON.parse(paired.stdout)).toMatchObject({ id: p.id, custody: 'external', pubkey: userPk });
    expect((await run(['channel', 'send', '--persona', p.id, '--group', 'sala', 'emparejado desde el CLI'], env)).stdout).toMatch(/^REPLICATED/m);

    // nostrconnect://: the CLI prints the offer once it listens for the answer, and the signer answers it.
    const third = new RecordingSigner();
    const phone = new Nip46Bunker(third, bunkerPool, [`ws://${SIGNER_ONION}`], { allowedKinds: [...SOVEREIGN_SIGNED_KINDS] });
    await phone.start();
    let answered = false;
    try {
      const args = ['persona', 'connect', '--nostrconnect', '--signer-relay', `ws://${SIGNER_ONION}`, '--label', 'Cli nostrconnect', '--relay', `ws://${RELAY_ONION}`, '--tor'];
      const connected = await run(args, env, (text) => {
        const uri = /nostrconnect:\/\/\S+(?=\n)/.exec(text)?.[0];
        if (uri && !answered) {
          answered = true;
          void phone.acceptNostrConnect(uri);
        }
      });
      expect(connected.status, connected.stderr).toBe(0);
      expect(connected.stderr).toMatch(/^abre esta URI en tu signer .*\nnostrconnect:\/\//m);
      expect(JSON.parse(connected.stdout)).toMatchObject({ custody: 'external', pubkey: await third.getPublicKey() });
    } finally {
      phone.stop();
    }
  }, 120_000);
});
