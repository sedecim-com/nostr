import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { connect } from 'node:http2';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateSecretKey, getPublicKey } from '@sedecim/nostr-core';
import { bearer, PolicyEngineClient } from '@sedecim/policy-client';
import { createPgPool, type Pool } from '@sedecim/service-kit';
import { AdmissionServer, AllowlistSync, BuzzAllowlistSink, BUZZ_ALLOWLIST_NOTE, createPolicyApi, decodeEventRequest, encodeEventReply, FileAllowlistSink, PolicyEngine } from '../src/index';

/** Minimal protobuf writer for the nauthz EventRequest (what nostr-rs-relay sends). */
function varint(n: number): number[] {
  const out: number[] = [];
  for (; n > 0x7f; n = Math.floor(n / 128)) out.push((n & 0x7f) | 0x80);
  return [...out, n];
}
function field(n: number, bytes: Uint8Array): number[] {
  return [(n << 3) | 2, ...varint(bytes.length), ...bytes];
}
function eventRequest(o: { authPubkey?: string; eventPubkey: string; kind: number; tags?: string[][] }): Uint8Array {
  // FR023-10: `repeated TagEntry tags = 6`, `TagEntry { repeated string values = 1 }`.
  const tags = (o.tags ?? []).flatMap((t) => field(6, new Uint8Array(t.flatMap((v) => field(1, Buffer.from(v))))));
  const event = [...field(2, Buffer.from(o.eventPubkey, 'hex')), 0x20, ...varint(o.kind), ...field(5, Buffer.from('hola')), ...tags];
  return new Uint8Array([...field(1, new Uint8Array(event)), ...(o.authPubkey ? field(5, Buffer.from(o.authPubkey, 'hex')) : [])]);
}

/** Calls EventAdmit over h2c like the relay's tonic client; returns [decision, message]. */
async function admit(port: number, req: Uint8Array): Promise<[number, string]> {
  const client = connect(`http://127.0.0.1:${port}`);
  try {
    const stream = client.request({ ':method': 'POST', ':path': '/nauthz.Authorization/EventAdmit', 'content-type': 'application/grpc', te: 'trailers' });
    const frame = Buffer.alloc(5 + req.length);
    frame.writeUInt32BE(req.length, 1);
    frame.set(req, 5);
    stream.end(frame);
    const chunks: Buffer[] = [];
    const trailers = new Promise<Record<string, unknown>>((r) => stream.on('trailers', (t) => r(t)));
    for await (const c of stream) chunks.push(c as Buffer);
    expect((await trailers)['grpc-status']).toBe('0');
    const body = Buffer.concat(chunks).subarray(5);
    const decision = body[1]!;
    const message = body.length > 2 ? body.subarray(4, 4 + body[3]!).toString() : '';
    return [decision, message];
  } finally {
    client.close();
  }
}

describe('relay allowlist sync (FR023-04)', () => {
  const adminSk = generateSecretKey();
  const admin = getPublicKey(adminSk);
  const alice = getPublicKey(generateSecretKey());
  const bob = getPublicKey(generateSecretKey());
  const indexer = getPublicKey(generateSecretKey());
  const engine = new PolicyEngine();
  const api = createPolicyApi(engine, { name: 'policy-sync-test', adminPubkeys: [admin], bearerTokens: { 'sync-token-1234': 'relay-allowlist' } });
  const admission = new AdmissionServer();
  let base: string;
  let grpcPort: number;
  let file: string;
  let failFetch = false;
  let sync: AllowlistSync;

  beforeAll(async () => {
    base = await api.listen();
    grpcPort = await admission.listen();
    file = join(await mkdtemp(join(tmpdir(), 'allowlist-')), 'allowlist.txt');
    const client = new PolicyEngineClient(base, bearer('sync-token-1234'));
    sync = new AllowlistSync({
      fetch: () => (failFetch ? Promise.reject(new Error('down')) : client.relayAllowlist()),
      sinks: [new FileAllowlistSink(file)],
      admission,
      extraPubkeys: [indexer],
    });
    for (const p of [alice, bob]) {
      await engine.upsertSubject(admin, { pubkey: p, roles: [], attributes: {} });
      await engine.registerDevice(admin, p);
    }
  });
  afterAll(async () => {
    await api.close();
    await admission.close();
  });

  it('denies every event before the first sync (fail closed)', async () => {
    expect(await admit(grpcPort, eventRequest({ authPubkey: alice, eventPubkey: alice, kind: 1 }))).toEqual([2, 'restricted: pubkey not in the institutional allowlist']);
  });

  it('applies the policy-engine allowlist plus service identities', async () => {
    expect(await sync.syncOnce()).toEqual([alice, bob, indexer].sort());
    expect((await readFile(file, 'utf8')).trim().split('\n')).toEqual([alice, bob, indexer].sort());
    // Admission is by the NIP-42 session, so gift wraps signed by ephemeral keys still pass.
    expect(await admit(grpcPort, eventRequest({ authPubkey: alice, eventPubkey: getPublicKey(generateSecretKey()), kind: 1059 }))).toEqual([1, '']);
    expect(await admit(grpcPort, eventRequest({ eventPubkey: alice, kind: 1 }))).toEqual([2, 'auth-required: NIP-42 authentication required to publish']);
    expect((await admit(grpcPort, eventRequest({ authPubkey: getPublicKey(generateSecretKey()), eventPubkey: alice, kind: 1 })))[0]).toBe(2);
  });

  it('revoking a subject removes it on the next sync; a failed fetch keeps the last list', async () => {
    await engine.revokeSubject(admin, bob);
    await sync.syncOnce();
    expect((await readFile(file, 'utf8')).trim().split('\n')).toEqual([alice, indexer].sort());
    expect((await admit(grpcPort, eventRequest({ authPubkey: bob, eventPubkey: bob, kind: 1 })))[0]).toBe(2);
    failFetch = true;
    expect(await sync.syncOnce()).toEqual([alice, indexer].sort());
    expect(sync.lastError).toMatch(/down/);
    expect((await admit(grpcPort, eventRequest({ authPubkey: alice, eventPubkey: alice, kind: 1 })))[0]).toBe(1);
    failFetch = false;
  });

  it('encodes replies as protobuf EventReply', () => {
    expect([...encodeEventReply(true)]).toEqual([0x08, 1]);
    expect([...encodeEventReply(false, 'no')]).toEqual([0x08, 2, 0x12, 2, 0x6e, 0x6f]);
  });
});

describe('admission by h: publish grants per channel and group (FR023-10)', () => {
  const adminSk = generateSecretKey();
  const admin = getPublicKey(adminSk);
  const key = () => getPublicKey(generateSecretKey());
  const [ana, beto, worker, outsider] = [key(), key(), key(), key()];
  const channel = 'b3f2c3a0-5c1e-4c55-9d7a-2f6a1c9e0d11';
  const group = 'cd'.repeat(32);
  const engine = new PolicyEngine();
  const api = createPolicyApi(engine, { name: 'policy-grants-test', adminPubkeys: [admin], bearerTokens: { 'sync-token-5678': 'relay-allowlist' } });
  const admission = new AdmissionServer();
  let grpcPort: number;
  let failGrants = false;
  let sync: AllowlistSync;
  /** A kind 445 (Marmot group message, signed by an ephemeral key) sent by a session authenticated as `auth`. */
  const post = (auth: string, h: string[] = []) =>
    admit(grpcPort, eventRequest({ authPubkey: auth, eventPubkey: getPublicKey(generateSecretKey()), kind: 445, tags: [['p', ana], ...h.map((v) => ['h', v]), ['e', 'ab'.repeat(32)]] }));

  beforeAll(async () => {
    const client = new PolicyEngineClient(await api.listen(), bearer('sync-token-5678'));
    grpcPort = await admission.listen();
    sync = new AllowlistSync({
      fetch: () => client.relayAllowlist(),
      fetchGrants: () => (failGrants ? Promise.reject(new Error('grants down')) : client.relayGrants()),
      sinks: [],
      admission,
      extraPubkeys: [worker],
    });
    for (const p of [ana, beto]) {
      await engine.upsertSubject(admin, { pubkey: p, roles: ['staff'], attributes: {} });
      await engine.registerDevice(admin, p);
    }
    await engine.upsertResource(admin, { id: channel, kind: 'channel', sensitivity: 'internal', members: [ana], rules: [{ actions: ['read', 'publish'], anyRole: ['staff'] }] });
    await engine.upsertResource(admin, { id: group, kind: 'group', sensitivity: 'internal', members: [beto], rules: [{ actions: ['publish'], anyRole: ['staff'] }] });
  });
  afterAll(async () => {
    await api.close();
    await admission.close();
  });

  it('reads the h tags of the event the relay sends', () => {
    const req = decodeEventRequest(eventRequest({ authPubkey: ana, eventPubkey: beto, kind: 9, tags: [['h', channel], ['p', beto], ['h'], ['h', group, 'wss://relay.example']] }));
    expect(req).toEqual({ authPubkey: ana, eventPubkey: beto, kind: 9, h: [channel, group] });
  });

  it('refuses events with h until the grants are loaded (fail closed); the rest follow the allowlist', () => {
    const fresh = new AdmissionServer();
    fresh.set([ana]);
    expect(fresh.decide({ authPubkey: ana, h: [channel] })).toEqual({ permit: false, message: 'restricted: channel permissions not loaded yet, retry later' });
    expect(fresh.decide({ authPubkey: ana })).toEqual({ permit: true });
  });

  it('admits in a registered channel or group only who may publish there', async () => {
    await sync.syncOnce();
    expect(sync.grants).toBe(2);
    expect(await post(ana, [channel])).toEqual([1, '']);
    expect(await post(beto, [channel])).toEqual([2, `restricted: not allowed to publish in ${channel}`]);
    expect(await post(beto, [group])).toEqual([1, '']);
    expect(await post(ana, [group])).toEqual([2, `restricted: not allowed to publish in ${group}`]);
    // Every h of the event counts, and the id is matched whatever its case.
    expect((await post(ana, [channel, group]))[0]).toBe(2);
    expect(await post(beto, [channel.toUpperCase()])).toEqual([2, `restricted: not allowed to publish in ${channel.toUpperCase()}`]);
    // An h nobody registered is left to the allowlist; without h, only the allowlist counts.
    expect(await post(beto, ['ef'.repeat(32)])).toEqual([1, '']);
    expect(await post(beto)).toEqual([1, '']);
    // Service identities (the rotation worker commits in the groups it administers) skip the grants, not the allowlist.
    expect(await post(worker, [channel])).toEqual([1, '']);
    expect(await post(outsider, [channel])).toEqual([2, 'restricted: pubkey not in the institutional allowlist']);
  });

  it('follows the policy at the next sync; a failed grants fetch keeps the last ones', async () => {
    await engine.upsertResource(admin, { id: channel, kind: 'channel', sensitivity: 'internal', members: [ana, beto], rules: [{ actions: ['read', 'publish'], anyRole: ['staff'] }] });
    await sync.syncOnce();
    expect(await post(beto, [channel])).toEqual([1, '']);
    failGrants = true;
    await engine.upsertResource(admin, { id: channel, kind: 'channel', sensitivity: 'internal', members: [ana], rules: [{ actions: ['read', 'publish'], anyRole: ['staff'] }] });
    await sync.syncOnce();
    expect(sync.lastError).toMatch(/grants: grants down/);
    expect(await post(beto, [channel])).toEqual([1, '']);
    failGrants = false;
    await sync.syncOnce();
    expect(sync.lastError).toBeUndefined();
    expect((await post(beto, [channel]))[0]).toBe(2);
    // Revoking the person closes every channel to them, through the allowlist.
    await engine.revokeSubject(admin, ana);
    await sync.syncOnce();
    expect(await post(ana, [channel])).toEqual([2, 'restricted: pubkey not in the institutional allowlist']);
  });
});

const PG = process.env.TEST_DATABASE_URL;
describe.skipIf(!PG)('Buzz pubkey_allowlist sink (postgres)', () => {
  let pool: Pool;
  const [c1, c2, archived] = ['11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333'];
  const alice = getPublicKey(generateSecretKey());
  const bob = getPublicKey(generateSecretKey());
  const manual = getPublicKey(generateSecretKey());
  const rows = async (community: string) =>
    (await pool.query("SELECT encode(pubkey, 'hex') AS p, note FROM pubkey_allowlist WHERE community_id = $1 ORDER BY 1", [community])).rows.map((r) => `${r.p}:${r.note ?? ''}`);

  beforeAll(async () => {
    // The subset of the Buzz schema (infra/buzz/PIN migrations) the sink touches. No other suite uses these names.
    pool = createPgPool(PG!);
    await pool.query('DROP TABLE IF EXISTS pubkey_allowlist, communities');
    await pool.query(`CREATE TABLE communities (id uuid PRIMARY KEY, host varchar(255) NOT NULL, archived_at timestamptz, deletion_state text NOT NULL DEFAULT 'active')`);
    await pool.query(`CREATE TABLE pubkey_allowlist (community_id uuid NOT NULL REFERENCES communities(id), pubkey bytea NOT NULL, added_by bytea, added_at timestamptz NOT NULL DEFAULT now(), note text, PRIMARY KEY (community_id, pubkey))`);
    await pool.query(`INSERT INTO communities (id, host, archived_at) VALUES ($1, 'relay.example', NULL), ($2, 'other.example', NULL), ($3, 'old.example', now())`, [c1, c2, archived]);
    await pool.query("INSERT INTO pubkey_allowlist (community_id, pubkey, note) VALUES ($1, decode($2, 'hex'), 'manual')", [c1, manual]);
  });
  afterAll(async () => {
    await pool.query('DROP TABLE IF EXISTS pubkey_allowlist, communities');
    await pool.end();
  });

  it('reconciles only its own rows, in the selected active communities', async () => {
    const sink = new BuzzAllowlistSink(pool, ['relay.example', 'old.example']);
    expect(await sink.apply([alice, bob])).toEqual({ added: 2, removed: 0 });
    expect(await rows(c1)).toEqual([`${alice}:${BUZZ_ALLOWLIST_NOTE}`, `${bob}:${BUZZ_ALLOWLIST_NOTE}`, `${manual}:manual`].sort());
    expect(await rows(c2)).toEqual([]);
    expect(await rows(archived)).toEqual([]);
    expect(await sink.apply([alice, bob])).toEqual({ added: 0, removed: 0 });
    expect(await sink.apply([alice])).toEqual({ added: 0, removed: 1 });
    expect(await rows(c1)).toEqual([`${alice}:${BUZZ_ALLOWLIST_NOTE}`, `${manual}:manual`].sort());
    // Every active community when no host is given.
    expect(await new BuzzAllowlistSink(pool).apply([alice])).toEqual({ added: 1, removed: 0 });
    expect(await rows(c2)).toEqual([`${alice}:${BUZZ_ALLOWLIST_NOTE}`]);
  });
});
