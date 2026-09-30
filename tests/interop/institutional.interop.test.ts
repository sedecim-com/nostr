/**
 * FR023-13: the institutional mode of the compose stack, end to end. The secure relay runs with
 * infra/secure-relay/config.institutional.toml (NIP-42 plus nauthz event admission by the relay-allowlist service), and
 * relay-allowlist follows the real policy-engine (FR023-04):
 * - a person the organisation registered, with an active device, can publish;
 * - a key the organisation does not know cannot, even authenticated;
 * - revoking the person closes the relay to them at the next sync.
 * FR023-10, «publicar» per resource:
 * - in a group the organisation registered, the secure relay admits only who may publish there (admission by `h`);
 * - in a private Buzz channel it registered, the NIP-29 members are who may publish there (relay-allowlist keeps them),
 *   so Buzz refuses everybody else.
 *
 * Needs the running stack with the institutional profile and that relay config (CI `stack` job):
 *   INSTITUTIONAL_RELAY_URL=ws://localhost:7000 STACK_POLICY_URL=http://localhost:8083 BUZZ_RELAY_URL=ws://localhost:3000 \
 *     POLICY_ADMIN_SECRET_KEY=<hex, one of POLICY_ADMIN_PUBKEYS> BUZZ_MEMBERSHIP_NSEC=<the relay-allowlist's> \
 *     npx vitest run tests/interop/institutional.interop.test.ts
 */
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { bytesToHex, generateSecretKey, getPublicKey, hexToBytes, nip19, type EventTemplate } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { nip98Fetch } from '@sedecim/service-kit';

const RELAY = process.env.INSTITUTIONAL_RELAY_URL;
const POLICY = process.env.STACK_POLICY_URL;
const ADMIN = process.env.POLICY_ADMIN_SECRET_KEY;
const BUZZ = process.env.BUZZ_RELAY_URL;
const MEMBERSHIP = process.env.BUZZ_MEMBERSHIP_NSEC;
const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;

/** Publishes `template` as `sk` to `relay`, authenticating with NIP-42 when the relay asks. */
async function publishTo(sk: Uint8Array, template: EventTemplate, relay: string) {
  const signer = new LocalSigner(sk);
  const pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'auto', authTimeoutMs: 3000 });
  try {
    return await pool.publishTo(await signer.signEvent(template), relay);
  } finally {
    pool.close();
  }
}

const publish = (sk: Uint8Array, content: string) => publishTo(sk, { kind: 1, content, tags: [] }, RELAY!);

/** The relay-allowlist syncs every ALLOWLIST_SYNC_INTERVAL_MS (2 s in CI): retries until `done` holds. */
async function until<T>(attempt: () => Promise<T>, done: (r: T) => boolean, ms = 45_000): Promise<T> {
  const end = Date.now() + ms;
  let last = await attempt();
  while (!done(last) && Date.now() < end) {
    await new Promise((r) => setTimeout(r, 1000));
    last = await attempt();
  }
  return last;
}

const publishUntil = (sk: Uint8Array, ok: boolean, ms = 45_000) => until(() => publish(sk, `institucional ${Date.now()}`), (r) => r.ok === ok, ms);

/** A person of the organisation: a subject with the `staff` role and an active device. */
async function person(admin: Uint8Array) {
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);
  expect((await nip98Fetch(admin, `${POLICY}/v1/subjects/${pk}`, 'PUT', { roles: ['staff'], attributes: {} })).status).toBe(200);
  expect((await nip98Fetch(admin, `${POLICY}/v1/devices`, 'POST', { owner: pk })).status).toBe(201);
  return { sk, pk };
}

describe.skipIf(!RELAY || !POLICY || !ADMIN)('institutional mode on the compose stack (FR023-13, FR023-04)', () => {
  const admin = hexToBytes(ADMIN ?? '00'.repeat(32));
  const member = generateSecretKey();
  const memberPk = getPublicKey(member);
  const outsider = generateSecretKey();

  it('the relay admits the people of the organisation with an active device, and nobody else', async () => {
    const subject = await nip98Fetch(admin, `${POLICY}/v1/subjects/${memberPk}`, 'PUT', { roles: ['staff'], attributes: {} });
    expect(subject.status, JSON.stringify(subject.json)).toBe(200);
    const device = await nip98Fetch(admin, `${POLICY}/v1/devices`, 'POST', { owner: memberPk });
    expect(device.status, JSON.stringify(device.json)).toBe(201);

    const admitted = await publishUntil(member, true);
    expect(admitted.ok, admitted.message).toBe(true);
    const refused = await publish(outsider, 'fuera de la organización');
    expect(refused.ok).toBe(false);
    expect(refused.message).toMatch(/restricted: pubkey not in the institutional allowlist/);
  }, 90_000);

  it('revoking the person closes the relay to them at the next sync', async () => {
    const revoked = await nip98Fetch(admin, `${POLICY}/v1/subjects/${memberPk}/revoke`, 'POST', {});
    expect(revoked.status, JSON.stringify(revoked.json)).toBe(200);
    const closed = await publishUntil(member, false);
    expect(closed.ok).toBe(false);
    expect(closed.message).toMatch(/restricted: pubkey not in the institutional allowlist/);
  }, 90_000);

  it('in a group the organisation registered, only who may publish there gets in (FR023-10, admission by h)', async () => {
    const [ana, beto] = [await person(admin), await person(admin)];
    // A Marmot group, registered by the id its kind 445 messages carry in `h` (its nostr_group_id).
    const group = bytesToHex(generateSecretKey());
    const put = await nip98Fetch(admin, `${POLICY}/v1/resources/${group}`, 'PUT', { kind: 'group', sensitivity: 'internal', members: [ana.pk], rules: [{ actions: ['read', 'publish'], anyRole: ['staff'] }] });
    expect(put.status, JSON.stringify(put.json)).toBe(200);
    const message = (h: string) => ({ kind: 445, content: 'cifrado', tags: [['h', h]] });

    const admitted = await until(() => publishTo(ana.sk, message(group), RELAY!), (r) => r.ok);
    expect(admitted.ok, admitted.message).toBe(true);
    const refused = await until(() => publishTo(beto.sk, message(group), RELAY!), (r) => /not allowed to publish/.test(r.message));
    expect(refused.ok).toBe(false);
    expect(refused.message).toContain(`restricted: not allowed to publish in ${group}`);
    // A group nobody registered is left to the allowlist.
    expect((await publishTo(beto.sk, message(bytesToHex(generateSecretKey())), RELAY!)).ok).toBe(true);
  }, 90_000);
});

describe.skipIf(!BUZZ || !POLICY || !ADMIN || !MEMBERSHIP)('NIP-29 membership follows the policy-engine on Buzz (FR023-10)', () => {
  const admin = hexToBytes(ADMIN ?? '00'.repeat(32));
  const membershipKey = MEMBERSHIP?.startsWith('nsec1') ? (nip19.decode(MEMBERSHIP).data as Uint8Array) : hexToBytes(MEMBERSHIP ?? '00'.repeat(32));

  it('the members of a registered private channel are who may publish there, and Buzz refuses the rest', async () => {
    const owner = generateSecretKey();
    const [ana, beto] = [await person(admin), await person(admin)];
    const channel = randomUUID();
    const post = (sk: Uint8Array, text: string) => publishTo(sk, { kind: 9, content: text, tags: [['h', channel]] }, BUZZ!);
    // Whoever creates the channel makes it private and the sync identity one of its admins.
    const created = await publishTo(owner, { kind: 9007, content: '', tags: [['h', channel], ['name', `fr023-10-${Date.now()}`], ['visibility', 'private']] }, BUZZ!);
    expect(created.ok, created.message).toBe(true);
    const admin9000 = await publishTo(owner, { kind: 9000, content: '', tags: [['h', channel], ['p', getPublicKey(membershipKey)], ['role', 'admin']] }, BUZZ!);
    expect(admin9000.ok, admin9000.message).toBe(true);
    expect((await post(ana.sk, 'antes de registrar')).message).toMatch(/restricted: not a channel member/);

    // The organisation registers the channel: ana may publish there, beto may not.
    const rules = [{ actions: ['read', 'publish'], anyRole: ['staff'] }];
    expect((await nip98Fetch(admin, `${POLICY}/v1/resources/${channel}`, 'PUT', { kind: 'channel', sensitivity: 'internal', members: [ana.pk], rules })).status).toBe(200);
    const admitted = await until(() => post(ana.sk, 'hola'), (r) => r.ok, 60_000);
    expect(admitted.ok, admitted.message).toBe(true);
    const refused = await post(beto.sk, 'fuera');
    expect(refused.ok).toBe(false);
    expect(refused.message).toMatch(/restricted: not a channel member/);

    // The policy changes: beto in, ana out.
    expect((await nip98Fetch(admin, `${POLICY}/v1/resources/${channel}`, 'PUT', { kind: 'channel', sensitivity: 'internal', members: [beto.pk], rules })).status).toBe(200);
    const betoIn = await until(() => post(beto.sk, 'dentro'), (r) => r.ok, 60_000);
    expect(betoIn.ok, betoIn.message).toBe(true);
    const anaOut = await until(() => post(ana.sk, 'ya no'), (r) => !r.ok, 60_000);
    expect(anaOut.message).toMatch(/restricted: not a channel member/);
  }, 240_000);
});
