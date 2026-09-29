/**
 * FR023-13: the institutional mode of the compose stack, end to end. The secure relay runs with
 * infra/secure-relay/config.institutional.toml (NIP-42 plus nauthz event admission by the relay-allowlist service), and
 * relay-allowlist follows the real policy-engine (FR023-04):
 * - a person the organisation registered, with an active device, can publish;
 * - a key the organisation does not know cannot, even authenticated;
 * - revoking the person closes the relay to them at the next sync.
 *
 * Needs the running stack with the institutional profile and that relay config (CI `stack` job):
 *   INSTITUTIONAL_RELAY_URL=ws://localhost:7000 STACK_POLICY_URL=http://localhost:8083 \
 *     POLICY_ADMIN_SECRET_KEY=<hex, one of POLICY_ADMIN_PUBKEYS> npx vitest run tests/interop/institutional.interop.test.ts
 */
import { describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateSecretKey, getPublicKey, hexToBytes } from '@sedecim/nostr-core';
import { LocalSigner } from '@sedecim/signer';
import { RelayPool, type WebSocketLike } from '@sedecim/relay-pool';
import { nip98Fetch } from '@sedecim/service-kit';

const RELAY = process.env.INSTITUTIONAL_RELAY_URL;
const POLICY = process.env.STACK_POLICY_URL;
const ADMIN = process.env.POLICY_ADMIN_SECRET_KEY;
const factory = (u: string) => new WebSocket(u) as unknown as WebSocketLike;

/** Publishes a note as `sk`, authenticating with NIP-42 when the relay asks. */
async function publish(sk: Uint8Array, content: string) {
  const signer = new LocalSigner(sk);
  const pool = new RelayPool({ webSocketFactory: factory, signer, authMode: 'auto', authTimeoutMs: 3000 });
  try {
    return await pool.publishTo(await signer.signEvent({ kind: 1, content, tags: [] }), RELAY!);
  } finally {
    pool.close();
  }
}

/** The relay-allowlist syncs every ALLOWLIST_SYNC_INTERVAL_MS (2 s in CI): retries until `ok` is what is expected. */
async function publishUntil(sk: Uint8Array, ok: boolean, ms = 45_000) {
  const end = Date.now() + ms;
  let last: Awaited<ReturnType<typeof publish>> | undefined;
  while (Date.now() < end) {
    last = await publish(sk, `institucional ${Date.now()}`);
    if (last.ok === ok) return last;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return last!;
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
});
