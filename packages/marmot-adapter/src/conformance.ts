import type { Signer } from '@sedecim/nostr-core';
import { assertHighSecurity } from './unavailable';
import type { GroupCryptoProvider, GroupNetwork, GroupStorage } from './types';

export interface ConformanceContext {
  provider: GroupCryptoProvider;
  makeMember: (name: string) => { signer: Signer; storage: GroupStorage; network: GroupNetwork };
  relays: string[];
}

/**
 * Behavioural conformance every provider must pass before the high-security flag is enabled (FR-025).
 * Returns the failed checks (empty = pass).
 */
export async function runConformance({ provider, makeMember, relays }: ConformanceContext): Promise<string[]> {
  const failures: string[] = [];
  try {
    assertHighSecurity(provider);
  } catch (e) {
    return [(e as Error).message];
  }
  const open = async (name: string) => {
    const m = makeMember(name);
    return provider.openSession({ ...m, deviceId: `${name}-device` });
  };
  const [a, b, c] = [await open('a'), await open('b'), await open('c')];
  const kpB = await b.publishKeyPackage(relays);
  const kpC = await c.publishKeyPackage(relays);
  const g0 = await a.createGroup({ name: 'conformance', relays });
  const g1 = await a.invite(g0.groupId, kpB);
  if (!g1.members.includes(b.pubkey)) failures.push('invited member missing from roster');
  if (g1.epoch <= g0.epoch) failures.push('adding a member must advance the epoch');
  const joinedB = await b.acceptInvites();
  if (!joinedB.some((g) => g.groupId === g0.groupId)) failures.push('member could not join from Welcome');
  await a.send(g0.groupId, 'hello');
  if (!(await b.sync(g0.groupId)).some((m) => m.content === 'hello' && m.sender === a.pubkey)) failures.push('member cannot decrypt group message');
  await a.invite(g0.groupId, kpC);
  await c.acceptInvites();
  await b.sync(g0.groupId);
  const removed = await a.removeMember(g0.groupId, b.pubkey);
  if (removed.members.includes(b.pubkey)) failures.push('removed member still in roster');
  await a.send(g0.groupId, 'after removal');
  const leak = await b.sync(g0.groupId).catch(() => []);
  if (leak.some((m) => m.content === 'after removal')) failures.push('removed member can still decrypt (no post-removal secrecy)');
  if (!(await c.sync(g0.groupId)).some((m) => m.content === 'after removal')) failures.push('remaining member cannot decrypt after removal');
  const before = (await c.group(g0.groupId)).epoch;
  const rotated = await c.rotate(g0.groupId);
  if (rotated.epoch <= before) failures.push('self-update must advance the epoch (PCS)');
  await a.sync(g0.groupId);
  await c.send(g0.groupId, 'post rotation');
  if (!(await a.sync(g0.groupId)).some((m) => m.content === 'post rotation')) failures.push('group unusable after self-update');
  [a, b, c].forEach((s) => s.close());
  return failures;
}
