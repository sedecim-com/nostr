/**
 * High-security groups (spec §10.3). Marmot = Nostr identity + MLS (RFC 9420). The product depends only
 * on this interface; a concrete provider (e.g. bindings to the pinned MDK version) is plugged in later.
 * NIP-EE is superseded by Marmot and must not be used.
 */
import type { NostrEvent, Signer } from '@sedecim/nostr-core';

/** Marmot event kinds (verify against the pinned MDK release before enabling). */
export const MARMOT_KINDS = { KeyPackage: 443, Welcome: 444, GroupMessage: 445, KeyPackageRelays: 10051 } as const;

export interface GroupCryptoProperties {
  forwardSecrecy: boolean;
  postCompromiseSecurity: boolean;
  multiDevice: boolean;
  implementation: string;
  version: string;
}

export interface GroupHandle {
  groupId: string;
  epoch: number;
  members: string[];
}

export interface GroupCryptoProvider {
  readonly properties: GroupCryptoProperties;
  /** Publishable key package for the local identity/device. */
  createKeyPackage(signer: Signer): Promise<NostrEvent>;
  createGroup(signer: Signer, opts: { name: string; memberKeyPackages: NostrEvent[]; relays: string[] }): Promise<{ group: GroupHandle; outbound: NostrEvent[] }>;
  addMembers(signer: Signer, groupId: string, keyPackages: NostrEvent[]): Promise<{ group: GroupHandle; outbound: NostrEvent[] }>;
  removeMembers(signer: Signer, groupId: string, pubkeys: string[]): Promise<{ group: GroupHandle; outbound: NostrEvent[] }>;
  /** Commit that rotates group secrets (e.g. after a device revocation — FR-024). */
  rotate(signer: Signer, groupId: string): Promise<{ group: GroupHandle; outbound: NostrEvent[] }>;
  encrypt(signer: Signer, groupId: string, plaintext: string): Promise<NostrEvent>;
  processIncoming(signer: Signer, evt: NostrEvent): Promise<{ groupId: string; plaintext?: string; sender?: string; group?: GroupHandle }>;
}

export class GroupCryptoUnavailableError extends Error {
  constructor() {
    super('No Marmot/MLS provider configured: high-security groups are unavailable (fail closed).');
  }
}

/** Default provider: refuses every operation so nothing is ever sent with weaker crypto by mistake. */
export class UnavailableGroupCryptoProvider implements GroupCryptoProvider {
  readonly properties: GroupCryptoProperties = { forwardSecrecy: false, postCompromiseSecurity: false, multiDevice: false, implementation: 'none', version: '0' };
  private fail(): never {
    throw new GroupCryptoUnavailableError();
  }
  async createKeyPackage(): Promise<NostrEvent> {
    return this.fail();
  }
  async createGroup(): Promise<never> {
    return this.fail();
  }
  async addMembers(): Promise<never> {
    return this.fail();
  }
  async removeMembers(): Promise<never> {
    return this.fail();
  }
  async rotate(): Promise<never> {
    return this.fail();
  }
  async encrypt(): Promise<NostrEvent> {
    return this.fail();
  }
  async processIncoming(): Promise<never> {
    return this.fail();
  }
}

/** Guards high-risk conversations: the provider must declare FS and PCS. */
export function assertHighSecurity(provider: GroupCryptoProvider): void {
  const p = provider.properties;
  if (!p.forwardSecrecy || !p.postCompromiseSecurity) {
    throw new Error(`group provider "${p.implementation}" lacks forward secrecy / post-compromise security required for high-security groups`);
  }
}

export interface ConformanceContext {
  provider: GroupCryptoProvider;
  makeSigner: () => Signer;
}

/**
 * Behavioural conformance checks every provider must pass before the feature flag is enabled
 * (FR-025). Returns a list of failed checks (empty = pass).
 */
export async function runConformance({ provider, makeSigner }: ConformanceContext): Promise<string[]> {
  const failures: string[] = [];
  try {
    assertHighSecurity(provider);
  } catch (e) {
    failures.push((e as Error).message);
    return failures;
  }
  const [a, b, c] = [makeSigner(), makeSigner(), makeSigner()];
  const kpB = await provider.createKeyPackage(b);
  const kpC = await provider.createKeyPackage(c);
  const { group } = await provider.createGroup(a, { name: 'conformance', memberKeyPackages: [kpB], relays: [] });
  const msg = await provider.encrypt(a, group.groupId, 'hello');
  const got = await provider.processIncoming(b, msg);
  if (got.plaintext !== 'hello') failures.push('member cannot decrypt group message');
  const added = await provider.addMembers(a, group.groupId, [kpC]);
  if (added.group.epoch <= group.epoch) failures.push('adding a member must advance the epoch');
  const removed = await provider.removeMembers(a, group.groupId, [await b.getPublicKey()]);
  const after = await provider.encrypt(a, removed.group.groupId, 'after removal');
  const leak = await provider.processIncoming(b, after).catch(() => ({ plaintext: undefined }));
  if (leak.plaintext) failures.push('removed member can still decrypt (no post-removal secrecy)');
  return failures;
}
