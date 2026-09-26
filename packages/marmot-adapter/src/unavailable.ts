import { GroupCryptoUnavailableError, type GroupCryptoProperties, type GroupCryptoProvider, type GroupSession } from './types';

/** Refuses every operation so nothing is ever sent with weaker crypto by mistake. */
export class UnavailableGroupCryptoProvider implements GroupCryptoProvider {
  readonly properties: GroupCryptoProperties = { forwardSecrecy: false, postCompromiseSecurity: false, multiDevice: false, implementation: 'none', version: '0' };
  async openSession(): Promise<GroupSession> {
    throw new GroupCryptoUnavailableError();
  }
}

/** Guards high-risk conversations: the provider must declare FS and PCS. */
export function assertHighSecurity(provider: GroupCryptoProvider): void {
  const p = provider.properties;
  if (!p.forwardSecrecy || !p.postCompromiseSecurity) {
    throw new Error(`group provider "${p.implementation}" lacks forward secrecy / post-compromise security required for high-security groups`);
  }
}
