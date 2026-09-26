import type { NostrEvent, Signer } from '@sedecim/nostr-core';
import { createDirectMessage, openDirectMessage, type DirectMessageInput, type WrappedMessage, type DirectMessage } from './nip17';
import type { WrapOptions } from './nip59';

export interface MessagingFlags {
  /** NIP-17 DMs: disabled until the E2E interop suite passes against the pinned relay (FR-017). */
  nip17: boolean;
  /** Read receipts are opt-in. */
  readReceipts: boolean;
}

export const DEFAULT_FLAGS: MessagingFlags = { nip17: false, readReceipts: false };

export class FeatureDisabledError extends Error {
  constructor(readonly feature: string) {
    super(`feature disabled: ${feature}`);
  }
}

/** Thin façade that enforces feature flags around NIP-17 building/opening. */
export class DirectMessenger {
  constructor(private readonly signer: Signer, private readonly flags: MessagingFlags = DEFAULT_FLAGS, private readonly wrapOptions: WrapOptions = {}) {}

  compose(input: DirectMessageInput): Promise<WrappedMessage> {
    if (!this.flags.nip17) throw new FeatureDisabledError('nip17');
    return createDirectMessage(this.signer, input, this.wrapOptions);
  }

  open(wrap: NostrEvent): Promise<DirectMessage> {
    if (!this.flags.nip17) throw new FeatureDisabledError('nip17');
    return openDirectMessage(this.signer, wrap);
  }
}
