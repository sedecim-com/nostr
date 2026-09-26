import type { WrapOptions } from './nip59';

export interface RelayAdapter {
  name: string;
  /** Gift-wrap options the relay accepts. */
  wrap: WrapOptions;
  /** Where client-encrypted attachments must be uploaded. */
  encryptedAttachments: 'relay-media' | 'blob-store';
  evidence: string;
}

/**
 * Explicit adapter for the pinned Buzz build (infra/buzz/PIN), derived from the interop gate
 * (docs/interop/buzz-02c6309-report.json): Buzz rejects NIP-59 timestamps randomised up to 2 days
 * ("invalid: event timestamp too far from server time") but accepts a bounded ±5 min window; its /media
 * endpoint only accepts sniffed images/video, so encrypted blobs go to a content-agnostic Blossom server.
 * Trade-off (disclosed in the panel): a smaller window gives relays a tighter timing estimate.
 */
export const BUZZ_PINNED_ADAPTER: RelayAdapter = {
  name: 'buzz@02c6309',
  wrap: { timestampJitterSeconds: 300 },
  encryptedAttachments: 'blob-store',
  evidence: 'docs/interop/buzz-02c6309-report.json',
};

/** Generic NIP-59 relays: full two-day randomisation. */
export const STANDARD_ADAPTER: RelayAdapter = {
  name: 'nip59-standard',
  wrap: {},
  encryptedAttachments: 'relay-media',
  evidence: 'NIP-59',
};
