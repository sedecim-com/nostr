import type { Signer } from '@sedecim/nostr-core';
import type { HttpClient, PreparedBlob } from './client';
import { uploadToServers } from './server-list';

/**
 * Uploads ciphertext that others fetch by its hash, e.g. a MIP-04 group file (encrypted before it gets here, so it goes
 * as `application/octet-stream`): to the first server that takes it and, with `mirror`, to the rest as well (best
 * effort). Resolves to the locator to share: the server's descriptor URL, or `server/<sha256>` when it names none.
 * The sovereign client and the web upload group files through this one function.
 */
export function ciphertextUploader(servers: readonly string[], signer: Signer, opts: { http?: HttpClient; mirror?: boolean } = {}): (ciphertext: Uint8Array, sha256: string) => Promise<{ url: string }> {
  return async (ciphertext, sha256) => {
    const blob: PreparedBlob = { data: ciphertext, sha256, originalSha256: sha256, mimeType: 'application/octet-stream', removedMetadata: [] };
    const up = await uploadToServers(blob, servers, signer, opts);
    return { url: up.descriptor.url || `${up.server}/${sha256}` };
  };
}
