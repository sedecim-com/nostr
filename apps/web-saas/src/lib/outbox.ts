import { bytesToHex, randomBytes } from '@sedecim/nostr-core';
import type { OutboxRecord } from '@sedecim/delivery-engine';

/** FR010-04: says when a send counts as replicated with fewer acceptances than the quorum of the profile. */
export function cappedQuorumNotice(r: Pick<OutboxRecord, 'quorum' | 'requestedQuorum' | 'relays'>): string | undefined {
  if (!r.requestedQuorum) return undefined;
  return `Solo hay ${r.relays.length} relay(s) para este envío: cuenta como replicado con ${r.quorum} aceptación(es), no con las ${r.requestedQuorum} del quorum de tu perfil.`;
}

/**
 * FR011-05 (scope §11.2): the operation id of what the user is sending. The same id comes back while they retry the
 * same send (same `key`: recipient or channel, text, file), so the retry reuses what was stored and queued instead of
 * making another event or rumor. A change to what is sent, or a send that went through, starts a new one.
 */
export class SendOperation {
  private key?: string;
  private id = '';

  /** The id for sending `key` now. */
  for(key: string): string {
    if (key !== this.key) {
      this.key = key;
      this.id = bytesToHex(randomBytes(16));
    }
    return this.id;
  }

  /** The send went through: the next one, even with the same text, is a new message. */
  done(): void {
    this.key = undefined;
  }
}

/** What identifies a file for SendOperation: the same file picked again is the same send. */
export function fileKey(f: { name: string; size: number; lastModified: number } | undefined): string {
  return f ? `${f.name}|${f.size}|${f.lastModified}` : '';
}
