import type { OutboxRecord } from '@sedecim/delivery-engine';

/** FR010-04: says when a send counts as replicated with fewer acceptances than the quorum of the profile. */
export function cappedQuorumNotice(r: Pick<OutboxRecord, 'quorum' | 'requestedQuorum' | 'relays'>): string | undefined {
  if (!r.requestedQuorum) return undefined;
  return `Solo hay ${r.relays.length} relay(s) para este envío: cuenta como replicado con ${r.quorum} aceptación(es), no con las ${r.requestedQuorum} del quorum de tu perfil.`;
}
