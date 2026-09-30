/**
 * FR011-05 (scope §11.1, §11.2): a DM as a client operation. The UI gives each send an id and keeps it while the
 * user retries that same send. The rumor is stored under the id before any seal or wrap exists, and each target's
 * wrap is queued in the outbox under an id derived from it (wrapOpId). A retry with the same id takes the stored
 * rumor and skips the targets already queued, so it makes no other rumor and no other event.
 */
import type { Rumor } from '@sedecim/nostr-core';

export interface DmOperation {
  opId: string;
  rumor: Rumor;
  /** Who gets a wrap: the recipients, then the sender (the copy for their other devices). */
  targets: string[];
  createdAt: number;
  /** When every target's wrap was in the outbox. */
  queuedAt?: number;
}

/** Where the operations are kept: the persona's encrypted local store (a Collection of @sedecim/encrypted-store). */
export interface DmOperationStore {
  get(opId: string): Promise<DmOperation | undefined>;
  put(opId: string, op: DmOperation): Promise<void>;
}

/** Outbox id of one target's wrap: the same on every retry of the operation. */
export function wrapOpId(opId: string, target: string): string {
  return `${opId}:${target}`;
}

/** A retry under an id that already holds another message: sending it would not be a retry. */
export class OperationMismatchError extends Error {
  constructor(readonly opId: string) {
    super(`la operación ${opId} ya guarda otro mensaje: un reintento debe repetir el mismo destinatario y el mismo texto`);
  }
}
