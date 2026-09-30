import type { EncryptedStore } from '@sedecim/encrypted-store/browser';
import { findReuse, UsageLedger, type PersonaUse, type ReuseWarning } from '@sedecim/identity/usage';
import type { PersonaBook, PersonaRecord } from './vault';

/**
 * FR006-07 (spec §14.1): the usage ledger of each persona of this browser, in the vault next to its outbox
 * (`usage-<persona id>`): keyed tags only, never the npub or the file hash (packages/identity/src/usage.ts). One
 * instance per persona and vault, so its key is made once.
 */
const ledgers = new WeakMap<EncryptedStore, Map<string, UsageLedger>>();

function ledgerOf(book: PersonaBook, personaId: string): UsageLedger {
  let byPersona = ledgers.get(book.store);
  if (!byPersona) ledgers.set(book.store, (byPersona = new Map()));
  let ledger = byPersona.get(personaId);
  if (!ledger) byPersona.set(personaId, (ledger = new UsageLedger(book.store.collection<string>(`usage-${personaId}`))));
  return ledger;
}

/**
 * What using these contacts or this file from `persona` would cross with the other personas of this browser. A web
 * persona is never high-risk (a browser cannot be Tor-only), so only contacts and files are warned about here; inviting
 * another of your own personas into a group is refused by the groups view.
 */
export async function reuseWarnings(book: PersonaBook, persona: PersonaRecord, uses: PersonaUse[]): Promise<ReuseWarning[]> {
  const others = (await book.list()).filter((p) => p.id !== persona.id);
  const out: ReuseWarning[] = [];
  for (const use of uses) out.push(...(await findReuse(persona, others, async (id) => ledgerOf(book, id), use)));
  return out;
}

/** Notes the uses in the persona's ledger, right before the first request that makes them. */
export async function recordUse(book: PersonaBook, persona: PersonaRecord, uses: PersonaUse[]): Promise<void> {
  for (const use of uses) await ledgerOf(book, persona.id).record(use);
}
