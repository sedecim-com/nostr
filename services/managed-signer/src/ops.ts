/**
 * FR026-04: operator commands of the managed signer. Run them where the service runs, with its configuration (same
 * vault, database and retention), e.g. inside its container:
 *
 *   node_modules/.bin/tsx services/managed-signer/src/ops.ts close-owner '<issuer>#<sub>' <ticket>
 *     ARCO cancellation received through the privacy contact, or a closed Acceso account: every live managed key of
 *     that owner leaves managed custody now and its material is destroyed after the retention window. <ticket> names
 *     the request in the usage log (the principal is `operator:<ticket>`).
 *   node_modules/.bin/tsx services/managed-signer/src/ops.ts retention
 *     Runs the retention job once (the service also runs it every hour).
 *
 * Output is JSON on stdout. The procedure is docs/runbooks/managed-custody-exit.md.
 */
import { ManagedSigner } from './service';
import { openStorage } from './storage';

const OWNER = /^\S{1,256}#\S{1,256}$/;
const TICKET = /^[A-Za-z0-9._:-]{1,64}$/;
const usage = "usage: ops.ts close-owner '<issuer>#<sub>' <ticket> | ops.ts retention";

/** The signer core over the service's own storage (never a fresh in-memory registry). */
async function openCore(): Promise<ManagedSigner> {
  const { vault, registry, devices, retentionDays, usageRetentionMonths, persistent } = await openStorage(process.env);
  if (!persistent) throw new Error('DATABASE_URL is not set: the operator commands act on the service registry, not on a fresh in-memory one');
  return new ManagedSigner(vault, { registry, devices, retentionDays, usageRetentionMonths });
}

async function run(argv: string[]): Promise<unknown> {
  const [command, ...args] = argv;
  if (command === 'close-owner') {
    const [owner, ticket] = args;
    if (!owner || !OWNER.test(owner)) throw new Error(`the owner is the Acceso user as the signer records it: '<issuer>#<sub>'\n${usage}`);
    if (!ticket || !TICKET.test(ticket)) throw new Error(`name the request (ticket) that asked for it: letters, digits and . _ : -\n${usage}`);
    const core = await openCore();
    const closed = await core.closeOwner(owner, `operator:${ticket}`);
    return { owner, closed: closed.map((c) => ({ key_id: c.keyId, destroy_after: new Date(c.destroyAfter).toISOString() })) };
  }
  if (command === 'retention') {
    return (await openCore()).runRetention();
  }
  throw new Error(usage);
}

run(process.argv.slice(2)).then(
  (out) => {
    process.stdout.write(`${JSON.stringify(out)}\n`);
    process.exit(0);
  },
  (err) => {
    process.stderr.write(`${(err as Error).message}\n`);
    process.exit(2);
  },
);
