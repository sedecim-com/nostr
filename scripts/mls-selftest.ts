/**
 * FR020-05: runs once the MLS removal-secrecy self-test (FR025-02, `assertRemovalSecrecy`) that every session runs
 * before opening groups.
 *
 *   tsx scripts/mls-selftest.ts
 *
 * Exit 0: the self-test passes. Exit 3: it failed closed (`UnsafeMlsImplementationError`). Exit 1: any other error.
 * scripts/mls-negative-control.sh runs it with ts-mls 2.0.0-rc.10 swapped in (must exit 3) and restored (must exit 0).
 */
import { assertRemovalSecrecy, UnsafeMlsImplementationError } from '@sedecim/marmot-adapter';

try {
  await assertRemovalSecrecy();
  console.log('mls self-test: ok (a removed member cannot read the next epoch)');
  process.exit(0);
} catch (err) {
  if (err instanceof UnsafeMlsImplementationError) {
    console.log(`mls self-test: fail closed: ${err.message}`);
    process.exit(3);
  }
  console.error(err);
  process.exit(1);
}
