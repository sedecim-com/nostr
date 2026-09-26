/**
 * Child process for crash.test.ts (NFR002-02): writes to a file-backed EncryptedStore without pause until
 * it is killed with SIGKILL. Each value is derived from (key, generation) so the parent can tell a
 * complete old value, a complete new value and a torn one apart.
 *
 *   tsx crash-writer.ts <dir> <passphrase>
 * stdout: "ready" once the current state is read, then "ack <key> <gen>" after each put resolves.
 */
import { writeSync } from 'node:fs';
import { EncryptedStore, FileBackend } from '../src/index';
import { CRASH_KEYS, crashValue, type CrashValue } from './crash-values';

const [dir, passphrase] = process.argv.slice(2);
if (!dir || !passphrase) throw new Error('usage: crash-writer.ts <dir> <passphrase>');

// Synchronous writes: an "ack" line is in the pipe before the next put starts.
const say = (line: string) => writeSync(1, `${line}\n`);

const store = await EncryptedStore.open(new FileBackend(dir), passphrase, { logN: 4 });
const col = store.collection<CrashValue>('crash');
const gens = new Map<string, number>();
for (const key of CRASH_KEYS) gens.set(key, (await col.get(key))?.gen ?? 0);
say('ready');

for (let i = 0; ; i = (i + 1) % CRASH_KEYS.length) {
  const key = CRASH_KEYS[i]!;
  const gen = gens.get(key)! + 1;
  await col.put(key, crashValue(key, gen));
  gens.set(key, gen);
  say(`ack ${key} ${gen}`);
}
