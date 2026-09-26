/**
 * NFR002-02: kill -9 in the middle of a write leaves the file-backed store consistent.
 * A child process (crash-writer.ts) writes without pause; it is SIGKILLed at a random moment, 30 times.
 * After each kill the store must open and decrypt, and every key must hold a complete value: the last
 * one the writer acknowledged, or the one it was writing when it died (never a torn or missing one).
 */
import { describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtemp, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EncryptedStore, FileBackend } from '../src/index';
import { CRASH_KEYS, crashValue, type CrashValue } from './crash-values';

const ITERATIONS = 30;
const PASSPHRASE = 'crash-test-passphrase';
// One process (node --import tsx), not the tsx CLI: the CLI forks node, and SIGKILL would only hit the wrapper.
const root = new URL('../../..', import.meta.url).pathname;
const writer = new URL('./crash-writer.ts', import.meta.url).pathname;

interface RunResult {
  acked: Map<string, number>;
  tempFilesAtKill: number;
}

/** Starts the writer, lets it write for a random time after "ready" and SIGKILLs it. */
function runAndKill(dir: string): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--import', 'tsx', writer, dir, PASSPHRASE], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
    const acked = new Map<string, number>();
    let buf = '';
    let stderr = '';
    let killed = false;
    let tempFilesAtKill = 0;
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString()));
    child.stdout.on('data', (d: Buffer) => {
      buf += d.toString();
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line === 'ready' && !killed) {
          // 0-120 ms of writing: several puts, and the kill usually lands inside one.
          setTimeout(async () => {
            killed = true;
            child.kill('SIGKILL');
            tempFilesAtKill = (await readdir(dir)).filter((f) => f.endsWith('.tmp')).length;
          }, Math.floor(Math.random() * 120));
        }
        const m = /^ack (\S+) (\d+)$/.exec(line);
        if (m) acked.set(m[1]!, Number(m[2]));
      }
    });
    child.on('error', reject);
    // 'close', not 'exit': every ack line written before the kill has been read.
    child.on('close', (code, signal) => {
      if (signal === 'SIGKILL' && killed) resolve({ acked, tempFilesAtKill });
      else reject(new Error(`writer exited on its own (code ${code}, signal ${signal}): ${stderr}`));
    });
  });
}

describe('FileBackend survives kill -9 during writes (NFR002-02)', () => {
  it(`stays consistent across ${ITERATIONS} SIGKILLs`, async () => {
    const dir = await mkdtemp(join(tmpdir(), 'store-crash-'));
    await EncryptedStore.open(new FileBackend(dir), PASSPHRASE, { logN: 4 });
    const durable = new Map<string, number>();
    let midWriteKills = 0;
    let acks = 0;

    for (let i = 0; i < ITERATIONS; i++) {
      const { acked, tempFilesAtKill } = await runAndKill(dir);
      if (tempFilesAtKill > 0) midWriteKills++;
      for (const [k, gen] of acked) {
        acks++;
        durable.set(k, gen);
      }

      // Reopen as a fresh process would: the passphrase check reads meta, every value must decrypt.
      const store = await EncryptedStore.open(new FileBackend(dir), PASSPHRASE, { logN: 4 });
      const col = store.collection<CrashValue>('crash');
      for (const key of CRASH_KEYS) {
        const value = await col.get(key);
        const last = durable.get(key) ?? 0;
        if (value === undefined) {
          expect(last, `iteration ${i}: ${key} lost its acknowledged value`).toBe(0);
          continue;
        }
        // Old (last ack) or new (the put in flight at the kill), complete and byte-exact.
        expect([last, last + 1], `iteration ${i}: ${key}`).toContain(value.gen);
        expect(value).toEqual(crashValue(key, value.gen));
        durable.set(key, value.gen);
      }
      expect((await col.all()).length).toBeLessThanOrEqual(CRASH_KEYS.length);
    }

    // Opening the store removed the temp files the killed writers left behind.
    expect((await readdir(dir)).filter((f) => f.endsWith('.tmp'))).toEqual([]);
    expect(acks, 'the writer never acknowledged a put: the test did not exercise anything').toBeGreaterThan(0);
    console.info(`crash test: ${ITERATIONS} kills, ${midWriteKills} with a write in flight (temp file on disk), ${acks} acks`);
  }, 180_000);
});
