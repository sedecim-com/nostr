/**
 * NFR007-03: what a failure of the sovereign CLI leaves. stderr gets one line, never the stack, the cause or the fields
 * of the error, and no secret. A report exists only as the persona's profile allows: written to a file with
 * --crash-report (manual-export, opt-in), kept sealed in the persona's store (opt-in, which Tor-only refuses), and
 * never sent. Real CLI processes.
 */
import { describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseCrashReport, type CrashReport } from '@sedecim/telemetry-policy';
import { SovereignClient } from '../src/index';
import { fatalLine } from '../src/crash';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const PASS = 'crash-reports-test';
const BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const bech32Like = (hrp: string, n: number) => `${hrp}1${Array.from(randomBytes(n), (b) => BECH32[b % 32]).join('')}`;
const word = (n: number) => Array.from(randomBytes(n), (b) => 'abcdefghijklmnopqrstuvwxyz'[b % 26]).join('');

function cli(dataDir: string, ...args: string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--import', 'tsx', CLI, ...args], { env: { ...process.env, SOVEREIGN_DATA_DIR: dataDir, SOVEREIGN_PASSPHRASE: PASS, SOVEREIGN_FLAGS: '/nonexistent' } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

/** A device with one persona per network, made in process (a cheap scrypt cost, kept in the stores' parameters). */
async function device() {
  const dataDir = await mkdtemp(join(tmpdir(), 'sovereign-crash-'));
  const client = new SovereignClient({ dataDir, passphrase: PASS, scryptLogN: 4 });
  try {
    const direct = await client.createPersona({ label: 'Directa', relays: ['ws://127.0.0.1:9'] });
    const tor = await client.createPersona({ label: 'Tor', relays: ['ws://sovereignrelayabcdefghijklmnopqrstuvwxyz234567abcdefghijk.onion'], tor: true });
    return { dataDir, direct: direct.id, tor: tor.id };
  } finally {
    client.close();
  }
}

/** Entries of the persona's store that hold crash reports (one file each, sealed). */
const reportFiles = (dataDir: string, persona: string) => readdirSync(join(dataDir, 'personas', persona)).filter((f) => f.startsWith('crash-reports__'));

describe('sovereign CLI: failures and crash reports (NFR007-03)', () => {
  it('NFR007-03: a fatal failure prints one line on stderr, without stack and without secrets, and leaves no report', async () => {
    const { dataDir } = await device();
    const user = `u${word(9)}`;
    const secrets = { nsec: bech32Like('nsec', 58), ncryptsec: bech32Like('ncryptsec', 152), pubkey: randomBytes(32).toString('hex'), userinfo: `pw${word(12)}`, token: `${randomBytes(12).toString('hex')}Ab`, ip: '203.0.113.47', user };
    const host = `relay-${word(6)}.example.org`;
    const onion = `${word(16).replace(/[01]/g, 'a')}${'abcdefghijklmnopqrstuvwxyz234567abcdefghijk'.slice(0, 40)}.onion`;
    const persona = `${secrets.nsec} ${secrets.ncryptsec} ${secrets.pubkey} wss://admin:${secrets.userinfo}@${host}/x?token=${secrets.token} ${secrets.ip} /home/${user}/fuentes.txt ${onion}`;
    const r = await cli(dataDir, 'whoami', '--persona', persona, '--crash-report', join(dataDir, 'never.json'));
    expect(r.status).toBe(1);
    const lines = r.stderr.trimEnd().split('\n');
    expect(lines[0]).toMatch(/^error: unknown persona \[REDACTED:nsec\] \[REDACTED:ncryptsec\] \[hex\] wss:\/\/relay-[a-z]+\.example\.org\/x\?\[…\] ip-[0-9a-f]{8} \/home\/<usuario>\/fuentes\.txt [a-z2-7]+\.onion$/);
    for (const [kind, value] of Object.entries(secrets)) expect(r.stderr, kind).not.toContain(value);
    // The terminal keeps what says which relay failed, as the rest of the CLI's output does.
    expect(lines[0]).toContain(host);
    expect(lines[0]).toContain(onion);
    expect(r.stderr).not.toMatch(/^\s+at /m);
    expect(r.stderr).not.toMatch(/\[cause\]|errno|syscall/);
    // No persona to read a profile from: no report, and it says so.
    expect(lines.slice(1)).toEqual([expect.stringMatching(/^aviso: sin una persona que los permita no hay informe de fallo: no se ha escrito /)]);
    expect(existsSync(join(dataDir, 'never.json'))).toBe(false);
  }, 60_000);

  it('NFR007-03: the fatal line never carries the stack, the cause or the fields of the error', () => {
    const user = `u${word(9)}`;
    const err = new Error(`cannot open /home/${user}/x`, { cause: new Error(`token=${word(20)}1`) });
    err.stack = `Error: x\n    at f (/home/${user}/secret-dir/a.js:1:1)`;
    Object.assign(err, { path: `/home/${user}/x`, config: { header: 'Bearer abc' } });
    const same = (s: string) => s; // the CLI masks IPs with its own maskIps
    expect(fatalLine(err, same)).toBe('error: cannot open /home/<usuario>/x');
    expect(fatalLine(`a string with ${user}`, same)).toBe(`error: a string with ${user}`);
    expect(fatalLine({ no: 'message' }, same)).toBe('error: [object]');
    expect(fatalLine(undefined, same)).toBe('error: [undefined]');
  });

  it('NFR007-03: manual-export writes the clean report only to the file asked for with --crash-report, and keeps nothing on the device', async () => {
    const { dataDir, direct } = await device();
    const user = `u${word(9)}`;
    const missing = `/home/${user}/fuentes/${word(8)}.txt`;
    const out = join(dataDir, 'informe.json');
    const failed = await cli(dataDir, 'group', 'send-file', '--persona', direct, '--group', 'g', '--file', missing, '--crash-report', out);
    expect(failed.status).toBe(1);
    expect(failed.stderr).toMatch(/^error: ENOENT: no such file or directory, open '\/home\/<usuario>\/fuentes\/[a-z]+\.txt'$/m);
    expect(failed.stderr).toMatch(/^informe de fallo limpio escrito en .*informe\.json: revísalo antes de compartirlo; no se ha enviado nada$/m);
    const text = readFileSync(out, 'utf8');
    expect(statSync(out).mode & 0o777).toBe(0o600);
    const report = JSON.parse(text) as CrashReport;
    expect(parseCrashReport(report)).toEqual(report); // what the file holds is a report and nothing else
    expect(report).toMatchObject({ format: 'acceso-nostr-crash-report', app: { name: 'sovereign-cli', version: '0.1.0' }, profile: 'sovereign', source: 'fatal', environment: { runtime: 'node' }, error: { name: 'Error', message: "ENOENT: no such file or directory, open '[ruta]'" } });
    expect(report.error.stack.find((f) => f.startsWith('at readGroupFile'))).toMatch(/^at readGroupFile \(sovereign-client\/cli\.ts:\d+:\d+\)$/);
    for (const value of [user, missing, direct, '/home/']) expect(text).not.toContain(value);
    expect(reportFiles(dataDir, direct)).toEqual([]);
    // Without --crash-report: only how to get one.
    const again = await cli(dataDir, 'group', 'send-file', '--persona', direct, '--group', 'g', '--file', missing);
    expect(again.stderr).toMatch(/^aviso: para guardar un informe limpio de este fallo, repite el comando con --crash-report ARCHIVO$/m);
    expect(reportFiles(dataDir, direct)).toEqual([]);
  }, 90_000);

  it('NFR007-03: opt-in keeps each report sealed in the persona store, lists, shows, exports and deletes them for real', async () => {
    const { dataDir, direct } = await device();
    const user = `u${word(9)}`;
    const set = await cli(dataDir, 'persona', 'crash-reports', '--persona', direct, 'opt-in');
    expect(set.status, set.stderr).toBe(0);
    expect(set.stdout).toBe('informes de fallo: opt-in\n');
    expect(set.stderr).toMatch(/^aviso: Informes de fallo guardados: .*como máximo 20 informes y 30 días cada uno/m);
    for (const args of [['--file', `/home/${user}/a.txt`], ['--file', `/home/${user}/b.txt`], []]) {
      const r = await cli(dataDir, 'group', 'send-file', '--persona', direct, '--group', 'g', ...args);
      expect(r.status).toBe(1);
      expect(r.stderr).toMatch(new RegExp(`^aviso: el informe limpio de este fallo queda guardado cifrado en este dispositivo \\(sovereign crash-report list --persona ${direct}\\)$`, 'm'));
    }
    // Two different failures (the same one twice counts twice), each in a file of the persona's store, sealed.
    const files = reportFiles(dataDir, direct);
    expect(files).toHaveLength(2);
    for (const f of files) {
      const raw = readFileSync(join(dataDir, 'personas', direct, f)).toString('latin1');
      for (const clear of ['acceso-nostr-crash-report', 'ENOENT', 'readGroupFile']) expect(raw).not.toContain(clear);
    }
    const list = await cli(dataDir, 'crash-report', 'list', '--persona', direct);
    expect(list.status, list.stderr).toBe(0);
    const rows = list.stdout.trimEnd().split('\n');
    expect(rows.at(-1)).toBe('2 informes guardados');
    expect(rows.slice(0, 2).map((l) => l.replace(/^[0-9a-f]{16}  \S+  /, ''))).toEqual(['  1 veces  Error: --file PATH required', "  2 veces  Error: ENOENT: no such file or directory, open '[ruta]'"]);
    const enoent = rows[1]!.slice(0, 16);
    const shown = await cli(dataDir, 'crash-report', 'show', '--persona', direct, '--id', enoent);
    const report = JSON.parse(shown.stdout) as CrashReport;
    expect(parseCrashReport(report)).toEqual(report);
    expect(shown.stdout).not.toContain(user);
    const out = join(dataDir, 'exportado.json');
    const exported = await cli(dataDir, 'crash-report', 'export', '--persona', direct, '--id', enoent, '--out', out);
    expect(exported.stdout).toMatch(/^informe [0-9a-f]{16} exportado a .*exportado\.json: revísalo antes de compartirlo; no se ha enviado nada$/m);
    expect([readFileSync(out, 'utf8'), statSync(out).mode & 0o777]).toEqual([shown.stdout, 0o600]);
    const one = await cli(dataDir, 'crash-report', 'clear', '--persona', direct, '--id', enoent);
    expect([one.stdout, reportFiles(dataDir, direct).length]).toEqual([`informe ${enoent} borrado\n`, 1]);
    const rest = await cli(dataDir, 'crash-report', 'clear', '--persona', direct);
    expect([rest.stdout, reportFiles(dataDir, direct)]).toEqual(['1 informes borrados\n', []]);
    // Back to manual-export: nothing more is kept.
    expect((await cli(dataDir, 'persona', 'crash-reports', '--persona', direct, 'manual-export')).status).toBe(0);
    await cli(dataDir, 'group', 'send-file', '--persona', direct, '--group', 'g');
    expect(reportFiles(dataDir, direct)).toEqual([]);
  }, 180_000);

  it('NFR007-03: a Tor-only persona generates no report by default and refuses opt-in; manual-export is allowed', async () => {
    const { dataDir, tor } = await device();
    const out = join(dataDir, 'tor.json');
    const failed = await cli(dataDir, 'group', 'send-file', '--persona', tor, '--group', 'g', '--crash-report', out);
    expect(failed.status).toBe(1);
    expect(failed.stderr).toMatch(/^aviso: esta persona no genera informes de fallo \(crashReports: off\): no se ha escrito .*tor\.json$/m);
    expect(existsSync(out)).toBe(false);
    const refused = await cli(dataDir, 'persona', 'crash-reports', '--persona', tor, 'opt-in');
    expect(refused.status).toBe(1);
    expect(refused.stderr).toMatch(/^error: En Tor-only los informes de fallo no se guardan en el dispositivo: elige off o manual-export/m);
    expect((await cli(dataDir, 'disclose', '--persona', tor)).stdout).toMatch(/^• \[crashReports=off\] Sin informes de fallo/m);
    const manual = await cli(dataDir, 'persona', 'crash-reports', '--persona', tor, 'manual-export');
    expect(manual.status, manual.stderr).toBe(0);
    const written = await cli(dataDir, 'group', 'send-file', '--persona', tor, '--group', 'g', '--crash-report', out);
    expect(written.status).toBe(1);
    expect((JSON.parse(readFileSync(out, 'utf8')) as CrashReport).profile).toBe('sovereign-tor');
    expect(reportFiles(dataDir, tor)).toEqual([]);
  }, 120_000);
});
