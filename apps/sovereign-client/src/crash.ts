import { readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import type { EncryptedStore } from '@sedecim/encrypted-store';
import { buildCrashReport, CrashReportStore, crashReportJson, nodeEnvironment, redactFreeText, type CrashReport, type CrashReportsMode, type CrashSource, type StoredCrashReport } from '@sedecim/telemetry-policy';

/*
 * NFR007-03 (docs/crash-reports.md): what a failure of the CLI leaves behind. stderr gets one line with the message
 * only, cleaned of secrets; a report exists only if the persona's profile allows it, and it is never sent: with
 * --crash-report FILE it is written to that file, and in 'opt-in' it is kept sealed in the persona's store.
 */

/** Persona-store collection with the opt-in reports, sealed with the passphrase like everything in that store. */
export const CRASH_COLLECTION = 'crash-reports';

const APP_VERSION = (JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version?: string }).version ?? '0.0.0';

export function crashStoreOf(store: EncryptedStore): CrashReportStore {
  return new CrashReportStore(store.collection<StoredCrashReport>(CRASH_COLLECTION));
}

/** The report of a failure of the CLI: the generic environment of this Node, never the persona. */
export function cliCrashReport(thrown: unknown, profile: string, source: CrashSource): CrashReport {
  return buildCrashReport(thrown, { app: 'sovereign-cli', appVersion: APP_VERSION, profile, environment: nodeEnvironment(process.platform, process.versions.node), source });
}

/** The message of whatever was thrown; a value that is not an error, by its type. */
function messageOf(thrown: unknown): string {
  if (typeof thrown === 'string') return thrown;
  try {
    const message = thrown !== null && typeof thrown === 'object' ? (thrown as { message?: unknown }).message : undefined;
    return typeof message === 'string' ? message : `[${thrown === null ? 'null' : typeof thrown}]`;
  } catch {
    return '[unreadable]';
  }
}

/**
 * Text for the person's terminal: without secrets (`redactFreeText`, the home directory as `~`) and with IPs masked
 * as everywhere else in the CLI (`maskIps`). Host names and .onion addresses stay: they say which relay failed.
 */
export function terminalText(text: string, maskIps: (s: string) => string): string {
  return maskIps(redactFreeText(text, { home: homedir() }));
}

/** The one line a fatal failure prints: never the stack, the cause or any other field of the error. */
export function fatalLine(thrown: unknown, maskIps: (s: string) => string): string {
  return `error: ${terminalText(messageOf(thrown), maskIps)}`;
}

export interface CrashTarget {
  mode: CrashReportsMode;
  /** `sovereign` or `sovereign-tor`. */
  profile: string;
  store: CrashReportStore;
}

/**
 * After a fatal failure: the report the persona's profile allows, and the lines that say what became of it. 'off',
 * no persona, or a persona whose profile cannot be read: no report. 'manual-export': only to `reportFile`, if given.
 * 'opt-in': also kept in the persona's store.
 */
export async function reportAfterFailure(thrown: unknown, source: CrashSource, opts: { persona?: string; reportFile?: string; target: () => Promise<CrashTarget | undefined>; maskIps: (s: string) => string }): Promise<string[]> {
  const notes: string[] = [];
  const target = opts.persona ? await opts.target().catch(() => undefined) : undefined;
  const file = opts.reportFile && terminalText(opts.reportFile, opts.maskIps);
  if (!target || target.mode === 'off') {
    if (file) notes.push(`aviso: ${target ? 'esta persona no genera informes de fallo (crashReports: off)' : 'sin una persona que los permita no hay informe de fallo'}: no se ha escrito ${file}`);
    return notes;
  }
  const report = cliCrashReport(thrown, target.profile, source);
  if (target.mode === 'opt-in') {
    await target.store.save(report);
    notes.push(`aviso: el informe limpio de este fallo queda guardado cifrado en este dispositivo (sovereign crash-report list --persona ${opts.persona})`);
  }
  if (opts.reportFile) {
    try {
      writeFileSync(opts.reportFile, crashReportJson(report), { mode: 0o600, flag: 'wx' });
      notes.push(`informe de fallo limpio escrito en ${file}: revísalo antes de compartirlo; no se ha enviado nada`);
    } catch (err) {
      notes.push(`aviso: no se pudo escribir el informe de fallo: ${terminalText(messageOf(err), opts.maskIps)}`);
    }
  } else notes.push('aviso: para guardar un informe limpio de este fallo, repite el comando con --crash-report ARCHIVO');
  return notes;
}
