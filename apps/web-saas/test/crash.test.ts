/**
 * NFR007-03: the web captures failures as the active persona's profile says: nothing in 'off' (no listener at all),
 * the last report in memory in 'manual-export', and also sealed in the browser vault in 'opt-in'. A report leaves
 * only as the file the person saves, exactly as previewed.
 */
import { describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { EncryptedStore, MemoryBackend } from '@sedecim/encrypted-store';
import { crashReportJson, type CrashReport } from '@sedecim/telemetry-policy/crash-report';
import { CRASH_COLLECTION, crashStore, downloadCrashReport, WebCrashReports, webCrashReports } from '../src/lib/crash';
import { CrashBoundary } from '../src/views/CrashReports';

const UA = 'Mozilla/5.0 (Linux; Android 14; SM-S918B Build/UP1A.231005.007) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.70 Mobile Safari/537.36';

/** An EventTarget that counts the listeners it holds. */
function windowLike() {
  const target = new EventTarget();
  const held = new Set<string>();
  return {
    held,
    addEventListener: (type: string, fn: (e: Event) => void) => (held.add(type), target.addEventListener(type, fn)),
    removeEventListener: (type: string, fn: (e: Event) => void) => (held.delete(type), target.removeEventListener(type, fn)),
    dispatch: (type: string, fields: Record<string, unknown>) => target.dispatchEvent(Object.assign(new Event(type), fields)),
  };
}

/** Values that must not reach a report, sown in a failure of the page. */
function poisonedFailure() {
  const user = `u${randomBytes(5).toString('hex').replace(/\d/g, 'x')}`;
  const pubkey = randomBytes(32).toString('hex');
  const text = `nos vemos en la plaza ${randomBytes(4).toString('hex').replace(/\d/g, 'y')}`;
  const err = new TypeError(`cannot render "${text}" of ${pubkey} from https://relay.example.org/?token=${randomBytes(12).toString('hex')}`, { cause: new Error(`at /home/${user}/x.txt`) });
  err.stack = `TypeError: ${err.message}\n    at Persona (https://app.example.org/assets/index-B5t3Xk2a.js:1:99)\n    at /home/${user}/project/apps/web-saas/src/views/PanelView.tsx:3:4`;
  return { err, values: [user, pubkey, text, 'relay.example.org', 'app.example.org'] };
}

const vault = () => EncryptedStore.withKey(new MemoryBackend(), randomBytes(32));
const rawEntries = (store: EncryptedStore) => [...(store.raw as MemoryBackend).data].filter(([k]) => k.startsWith(`${CRASH_COLLECTION}:`));

describe('web crash reports (NFR007-03)', () => {
  it('NFR007-03: off holds no listener and captures nothing; a profile that captures adds them, locking removes them and forgets', () => {
    const win = windowLike();
    const crash = new WebCrashReports(win, UA);
    crash.configure({ mode: 'off' });
    win.dispatch('error', { error: new Error('boom'), message: 'boom' });
    expect([win.held.size, crash.capture.lastReport()]).toEqual([0, undefined]);
    crash.configure({ mode: 'manual-export', profile: 'convenience' });
    expect([...win.held].sort()).toEqual(['error', 'unhandledrejection']);
    const { err, values } = poisonedFailure();
    win.dispatch('error', { error: err, message: err.message });
    const fromError = crash.capture.lastReport()!;
    expect(fromError).toMatchObject({ app: { name: 'acceso-nostr-web' }, profile: 'convenience', source: 'error', environment: { os: 'android', runtime: 'chrome', runtimeMajor: 129 }, error: { name: 'TypeError', cause: { name: 'Error', message: 'at [ruta]' } } });
    expect(fromError.error.stack).toEqual(['at Persona (index-B5t3Xk2a.js:1:99)', 'at web-saas/PanelView.tsx:3:4']);
    win.dispatch('unhandledrejection', { reason: `${values[1]} ${values[2]}` });
    expect(crash.capture.lastReport()).toMatchObject({ source: 'unhandledrejection', error: { name: '_NonError', message: '[string]' } });
    // A script of another origin gives only a message and a position.
    win.dispatch('error', { error: null, message: 'Script error.', filename: `https://cdn.example.org/${values[0]}/lib.js`, lineno: 1, colno: 2 });
    expect(crash.capture.lastReport()?.error).toEqual({ name: '_OTHER', message: 'Script error.', stack: ['at lib.js:1:2'] });
    const json = [fromError, crash.capture.lastReport()!].map(crashReportJson).join('');
    for (const v of values) expect(json).not.toContain(v);
    expect(json).not.toContain('SM-S918B');
    crash.configure({ mode: undefined }); // locked: no persona
    expect([win.held.size, crash.capture.lastReport()]).toEqual([0, undefined]);
  });

  it('NFR007-03: manual-export keeps nothing in the vault; opt-in keeps the report sealed in it, and clearing deletes the entries', async () => {
    const store = vault();
    const win = windowLike();
    const crash = new WebCrashReports(win, UA);
    crash.configure({ mode: 'manual-export', store });
    const { err, values } = poisonedFailure();
    win.dispatch('error', { error: err, message: err.message });
    await new Promise((r) => setTimeout(r, 20));
    expect(rawEntries(store)).toEqual([]);
    crash.configure({ mode: 'opt-in', profile: 'convenience', store });
    win.dispatch('error', { error: err, message: err.message });
    await new Promise((r) => setTimeout(r, 20));
    const entries = rawEntries(store);
    expect(entries).toHaveLength(1);
    // Sealed with the vault key: neither the format nor the text of the report is readable in the backend.
    const raw = Buffer.from(entries[0]![1]).toString('latin1');
    for (const clear of ['acceso-nostr-crash-report', 'TypeError', 'texto']) expect(raw).not.toContain(clear);
    const kept = await crashStore(store).list();
    expect(kept.map((r) => r.report)).toEqual([crash.capture.lastReport()]);
    for (const v of values) expect(JSON.stringify(kept)).not.toContain(v);
    expect(await crashStore(store).clear()).toBe(1);
    expect(rawEntries(store)).toEqual([]);
  });

  it('NFR007-03: a failing view is captured with its component stack by the boundary, which says where the report is only when there is one', () => {
    const crash = webCrashReports();
    const boundary = new CrashBoundary({ children: null });
    const componentStack = '\n    at PanelView (http://localhost:5173/src/views/PanelView.tsx?t=1:30:20)\n    at div';
    crash.configure({ mode: 'off' });
    boundary.componentDidCatch(new Error('render'), { componentStack });
    expect(crash.capture.lastReport()).toBeUndefined();
    boundary.state = CrashBoundary.getDerivedStateFromError();
    const offText = renderToStaticMarkup(createElement(() => boundary.render()));
    expect(offText).toContain('Esta sección ha fallado y se ha detenido');
    expect(offText).not.toContain('Informes de fallo');
    crash.configure({ mode: 'manual-export' });
    boundary.componentDidCatch(new RangeError('render'), { componentStack });
    expect(crash.capture.lastReport()).toMatchObject({ source: 'component', error: { name: 'RangeError' }, componentStack: ['at PanelView (PanelView.tsx:30:20)', 'at div'] });
    expect(renderToStaticMarkup(createElement(() => boundary.render()))).toContain('«Informes de fallo»');
    crash.configure({ mode: 'off' });
  });

  it('NFR007-03: the file holds exactly the previewed JSON, saved by the browser without any request', async () => {
    const crash = new WebCrashReports(undefined, UA);
    crash.configure({ mode: 'manual-export' });
    const report = crash.capture.capture(poisonedFailure().err, 'error') as CrashReport;
    const g = globalThis as Record<string, unknown>;
    const saved = { document: g.document, fetch: g.fetch, create: URL.createObjectURL, revoke: URL.revokeObjectURL };
    const blobs: Blob[] = [];
    const clicked: Array<{ href: string; download: string }> = [];
    let requests = 0;
    g.fetch = () => {
      requests++;
      throw new Error('no network');
    };
    g.document = { createElement: () => ({ href: '', download: '', click(this: { href: string; download: string }) { clicked.push({ href: this.href, download: this.download }); } }) };
    URL.createObjectURL = (b: Blob) => (blobs.push(b), 'blob:report');
    URL.revokeObjectURL = () => undefined;
    try {
      downloadCrashReport(report);
    } finally {
      Object.assign(g, { document: saved.document, fetch: saved.fetch });
      URL.createObjectURL = saved.create;
      URL.revokeObjectURL = saved.revoke;
    }
    expect(clicked).toEqual([{ href: 'blob:report', download: 'acceso-nostr-informe-de-fallo.json' }]);
    expect(blobs[0]!.type).toBe('application/json');
    expect(await blobs[0]!.text()).toBe(crashReportJson(report));
    expect(requests).toBe(0);
  });
});
